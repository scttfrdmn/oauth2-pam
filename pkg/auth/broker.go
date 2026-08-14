package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/mapper"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider/registry"
	"github.com/scttfrdmn/oauth2-pam/pkg/security"
)

// Session status values. These are the wire values carried in the IPC
// response's "status" field and are the authoritative signal a client uses to
// decide what to do next.
//
// The central invariant, relied on by the PAM module and enforced by
// successResponse/pendingResponse/errorResponse below:
//
//	Success == true  if and only if  Status == StatusAuthorized
//
// and UserID (the mapped local Unix username) is populated only in that case.
// A client must never treat any other status as an authenticated user.
const (
	// StatusPending means a device flow is in progress: the user has been
	// given a code and URL but has not yet completed authorization at the
	// provider. The client should keep polling check_session.
	StatusPending = "pending"

	// StatusAuthorized means the device flow completed, the identity was
	// mapped, and the mapped local user matched the requested login. This is
	// the only status that grants access.
	StatusAuthorized = "authorized"

	// StatusDenied means the attempt was rejected: the user declined at the
	// provider, access controls refused them, or the mapped local user did
	// not match the requested login. Terminal; do not retry by polling.
	StatusDenied = "denied"

	// StatusExpired means the device code or session lifetime elapsed before
	// authorization completed. Terminal.
	StatusExpired = "expired"

	// StatusError means the attempt failed for an operational reason (provider
	// unreachable, mapping service down, internal error) rather than a
	// decision about the user. Terminal.
	StatusError = "error"
)

// terminalGrace is how long a failed session is retained so that a polling
// client learns the real outcome instead of "session not found", which is
// indistinguishable from a bad or forged session ID.
const terminalGrace = 2 * time.Minute

// maxPendingFlowsPerUser bounds how many device flows one requested username
// may have in flight at once. Pending flows deliberately do not count toward
// Authentication.MaxConcurrentSessions (abandoned SSH attempts would otherwise
// lock the user out until cleanup ran), so this const keeps that state
// bounded. Exceeding it evicts the oldest pending flow rather than rejecting
// the new one, so a user opening several terminals is never locked out.
const maxPendingFlowsPerUser = 3

// Broker manages authentication requests, device flows, and sessions.
type Broker struct {
	config *config.Config
	// providers in configuration order; providers[0] is the default for a request
	// that does not name one. byName indexes the same values.
	providers    []provider.Provider
	byName       map[string]provider.Provider
	mapper       *mapper.Chain
	tokenManager *TokenManager
	auditLogger  *security.AuditLogger
	sessions     map[string]*Session
	// pollCancel holds the cancel function for each session's polling goroutine,
	// guarded by sessionMutex alongside sessions. Without it, a session that was
	// evicted, revoked, or failed left its poller running until the provider's
	// device code expired — still hitting the provider every few seconds, no
	// longer counted by countPendingFlows, and with nowhere to deliver a result.
	pollCancel   map[string]context.CancelFunc
	sessionMutex sync.RWMutex
	stopChan     chan struct{}
	wg           sync.WaitGroup
	// ctx is stored at Start() so background goroutines share the broker lifecycle.
	ctx context.Context
}

// Session represents an authentication session in any state — pending,
// authorized, or terminally failed.
type Session struct {
	ID                 string
	TokenID            string // key into TokenManager for the stored access token
	LocalUser          string
	RequestedLocalUser string // UserID from the PAM auth request; used by Tier 0 enrollment
	// ProviderLogin is the identity's username at the provider, whatever that
	// provider calls it.
	ProviderLogin    string
	Email            string
	Groups           []string
	Provider         string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	LastAccessed     time.Time
	SourceIP         string
	TokenFingerprint string
	// Status is one of the Status* constants. IsActive is retained as the
	// single boolean gate on access and is true only when Status is
	// StatusAuthorized.
	Status       string
	ErrorMessage string
	IsActive     bool
	Metadata     map[string]string
}

// AuthRequest is an authentication request from the PAM module.
type AuthRequest struct {
	UserID     string
	SourceIP   string
	UserAgent  string
	TargetHost string
	LoginType  string // "ssh", "console", "gui"
	DeviceID   string
	SessionID  string
	Timestamp  time.Time
	Metadata   map[string]string

	// Provider names which configured provider to authenticate against. Empty
	// means the first one configured, which is the whole story on a
	// single-provider host; a name that is not configured is an error rather
	// than a silent fall back to the default.
	Provider string
}

// AuthResponse is the broker's response to an auth request.
//
// Status is the field clients must branch on. Success is a convenience mirror
// of Status == StatusAuthorized and nothing else; see the Status* constants.
type AuthResponse struct {
	Success          bool
	Status           string // one of the Status* constants
	UserID           string // local Unix username; set only when authorized
	Email            string
	Groups           []string
	SessionID        string
	DeviceCode       string // user-visible code (e.g. "ABCD-1234")
	DeviceURL        string
	QRCode           string
	ExpiresAt        time.Time
	RequiresDevice   bool
	RequiresApproval bool
	ErrorCode        string
	ErrorMessage     string
	Metadata         map[string]string
}

// NewBroker creates and validates a new Broker whose providers talk to
// github.com.
func NewBroker(cfg *config.Config) (*Broker, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if len(cfg.Providers) == 0 {
		return nil, fmt.Errorf("at least one provider must be configured")
	}

	// The registry maps providers[].type to an implementation, so a new provider
	// type needs no change here.
	providers, err := registry.NewAll(cfg)
	if err != nil {
		return nil, err
	}

	return NewBrokerWithProviders(cfg, providers)
}

// NewBrokerWithProviders creates a Broker from already-constructed providers.
// It exists so callers can supply providers the registry would not build from
// config alone — pointed at a GitHub Enterprise Server, at the fake GitHub the
// end-to-end tests run against, or at a test double implementing the interface.
//
// The first provider is the default for requests that do not name one.
func NewBrokerWithProviders(cfg *config.Config, providers []provider.Provider) (*Broker, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if cfg.Server.SocketPath == "" {
		return nil, fmt.Errorf("server.socket_path is required")
	}
	if len(providers) == 0 {
		return nil, fmt.Errorf("at least one provider must be configured")
	}

	tokenManager, err := NewTokenManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("token manager: %w", err)
	}

	auditLogger, err := security.NewAuditLogger(cfg.Audit)
	if err != nil {
		return nil, fmt.Errorf("audit logger: %w", err)
	}

	byName := make(map[string]provider.Provider, len(providers))
	for _, p := range providers {
		if _, dup := byName[p.Name()]; dup {
			// config.Validate rejects duplicate names, but a caller constructing
			// providers directly bypasses it, and a silently shadowed provider
			// would make audit records ambiguous.
			return nil, fmt.Errorf("two providers are both named %q", p.Name())
		}
		byName[p.Name()] = p
	}

	return &Broker{
		config:       cfg,
		providers:    providers,
		byName:       byName,
		mapper:       mapper.New(cfg.Mapper),
		tokenManager: tokenManager,
		auditLogger:  auditLogger,
		sessions:     make(map[string]*Session),
		pollCancel:   make(map[string]context.CancelFunc),
		stopChan:     make(chan struct{}),
	}, nil
}

// Start starts the broker background services.
func (b *Broker) Start(ctx context.Context) error {
	b.ctx = ctx
	log.Info().Msg("Starting oauth2-pam broker services")

	if err := b.tokenManager.Start(ctx); err != nil {
		return fmt.Errorf("start token manager: %w", err)
	}
	if err := b.auditLogger.Start(ctx); err != nil {
		return fmt.Errorf("start audit logger: %w", err)
	}

	b.wg.Add(1)
	go b.sessionCleanup(ctx)

	log.Info().Msg("oauth2-pam broker services started")
	return nil
}

// Stop shuts down broker background services.
func (b *Broker) Stop() error {
	log.Info().Msg("Stopping oauth2-pam broker services")

	close(b.stopChan)
	b.wg.Wait()

	if err := b.tokenManager.Stop(); err != nil {
		log.Error().Err(err).Msg("Error stopping token manager")
	}
	if err := b.auditLogger.Stop(); err != nil {
		log.Error().Err(err).Msg("Error stopping audit logger")
	}

	log.Info().Msg("oauth2-pam broker services stopped")
	return nil
}

// Authenticate handles an authentication request from the PAM module.
//
// It starts a Device Flow and returns Status == StatusPending with the user
// code and URL. It deliberately never returns Success == true: at this point
// the user has not yet visited the provider, so there is nothing to grant. The
// client must display the instructions and then poll CheckSession until the
// status becomes terminal.
func (b *Broker) Authenticate(req *AuthRequest) (*AuthResponse, error) {
	log.Debug().
		Str("user_id", req.UserID).
		Str("source_ip", req.SourceIP).
		Str("login_type", req.LoginType).
		Msg("Processing authentication request")

	b.auditLogger.LogAuthEvent(security.AuditEvent{
		EventType:  "authentication_attempt",
		UserID:     req.UserID,
		SourceIP:   req.SourceIP,
		TargetHost: req.TargetHost,
		AuthMethod: req.LoginType,
		Success:    false,
		Timestamp:  time.Now(),
	})

	prov, err := b.selectProvider(req.Provider)
	if err != nil {
		log.Warn().Err(err).Str("provider", req.Provider).Msg("Cannot select a provider")
		return errorResponse("NO_PROVIDER", err.Error()), nil
	}

	// Enforce the per-user limit on *established* sessions. Pending flows are
	// counted separately below: an abandoned SSH attempt must not consume a
	// session slot.
	if max := b.config.Authentication.MaxConcurrentSessions; max > 0 {
		if b.countUserSessions(req.UserID) >= max {
			return &AuthResponse{
				Success:      false,
				Status:       StatusDenied,
				ErrorCode:    "SESSION_LIMIT_REACHED",
				ErrorMessage: "Maximum concurrent sessions reached",
			}, nil
		}
	}

	// Global cap on device flows awaiting authorization. Each one holds a
	// goroutine polling the provider, so this bounds the work a burst of login
	// attempts can create broker-wide.
	//
	// Checked before eviction, not after. The other order made the cap
	// unreachable for a single username: eviction keeps that user's pending count
	// at maxPendingFlowsPerUser, so countPendingFlows never climbed toward the
	// global limit however many requests arrived. Verified before the fix: a cap
	// of 10 accepted 30 requests.
	if max := b.config.Security.RateLimiting.MaxConcurrentAuths; max > 0 {
		if n := b.countPendingFlows(); n >= max {
			log.Warn().Int("pending", n).Int("max", max).
				Msg("Concurrent device flow limit reached; rejecting authentication")
			return errorResponse("AUTH_LIMIT_REACHED",
				"Too many authentications in progress; try again shortly"), nil
		}
	}

	// Bound in-flight device flows for this user, evicting the oldest.
	b.evictExcessPendingFlows(req.UserID)

	// Start device flow
	deviceFlow, err := prov.StartDeviceFlow(b.ctx)
	if err != nil {
		b.auditLogger.LogAuthEvent(security.AuditEvent{
			EventType:    "device_flow_failed",
			UserID:       req.UserID,
			SourceIP:     req.SourceIP,
			TargetHost:   req.TargetHost,
			Provider:     prov.Name(),
			Success:      false,
			ErrorMessage: err.Error(),
			Timestamp:    time.Now(),
		})
		return errorResponse("DEVICE_FLOW_FAILED", err.Error()), nil
	}

	// The provider chose these two strings, and they are printed to a terminal by
	// a root process before anyone has authenticated — so they are sanitized here,
	// once, at the point they enter an AuthResponse.
	//
	// Sanitizing them in the prompt formatters is not sufficient, and it was
	// tempting to stop there. The reply also carries device_url and device_code as
	// their own fields, and docs/wire-protocol.md describes them as "the parts, for
	// a client that wants to format its own prompt" — an invitation this project
	// extends to consumers it does not control. A consumer that accepts it would
	// receive raw provider bytes and draw them on a pre-auth tty. The contract has
	// to be clean at the boundary, not merely clean by the time this
	// implementation's own formatter is done with it.
	//
	// For github.com this is theoretical. For a configured Enterprise base_url it
	// is not: that server picks verification_uri and user_code, so without this it
	// picks what every host configured against it draws on screen. See #45.
	deviceURL := SanitizePromptValue(deviceFlow.DeviceURL)
	userCode := SanitizePromptValue(deviceFlow.UserCode)

	// Generated from the sanitized URL, so the QR encodes what the text says.
	qrCode, err := GenerateQRCode(deviceURL)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate QR code")
		qrCode = ""
	}

	// Generate a cryptographically random session ID server-side.
	// The PAM client's req.SessionID is intentionally ignored to prevent
	// session fixation attacks.
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("generate session ID: %w", err)
	}

	// The flow lives until the user approves it, but no longer than the broker is
	// willing to wait — see AuthenticationConfig.DeviceFlowTimeout for why the
	// provider's own expiry is the wrong bound.
	expiresAt := b.deviceFlowDeadline(deviceFlow)

	// Create a pending session
	session := &Session{
		ID:                 sessionID,
		RequestedLocalUser: req.UserID,
		Provider:           prov.Name(),
		CreatedAt:          time.Now(),
		ExpiresAt:          expiresAt,
		LastAccessed:       time.Now(),
		SourceIP:           req.SourceIP,
		Status:             StatusPending,
		IsActive:           false,
		Metadata:           req.Metadata,
	}
	b.setSession(session)

	// Poll in the background; update session when the device flow completes.
	// The poller's context is cancelled the moment the session stops being
	// interesting, so a login nobody is waiting for stops talking to the provider.
	pollCtx, cancel := context.WithCancel(b.baseContext())
	b.sessionMutex.Lock()
	b.pollCancel[sessionID] = cancel
	b.sessionMutex.Unlock()

	b.wg.Add(1)
	go b.pollDeviceAuthorization(pollCtx, sessionID, prov, deviceFlow, expiresAt)

	// Success is false: a started device flow is not an authenticated user.
	return &AuthResponse{
		Success:        false,
		Status:         StatusPending,
		SessionID:      sessionID,
		DeviceCode:     userCode,
		DeviceURL:      deviceURL,
		QRCode:         qrCode,
		ExpiresAt:      expiresAt,
		RequiresDevice: true,
		Metadata: map[string]string{
			"provider":         prov.Name(),
			"polling_interval": fmt.Sprintf("%d", deviceFlow.PollingInterval),
		},
	}, nil
}

// CheckSession returns the current state of a session. This is the call the
// PAM module polls while the user completes the device flow.
func (b *Broker) CheckSession(sessionID string) (*AuthResponse, error) {
	session := b.getSession(sessionID)
	if session == nil {
		return &AuthResponse{
			Success:      false,
			Status:       StatusError,
			ErrorCode:    "SESSION_NOT_FOUND",
			ErrorMessage: "Session not found",
		}, nil
	}

	// Terminal failure recorded by the background poller. Reported verbatim so
	// the client can stop polling immediately instead of waiting out its
	// deadline on a flow that will never complete.
	switch session.Status {
	case StatusDenied, StatusExpired, StatusError:
		return &AuthResponse{
			Success:      false,
			Status:       session.Status,
			SessionID:    sessionID,
			ErrorCode:    terminalErrorCode(session.Status),
			ErrorMessage: session.ErrorMessage,
		}, nil
	}

	if !session.IsActive {
		if session.ExpiresAt.Before(time.Now()) {
			// Device code lifetime elapsed without the poller noticing yet.
			b.failSession(sessionID, StatusExpired, "Device authorization expired")
			return &AuthResponse{
				Success:      false,
				Status:       StatusExpired,
				SessionID:    sessionID,
				ErrorCode:    "SESSION_EXPIRED",
				ErrorMessage: "Device authorization expired",
			}, nil
		}
		return &AuthResponse{
			Success:        false,
			Status:         StatusPending,
			SessionID:      sessionID,
			RequiresDevice: true,
			ExpiresAt:      session.ExpiresAt,
		}, nil
	}

	if session.ExpiresAt.Before(time.Now()) {
		b.removeSession(sessionID)
		return &AuthResponse{
			Success:      false,
			Status:       StatusExpired,
			ErrorCode:    "SESSION_EXPIRED",
			ErrorMessage: "Session has expired",
		}, nil
	}

	return b.successResponse(session), nil
}

// terminalErrorCode maps a terminal status to the wire error code.
func terminalErrorCode(status string) string {
	switch status {
	case StatusDenied:
		return "AUTHENTICATION_DENIED"
	case StatusExpired:
		return "SESSION_EXPIRED"
	default:
		return "AUTHENTICATION_FAILED"
	}
}

// RefreshSession extends a session if it is close to expiry.
//
// A refresh is an extension of something that is still live, never a second
// chance at an authorization. Three things must hold; only the first of them used
// to be checked:
//
//   - The session is authorized. A pending or terminally failed session has
//     nothing to extend.
//   - It has not already expired. An expired session is removed and answered
//     SESSION_EXPIRED, exactly as CheckSession does — the two verbs used to
//     disagree, and a client that called refresh_session first never reached the
//     check that would have noticed, so an expired session came back authorized
//     with an hour added to it.
//   - It is not past the absolute security.max_token_age ceiling. That is the
//     one bound a refresh loop cannot talk its way around; see #43.
//
// The extension itself goes through extendSession, a compare-and-set, because
// the session read here is a snapshot and writing it back wholesale undid any
// concurrent revocation.
func (b *Broker) RefreshSession(sessionID string) (*AuthResponse, error) {
	session := b.getSession(sessionID)
	if session == nil {
		return errorResponse("SESSION_NOT_FOUND", "Session not found"), nil
	}

	// Only an authorized session can be refreshed; a pending or failed one has
	// nothing to extend.
	if !session.IsActive || session.Status != StatusAuthorized {
		return &AuthResponse{
			Success:      false,
			Status:       session.Status,
			SessionID:    sessionID,
			ErrorCode:    "SESSION_NOT_ACTIVE",
			ErrorMessage: "Session is not authorized",
		}, nil
	}

	now := time.Now()

	if session.ExpiresAt.Before(now) {
		b.removeSession(sessionID)
		return expiredSessionResponse(sessionID, "Session has expired"), nil
	}

	// The absolute age ceiling, checked before the "no extension needed" branch
	// below so that neither answer can report a session the operator's policy
	// says is over as authorized. Past it the session is revoked rather than
	// refused-and-left: its token is destroyed at the provider, which is the
	// whole point of having a ceiling.
	if b.pastMaxTokenAge(session, now) {
		log.Info().
			Str("session_id", sessionID).
			Str("local_user", session.LocalUser).
			Dur("age", now.Sub(session.CreatedAt)).
			Dur("max_token_age", b.config.Security.MaxTokenAge).
			Msg("Session reached security.max_token_age; revoking instead of extending")
		if err := b.RevokeSession(sessionID); err != nil {
			log.Warn().Err(err).Str("session_id", sessionID).
				Msg("Failed to revoke a session past max_token_age")
		}
		return expiredSessionResponse(sessionID,
			"Session has reached the maximum permitted age"), nil
	}

	// The token is what the session authorizes the use of. If it no longer
	// resolves it has been revoked or has aged out of the store, and the session
	// is a shell that must not be reported as authorized — let alone extended.
	//
	// This is deliberately a second, independent check on the same fact the
	// compare-and-set below establishes: it is the one that catches a session
	// that was resurrected, or was never torn down properly, by some path other
	// than the window between the read above and the write below.
	if session.TokenID != "" {
		if _, err := b.tokenManager.GetDecryptedAccessToken(session.TokenID); err != nil {
			log.Warn().Err(err).Str("session_id", sessionID).
				Msg("Authorized session has no usable token; refusing to refresh")
			b.removeSession(sessionID)
			return expiredSessionResponse(sessionID, "Session credentials are no longer valid"), nil
		}
	}

	if time.Until(session.ExpiresAt) > b.config.Authentication.RefreshThreshold {
		return b.successResponse(session), nil
	}

	// Extend the session lifetime, but only if it is still the same authorized
	// session that was read above.
	expiresAt := now.Add(b.config.Authentication.TokenLifetime)
	if !b.extendSession(sessionID, session.CreatedAt, func(s *Session) {
		s.ExpiresAt = expiresAt
		s.LastAccessed = now
	}) {
		// Revoked, expired, or replaced while this call was deciding. Report what
		// is true now rather than the snapshot's view of it. The error codes are
		// the same two a caller would have got a moment earlier; the messages name
		// the window, because "it was there when I read it" is the only distinction
		// worth having in a log — and it is what a test can count to know the
		// window was really exercised.
		if live := b.getSession(sessionID); live != nil {
			return &AuthResponse{
				Success:      false,
				Status:       live.Status,
				SessionID:    sessionID,
				ErrorCode:    "SESSION_NOT_ACTIVE",
				ErrorMessage: msgDeactivatedWhileRefreshing,
			}, nil
		}
		return errorResponse("SESSION_NOT_FOUND", msgRevokedWhileRefreshing), nil
	}

	// session is this call's private snapshot and never goes back into the map;
	// bringing it up to date is only so the reply states the expiry that was
	// actually stored.
	session.ExpiresAt = expiresAt
	session.LastAccessed = now

	return b.successResponse(session), nil
}

// The two messages RefreshSession uses when its compare-and-set refuses, named
// so the race regression test can count the interleavings it claims to exercise
// instead of assuming they happened. error_message is diagnostic by contract —
// see docs/wire-protocol.md — so no client decides anything on these.
const (
	msgRevokedWhileRefreshing     = "Session was revoked while it was being refreshed"
	msgDeactivatedWhileRefreshing = "Session stopped being authorized while it was being refreshed"
)

// expiredSessionResponse is the reply for a session that has run out of time,
// whether by its own expiry or by the absolute age ceiling. Both are
// SESSION_EXPIRED: from a client's point of view the session ran out of time,
// and the reason is the broker's log's business.
func expiredSessionResponse(sessionID, message string) *AuthResponse {
	return &AuthResponse{
		Success:      false,
		Status:       StatusExpired,
		SessionID:    sessionID,
		ErrorCode:    "SESSION_EXPIRED",
		ErrorMessage: message,
	}
}

// RevokeSession removes a session and revokes its stored access token.
func (b *Broker) RevokeSession(sessionID string) error {
	session := b.getSession(sessionID)
	if session == nil {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	if session.TokenID != "" {
		// Best-effort: revoke the token at GitHub before removing it locally.
		// Order matters: decrypt first (needs the local copy), then revoke at
		// GitHub, then delete from the token store.
		if plaintext, err := b.tokenManager.GetDecryptedAccessToken(session.TokenID); err != nil {
			log.Warn().Err(err).Str("session_id", sessionID).Msg("Could not decrypt token for GitHub revocation")
		} else if p := b.providerByName(session.Provider); p != nil {
			if err := p.RevokeAccessToken(b.ctx, plaintext); err != nil {
				log.Warn().Err(err).Str("session_id", sessionID).Msg("GitHub token revocation failed (token may remain valid at GitHub)")
			}
		}
		b.tokenManager.RevokeToken(session.TokenID)
	}

	b.removeSession(sessionID)

	b.auditLogger.LogAuthEvent(security.AuditEvent{
		EventType: "session_revoked",
		UserID:    session.LocalUser,
		SessionID: sessionID,
		Provider:  session.Provider,
		Success:   true,
		Timestamp: time.Now(),
	})

	return nil
}

// --- background polling ---

// pollDeviceAuthorization polls the provider's token endpoint in the background.
// It takes sessionID (not a *Session pointer) to avoid data races; all
// session reads/writes go through getSession/setSession under the mutex.
//
// ctx is cancelled when the session is evicted, revoked, or fails, so the
// goroutine and its provider traffic stop with it. deadline is when the broker
// gives up waiting, which may be earlier than the provider's own code expiry.
func (b *Broker) pollDeviceAuthorization(
	ctx context.Context,
	sessionID string,
	prov provider.Provider,
	df *provider.DeviceFlow,
	deadline time.Time,
) {
	defer b.wg.Done()
	defer b.forgetPoll(sessionID)

	interval := time.Duration(df.PollingInterval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	timeout := time.NewTimer(time.Until(deadline))
	defer timeout.Stop()

	for {
		select {
		case <-b.stopChan:
			return

		case <-ctx.Done():
			// The session this poll belonged to is gone. Whatever removed it has
			// already recorded why, so there is nothing to report here.
			log.Debug().Str("session_id", sessionID).Msg("Device flow poll cancelled")
			return

		case <-timeout.C:
			log.Warn().
				Str("session_id", sessionID).
				Msg("Device flow expired")
			b.failSession(sessionID, StatusExpired, "Device authorization expired")
			return

		case <-ticker.C:
			token, err := prov.PollDeviceAuthorization(ctx, df.DeviceCode)
			if err != nil {
				// errors.Is, not equality: an implementation is entitled to wrap
				// a sentinel with context ("poll acme-sso: %w"), and treating
				// that as an unknown error would fail a login that is merely
				// still pending.
				switch {
				case errors.Is(err, provider.ErrAuthorizationPending):
					continue
				case errors.Is(err, provider.ErrSlowDown):
					interval += 5 * time.Second
					ticker.Reset(interval)
					continue
				case errors.Is(err, provider.ErrExpiredToken):
					b.failSession(sessionID, StatusExpired, "Device code expired before authorization")
					return
				case errors.Is(err, provider.ErrAccessDenied):
					b.auditLogger.LogAuthEvent(security.AuditEvent{
						EventType:    "authentication_denied",
						SessionID:    sessionID,
						Provider:     prov.Name(),
						Success:      false,
						ErrorMessage: "user denied authorization",
						Timestamp:    time.Now(),
					})
					b.failSession(sessionID, StatusDenied, "Authorization denied at provider")
					return
				default:
					log.Error().Err(err).Str("session_id", sessionID).Msg("Device poll error")
					b.failSession(sessionID, StatusError, "Provider polling failed")
					return
				}
			}

			// Token obtained — fetch identity (retry up to 3x for transient errors).
			var identity *provider.Identity
			for attempt := 1; attempt <= 3; attempt++ {
				identity, err = prov.GetIdentity(ctx, token)
				if err == nil {
					break
				}
				if !isTransientError(err) || attempt == 3 {
					log.Error().Err(err).Int("attempt", attempt).
						Str("session_id", sessionID).Msg("Failed to resolve provider identity")
					b.auditLogger.LogAuthEvent(security.AuditEvent{
						EventType:    "authentication_failed",
						SessionID:    sessionID,
						Provider:     prov.Name(),
						Success:      false,
						ErrorMessage: err.Error(),
						Timestamp:    time.Now(),
					})
					// checkAccess failures (not in the required org/team) arrive
					// here and are a decision about the user, not an outage.
					b.failSession(sessionID, identityFailureStatus(err), "Identity could not be established")
					return
				}
				log.Warn().Err(err).Int("attempt", attempt).
					Str("session_id", sessionID).Msg("Transient error fetching identity, retrying")
				time.Sleep(2 * time.Second)
			}

			// Get a snapshot of the current session state (holds no live pointer).
			{
				current := b.getSession(sessionID)
				if current == nil {
					// Session was removed externally (revoked or timed out).
					return
				}

				// Map to local user; retry transient errors up to 3x.
				var mapResult *mapper.Result
				for attempt := 1; attempt <= 3; attempt++ {
					mapResult, err = b.mapper.Map(ctx, identity, current.RequestedLocalUser)
					if err == nil {
						break
					}
					if !isTransientError(err) || attempt == 3 {
						log.Error().Err(err).Int("attempt", attempt).
							Str("session_id", sessionID).
							Str("provider_login", identity.Login).
							Msg("Identity mapping failed")
						b.auditLogger.LogAuthEvent(security.AuditEvent{
							EventType:    "authentication_failed",
							UserID:       identity.Login,
							SessionID:    sessionID,
							Provider:     prov.Name(),
							Success:      false,
							ErrorMessage: err.Error(),
							Timestamp:    time.Now(),
						})
						// No mapping, and a mapping to an account this path may not
						// reach, are both decisions about the identity; anything
						// else is an operational failure.
						status := StatusError
						if errors.Is(err, mapper.ErrNoMapping) || errors.Is(err, mapper.ErrForbiddenLocalUser) {
							status = StatusDenied
						}
						b.failSession(sessionID, status, "No local account mapping for this identity")
						return
					}
					log.Warn().Err(err).Int("attempt", attempt).
						Str("session_id", sessionID).Msg("Transient error mapping identity, retrying")
					time.Sleep(2 * time.Second)
				}

				// The mapped local user must be the account the login was for.
				// This is the authoritative check: the broker will not activate a
				// session whose mapped user differs from the requested one, so a
				// stale or hostile client cannot skip it. Without this, an
				// identity mapping to "alice" would authorize `ssh root@host`.
				//
				// Compared unconditionally. It used to be skipped when the
				// requested user was empty, which meant a request that named no
				// account activated as whatever the identity mapped to — the check
				// failing open in exactly the case where there is nothing to check
				// against. validateRequest now rejects such a request at the door
				// as well; both belong here, since either one alone is a single
				// point of failure for the invariant the design rests on.
				if mapResult.LocalUser != current.RequestedLocalUser {
					log.Warn().
						Str("session_id", sessionID).
						Str("requested_user", current.RequestedLocalUser).
						Str("mapped_user", mapResult.LocalUser).
						Str("provider_login", identity.Login).
						Msg("Mapped local user does not match requested login; denying")
					b.auditLogger.LogAuthEvent(security.AuditEvent{
						EventType:    "authentication_denied",
						UserID:       current.RequestedLocalUser,
						SessionID:    sessionID,
						Provider:     prov.Name(),
						Success:      false,
						ErrorMessage: "mapped local user does not match requested login",
						Timestamp:    time.Now(),
						Metadata: map[string]interface{}{
							"provider_login": identity.Login,
							"requested_user": current.RequestedLocalUser,
							"mapped_user":    mapResult.LocalUser,
						},
					})
					b.failSession(sessionID, StatusDenied,
						"Authenticated identity is not authorized for this account")
					return
				}

				// Store the token in the encrypted token manager.
				tokenLifetime := b.config.Authentication.TokenLifetime
				if tokenLifetime <= 0 {
					tokenLifetime = 8 * time.Hour
				}
				tokenID, err := b.tokenManager.StoreToken(
					sessionID, mapResult.LocalUser,
					token.AccessToken, "",
					time.Now().Add(tokenLifetime),
				)
				if err != nil {
					log.Error().Err(err).Str("session_id", sessionID).Msg("Failed to store token")
					b.failSession(sessionID, StatusError, "Internal error storing credentials")
					return
				}

				// Activate the session, but only if it is still the pending one
				// this poll started on.
				//
				// Everything above — the identity fetch with its retries, the
				// mapper with its 5s script timeout, the token store — takes
				// seconds, and the session can be revoked or expired in that
				// window. Writing the snapshot back wholesale was a lost update:
				// with a 3s device code and a slow mapper, check_session reported
				// "expired" at t+4s and "authorized" at t+10s, creating a live
				// eight-hour session holding a real access token that no login was
				// waiting on. The compare-and-set refuses that, and subsumes the
				// revoked-during-flow guard this replaced.
				activated := b.activateSession(sessionID, current.CreatedAt, func(s *Session) {
					s.LocalUser = mapResult.LocalUser
					s.ProviderLogin = identity.Login
					s.Email = identity.Email
					s.Groups = mapResult.Groups
					s.TokenFingerprint = token.Fingerprint
					s.TokenID = tokenID
					s.Status = StatusAuthorized
					s.IsActive = true
					// The session now governs a live login rather than a device
					// code, so switch to the configured session lifetime.
					s.ExpiresAt = time.Now().Add(tokenLifetime)
					s.LastAccessed = time.Now()
				})
				if !activated {
					b.tokenManager.RevokeToken(tokenID)
					log.Info().Str("session_id", sessionID).
						Msg("Session no longer pending when the device flow completed; discarding result")
					return
				}

				b.auditLogger.LogAuthEvent(security.AuditEvent{
					EventType:  "authentication_success",
					UserID:     mapResult.LocalUser,
					Email:      identity.Email,
					Groups:     mapResult.Groups,
					SessionID:  sessionID,
					Provider:   prov.Name(),
					AuthMethod: "github_device_flow",
					Success:    true,
					Timestamp:  time.Now(),
					Metadata: map[string]interface{}{
						"provider_login":   identity.Login,
						"provider_subject": identity.Subject,
						"claims":           identity.Claims,
					},
				})

				log.Info().
					Str("session_id", sessionID).
					Str("local_user", mapResult.LocalUser).
					Str("provider_login", identity.Login).
					Msg("Authentication successful")
				return
			} // end inner block
		}
	}
}

// identityFailureStatus classifies a GetIdentity failure. A provider-level
// access-control refusal (not in the required org or team) is a denial; an
// unreachable API is an error.
func identityFailureStatus(err error) string {
	if errors.Is(err, provider.ErrAccessForbidden) {
		return StatusDenied
	}
	return StatusError
}

// isTransientError returns true for network/IO errors that may resolve on retry,
// as opposed to fatal errors (auth denied, identity not found, etc.).
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// --- session helpers ---

// getSession returns a copy of the session, not a live pointer into the map.
// Callers receive an immutable snapshot; writes must go through setSession.
func (b *Broker) getSession(sessionID string) *Session {
	if sessionID == "" {
		return nil
	}
	b.sessionMutex.RLock()
	defer b.sessionMutex.RUnlock()
	s, ok := b.sessions[sessionID]
	if !ok {
		return nil
	}
	snapshot := *s
	// Deep-copy reference fields so mutations to the stored session cannot
	// corrupt a caller's snapshot (and vice versa).
	snapshot.Groups = append([]string(nil), s.Groups...)
	if s.Metadata != nil {
		snapshot.Metadata = make(map[string]string, len(s.Metadata))
		for k, v := range s.Metadata {
			snapshot.Metadata[k] = v
		}
	}
	return &snapshot
}

// activateSession promotes a pending session to authorized under a single lock,
// applying mutate to the stored entry. It returns false — changing nothing — if
// the session is gone, is no longer pending, or is not the same one the caller
// started with: CreatedAt distinguishes a session that was removed and had its
// ID reused from the one still in flight.
//
// This is the only place a session becomes active, so it is the only place the
// invariant "an authorized session was pending a moment ago" has to hold.
func (b *Broker) activateSession(sessionID string, createdAt time.Time, mutate func(*Session)) bool {
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()

	s, ok := b.sessions[sessionID]
	if !ok || s.IsActive || s.Status != StatusPending || !s.CreatedAt.Equal(createdAt) {
		return false
	}
	mutate(s)
	return true
}

// extendSession pushes an authorized session's lifetime out under a single lock,
// applying mutate to the stored entry. It returns false — changing nothing — if
// the session is gone, is no longer an authorized one, or is not the same
// session the caller read: as in activateSession, CreatedAt distinguishes a
// session that was removed and had its ID reused from the one being refreshed.
//
// It exists for the same reason activateSession does. RefreshSession decides on a
// snapshot, and writing that snapshot back with setSession was a lost update: a
// RevokeSession or a cleanup pass that deleted the session in between was
// silently undone, and the re-inserted entry named a TokenID that had already
// been destroyed at the provider. The result was an authorized session with no
// token, no poller, and a brand-new hour to live, which check_session answered
// with success. Reproduced on 1 of 200 unassisted attempts before this.
func (b *Broker) extendSession(sessionID string, createdAt time.Time, mutate func(*Session)) bool {
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()

	s, ok := b.sessions[sessionID]
	if !ok || !s.IsActive || s.Status != StatusAuthorized || !s.CreatedAt.Equal(createdAt) {
		return false
	}
	mutate(s)
	return true
}

// pastMaxTokenAge reports whether a session has outlived
// security.max_token_age, the absolute ceiling on how old a session may become
// however many times it is refreshed. Measured from CreatedAt, which no
// extension moves.
//
// 0 means unset, matching the config-consistency check in pkg/config that was
// for a while the only place this value was read at all. The comparison is
// strictly greater-than, so a session exactly at the ceiling is still inside it.
func (b *Broker) pastMaxTokenAge(s *Session, now time.Time) bool {
	max := b.config.Security.MaxTokenAge
	if max <= 0 {
		return false
	}
	return now.Sub(s.CreatedAt) > max
}

// baseContext is the parent for per-session polling contexts. Start records the
// broker's context; a broker used without Start (some tests, and any future
// caller that only wants Authenticate) still needs a usable parent.
func (b *Broker) baseContext() context.Context {
	if b.ctx != nil {
		return b.ctx
	}
	return context.Background()
}

// deviceFlowDeadline is when the broker stops waiting for the user to approve a
// flow: the sooner of the provider's device-code expiry and
// authentication.device_flow_timeout.
func (b *Broker) deviceFlowDeadline(df *provider.DeviceFlow) time.Time {
	limit := b.config.Authentication.DeviceFlowTimeout
	if limit <= 0 {
		return df.ExpiresAt
	}
	own := time.Now().Add(limit)
	if own.Before(df.ExpiresAt) {
		return own
	}
	return df.ExpiresAt
}

// cancelPoll stops the polling goroutine for a session, if one is still running.
// Safe to call for a session that has none.
//
// The cancel function is taken under the lock and invoked outside it: callers
// include paths that already hold sessionMutex, and cancel() must never be able
// to re-enter it.
func (b *Broker) cancelPoll(sessionID string) {
	b.sessionMutex.Lock()
	cancel := b.pollCancel[sessionID]
	delete(b.pollCancel, sessionID)
	b.sessionMutex.Unlock()

	if cancel != nil {
		cancel()
	}
}

// forgetPoll drops a finished poller's cancel function without calling it, so
// the map does not grow with one entry per completed login.
func (b *Broker) forgetPoll(sessionID string) {
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()
	delete(b.pollCancel, sessionID)
}

// countUserSessions returns the number of *established* sessions for userID.
//
// Pending device flows are excluded deliberately. Counting them meant that
// three abandoned SSH attempts (a user who closed the terminal without
// visiting GitHub) exhausted max_concurrent_sessions and locked the account out
// until the five-minute cleanup ticker ran. Pending state is bounded by
// maxPendingFlowsPerUser instead.
func (b *Broker) countUserSessions(userID string) int {
	b.sessionMutex.RLock()
	defer b.sessionMutex.RUnlock()
	count := 0
	for _, s := range b.sessions {
		if !s.IsActive {
			continue
		}
		if s.RequestedLocalUser == userID || s.LocalUser == userID {
			count++
		}
	}
	return count
}

// countPendingFlows returns the number of device flows awaiting authorization
// across all users.
func (b *Broker) countPendingFlows() int {
	b.sessionMutex.RLock()
	defer b.sessionMutex.RUnlock()
	count := 0
	for _, s := range b.sessions {
		if s.Status == StatusPending && !s.IsActive {
			count++
		}
	}
	return count
}

// failSession marks a session terminally failed and retains it for
// terminalGrace so a polling client learns the outcome. Removing the session
// instead would report SESSION_NOT_FOUND, which a client cannot distinguish
// from a bad session ID — so it would keep polling until its own deadline
// rather than failing the login promptly.
//
// Any token already stored for the session is revoked: a failed flow must not
// leave credentials behind.
func (b *Broker) failSession(sessionID, status, message string) {
	var tokenID string

	// Stop polling first: a flow that has failed has nothing left to wait for,
	// and CheckSession reaches here too, so the poller may still be running.
	b.cancelPoll(sessionID)

	b.sessionMutex.Lock()
	s, ok := b.sessions[sessionID]
	if ok && s.Status != StatusPending {
		// Terminal states are final. Cancelling the poller (above) makes the
		// in-flight provider and mapper calls fail, and those failures arrive back
		// here — without this guard, a session CheckSession had already reported
		// as "expired" would be rewritten as "error" moments later, changing the
		// answer a client had already been given.
		b.sessionMutex.Unlock()
		return
	}
	if ok {
		tokenID = s.TokenID
		s.Status = status
		s.ErrorMessage = message
		s.IsActive = false
		s.TokenID = ""
		s.ExpiresAt = time.Now().Add(terminalGrace)
	}
	b.sessionMutex.Unlock()

	if !ok {
		return
	}
	if tokenID != "" {
		b.tokenManager.RevokeToken(tokenID)
	}

	log.Debug().
		Str("session_id", sessionID).
		Str("status", status).
		Msg("Session marked terminally failed")
}

// evictExcessPendingFlows drops the oldest pending flows for userID until at
// most maxPendingFlowsPerUser-1 remain, leaving room for the flow about to
// start. Evicting rather than rejecting means a user with several terminals
// open always gets a usable prompt in the newest one.
func (b *Broker) evictExcessPendingFlows(userID string) {
	// Cancels are collected under the lock and invoked after it, so an evicted
	// flow's goroutine stops talking to the provider. Without this, eviction
	// deleted the session and left the poller running to the device code's
	// expiry — untracked traffic against the provider's per-app rate limit.
	var cancels []context.CancelFunc

	b.sessionMutex.Lock()

	var pending []*Session
	for _, s := range b.sessions {
		if s.Status == StatusPending && !s.IsActive && s.RequestedLocalUser == userID {
			pending = append(pending, s)
		}
	}
	if len(pending) < maxPendingFlowsPerUser {
		b.sessionMutex.Unlock()
		return
	}

	sort.Slice(pending, func(i, j int) bool {
		return pending[i].CreatedAt.Before(pending[j].CreatedAt)
	})
	for _, s := range pending[:len(pending)-(maxPendingFlowsPerUser-1)] {
		delete(b.sessions, s.ID)
		if cancel := b.pollCancel[s.ID]; cancel != nil {
			cancels = append(cancels, cancel)
			delete(b.pollCancel, s.ID)
		}
		log.Debug().
			Str("session_id", s.ID).
			Str("user_id", userID).
			Msg("Evicted oldest pending device flow")
	}
	b.sessionMutex.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
}

// generateSessionID creates a 16-byte cryptographically random session ID.
func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (b *Broker) setSession(session *Session) {
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()
	b.sessions[session.ID] = session
}

// providerByName returns the provider with the given name, or nil.
func (b *Broker) providerByName(name string) provider.Provider {
	return b.byName[name]
}

// selectProvider resolves the provider a request asked for.
//
// An empty name means the first configured provider, which is the whole story on
// a single-provider host and the documented default elsewhere. A name that is not
// configured is an error rather than a silent fall back to the default: a client
// that asked for a specific provider and got a different one would be
// authenticated against an identity source nobody chose.
func (b *Broker) selectProvider(name string) (provider.Provider, error) {
	if len(b.providers) == 0 {
		return nil, fmt.Errorf("no authentication provider is configured")
	}
	if name == "" {
		return b.providers[0], nil
	}
	p, ok := b.byName[name]
	if !ok {
		return nil, fmt.Errorf("no provider named %q is configured", name)
	}
	return p, nil
}

func (b *Broker) removeSession(sessionID string) {
	// A removed session's poller has nowhere to deliver a result.
	b.cancelPoll(sessionID)

	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()
	delete(b.sessions, sessionID)
}

// errorResponse builds a terminal operational-failure response.
func errorResponse(code, message string) *AuthResponse {
	return &AuthResponse{
		Success:      false,
		Status:       StatusError,
		ErrorCode:    code,
		ErrorMessage: message,
	}
}

func (b *Broker) successResponse(session *Session) *AuthResponse {
	return &AuthResponse{
		Success:   true,
		Status:    StatusAuthorized,
		UserID:    session.LocalUser,
		Email:     session.Email,
		Groups:    session.Groups,
		SessionID: session.ID,
		ExpiresAt: session.ExpiresAt,
		Metadata: map[string]string{
			"provider":       session.Provider,
			"provider_login": session.ProviderLogin,
			"last_accessed":  session.LastAccessed.Format(time.RFC3339),
		},
	}
}

func (b *Broker) sessionCleanup(ctx context.Context) {
	defer b.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stopChan:
			return
		case <-ticker.C:
			b.cleanupExpiredSessions(time.Now())
		}
	}
}

// cleanupExpiredSessions revokes every session that has run out of time and
// returns how many it revoked. A session is out of time either because its own
// ExpiresAt has passed or because it has outlived security.max_token_age — the
// ceiling has to be swept for as well as checked on refresh, or a session nobody
// ever calls refresh_session on simply lives to its extended expiry.
//
// Split out of sessionCleanup's ticker loop, and takes `now` as an argument, so
// a test can drive one sweep instead of waiting five minutes for the tick.
func (b *Broker) cleanupExpiredSessions(now time.Time) int {
	var expired []string

	b.sessionMutex.RLock()
	for id, s := range b.sessions {
		if s.ExpiresAt.Before(now) || b.pastMaxTokenAge(s, now) {
			expired = append(expired, id)
		}
	}
	b.sessionMutex.RUnlock()

	for _, id := range expired {
		if err := b.RevokeSession(id); err != nil {
			log.Warn().Err(err).Str("session_id", id).Msg("Failed to revoke expired session during cleanup")
		}
	}

	if len(expired) > 0 {
		log.Info().Int("count", len(expired)).Msg("Cleaned up expired sessions")
	}
	return len(expired)
}
