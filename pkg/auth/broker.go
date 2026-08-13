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
	"github.com/scttfrdmn/oauth2-pam/pkg/provider/github"
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
	config       *config.Config
	providers    []*github.Provider
	mapper       *mapper.Chain
	tokenManager *TokenManager
	auditLogger  *security.AuditLogger
	sessions     map[string]*Session
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
	GitHubLogin        string
	Email              string
	Groups             []string
	Provider           string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	LastAccessed       time.Time
	SourceIP           string
	TokenFingerprint   string
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

// NewBroker creates and validates a new Broker.
func NewBroker(cfg *config.Config) (*Broker, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if cfg.Server.SocketPath == "" {
		return nil, fmt.Errorf("server.socket_path is required")
	}
	if len(cfg.Providers) == 0 {
		return nil, fmt.Errorf("at least one provider must be configured")
	}

	// Build provider instances
	providers := make([]*github.Provider, 0, len(cfg.Providers))
	for _, pc := range cfg.Providers {
		p, err := github.New(pc)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", pc.Name, err)
		}
		providers = append(providers, p)
	}

	tokenManager, err := NewTokenManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("token manager: %w", err)
	}

	auditLogger, err := security.NewAuditLogger(cfg.Audit)
	if err != nil {
		return nil, fmt.Errorf("audit logger: %w", err)
	}

	return &Broker{
		config:       cfg,
		providers:    providers,
		mapper:       mapper.New(cfg.Mapper),
		tokenManager: tokenManager,
		auditLogger:  auditLogger,
		sessions:     make(map[string]*Session),
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

	// Pick the first configured provider (single-provider for now)
	if len(b.providers) == 0 {
		return errorResponse("NO_PROVIDER", "No authentication provider configured"), nil
	}
	provider := b.providers[0]

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

	// Bound in-flight device flows for this user, evicting the oldest.
	b.evictExcessPendingFlows(req.UserID)

	// Global cap on device flows awaiting authorization. Each one holds a
	// goroutine polling the provider, so this bounds the work a burst of login
	// attempts can create broker-wide.
	if max := b.config.Security.RateLimiting.MaxConcurrentAuths; max > 0 {
		if n := b.countPendingFlows(); n >= max {
			log.Warn().Int("pending", n).Int("max", max).
				Msg("Concurrent device flow limit reached; rejecting authentication")
			return errorResponse("AUTH_LIMIT_REACHED",
				"Too many authentications in progress; try again shortly"), nil
		}
	}

	// Start device flow
	deviceFlow, err := provider.StartDeviceFlow(b.ctx)
	if err != nil {
		b.auditLogger.LogAuthEvent(security.AuditEvent{
			EventType:    "device_flow_failed",
			UserID:       req.UserID,
			SourceIP:     req.SourceIP,
			TargetHost:   req.TargetHost,
			Provider:     provider.Name(),
			Success:      false,
			ErrorMessage: err.Error(),
			Timestamp:    time.Now(),
		})
		return errorResponse("DEVICE_FLOW_FAILED", err.Error()), nil
	}

	// Generate QR code (best-effort)
	qrCode, err := GenerateQRCode(deviceFlow.DeviceURL)
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

	// Create a pending session
	session := &Session{
		ID:                 sessionID,
		RequestedLocalUser: req.UserID,
		Provider:           provider.Name(),
		CreatedAt:          time.Now(),
		ExpiresAt:          deviceFlow.ExpiresAt,
		LastAccessed:       time.Now(),
		SourceIP:           req.SourceIP,
		Status:             StatusPending,
		IsActive:           false,
		Metadata:           req.Metadata,
	}
	b.setSession(session)

	// Poll in the background; update session when the device flow completes.
	b.wg.Add(1)
	go b.pollDeviceAuthorization(sessionID, provider, deviceFlow)

	// Success is false: a started device flow is not an authenticated user.
	return &AuthResponse{
		Success:        false,
		Status:         StatusPending,
		SessionID:      sessionID,
		DeviceCode:     deviceFlow.UserCode,
		DeviceURL:      deviceFlow.DeviceURL,
		QRCode:         qrCode,
		ExpiresAt:      deviceFlow.ExpiresAt,
		RequiresDevice: true,
		Metadata: map[string]string{
			"provider":         provider.Name(),
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

	if time.Until(session.ExpiresAt) > b.config.Authentication.RefreshThreshold {
		return b.successResponse(session), nil
	}

	// Extend the session lifetime
	session.ExpiresAt = time.Now().Add(b.config.Authentication.TokenLifetime)
	session.LastAccessed = time.Now()
	b.setSession(session)

	return b.successResponse(session), nil
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

// pollDeviceAuthorization polls the GitHub token endpoint in the background.
// It takes sessionID (not a *Session pointer) to avoid data races; all
// session reads/writes go through getSession/setSession under the mutex.
func (b *Broker) pollDeviceAuthorization(sessionID string, provider *github.Provider, df *github.DeviceFlow) {
	defer b.wg.Done()

	interval := time.Duration(df.PollingInterval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	timeout := time.NewTimer(time.Until(df.ExpiresAt))
	defer timeout.Stop()

	for {
		select {
		case <-b.stopChan:
			return

		case <-timeout.C:
			log.Warn().
				Str("session_id", sessionID).
				Msg("Device flow expired")
			b.failSession(sessionID, StatusExpired, "Device authorization expired")
			return

		case <-ticker.C:
			token, err := provider.PollDeviceAuthorization(b.ctx, df.DeviceCode)
			if err != nil {
				switch err {
				case github.ErrAuthorizationPending:
					continue
				case github.ErrSlowDown:
					interval += 5 * time.Second
					ticker.Reset(interval)
					continue
				case github.ErrExpiredToken:
					b.failSession(sessionID, StatusExpired, "Device code expired before authorization")
					return
				case github.ErrAccessDenied:
					b.auditLogger.LogAuthEvent(security.AuditEvent{
						EventType:    "authentication_denied",
						SessionID:    sessionID,
						Provider:     provider.Name(),
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
			var identity *github.Identity
			for attempt := 1; attempt <= 3; attempt++ {
				identity, err = provider.GetIdentity(b.ctx, token)
				if err == nil {
					break
				}
				if !isTransientError(err) || attempt == 3 {
					log.Error().Err(err).Int("attempt", attempt).
						Str("session_id", sessionID).Msg("Failed to get GitHub identity")
					b.auditLogger.LogAuthEvent(security.AuditEvent{
						EventType:    "authentication_failed",
						SessionID:    sessionID,
						Provider:     provider.Name(),
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
					mapResult, err = b.mapper.Map(b.ctx, identity, current.RequestedLocalUser)
					if err == nil {
						break
					}
					if !isTransientError(err) || attempt == 3 {
						log.Error().Err(err).Int("attempt", attempt).
							Str("session_id", sessionID).
							Str("github_login", identity.Login).
							Msg("Identity mapping failed")
						b.auditLogger.LogAuthEvent(security.AuditEvent{
							EventType:    "authentication_failed",
							UserID:       identity.Login,
							SessionID:    sessionID,
							Provider:     provider.Name(),
							Success:      false,
							ErrorMessage: err.Error(),
							Timestamp:    time.Now(),
						})
						// No mapping is a decision (this identity has no local
						// account); anything else is an operational failure.
						status := StatusError
						if errors.Is(err, mapper.ErrNoMapping) {
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
				if current.RequestedLocalUser != "" && mapResult.LocalUser != current.RequestedLocalUser {
					log.Warn().
						Str("session_id", sessionID).
						Str("requested_user", current.RequestedLocalUser).
						Str("mapped_user", mapResult.LocalUser).
						Str("github_login", identity.Login).
						Msg("Mapped local user does not match requested login; denying")
					b.auditLogger.LogAuthEvent(security.AuditEvent{
						EventType:    "authentication_denied",
						UserID:       current.RequestedLocalUser,
						SessionID:    sessionID,
						Provider:     provider.Name(),
						Success:      false,
						ErrorMessage: "mapped local user does not match requested login",
						Timestamp:    time.Now(),
						Metadata: map[string]interface{}{
							"github_login":   identity.Login,
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

				// Guard: if the session was revoked while we were fetching identity /
				// mapping / storing the token, discard the result rather than
				// recreating a session the admin just removed.
				if b.getSession(sessionID) == nil {
					b.tokenManager.RevokeToken(tokenID)
					log.Info().Str("session_id", sessionID).
						Msg("Session revoked during device flow; discarding authentication result")
					return
				}

				// Update the session snapshot and write it back under the mutex.
				current.LocalUser = mapResult.LocalUser
				current.GitHubLogin = identity.Login
				current.Email = identity.Email
				current.Groups = mapResult.Groups
				current.TokenFingerprint = token.Fingerprint
				current.TokenID = tokenID
				current.Status = StatusAuthorized
				current.IsActive = true
				// The session now governs a live login rather than a device code,
				// so switch to the configured session lifetime.
				current.ExpiresAt = time.Now().Add(tokenLifetime)
				current.LastAccessed = time.Now()
				b.setSession(current)

				b.auditLogger.LogAuthEvent(security.AuditEvent{
					EventType:  "authentication_success",
					UserID:     mapResult.LocalUser,
					Email:      identity.Email,
					Groups:     mapResult.Groups,
					SessionID:  sessionID,
					Provider:   provider.Name(),
					AuthMethod: "github_device_flow",
					Success:    true,
					Timestamp:  time.Now(),
					Metadata: map[string]interface{}{
						"github_login": identity.Login,
						"github_orgs":  identity.Orgs,
					},
				})

				log.Info().
					Str("session_id", sessionID).
					Str("local_user", mapResult.LocalUser).
					Str("github_login", identity.Login).
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
	if errors.Is(err, github.ErrAccessForbidden) {
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
	if errors.As(err, &netErr) {
		return true
	}
	return false
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

	b.sessionMutex.Lock()
	s, ok := b.sessions[sessionID]
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
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()

	var pending []*Session
	for _, s := range b.sessions {
		if s.Status == StatusPending && !s.IsActive && s.RequestedLocalUser == userID {
			pending = append(pending, s)
		}
	}
	if len(pending) < maxPendingFlowsPerUser {
		return
	}

	sort.Slice(pending, func(i, j int) bool {
		return pending[i].CreatedAt.Before(pending[j].CreatedAt)
	})
	for _, s := range pending[:len(pending)-(maxPendingFlowsPerUser-1)] {
		delete(b.sessions, s.ID)
		log.Debug().
			Str("session_id", s.ID).
			Str("user_id", userID).
			Msg("Evicted oldest pending device flow")
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

// providerByName returns the first provider whose Name() matches name, or nil.
func (b *Broker) providerByName(name string) *github.Provider {
	for _, p := range b.providers {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

func (b *Broker) removeSession(sessionID string) {
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
			"provider":      session.Provider,
			"github_login":  session.GitHubLogin,
			"last_accessed": session.LastAccessed.Format(time.RFC3339),
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
			now := time.Now()
			var expired []string

			b.sessionMutex.RLock()
			for id, s := range b.sessions {
				if s.ExpiresAt.Before(now) {
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
		}
	}
}
