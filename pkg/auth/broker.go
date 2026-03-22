package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/pam-oauth2/pkg/config"
	"github.com/scttfrdmn/pam-oauth2/pkg/mapper"
	"github.com/scttfrdmn/pam-oauth2/pkg/provider/github"
	"github.com/scttfrdmn/pam-oauth2/pkg/security"
)

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

// Session represents an active authentication session.
type Session struct {
	ID                 string
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
	IsActive           bool
	Metadata           map[string]interface{}
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
	Metadata   map[string]interface{}
}

// AuthResponse is the broker's response to an auth request.
type AuthResponse struct {
	Success          bool
	UserID           string   // local Unix username
	Email            string
	Groups           []string
	SessionID        string
	DeviceCode       string   // user-visible code (e.g. "ABCD-1234")
	DeviceURL        string
	QRCode           string
	ExpiresAt        time.Time
	RequiresDevice   bool
	RequiresApproval bool
	ErrorCode        string
	ErrorMessage     string
	Metadata         map[string]interface{}
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
	log.Info().Msg("Starting pam-oauth2 broker services")

	if err := b.tokenManager.Start(ctx); err != nil {
		return fmt.Errorf("start token manager: %w", err)
	}
	if err := b.auditLogger.Start(ctx); err != nil {
		return fmt.Errorf("start audit logger: %w", err)
	}

	b.wg.Add(1)
	go b.sessionCleanup(ctx)

	log.Info().Msg("pam-oauth2 broker services started")
	return nil
}

// Stop shuts down broker background services.
func (b *Broker) Stop() error {
	log.Info().Msg("Stopping pam-oauth2 broker services")

	close(b.stopChan)
	b.wg.Wait()

	if err := b.tokenManager.Stop(); err != nil {
		log.Error().Err(err).Msg("Error stopping token manager")
	}
	if err := b.auditLogger.Stop(); err != nil {
		log.Error().Err(err).Msg("Error stopping audit logger")
	}

	log.Info().Msg("pam-oauth2 broker services stopped")
	return nil
}

// Authenticate handles an authentication request from the PAM module.
// On first call it kicks off a Device Flow and returns RequiresDevice=true
// with the user code. The PAM module then polls via CheckSession until the
// device flow completes.
func (b *Broker) Authenticate(req *AuthRequest) (*AuthResponse, error) {
	log.Debug().
		Str("user_id", req.UserID).
		Str("source_ip", req.SourceIP).
		Str("login_type", req.LoginType).
		Msg("Processing authentication request")

	// Check for an existing active session
	if session := b.getSession(req.SessionID); session != nil {
		if session.IsActive && session.ExpiresAt.After(time.Now()) {
			return b.successResponse(session), nil
		}
		b.removeSession(req.SessionID)
	}

	// Pick the first configured provider (single-provider for now)
	if len(b.providers) == 0 {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "NO_PROVIDER",
			ErrorMessage: "No authentication provider configured",
		}, nil
	}
	provider := b.providers[0]

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
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "DEVICE_FLOW_FAILED",
			ErrorMessage: err.Error(),
		}, nil
	}

	// Generate QR code (best-effort)
	qrCode, err := GenerateQRCode(deviceFlow.DeviceURL)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate QR code")
		qrCode = ""
	}

	// Create a pending session keyed by SessionID
	session := &Session{
		ID:                 req.SessionID,
		RequestedLocalUser: req.UserID,
		Provider:           provider.Name(),
		CreatedAt:          time.Now(),
		ExpiresAt:          deviceFlow.ExpiresAt,
		LastAccessed:       time.Now(),
		SourceIP:           req.SourceIP,
		IsActive:           false,
		Metadata:           req.Metadata,
	}
	b.setSession(session)

	// Poll in the background; update session when done
	b.wg.Add(1)
	go b.pollDeviceAuthorization(session, provider, deviceFlow)

	return &AuthResponse{
		Success:        true,
		SessionID:      session.ID,
		DeviceCode:     deviceFlow.UserCode,
		DeviceURL:      deviceFlow.DeviceURL,
		QRCode:         qrCode,
		ExpiresAt:      deviceFlow.ExpiresAt,
		RequiresDevice: true,
		Metadata: map[string]interface{}{
			"provider":         provider.Name(),
			"polling_interval": deviceFlow.PollingInterval,
		},
	}, nil
}

// CheckSession returns the current state of a session.
func (b *Broker) CheckSession(sessionID string) (*AuthResponse, error) {
	session := b.getSession(sessionID)
	if session == nil {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "SESSION_NOT_FOUND",
			ErrorMessage: "Session not found",
		}, nil
	}

	if !session.IsActive {
		return &AuthResponse{
			Success:        true,
			SessionID:      sessionID,
			RequiresDevice: true,
			ExpiresAt:      session.ExpiresAt,
			Metadata:       map[string]interface{}{"status": "pending"},
		}, nil
	}

	if session.ExpiresAt.Before(time.Now()) {
		b.removeSession(sessionID)
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "SESSION_EXPIRED",
			ErrorMessage: "Session has expired",
		}, nil
	}

	return b.successResponse(session), nil
}

// RefreshSession extends a session if it is close to expiry.
func (b *Broker) RefreshSession(sessionID string) (*AuthResponse, error) {
	session := b.getSession(sessionID)
	if session == nil {
		return &AuthResponse{
			Success:      false,
			ErrorCode:    "SESSION_NOT_FOUND",
			ErrorMessage: "Session not found",
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

// RevokeSession removes a session.
func (b *Broker) RevokeSession(sessionID string) error {
	session := b.getSession(sessionID)
	if session == nil {
		return fmt.Errorf("session not found: %s", sessionID)
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

func (b *Broker) pollDeviceAuthorization(session *Session, provider *github.Provider, df *github.DeviceFlow) {
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
				Str("session_id", session.ID).
				Msg("Device flow expired")
			b.removeSession(session.ID)
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
					b.removeSession(session.ID)
					return
				case github.ErrAccessDenied:
					b.auditLogger.LogAuthEvent(security.AuditEvent{
						EventType:    "authentication_denied",
						SessionID:    session.ID,
						Provider:     provider.Name(),
						Success:      false,
						ErrorMessage: "user denied authorization",
						Timestamp:    time.Now(),
					})
					b.removeSession(session.ID)
					return
				default:
					log.Error().Err(err).Str("session_id", session.ID).Msg("Device poll error")
					b.removeSession(session.ID)
					return
				}
			}

			// Token obtained — fetch identity
			identity, err := provider.GetIdentity(b.ctx, token)
			if err != nil {
				log.Error().Err(err).Str("session_id", session.ID).Msg("Failed to get GitHub identity")
				b.auditLogger.LogAuthEvent(security.AuditEvent{
					EventType:    "authentication_failed",
					SessionID:    session.ID,
					Provider:     provider.Name(),
					Success:      false,
					ErrorMessage: err.Error(),
					Timestamp:    time.Now(),
				})
				b.removeSession(session.ID)
				return
			}

			// Map to local user; pass the PAM-requested username for Tier 0 enrollment lookup
			mapResult, err := b.mapper.Map(b.ctx, identity, session.RequestedLocalUser)
			if err != nil {
				log.Error().Err(err).
					Str("session_id", session.ID).
					Str("github_login", identity.Login).
					Msg("Identity mapping failed")
				b.auditLogger.LogAuthEvent(security.AuditEvent{
					EventType:    "authentication_failed",
					UserID:       identity.Login,
					SessionID:    session.ID,
					Provider:     provider.Name(),
					Success:      false,
					ErrorMessage: err.Error(),
					Timestamp:    time.Now(),
				})
				b.removeSession(session.ID)
				return
			}

			// Update session with resolved identity
			session.LocalUser = mapResult.LocalUser
			session.GitHubLogin = identity.Login
			session.Email = identity.Email
			session.Groups = mapResult.Groups
			session.TokenFingerprint = token.Fingerprint
			session.IsActive = true
			b.setSession(session)

			b.auditLogger.LogAuthEvent(security.AuditEvent{
				EventType:  "authentication_success",
				UserID:     mapResult.LocalUser,
				Email:      identity.Email,
				Groups:     mapResult.Groups,
				SessionID:  session.ID,
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
				Str("session_id", session.ID).
				Str("local_user", mapResult.LocalUser).
				Str("github_login", identity.Login).
				Msg("Authentication successful")
			return
		}
	}
}

// --- session helpers ---

func (b *Broker) getSession(sessionID string) *Session {
	if sessionID == "" {
		return nil
	}
	b.sessionMutex.RLock()
	defer b.sessionMutex.RUnlock()
	return b.sessions[sessionID]
}

func (b *Broker) setSession(session *Session) {
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()
	b.sessions[session.ID] = session
}

func (b *Broker) removeSession(sessionID string) {
	b.sessionMutex.Lock()
	defer b.sessionMutex.Unlock()
	delete(b.sessions, sessionID)
}

func (b *Broker) successResponse(session *Session) *AuthResponse {
	return &AuthResponse{
		Success:   true,
		UserID:    session.LocalUser,
		Email:     session.Email,
		Groups:    session.Groups,
		SessionID: session.ID,
		ExpiresAt: session.ExpiresAt,
		Metadata: map[string]interface{}{
			"provider":      session.Provider,
			"github_login":  session.GitHubLogin,
			"last_accessed": session.LastAccessed,
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
				_ = b.RevokeSession(id)
			}

			if len(expired) > 0 {
				log.Info().Int("count", len(expired)).Msg("Cleaned up expired sessions")
			}
		}
	}
}
