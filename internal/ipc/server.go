package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/pkg/auth"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

// maxRequestSize is the largest JSON body accepted from a PAM client.
// Requests larger than this are rejected before decoding to prevent
// memory exhaustion attacks.
const maxRequestSize = 64 * 1024 // 64 KB

// Server handles IPC communication between the PAM module and the broker.
type Server struct {
	socketPath  string
	broker      *auth.Broker
	listener    net.Listener
	rateLimiter *rateLimiter
	stopChan    chan struct{}
	wg          sync.WaitGroup
	stopOnce    sync.Once
}

// Request is a message from the PAM module.
type Request struct {
	Type       string                 `json:"type"`       // authenticate, check_session, refresh_session, revoke_session
	UserID     string                 `json:"user_id"`
	SourceIP   string                 `json:"source_ip"`
	UserAgent  string                 `json:"user_agent"`
	TargetHost string                 `json:"target_host"`
	LoginType  string                 `json:"login_type"` // ssh, console, gui
	DeviceID   string                 `json:"device_id"`
	SessionID  string                 `json:"session_id"`
	Metadata   map[string]string `json:"metadata"`
}

// Response is a message from the broker to the PAM module.
type Response struct {
	Success          bool                   `json:"success"`
	UserID           string                 `json:"user_id"`
	Email            string                 `json:"email"`
	Groups           []string               `json:"groups"`
	SessionID        string                 `json:"session_id"`
	DeviceCode       string                 `json:"device_code"`
	DeviceURL        string                 `json:"device_url"`
	QRCode           string                 `json:"qr_code"`
	ExpiresAt        time.Time              `json:"expires_at"`
	RequiresDevice   bool                   `json:"requires_device"`
	RequiresApproval bool                   `json:"requires_approval"`
	ErrorCode        string                 `json:"error_code"`
	ErrorMessage     string                 `json:"error_message"`
	Instructions     string                 `json:"instructions"`
	Metadata         map[string]string `json:"metadata"`
}

// NewServer creates a new IPC server.
func NewServer(socketPath string, broker *auth.Broker, cfg *config.Config) (*Server, error) {
	rl := newRateLimiter(cfg.Security.RateLimiting.MaxRequestsPerMinute)
	return &Server{
		socketPath:  socketPath,
		broker:      broker,
		rateLimiter: rl,
		stopChan:    make(chan struct{}),
	}, nil
}

// Start begins accepting connections on the Unix socket.
func (s *Server) Start(ctx context.Context) error {
	if err := os.RemoveAll(s.socketPath); err != nil {
		return fmt.Errorf("remove existing socket: %w", err)
	}
	// Directory needs to be accessible by the PAM module process (root-owned,
	// group oauth2-pam). The socket itself is 0660.
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0750); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.socketPath, err)
	}
	s.listener = l

	// 0660: readable/writable by owner and group (oauth2-pam) only.
	// The PAM module process must run as a member of the oauth2-pam group.
	// 0666 (world-writable) would allow any local user to send arbitrary
	// requests to the broker.
	if err := os.Chmod(s.socketPath, 0660); err != nil {
		log.Warn().Err(err).Str("socket", s.socketPath).Msg("Failed to set socket permissions")
	}

	log.Info().Str("socket", s.socketPath).Msg("IPC server started")

	s.wg.Add(2)
	go s.acceptConnections(ctx)
	go s.evictRateLimitWindows(ctx)

	return nil
}

// Stop shuts down the IPC server.
func (s *Server) Stop() error {
	s.stopOnce.Do(func() {
		close(s.stopChan)
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.wg.Wait()
		if err := os.RemoveAll(s.socketPath); err != nil {
			log.Warn().Err(err).Str("socket", s.socketPath).Msg("Failed to remove socket file")
		}
		log.Info().Msg("IPC server stopped")
	})
	return nil
}

func (s *Server) acceptConnections(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
		}

		if ul, ok := s.listener.(*net.UnixListener); ok {
			_ = ul.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-s.stopChan:
				return
			default:
				log.Error().Err(err).Msg("Accept error")
				return
			}
		}

		// Check rate limit before spawning a goroutine.
		uid := peerUID(conn)
		if !s.rateLimiter.allow(uid) {
			log.Warn().Uint32("uid", uid).Msg("Rate limit exceeded, rejecting connection")
			s.sendErrorOnConn(conn, "RATE_LIMITED", "Too many requests; try again later")
			_ = conn.Close()
			continue
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Reject requests that exceed the size limit before JSON decoding.
	limited := io.LimitReader(conn, maxRequestSize+1)

	var req Request
	if err := json.NewDecoder(limited).Decode(&req); err != nil {
		log.Error().Err(err).Msg("Decode IPC request")
		s.sendError(conn, "INVALID_REQUEST", "Failed to decode request")
		return
	}

	if err := validateRequest(&req); err != nil {
		log.Warn().Err(err).Msg("Invalid IPC request fields")
		s.sendError(conn, "INVALID_REQUEST", "Invalid request fields")
		return
	}

	resp := s.dispatch(&req)

	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		log.Error().Err(err).Msg("Encode IPC response")
	}

	log.Debug().
		Str("type", req.Type).
		Str("user_id", req.UserID).
		Bool("success", resp.Success).
		Msg("IPC request handled")
}

// validateRequest checks that all fields are within expected bounds.
// Returns a non-nil error if any field is out of range.
func validateRequest(req *Request) error {
	// Whitelist request types
	switch req.Type {
	case "authenticate", "check_session", "refresh_session", "revoke_session":
		// valid
	default:
		return fmt.Errorf("unknown request type %q", req.Type)
	}

	if len(req.UserID) > 256 {
		return fmt.Errorf("user_id too long (%d bytes)", len(req.UserID))
	}
	if strings.ContainsRune(req.UserID, '\x00') {
		return fmt.Errorf("user_id contains NUL byte")
	}
	if len(req.SessionID) > 128 {
		return fmt.Errorf("session_id too long (%d bytes)", len(req.SessionID))
	}
	if len(req.SourceIP) > 45 {
		return fmt.Errorf("source_ip too long (%d bytes)", len(req.SourceIP))
	}
	if len(req.TargetHost) > 253 {
		return fmt.Errorf("target_host too long (%d bytes)", len(req.TargetHost))
	}
	if req.LoginType != "" &&
		req.LoginType != "ssh" &&
		req.LoginType != "console" &&
		req.LoginType != "gui" {
		return fmt.Errorf("invalid login_type %q", req.LoginType)
	}
	for k, v := range req.Metadata {
		if strings.ContainsRune(k, '\x00') || strings.ContainsRune(v, '\x00') {
			return fmt.Errorf("metadata contains NUL byte")
		}
	}
	return nil
}

func (s *Server) dispatch(req *Request) *Response {
	switch req.Type {
	case "authenticate":
		return s.handleAuthenticate(req)
	case "check_session":
		return s.handleCheckSession(req)
	case "refresh_session":
		return s.handleRefreshSession(req)
	case "revoke_session":
		return s.handleRevokeSession(req)
	default:
		// Already caught by validateRequest, but keep as a safety net.
		return &Response{
			Success:      false,
			ErrorCode:    "INVALID_REQUEST_TYPE",
			ErrorMessage: "Unknown request type",
		}
	}
}

func (s *Server) handleAuthenticate(req *Request) *Response {
	authReq := &auth.AuthRequest{
		UserID:     req.UserID,
		SourceIP:   req.SourceIP,
		UserAgent:  req.UserAgent,
		TargetHost: req.TargetHost,
		LoginType:  req.LoginType,
		DeviceID:   req.DeviceID,
		// req.SessionID is intentionally not forwarded — the broker generates
		// its own session IDs with crypto/rand to prevent session fixation.
		Timestamp: time.Now(),
		Metadata:  req.Metadata,
	}

	ar, err := s.broker.Authenticate(authReq)
	if err != nil {
		log.Error().Err(err).Str("user_id", req.UserID).Msg("Authenticate error")
		return &Response{
			Success:      false,
			ErrorCode:    "AUTHENTICATION_FAILED",
			ErrorMessage: "Authentication failed",
		}
	}

	resp := authResponseToIPC(ar)
	if ar.RequiresDevice {
		resp.Instructions = formatInstructions(req.LoginType, ar.DeviceURL, ar.DeviceCode, ar.QRCode)
	}
	return resp
}

func (s *Server) handleCheckSession(req *Request) *Response {
	ar, err := s.broker.CheckSession(req.SessionID)
	if err != nil {
		return &Response{
			Success:      false,
			ErrorCode:    "SESSION_CHECK_FAILED",
			ErrorMessage: "Session check failed",
		}
	}
	return authResponseToIPC(ar)
}

func (s *Server) handleRefreshSession(req *Request) *Response {
	ar, err := s.broker.RefreshSession(req.SessionID)
	if err != nil {
		return &Response{
			Success:      false,
			ErrorCode:    "SESSION_REFRESH_FAILED",
			ErrorMessage: "Session refresh failed",
		}
	}
	return authResponseToIPC(ar)
}

func (s *Server) handleRevokeSession(req *Request) *Response {
	if err := s.broker.RevokeSession(req.SessionID); err != nil {
		return &Response{
			Success:      false,
			ErrorCode:    "SESSION_REVOCATION_FAILED",
			ErrorMessage: "Session revocation failed",
		}
	}
	return &Response{Success: true}
}

func (s *Server) sendError(conn net.Conn, code, message string) {
	resp := &Response{Success: false, ErrorCode: code, ErrorMessage: message}
	_ = json.NewEncoder(conn).Encode(resp)
}

// sendErrorOnConn is used before the deadline is set (e.g. rate-limit rejection).
func (s *Server) sendErrorOnConn(conn net.Conn, code, message string) {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	s.sendError(conn, code, message)
}

func authResponseToIPC(ar *auth.AuthResponse) *Response {
	return &Response{
		Success:          ar.Success,
		UserID:           ar.UserID,
		Email:            ar.Email,
		Groups:           ar.Groups,
		SessionID:        ar.SessionID,
		DeviceCode:       ar.DeviceCode,
		DeviceURL:        ar.DeviceURL,
		QRCode:           ar.QRCode,
		ExpiresAt:        ar.ExpiresAt,
		RequiresDevice:   ar.RequiresDevice,
		RequiresApproval: ar.RequiresApproval,
		ErrorCode:        ar.ErrorCode,
		ErrorMessage:     ar.ErrorMessage,
		Metadata:         ar.Metadata,
	}
}

func formatInstructions(loginType, deviceURL, deviceCode, qrCode string) string {
	switch loginType {
	case "console":
		return auth.FormatConsoleInstructions(deviceURL, deviceCode, qrCode)
	case "gui":
		return auth.FormatGUIInstructions(deviceURL, deviceCode, qrCode)
	default: // ssh
		return auth.FormatDeviceInstructions(deviceURL, deviceCode, qrCode)
	}
}

// evictRateLimitWindows periodically cleans up stale rate-limit entries.
func (s *Server) evictRateLimitWindows(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.rateLimiter.evict()
		}
	}
}
