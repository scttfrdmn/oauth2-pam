package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/pam-oauth2/pkg/auth"
)

// Server handles IPC communication between the PAM module and the broker.
type Server struct {
	socketPath string
	broker     *auth.Broker
	listener   net.Listener
	stopChan   chan struct{}
	wg         sync.WaitGroup
	stopOnce   sync.Once
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
	Metadata   map[string]interface{} `json:"metadata"`
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
	Metadata         map[string]interface{} `json:"metadata"`
}

// NewServer creates a new IPC server.
func NewServer(socketPath string, broker *auth.Broker) (*Server, error) {
	return &Server{
		socketPath: socketPath,
		broker:     broker,
		stopChan:   make(chan struct{}),
	}, nil
}

// Start begins accepting connections on the Unix socket.
func (s *Server) Start(ctx context.Context) error {
	if err := os.RemoveAll(s.socketPath); err != nil {
		return fmt.Errorf("remove existing socket: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0755); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.socketPath, err)
	}
	s.listener = l

	if err := os.Chmod(s.socketPath, 0666); err != nil {
		log.Warn().Err(err).Str("socket", s.socketPath).Msg("Failed to set socket permissions")
	}

	log.Info().Str("socket", s.socketPath).Msg("IPC server started")

	s.wg.Add(1)
	go s.acceptConnections(ctx)

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

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		log.Error().Err(err).Msg("Decode IPC request")
		s.sendError(conn, "INVALID_REQUEST", "Failed to decode request")
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
		return &Response{
			Success:      false,
			ErrorCode:    "INVALID_REQUEST_TYPE",
			ErrorMessage: fmt.Sprintf("unknown request type: %s", req.Type),
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
		SessionID:  req.SessionID,
		Timestamp:  time.Now(),
		Metadata:   req.Metadata,
	}

	ar, err := s.broker.Authenticate(authReq)
	if err != nil {
		log.Error().Err(err).Str("user_id", req.UserID).Msg("Authenticate error")
		return &Response{
			Success:      false,
			ErrorCode:    "AUTHENTICATION_FAILED",
			ErrorMessage: err.Error(),
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
			ErrorMessage: err.Error(),
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
			ErrorMessage: err.Error(),
		}
	}
	return authResponseToIPC(ar)
}

func (s *Server) handleRevokeSession(req *Request) *Response {
	if err := s.broker.RevokeSession(req.SessionID); err != nil {
		return &Response{
			Success:      false,
			ErrorCode:    "SESSION_REVOCATION_FAILED",
			ErrorMessage: err.Error(),
		}
	}
	return &Response{Success: true}
}

func (s *Server) sendError(conn net.Conn, code, message string) {
	resp := &Response{Success: false, ErrorCode: code, ErrorMessage: message}
	_ = json.NewEncoder(conn).Encode(resp)
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
