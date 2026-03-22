package pam

/*
#cgo CFLAGS: -I${SRCDIR} -I/usr/include/security
#cgo LDFLAGS: -lpam -ljson-c
#include "cgo_bridge.h"
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// AuthRequest is a minimal auth request sent to the broker over the socket.
type AuthRequest struct {
	Type       string            `json:"type"`
	UserID     string            `json:"user_id"`
	LoginType  string            `json:"login_type"`
	TargetHost string            `json:"target_host"`
	Metadata   map[string]string `json:"metadata"`
}

// AuthResponse is the broker's response parsed by the PAM module.
type AuthResponse struct {
	Success        bool   `json:"success"`
	RequiresDevice bool   `json:"requires_device,omitempty"`
	Instructions   string `json:"instructions,omitempty"`
	ErrorMessage   string `json:"error_message,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
	UserID         string `json:"user_id,omitempty"`
}

// ConnectToBroker opens a connection to the broker Unix socket.
func ConnectToBroker(socketPath string) (int, error) {
	cs := C.CString(socketPath)
	defer C.free(unsafe.Pointer(cs))

	sock := C.connect_to_broker(cs)
	if sock == -1 {
		return -1, fmt.Errorf("failed to connect to broker at %s", socketPath)
	}
	return int(sock), nil
}

// SendAuthRequest sends an authentication request over the socket.
func SendAuthRequest(sock int, username, service, rhost, tty string) error {
	cu := C.CString(username)
	cs := C.CString(service)
	cr := C.CString(rhost)
	ct := C.CString(tty)
	defer C.free(unsafe.Pointer(cu))
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(cr))
	defer C.free(unsafe.Pointer(ct))

	if C.send_auth_request(C.int(sock), cu, cs, cr, ct) != 0 {
		return fmt.Errorf("failed to send authentication request")
	}
	return nil
}

// ReceiveAuthResponse reads and parses the broker's JSON response.
func ReceiveAuthResponse(sock int) (*AuthResponse, error) {
	var buf [MAX_RESPONSE_SIZE]C.char
	if C.receive_auth_response(C.int(sock), &buf[0], MAX_RESPONSE_SIZE) != 0 {
		return nil, fmt.Errorf("failed to receive authentication response")
	}

	s := C.GoString(&buf[0])
	if s == "" {
		return nil, fmt.Errorf("empty response from broker")
	}

	var resp AuthResponse
	if err := json.Unmarshal([]byte(s), &resp); err != nil {
		return nil, fmt.Errorf("parse authentication response: %w", err)
	}
	return &resp, nil
}

// LogPAMMessage logs a message through syslog at the given priority.
func LogPAMMessage(priority int, message string) {
	cm := C.CString(message)
	defer C.free(unsafe.Pointer(cm))
	C.log_pam_message_string(C.int(priority), cm)
}

// CloseSocket closes the broker socket.
func CloseSocket(sock int) {
	C.close(C.int(sock))
}

// IsSocketPathValid returns true if the path is a plausible Unix socket path.
func IsSocketPathValid(socketPath string) bool {
	return socketPath != "" && socketPath[0] == '/' && len(socketPath) <= 107
}

// GetLoginType maps a PAM service name / tty to a login type string.
func GetLoginType(service, tty string) string {
	switch service {
	case "sshd":
		return "ssh"
	case "gdm", "lightdm", "sddm":
		return "gui"
	default:
		if len(tty) >= 3 && tty[:3] == "tty" {
			return "console"
		}
		return "unknown"
	}
}

// BuildAuthRequest constructs an AuthRequest from PAM environment values.
func BuildAuthRequest(username, service, rhost, tty string) *AuthRequest {
	return &AuthRequest{
		Type:       "authenticate",
		UserID:     username,
		LoginType:  GetLoginType(service, tty),
		TargetHost: rhost,
		Metadata: map[string]string{
			"service": service,
			"tty":     tty,
			"pid":     fmt.Sprintf("%d", C.getpid()),
		},
	}
}

// SerializeAuthRequest marshals an AuthRequest to JSON.
func SerializeAuthRequest(req *AuthRequest) ([]byte, error) {
	return json.Marshal(req)
}

// MAX_RESPONSE_SIZE matches the C constant.
const MAX_RESPONSE_SIZE = 8192
