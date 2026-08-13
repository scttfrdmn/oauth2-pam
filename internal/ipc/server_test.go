package ipc

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oauth2-pam/pkg/auth"
)

func TestValidateRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     Request
		wantErr string // substring; empty means the request must be accepted
	}{
		{"authenticate", Request{Type: "authenticate"}, ""},
		{"check_session", Request{Type: "check_session"}, ""},
		{"refresh_session", Request{Type: "refresh_session"}, ""},
		{"revoke_session", Request{Type: "revoke_session"}, ""},
		{"empty type", Request{}, "unknown request type"},
		{"unknown type", Request{Type: "sudo"}, "unknown request type"},

		{"user id at the limit", Request{Type: "authenticate", UserID: strings.Repeat("a", 256)}, ""},
		{"user id over the limit", Request{Type: "authenticate", UserID: strings.Repeat("a", 257)}, "user_id too long"},
		// A NUL would truncate the name inside the C module, so "alice\x00bob"
		// could be audited as one user and acted on as another.
		{"user id with NUL", Request{Type: "authenticate", UserID: "alice\x00bob"}, "NUL byte"},

		{"session id at the limit", Request{Type: "check_session", SessionID: strings.Repeat("a", 128)}, ""},
		{"session id over the limit", Request{Type: "check_session", SessionID: strings.Repeat("a", 129)}, "session_id too long"},
		{"source ip over the limit", Request{Type: "authenticate", SourceIP: strings.Repeat("a", 46)}, "source_ip too long"},
		{"target host over the limit", Request{Type: "authenticate", TargetHost: strings.Repeat("a", 254)}, "target_host too long"},

		{"login type ssh", Request{Type: "authenticate", LoginType: "ssh"}, ""},
		{"login type console", Request{Type: "authenticate", LoginType: "console"}, ""},
		{"login type gui", Request{Type: "authenticate", LoginType: "gui"}, ""},
		{"empty login type defaults", Request{Type: "authenticate", LoginType: ""}, ""},
		{"invalid login type", Request{Type: "authenticate", LoginType: "telnet"}, "invalid login_type"},

		{
			"metadata value with NUL",
			Request{Type: "authenticate", Metadata: map[string]string{"k": "v\x00"}},
			"NUL byte",
		},
		{
			"metadata key with NUL",
			Request{Type: "authenticate", Metadata: map[string]string{"k\x00": "v"}},
			"NUL byte",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRequest(&tc.req)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRequest() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateRequest() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("validateRequest() = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// rawRoundtrip writes arbitrary bytes to the socket, bypassing Request
// marshalling, so a test can send something a well-behaved client never would.
func (h *harness) rawRoundtrip(payload []byte) Response {
	h.t.Helper()

	conn, err := net.DialTimeout("unix", h.socket, 5*time.Second)
	if err != nil {
		h.t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// The server may reject and reply before the whole body is written, so a
	// short write here is expected rather than a failure.
	_, _ = conn.Write(payload)

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		h.t.Fatalf("decode response: %v", err)
	}
	return resp
}

// TestOversizedRequestIsRejected: the read is capped before decoding so a local
// caller cannot make the broker allocate without bound.
func TestOversizedRequestIsRejected(t *testing.T) {
	h := newHarness(t)

	// A syntactically valid request whose user_id alone exceeds the 64 KB cap.
	oversized, err := json.Marshal(Request{Type: "authenticate", UserID: strings.Repeat("a", 70*1024)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(oversized) <= maxRequestSize {
		t.Fatalf("test payload is %d bytes, not over the %d-byte cap", len(oversized), maxRequestSize)
	}

	resp := h.rawRoundtrip(oversized)
	if resp.Success {
		t.Error("an oversized request succeeded")
	}
	if resp.ErrorCode != "INVALID_REQUEST" {
		t.Errorf("error_code = %q, want INVALID_REQUEST", resp.ErrorCode)
	}
	if resp.Status != auth.StatusError {
		t.Errorf("status = %q, want %q", resp.Status, auth.StatusError)
	}
}

func TestMalformedRequestIsRejected(t *testing.T) {
	h := newHarness(t)

	resp := h.rawRoundtrip([]byte("this is not json\n"))
	if resp.Success {
		t.Error("a malformed request succeeded")
	}
	if resp.ErrorCode != "INVALID_REQUEST" {
		t.Errorf("error_code = %q, want INVALID_REQUEST", resp.ErrorCode)
	}
}

func TestInvalidFieldsAreRejectedOverTheWire(t *testing.T) {
	h := newHarness(t)

	resp := h.roundtrip(Request{Type: "authenticate", LoginType: "telnet"})
	if resp.Success {
		t.Error("a request with an invalid login_type succeeded")
	}
	if resp.ErrorCode != "INVALID_REQUEST" {
		t.Errorf("error_code = %q, want INVALID_REQUEST", resp.ErrorCode)
	}
}

// TestSocketPermissions: 0660 keeps arbitrary local users from talking to the
// broker. A world-writable socket would let any user request a device flow for
// any account.
func TestSocketPermissions(t *testing.T) {
	h := newHarness(t)

	info, err := os.Stat(h.socket)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0660 {
		t.Errorf("socket mode = %04o, want 0660", perm)
	}
}

// TestClientSessionIDIsIgnored covers session fixation: the broker must mint
// its own session ID rather than trust the one the client offers.
func TestClientSessionIDIsIgnored(t *testing.T) {
	h := newHarness(t)

	const attacker = "attacker-chosen-session-id"
	resp := h.roundtrip(Request{Type: "authenticate", UserID: "alice", LoginType: "ssh", SessionID: attacker})

	if resp.SessionID == attacker {
		t.Error("the broker adopted the client-supplied session ID (session fixation)")
	}
	if resp.SessionID == "" {
		t.Fatal("no session ID was issued")
	}
	// And the attacker's ID must not resolve to anything.
	if got := h.check(attacker); got.ErrorCode != "SESSION_NOT_FOUND" {
		t.Errorf("client-chosen session ID resolved to %+v", got)
	}
}

func TestServerIOTimeoutsComeFromConfig(t *testing.T) {
	tests := []struct {
		name              string
		read, write       time.Duration
		wantRead, wantWrt time.Duration
	}{
		{"configured", 5 * time.Second, 7 * time.Second, 5 * time.Second, 7 * time.Second},
		{"unset falls back to the default", 0, 0, defaultIOTimeout, defaultIOTimeout},
		{"negative falls back to the default", -time.Second, -time.Second, defaultIOTimeout, defaultIOTimeout},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig("/tmp/unused.sock")
			cfg.Server.ReadTimeout = tc.read
			cfg.Server.WriteTimeout = tc.write

			srv, err := NewServer(cfg.Server.SocketPath, nil, cfg)
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			if srv.readTimeout != tc.wantRead {
				t.Errorf("readTimeout = %s, want %s", srv.readTimeout, tc.wantRead)
			}
			if srv.writeTimeout != tc.wantWrt {
				t.Errorf("writeTimeout = %s, want %s", srv.writeTimeout, tc.wantWrt)
			}
		})
	}
}

// --- rate limiter ---

func TestRateLimiterAllowsUpToTheLimit(t *testing.T) {
	rl := newRateLimiter(3)

	for i := 1; i <= 3; i++ {
		if !rl.allow(1000) {
			t.Fatalf("request %d denied, want allowed", i)
		}
	}
	if rl.allow(1000) {
		t.Error("request 4 allowed, want denied")
	}
}

func TestRateLimiterIsPerUID(t *testing.T) {
	rl := newRateLimiter(1)

	if !rl.allow(1000) {
		t.Fatal("uid 1000 first request denied")
	}
	if rl.allow(1000) {
		t.Error("uid 1000 second request allowed")
	}
	// One noisy user must not lock everyone else out.
	if !rl.allow(1001) {
		t.Error("uid 1001 was denied because uid 1000 exhausted its window")
	}
}

func TestRateLimiterWindowResets(t *testing.T) {
	rl := newRateLimiter(1)

	if !rl.allow(1000) {
		t.Fatal("first request denied")
	}
	if rl.allow(1000) {
		t.Fatal("second request in the same window allowed")
	}

	// Age the window instead of sleeping a minute.
	rl.mu.Lock()
	rl.windows[1000].resetAt = time.Now().Add(-time.Second)
	rl.mu.Unlock()

	if !rl.allow(1000) {
		t.Error("request denied after the window elapsed")
	}
}

func TestRateLimiterEvictsStaleWindows(t *testing.T) {
	rl := newRateLimiter(10)

	rl.allow(1000)
	rl.allow(1001)

	rl.mu.Lock()
	rl.windows[1000].resetAt = time.Now().Add(-time.Second) // stale
	rl.mu.Unlock()

	rl.evict()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if _, ok := rl.windows[1000]; ok {
		t.Error("stale window was not evicted; the map grows without bound")
	}
	if _, ok := rl.windows[1001]; !ok {
		t.Error("a live window was evicted")
	}
}

// TestUnknownPeerBucketIsNotRoot guards the reason unknownPeerBucket exists:
// peerUID used to return 0 for every peer it could not identify, so unknown
// callers and root shared a window and the logs called them root.
func TestUnknownPeerBucketIsNotRoot(t *testing.T) {
	if unknownPeerBucket == 0 {
		t.Fatal("unknownPeerBucket is 0, which is root's real UID")
	}

	rl := newRateLimiter(1)
	if !rl.allow(unknownPeerBucket) {
		t.Fatal("first unidentified request denied")
	}
	if rl.allow(unknownPeerBucket) {
		t.Error("second unidentified request allowed; the shared bucket is not counting")
	}
	if !rl.allow(0) {
		t.Error("root was denied because unidentified callers exhausted its window")
	}
}

func TestRateLimiterDefaultsWhenUnset(t *testing.T) {
	for _, maxRPM := range []int{0, -1} {
		rl := newRateLimiter(maxRPM)
		if rl.maxRPM != 60 {
			t.Errorf("newRateLimiter(%d).maxRPM = %d, want the 60 default", maxRPM, rl.maxRPM)
		}
	}
}

// TestAuthResponseInvariant locks in the contract the PAM module relies on:
// success is true only for the authorized status.
func TestAuthResponseInvariant(t *testing.T) {
	statuses := []string{
		auth.StatusPending,
		auth.StatusAuthorized,
		auth.StatusDenied,
		auth.StatusExpired,
		auth.StatusError,
	}

	for _, status := range statuses {
		ar := &auth.AuthResponse{Status: status, Success: status == auth.StatusAuthorized}
		resp := authResponseToIPC(ar)

		if resp.Status != status {
			t.Errorf("status %q was not carried onto the wire (got %q)", status, resp.Status)
		}
		if want := status == auth.StatusAuthorized; resp.Success != want {
			t.Errorf("status %q: success = %v, want %v", status, resp.Success, want)
		}
	}
}

func TestUnknownRequestTypeNeverReachesDispatch(t *testing.T) {
	// dispatch has a default branch as a safety net; make sure it fails closed
	// if validateRequest is ever bypassed.
	srv, err := NewServer("/tmp/unused.sock", nil, testConfig("/tmp/unused.sock"))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	resp := srv.dispatch(&Request{Type: "definitely-not-a-real-type"})
	if resp.Success {
		t.Error("dispatch succeeded on an unknown request type")
	}
	if resp.Status != auth.StatusError {
		t.Errorf("status = %q, want %q", resp.Status, auth.StatusError)
	}
}
