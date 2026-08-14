package ipc

import (
	"context"
	"encoding/json"
	"fmt"
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
		{"authenticate", Request{Type: "authenticate", UserID: "alice"}, ""},
		// An authenticate request with no username makes the broker's
		// mapped-equals-requested check vacuous, so it is refused outright.
		{"authenticate with no user", Request{Type: "authenticate"}, "non-empty user_id"},
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
		{"source ip over the limit", Request{Type: "authenticate", UserID: "alice", SourceIP: strings.Repeat("a", 46)}, "source_ip too long"},
		{"target host over the limit", Request{Type: "authenticate", UserID: "alice", TargetHost: strings.Repeat("a", 254)}, "target_host too long"},

		{"login type ssh", Request{Type: "authenticate", UserID: "alice", LoginType: "ssh"}, ""},
		{"login type console", Request{Type: "authenticate", UserID: "alice", LoginType: "console"}, ""},
		{"login type gui", Request{Type: "authenticate", UserID: "alice", LoginType: "gui"}, ""},
		{"empty login type defaults", Request{Type: "authenticate", UserID: "alice", LoginType: ""}, ""},
		{"invalid login type", Request{Type: "authenticate", UserID: "alice", LoginType: "telnet"}, "invalid login_type"},

		{
			"metadata value with NUL",
			Request{Type: "authenticate", UserID: "alice", Metadata: map[string]string{"k": "v\x00"}},
			"NUL byte",
		},
		{
			"metadata key with NUL",
			Request{Type: "authenticate", UserID: "alice", Metadata: map[string]string{"k\x00": "v"}},
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
		if !rl.allow("uid:1000") {
			t.Fatalf("request %d denied, want allowed", i)
		}
	}
	if rl.allow("uid:1000") {
		t.Error("request 4 allowed, want denied")
	}
}

func TestRateLimiterIsPerKey(t *testing.T) {
	rl := newRateLimiter(1)

	if !rl.allow("uid:1000") {
		t.Fatal("uid 1000 first request denied")
	}
	if rl.allow("uid:1000") {
		t.Error("uid 1000 second request allowed")
	}
	// One noisy user must not lock everyone else out.
	if !rl.allow("uid:1001") {
		t.Error("uid 1001 was denied because uid 1000 exhausted its window")
	}
}

func TestRateLimiterWindowResets(t *testing.T) {
	rl := newRateLimiter(1)

	if !rl.allow("uid:1000") {
		t.Fatal("first request denied")
	}
	if rl.allow("uid:1000") {
		t.Fatal("second request in the same window allowed")
	}

	// Age the window instead of sleeping a minute.
	rl.mu.Lock()
	rl.windows["uid:1000"].resetAt = time.Now().Add(-time.Second)
	rl.mu.Unlock()

	if !rl.allow("uid:1000") {
		t.Error("request denied after the window elapsed")
	}
}

func TestRateLimiterEvictsStaleWindows(t *testing.T) {
	rl := newRateLimiter(10)

	rl.allow("uid:1000")
	rl.allow("uid:1001")

	rl.mu.Lock()
	rl.windows["uid:1000"].resetAt = time.Now().Add(-time.Second) // stale
	rl.mu.Unlock()

	rl.evict()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if _, ok := rl.windows["uid:1000"]; ok {
		t.Error("stale window was not evicted; the map grows without bound")
	}
	if _, ok := rl.windows["uid:1001"]; !ok {
		t.Error("a live window was evicted")
	}
}

// TestUnknownPeerKeyIsNotRoot guards the reason unknownPeerKey exists: peerUID
// used to return 0 for every peer it could not identify, so unknown callers and
// root shared a window and the logs called them root.
func TestUnknownPeerKeyIsNotRoot(t *testing.T) {
	if callerKey(0, true) == unknownPeerKey {
		t.Fatal("the unknown-peer bucket collides with root's real UID")
	}

	rl := newRateLimiter(1)
	if !rl.allow(unknownPeerKey) {
		t.Fatal("first unidentified request denied")
	}
	if rl.allow(unknownPeerKey) {
		t.Error("second unidentified request allowed; the shared bucket is not counting")
	}
	if !rl.allow(callerKey(0, true)) {
		t.Error("root was denied because unidentified callers exhausted its window")
	}
}

// TestPollsAreBucketedPerSessionNotPerCaller is the regression test for a
// verified host-wide login DoS: every PAM caller is sshd as root, so charging
// check_session polls to the caller's UID meant a handful of concurrent logins
// exhausted one shared window and the next poll came back RATE_LIMITED, which
// the module treats as terminal. Two logins must not compete for one budget.
func TestPollsAreBucketedPerSessionNotPerCaller(t *testing.T) {
	rl := newRateLimiter(2)

	for i := 0; i < 2; i++ {
		if !rl.allow(sessionKey("session-a")) {
			t.Fatalf("poll %d for session-a denied", i+1)
		}
	}
	if rl.allow(sessionKey("session-a")) {
		t.Error("session-a exceeded its own budget without being denied")
	}
	// The other login, from the same root caller, is unaffected.
	if !rl.allow(sessionKey("session-b")) {
		t.Error("session-b was denied because session-a exhausted its window")
	}
	if !rl.allow(callerKey(0, true)) {
		t.Error("an authenticate request was denied by another session's polling")
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

// --- session rate-limit key space ---

// newLimiterTestServer is a Server with its limiters wired as production wires
// them, and nothing else started. Everything below exercises allowRequest and the
// eviction sweep, neither of which touches the broker or the socket.
func newLimiterTestServer(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer("/tmp/unused.sock", nil, testConfig("/tmp/unused.sock"))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

// anonymousConn is a connection carrying no peer credentials, so peerUID reports
// the caller as unidentified — the same bucket a caller the broker cannot name
// would land in.
func anonymousConn(t *testing.T) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	return server
}

func TestSessionLimiterIsBuiltWithABoundedKeySpace(t *testing.T) {
	srv := newLimiterTestServer(t)

	// The session limiter is keyed on a value the caller chooses, so its map needs
	// a ceiling; the caller limiter is keyed on UIDs and must not have one.
	if srv.sessionLimiter.maxKeys != maxSessionLimiterKeys {
		t.Errorf("sessionLimiter.maxKeys = %d, want %d", srv.sessionLimiter.maxKeys, maxSessionLimiterKeys)
	}
	if srv.rateLimiter.maxKeys != 0 {
		t.Errorf("rateLimiter.maxKeys = %d, want 0: capping the per-UID limiter can only refuse real callers", srv.rateLimiter.maxKeys)
	}
	if srv.newSessionLimiter == nil {
		t.Fatal("no limiter charges the introduction of a new session ID")
	}
	if srv.newSessionLimiter.maxRPM != maxNewSessionsPerMinute {
		t.Errorf("newSessionLimiter.maxRPM = %d, want %d", srv.newSessionLimiter.maxRPM, maxNewSessionsPerMinute)
	}
}

// TestEvictionSweepReachesEveryLimiter is the regression test for the one-line
// half of the bug: the sweep ran every five minutes and cleaned only
// s.rateLimiter, so the one limiter with a caller-supplied key space —
// sessionLimiter — kept every window it ever allocated for the life of the
// process. It drives the real goroutine rather than calling evictNow by hand, so
// a sweep that forgets a limiter fails here.
func TestEvictionSweepReachesEveryLimiter(t *testing.T) {
	srv := newLimiterTestServer(t)
	srv.evictInterval = 5 * time.Millisecond

	limiters := map[string]*rateLimiter{
		"rateLimiter":       srv.rateLimiter,
		"sessionLimiter":    srv.sessionLimiter,
		"newSessionLimiter": srv.newSessionLimiter,
	}
	for name, rl := range limiters {
		if !rl.allow("stale-key") {
			t.Fatalf("%s refused its first request", name)
		}
		rl.stale(t, "stale-key")
	}

	ctx, cancel := context.WithCancel(context.Background())
	srv.wg.Add(1)
	go srv.evictRateLimitWindows(ctx)
	t.Cleanup(func() {
		cancel()
		srv.wg.Wait()
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		remaining := []string{}
		for name, rl := range limiters {
			if rl.windowCount() != 0 {
				remaining = append(remaining, name)
			}
		}
		if len(remaining) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the eviction sweep never reached %v; those windows are retained for the life of the process", remaining)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestUnknownSessionIDFloodStaysBounded is the measured reproduction from the
// issue, in-tree: 3000 check_session requests with a distinct invented session ID
// each left sessionLimiter holding 3000 permanent windows, with nothing charged to
// the caller and nothing refused.
func TestUnknownSessionIDFloodStaysBounded(t *testing.T) {
	srv := newLimiterTestServer(t)
	conn := anonymousConn(t)

	const flood = 3000
	refused := 0
	for i := 0; i < flood; i++ {
		req := &Request{Type: "check_session", SessionID: fmt.Sprintf("invented-session-%d", i)}
		if !srv.allowRequest(conn, req) {
			refused++
		}
	}

	if refused == 0 {
		t.Errorf("none of %d requests naming a session ID the broker never issued was refused; the flood costs the caller nothing", flood)
	}
	windows := srv.sessionLimiter.windowCount()
	if windows > maxNewSessionsPerMinute {
		t.Errorf("sessionLimiter holds %d windows after %d invented session IDs, want at most the caller's per-minute allowance of %d",
			windows, flood, maxNewSessionsPerMinute)
	}
	if windows > maxSessionLimiterKeys {
		t.Errorf("sessionLimiter holds %d windows, over its own ceiling of %d", windows, maxSessionLimiterKeys)
	}
	// The charge lands in one bucket per caller, not one per session.
	if got := srv.newSessionLimiter.windowCount(); got != 1 {
		t.Errorf("newSessionLimiter holds %d windows, want 1 (a single caller)", got)
	}
}

// TestEstablishedSessionPollsSurviveAnUnknownSessionFlood is the no-regression
// half, and the reason the caller is charged for *introducing* a session ID
// rather than for every session request. The PAM module polls check_session for
// up to five minutes per login and every caller is sshd as root, so a per-caller
// charge on each poll is a host-wide login DoS (see
// TestPollsAreBucketedPerSessionNotPerCaller). An in-flight login must keep
// polling even while the same UID is exhausting its new-session allowance.
func TestEstablishedSessionPollsSurviveAnUnknownSessionFlood(t *testing.T) {
	srv := newLimiterTestServer(t)
	conn := anonymousConn(t)

	poll := func() bool {
		return srv.allowRequest(conn, &Request{Type: "check_session", SessionID: "a-real-session"})
	}

	if !poll() {
		t.Fatal("the first poll of a real session was refused")
	}

	// Exhaust the caller's allowance for introducing session IDs, twice over.
	for i := 0; i < maxNewSessionsPerMinute*2; i++ {
		srv.allowRequest(conn, &Request{Type: "check_session", SessionID: fmt.Sprintf("invented-%d", i)})
	}
	if srv.allowRequest(conn, &Request{Type: "check_session", SessionID: "one-more-invented"}) {
		t.Fatal("the caller's new-session allowance was never exhausted; the flood is unbounded")
	}

	// A full minute of polling at the module's fastest permitted interval, from
	// the session that is actually logging in. One unit is left for the revoke
	// below, since the per-session budget is what bounds this bucket.
	for i := 2; i < maxSessionRequestsPerMinute; i++ {
		if !poll() {
			t.Fatalf("poll %d of an established session was refused while another caller flooded invented IDs; this fails a legitimate login", i)
		}
	}
	// refresh_session and revoke_session for that session are the same bucket.
	if !srv.allowRequest(conn, &Request{Type: "revoke_session", SessionID: "a-real-session"}) {
		t.Error("revoking an established session was refused")
	}
}

// TestLegitimatePollSequenceIsNeverRateLimited runs the module's actual sequence
// over the socket — authenticate, poll, revoke — and asserts nothing in it is
// answered with RATE_LIMITED. The limiter changes above are only safe if this
// holds.
func TestLegitimatePollSequenceIsNeverRateLimited(t *testing.T) {
	h := newHarness(t)

	started := h.authenticate("alice")
	if started.ErrorCode == ErrorCodeRateLimited {
		t.Fatal("authenticate was rate limited")
	}
	if started.SessionID == "" {
		t.Fatalf("no session was issued: %+v", started)
	}

	// 60 polls is five minutes at the module's default interval, and half the
	// per-session budget.
	for i := 1; i <= 60; i++ {
		got := h.check(started.SessionID)
		if got.ErrorCode == ErrorCodeRateLimited {
			t.Fatalf("poll %d of a real session was answered RATE_LIMITED: %+v", i, got)
		}
	}

	revoked := h.roundtrip(Request{Type: "revoke_session", SessionID: started.SessionID})
	if revoked.ErrorCode == ErrorCodeRateLimited {
		t.Fatal("revoke_session at logout was rate limited")
	}
	if !revoked.Success {
		t.Errorf("revoke_session failed: %+v", revoked)
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
