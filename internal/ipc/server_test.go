package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
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

		// user_agent and device_id had no bound and no NUL check at all: a 64 KB
		// user_agent was accepted and written to the audit trail, and a NUL
		// survived into both. Everything a request carries is bounded, including
		// the fields nothing here interprets.
		{"user agent at the limit", Request{Type: "authenticate", UserID: "alice", UserAgent: strings.Repeat("a", maxUserAgentLen)}, ""},
		{"user agent over the limit", Request{Type: "authenticate", UserID: "alice", UserAgent: strings.Repeat("a", maxUserAgentLen+1)}, "user_agent too long"},
		{"user agent of 64 KB", Request{Type: "authenticate", UserID: "alice", UserAgent: strings.Repeat("a", 65476)}, "user_agent too long"},
		{"device id at the limit", Request{Type: "authenticate", UserID: "alice", DeviceID: strings.Repeat("a", maxDeviceIDLen)}, ""},
		{"device id over the limit", Request{Type: "authenticate", UserID: "alice", DeviceID: strings.Repeat("a", maxDeviceIDLen+1)}, "device_id too long"},

		// docs/wire-protocol.md requires a receiver to accept a zoned IPv6
		// literal, and it is the one address shape a well-meaning validator
		// breaks: net.ParseIP fails on a zone, as does inet_pton. This request is
		// accepted because source_ip is length-bounded audit context here and
		// nothing parses it — pinned so that stays a decision rather than a
		// detail someone "fixes" into refusing link-local logins.
		{"zoned IPv6 source ip", Request{Type: "authenticate", UserID: "alice", SourceIP: "fe80::1%eth0"}, ""},
		// A console login has no source address at all. Absent means "origin
		// unknown", never a malformed request.
		{"absent source ip", Request{Type: "authenticate", UserID: "alice", SourceIP: ""}, ""},
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
		// metadata is a map, so the count is a bound of its own: 3000 keys used to
		// be accepted, none of them individually remarkable.
		{
			"metadata at the entry limit",
			Request{Type: "authenticate", UserID: "alice", Metadata: metadataWith(maxMetadataEntries)},
			"",
		},
		{
			"metadata over the entry limit",
			Request{Type: "authenticate", UserID: "alice", Metadata: metadataWith(maxMetadataEntries + 1)},
			"too many entries",
		},
		{
			"metadata flood",
			Request{Type: "authenticate", UserID: "alice", Metadata: metadataWith(3000)},
			"too many entries",
		},
		{
			"metadata key over the limit",
			Request{Type: "authenticate", UserID: "alice", Metadata: map[string]string{strings.Repeat("k", maxMetadataKeyLen+1): "v"}},
			"metadata key too long",
		},
		{
			"metadata value over the limit",
			Request{Type: "authenticate", UserID: "alice", Metadata: map[string]string{"k": strings.Repeat("v", maxMetadataValueLen+1)}},
			"metadata value too long",
		},
		// What the reference client actually sends, so the ceilings above cannot be
		// tightened into refusing it.
		{
			"the reference client's metadata",
			Request{Type: "authenticate", UserID: "alice", Metadata: map[string]string{
				"service": "sshd", "tty": "ssh", "pid": "12345", "rhost": "client.example.com",
			}},
			"",
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

// metadataWith builds a metadata map of n entries, each small enough that only
// the count can be what refuses it.
func metadataWith(n int) map[string]string {
	m := make(map[string]string, n)
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("k%d", i)] = "v"
	}
	return m
}

// TestEveryRequestStringIsBounded is what keeps broker conformance item 6 —
// "bounds every request field" — true as Request grows.
//
// The claim was false when it was written: user_agent and device_id were added to
// the struct and never to the validator, because the validator was a run of ifs
// somebody had to remember to extend. This test reads the struct rather than a
// list of names, so a new string field fails here until it is either bounded in
// requestFields or whitelisted against fixed values the way type and login_type
// are.
func TestEveryRequestStringIsBounded(t *testing.T) {
	bounded := map[string]int{}
	for _, f := range requestFields(&Request{}) {
		if f.max <= 0 {
			t.Errorf("requestFields lists %q with max %d; a non-positive ceiling refuses every value", f.name, f.max)
		}
		bounded[f.name] = f.max
	}
	// Whitelisted against a fixed set of values in validateRequest, which is a
	// tighter bound than a length.
	whitelisted := map[string]bool{"type": true, "login_type": true}

	rt := reflect.TypeOf(Request{})
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		if field.Type.Kind() != reflect.String {
			continue
		}
		name := jsonName(field)
		if _, ok := bounded[name]; ok {
			continue
		}
		if whitelisted[name] {
			continue
		}
		t.Errorf("request field %q (%s) is neither bounded in requestFields nor whitelisted; "+
			"it reaches the log and the audit trail with whatever length and bytes the caller chose",
			name, field.Name)
	}
}

// TestEveryBoundedFieldRefusesNULAndOverlength drives requestFields itself, so a
// field added to the list is covered without a test being written for it — which
// is the whole reason the list exists.
//
// The NUL half is the one that had holes: session_id, source_ip and target_host
// were length-bounded with no NUL check, and source_ip and target_host are copied
// into an audit event verbatim.
func TestEveryBoundedFieldRefusesNULAndOverlength(t *testing.T) {
	for _, f := range requestFields(&Request{}) {
		t.Run(f.name, func(t *testing.T) {
			// check_session rather than authenticate so that a user_id set to a NUL
			// string is refused by the NUL check and not by the non-empty rule.
			withNUL := Request{Type: "check_session", UserID: "alice"}
			setRequestString(t, &withNUL, f.name, "alice\x00bob")
			assertRejected(t, &withNUL, "NUL byte")

			tooLong := Request{Type: "check_session", UserID: "alice"}
			setRequestString(t, &tooLong, f.name, strings.Repeat("a", f.max+1))
			assertRejected(t, &tooLong, f.name+" too long")

			atLimit := Request{Type: "check_session", UserID: "alice"}
			setRequestString(t, &atLimit, f.name, strings.Repeat("a", f.max))
			if err := validateRequest(&atLimit); err != nil {
				t.Errorf("a %s of exactly %d bytes was refused (%v); the bound must be a maximum, not one short of it",
					f.name, f.max, err)
			}
		})
	}
}

func assertRejected(t *testing.T, req *Request, want string) {
	t.Helper()
	err := validateRequest(req)
	if err == nil {
		t.Fatalf("validateRequest() = nil, want an error mentioning %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("validateRequest() = %q, want it to mention %q", err, want)
	}
}

// setRequestString sets the request field carrying the given wire name, so a test
// can be driven from requestFields rather than from a struct literal per field.
func setRequestString(t *testing.T, req *Request, wireName, value string) {
	t.Helper()
	rv := reflect.ValueOf(req).Elem()
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).Type.Kind() == reflect.String && jsonName(rt.Field(i)) == wireName {
			rv.Field(i).SetString(value)
			return
		}
	}
	t.Fatalf("requestFields names %q but Request has no string field with that json tag", wireName)
}

func jsonName(field reflect.StructField) string {
	name := strings.Split(field.Tag.Get("json"), ",")[0]
	if name == "" {
		return field.Name
	}
	return name
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

// TestOversizedRequestIsRejected: the read is capped at 64 KB so a local caller
// cannot make the broker allocate without bound.
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
	// And it says it was too big. Capping the read truncates the object, so the
	// decoder's own account of it is "unexpected EOF" — which sends a client
	// looking for a bug in its serializer instead of at the size of what it sent.
	if !strings.Contains(resp.ErrorMessage, "limit") {
		t.Errorf("error_message = %q; an oversized request must be reported as a size "+
			"failure, not as a decode failure", resp.ErrorMessage)
	}
}

// TestRequestSizeCapBoundary pins both sides of the 64 KB cap to the byte.
//
// The over-by-one half is the one worth having: the read is capped at
// maxRequestSize+1 so that reaching the extra byte is what identifies an
// oversized body, which means a body of exactly maxRequestSize+1 bytes decodes
// cleanly inside the limiter. Without a check on what was actually consumed, that
// one byte is the difference between the documented limit and the enforced one.
func TestRequestSizeCapBoundary(t *testing.T) {
	// requestOfSize builds a valid check_session body of exactly n bytes by padding
	// the session ID. Padding a field rather than adding whitespace keeps the bytes
	// inside the JSON value, which is what the decoder has to read to find its end
	// and therefore what the cap is protecting.
	requestOfSize := func(t *testing.T, n int) []byte {
		t.Helper()
		empty, err := json.Marshal(Request{Type: "check_session"})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		body, err := json.Marshal(Request{Type: "check_session", SessionID: strings.Repeat("a", n-len(empty))})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if len(body) != n {
			t.Fatalf("built a %d-byte body, want exactly %d", len(body), n)
		}
		return body
	}

	t.Run("exactly at the cap", func(t *testing.T) {
		h := newHarness(t)
		resp := h.rawRoundtrip(requestOfSize(t, maxRequestSize))
		// The session ID is far over its own 128-byte bound, so the answer is a field
		// refusal — what matters is that it got as far as being validated rather than
		// being refused for its size.
		if strings.Contains(resp.ErrorMessage, "limit") {
			t.Errorf("a request of exactly %d bytes was refused for its size (%q); the cap "+
				"is a maximum, not one byte short of it", maxRequestSize, resp.ErrorMessage)
		}
	})

	t.Run("one byte over the cap", func(t *testing.T) {
		h := newHarness(t)
		resp := h.rawRoundtrip(requestOfSize(t, maxRequestSize+1))
		if resp.ErrorCode != "INVALID_REQUEST" {
			t.Errorf("error_code = %q, want INVALID_REQUEST", resp.ErrorCode)
		}
		if !strings.Contains(resp.ErrorMessage, "limit") {
			t.Errorf("a request of %d bytes was answered %q; one byte over the cap is over "+
				"the cap, and the limiter's spare byte must not become a spare byte of budget",
				maxRequestSize+1, resp.ErrorMessage)
		}
	})
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
//
// The directory mode is asserted alongside it because the two together are the
// entire trust boundary. With the packaged unit running as root:root, 0750 on the
// directory plus 0660 on the socket is what makes the broker reachable by root
// and nobody else — and that fact is what several findings' severity rests on. It
// is not enforced by anything at runtime, so it is enforced here: widening either
// mode should fail a test rather than ship.
func TestSocketPermissions(t *testing.T) {
	h := newHarness(t)

	info, err := os.Stat(h.socket)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0660 {
		t.Errorf("socket mode = %04o, want 0660", perm)
	}
	// Group and world must have no write bit, however the mode is spelled.
	if perm := info.Mode().Perm(); perm&0002 != 0 {
		t.Errorf("socket mode %04o is world-writable; any local user could drive the broker", perm)
	}

	dir, err := os.Stat(filepath.Dir(h.socket))
	if err != nil {
		t.Fatalf("stat socket directory: %v", err)
	}
	// t.TempDir() is 0700, so a harness socket lives somewhere stricter than the
	// packaged runtime directory. Assert the property that matters in both cases —
	// nothing for other — rather than the exact mode, which only production sets.
	if perm := dir.Mode().Perm(); perm&0007 != 0 {
		t.Errorf("socket directory mode = %04o, want no access for other; "+
			"a traversable directory exposes the socket regardless of its own mode", perm)
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

// TestDispatchBudgetBoundsTheHandlerSlot is the regression test for a false
// comment with real consequences: maxConcurrentHandlers said a slot could not be
// held longer than server.read_timeout, but dispatch runs inside the slot and its
// only clock was the provider HTTP client's 30s. 64 connections against a
// provider that accepts and stalls held every slot, and acceptConnections blocks
// after accepting, so no login on the host was served — including polls for
// logins that had already succeeded.
//
// The comment is now true because dispatchWithin makes it true. What this test
// pins is the property the comment claims: the handler comes back on its own.
func TestDispatchBudgetBoundsTheHandlerSlot(t *testing.T) {
	// A dispatch that never returns, standing in for a provider that accepts the
	// connection and says nothing. Released at the end so the goroutine does not
	// outlive the test.
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })

	entered := make(chan struct{})
	dispatch := func(*Request) *Response {
		close(entered)
		<-stall
		return &Response{Success: true, Status: auth.StatusAuthorized}
	}

	start := time.Now()
	resp := dispatchWithin(20*time.Millisecond, &Request{Type: "authenticate", UserID: "alice"}, dispatch)
	elapsed := time.Since(start)

	<-entered
	if elapsed > 5*time.Second {
		t.Errorf("dispatchWithin held its caller for %s against a 20ms budget", elapsed)
	}
	if resp.Success {
		t.Error("a dispatch that never answered was reported as a success")
	}
	if resp.Status != auth.StatusError {
		t.Errorf("status = %q, want %q", resp.Status, auth.StatusError)
	}
	// The verb's own internal-error code, not a new one: see verbErrorCode.
	if resp.ErrorCode != "AUTHENTICATION_FAILED" {
		t.Errorf("error_code = %q, want AUTHENTICATION_FAILED", resp.ErrorCode)
	}
}

// TestDispatchWithinPassesTheReplyThrough is the no-regression half. The budget
// is a backstop for a provider with no clock of its own, and it must be invisible
// to every request that answers in time — including the reply's error code, which
// dispatchWithin only substitutes on a timeout.
func TestDispatchWithinPassesTheReplyThrough(t *testing.T) {
	want := &Response{Success: true, Status: auth.StatusAuthorized, UserID: "alice"}
	got := dispatchWithin(5*time.Second, &Request{Type: "authenticate", UserID: "alice"},
		func(*Request) *Response { return want })

	if got != want {
		t.Errorf("dispatchWithin returned %+v, want the dispatch's own reply %+v", got, want)
	}
}

// TestVerbErrorCodeIsRegisteredInTheSpec: a timeout is reported with the verb's
// own internal-error code because those are already in docs/wire-protocol.md and
// a client already treats them as terminal. A code invented here would be a
// contract change and a C-module change for nothing.
func TestVerbErrorCodeIsRegisteredInTheSpec(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "docs", "wire-protocol.md"))
	if err != nil {
		t.Fatalf("read the spec: %v", err)
	}
	for _, verb := range []string{"authenticate", "check_session", "refresh_session", "revoke_session"} {
		code := verbErrorCode(verb)
		if !strings.Contains(string(spec), code) {
			t.Errorf("%s times out as %q, which docs/wire-protocol.md does not register; "+
				"a client cannot be expected to know what it means", verb, code)
		}
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
