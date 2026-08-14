package ipc

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/scttfrdmn/oauth2-pam/pkg/auth"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider/github"
)

func TestMain(m *testing.M) {
	// The broker is deliberately chatty; silence it so a failing assertion is
	// readable.
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

// harness is a real broker behind a real IPC server on a real Unix socket,
// talking to a fake GitHub. Only the human and the network are simulated.
type harness struct {
	t      *testing.T
	fake   *fakeGitHub
	socket string
}

// newHarness starts the stack. Options mutate the config before the broker is
// built, so a test can change policy (mapping rules, limits) without a second
// constructor.
func newHarness(t *testing.T, opts ...func(*config.Config)) *harness {
	t.Helper()

	fake := newFakeGitHub(t)

	// Unix socket paths are capped at ~104 bytes by sun_path, and macOS
	// TMPDIR is already long, so build the socket under /tmp rather than
	// t.TempDir().
	dir, err := os.MkdirTemp("/tmp", "o2p")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "b.sock")

	cfg := testConfig(socket)
	for _, opt := range opts {
		opt(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test config is invalid: %v", err)
	}

	prov, err := github.NewWithEndpoints(cfg.Providers[0], fake.endpoints())
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}
	broker, err := auth.NewBrokerWithProviders(cfg, []provider.Provider{prov})
	if err != nil {
		t.Fatalf("build broker: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	if err := broker.Start(ctx); err != nil {
		t.Fatalf("start broker: %v", err)
	}
	t.Cleanup(func() { _ = broker.Stop() })

	srv, err := NewServer(socket, broker, cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	return &harness{t: t, fake: fake, socket: socket}
}

func testConfig(socket string) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			SocketPath:   socket,
			LogLevel:     "disabled",
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Providers: []config.ProviderConfig{{
			Name:         "github",
			Type:         "github",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			GitHub:       config.GitHubConfig{RequireOrg: "acme"},
		}},
		Mapper: config.MapperConfig{
			Rules: []config.MappingRule{{
				Match:     config.MatchCriteria{GitHubOrg: "acme"},
				LocalUser: "{{ .Login }}",
				Groups:    []string{"devs"},
			}},
		},
		Authentication: config.AuthenticationConfig{
			TokenLifetime:         time.Hour,
			RefreshThreshold:      time.Minute,
			MaxConcurrentSessions: 10,
		},
		Security: config.SecurityConfig{
			SecureTokenStorage: true,
			TokenEncryptionKey: "0123456789abcdef0123456789abcdef",
			MaxTokenAge:        24 * time.Hour,
			RateLimiting: config.RateLimiting{
				MaxRequestsPerMinute: 10000,
				MaxConcurrentAuths:   10,
			},
		},
		Audit: config.AuditConfig{Enabled: false},
	}
}

// roundtrip sends one request over the socket and returns the reply, exactly as
// the PAM module does: connect, write one JSON object, read one JSON object.
func (h *harness) roundtrip(req Request) Response {
	h.t.Helper()

	conn, err := net.DialTimeout("unix", h.socket, 5*time.Second)
	if err != nil {
		h.t.Fatalf("dial %s: %v", h.socket, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		h.t.Fatalf("encode request: %v", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		h.t.Fatalf("decode response: %v", err)
	}
	return resp
}

func (h *harness) authenticate(user string) Response {
	h.t.Helper()
	return h.roundtrip(Request{Type: "authenticate", UserID: user, LoginType: "ssh"})
}

func (h *harness) check(sessionID string) Response {
	h.t.Helper()
	return h.roundtrip(Request{Type: "check_session", SessionID: sessionID})
}

// waitForTerminal polls check_session the way the PAM module does, until the
// status stops being "pending".
func (h *harness) waitForTerminal(sessionID string) Response {
	h.t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	var last Response
	for time.Now().Before(deadline) {
		last = h.check(sessionID)
		if last.Status != auth.StatusPending {
			return last
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatalf("session %s never left pending; last response %+v", sessionID, last)
	return last
}

// TestAuthenticateIsNotAuthentication is the regression test for the auth
// bypass: starting a device flow must not report success. v0.1.1 returned
// Success: true here, and the PAM module returned PAM_SUCCESS on it, so any
// username could log in without ever visiting GitHub.
func TestAuthenticateIsNotAuthentication(t *testing.T) {
	h := newHarness(t)

	resp := h.authenticate("alice")

	if resp.Success {
		t.Error("authenticate reported success before the user authorized: this is the auth bypass")
	}
	if resp.Status != auth.StatusPending {
		t.Errorf("status = %q, want %q", resp.Status, auth.StatusPending)
	}
	if resp.UserID != "" {
		t.Errorf("user_id = %q, want empty while pending", resp.UserID)
	}
	if !resp.RequiresDevice {
		t.Error("requires_device = false, want true")
	}
	if resp.SessionID == "" {
		t.Error("session_id is empty; the client has nothing to poll")
	}
	if resp.DeviceCode == "" {
		t.Error("device_code is empty; the user has no code to enter")
	}
	if resp.Instructions == "" {
		t.Error("instructions are empty; the user is told nothing")
	}
	if got := resp.Metadata["polling_interval"]; got == "" {
		t.Error("metadata.polling_interval is empty; the client cannot pace its polling")
	}
}

// TestSessionStaysPendingUntilUserAuthorizes checks that the broker reports
// pending for as long as GitHub does, and that it is really polling.
func TestSessionStaysPendingUntilUserAuthorizes(t *testing.T) {
	h := newHarness(t)

	start := h.authenticate("alice")
	if start.Status != auth.StatusPending {
		t.Fatalf("status = %q, want pending", start.Status)
	}

	// Long enough for several 1s poll ticks against the fake.
	time.Sleep(2500 * time.Millisecond)

	resp := h.check(start.SessionID)
	if resp.Success || resp.Status != auth.StatusPending {
		t.Errorf("session became success=%v status=%q while GitHub still said authorization_pending",
			resp.Success, resp.Status)
	}
	if n := h.fake.polls(); n < 2 {
		t.Errorf("broker polled the token endpoint %d times; expected it to keep polling", n)
	}
}

// TestFullFlowAuthorizes walks the happy path all the way through.
func TestFullFlowAuthorizes(t *testing.T) {
	h := newHarness(t)

	start := h.authenticate("alice")
	if start.Status != auth.StatusPending {
		t.Fatalf("status = %q, want pending", start.Status)
	}

	h.fake.grant() // the user approves in their browser

	resp := h.waitForTerminal(start.SessionID)
	if !resp.Success {
		t.Fatalf("flow did not authorize: status=%q error=%q", resp.Status, resp.ErrorMessage)
	}
	if resp.Status != auth.StatusAuthorized {
		t.Errorf("status = %q, want %q", resp.Status, auth.StatusAuthorized)
	}
	if resp.UserID != "alice" {
		t.Errorf("user_id = %q, want %q", resp.UserID, "alice")
	}
	if resp.SessionID != start.SessionID {
		t.Errorf("session_id = %q, want %q", resp.SessionID, start.SessionID)
	}
	if resp.Metadata["provider_login"] != "alice" {
		t.Errorf("metadata.provider_login = %q, want alice", resp.Metadata["provider_login"])
	}
}

// TestMappedUserMustMatchRequestedLogin covers the second half of the bypass:
// an identity that maps to alice must not authorize a login as bob. The check
// is enforced by the broker, so no client cooperation is required.
func TestMappedUserMustMatchRequestedLogin(t *testing.T) {
	h := newHarness(t)

	// GitHub user alice, but the login attempt is for bob.
	start := h.authenticate("bob")
	if start.Status != auth.StatusPending {
		t.Fatalf("status = %q, want pending", start.Status)
	}

	h.fake.grant()

	resp := h.waitForTerminal(start.SessionID)
	if resp.Success {
		t.Fatal("identity mapping to \"alice\" authorized a login as \"bob\"")
	}
	if resp.Status != auth.StatusDenied {
		t.Errorf("status = %q, want %q", resp.Status, auth.StatusDenied)
	}
	if resp.UserID != "" {
		t.Errorf("user_id = %q, want empty on denial", resp.UserID)
	}
	if resp.ErrorCode != "AUTHENTICATION_DENIED" {
		t.Errorf("error_code = %q, want AUTHENTICATION_DENIED", resp.ErrorCode)
	}
}

// TestMappedUserMatchingRequestedLoginAuthorizes is the companion to the test
// above. Without it, TestMappedUserMustMatchRequestedLogin would also pass if a
// login as bob could never succeed for some unrelated reason, and the mismatch
// check it exists to cover would be untested.
func TestMappedUserMatchingRequestedLoginAuthorizes(t *testing.T) {
	h := newHarness(t)

	// Same login attempt as the mismatch test; the only change is who GitHub
	// says the authorizing user is.
	h.fake.setLogin("bob")

	start := h.authenticate("bob")
	if start.Status != auth.StatusPending {
		t.Fatalf("status = %q, want pending", start.Status)
	}

	h.fake.grant()

	resp := h.waitForTerminal(start.SessionID)
	if !resp.Success {
		t.Fatalf("status = %q (%s), want an authorized login as bob", resp.Status, resp.ErrorCode)
	}
	if resp.UserID != "bob" {
		t.Errorf("user_id = %q, want %q", resp.UserID, "bob")
	}
}

// TestUserDenialAtProviderIsDenied covers the RFC 8628 access_denied path.
func TestUserDenialAtProviderIsDenied(t *testing.T) {
	h := newHarness(t)

	start := h.authenticate("alice")
	h.fake.failWith("access_denied")

	resp := h.waitForTerminal(start.SessionID)
	if resp.Success {
		t.Fatal("a provider-side denial authorized the login")
	}
	if resp.Status != auth.StatusDenied {
		t.Errorf("status = %q, want %q", resp.Status, auth.StatusDenied)
	}
}

// TestExpiredDeviceCodeIsExpired distinguishes "expired" from "denied" so the
// PAM module can tell the user to try again rather than that they were refused.
func TestExpiredDeviceCodeIsExpired(t *testing.T) {
	h := newHarness(t)

	start := h.authenticate("alice")
	h.fake.failWith("expired_token")

	resp := h.waitForTerminal(start.SessionID)
	if resp.Status != auth.StatusExpired {
		t.Errorf("status = %q, want %q", resp.Status, auth.StatusExpired)
	}
	if resp.ErrorCode != "SESSION_EXPIRED" {
		t.Errorf("error_code = %q, want SESSION_EXPIRED", resp.ErrorCode)
	}
}

// TestIdentityOutsideRequiredOrgIsDenied checks that a provider-level access
// control refusal is reported as a decision about the user (denied), not as an
// outage (error) — the two lead to different PAM return codes.
func TestIdentityOutsideRequiredOrgIsDenied(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Providers[0].GitHub.RequireOrg = "other-org"
	})

	start := h.authenticate("alice")
	h.fake.grant()

	resp := h.waitForTerminal(start.SessionID)
	if resp.Success {
		t.Fatal("a user outside the required org was authorized")
	}
	if resp.Status != auth.StatusDenied {
		t.Errorf("status = %q, want %q", resp.Status, auth.StatusDenied)
	}
}

// TestNoMappingIsDenied covers an authenticated identity with no local account.
func TestNoMappingIsDenied(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Mapper.Rules[0].Match.GitHubLogin = "someone-else"
	})

	start := h.authenticate("alice")
	h.fake.grant()

	resp := h.waitForTerminal(start.SessionID)
	if resp.Status != auth.StatusDenied {
		t.Errorf("status = %q, want %q (error=%q)", resp.Status, auth.StatusDenied, resp.ErrorMessage)
	}
}

// TestRevokeSessionRevokesAtGitHub checks that logout does not leave a live
// OAuth token behind at the provider.
func TestRevokeSessionRevokesAtGitHub(t *testing.T) {
	h := newHarness(t)

	start := h.authenticate("alice")
	h.fake.grant()
	if resp := h.waitForTerminal(start.SessionID); !resp.Success {
		t.Fatalf("setup: flow did not authorize: %+v", resp)
	}

	resp := h.roundtrip(Request{Type: "revoke_session", SessionID: start.SessionID})
	if !resp.Success {
		t.Fatalf("revoke_session failed: %q", resp.ErrorMessage)
	}

	revoked := h.fake.revokedTokens()
	if len(revoked) != 1 {
		t.Fatalf("GitHub saw %d revocations, want 1 (the token may still be live)", len(revoked))
	}
	if revoked[0] != h.fake.accessToken {
		t.Errorf("revoked token = %q, want the issued access token", revoked[0])
	}

	// The session must be gone, not merely inactive.
	after := h.check(start.SessionID)
	if after.Success {
		t.Error("revoked session still authorizes")
	}
	if after.ErrorCode != "SESSION_NOT_FOUND" {
		t.Errorf("error_code = %q, want SESSION_NOT_FOUND", after.ErrorCode)
	}
}

// TestRefreshRejectsPendingSession makes sure refresh cannot be used as a side
// door to activate a flow the user never completed.
func TestRefreshRejectsPendingSession(t *testing.T) {
	h := newHarness(t)

	start := h.authenticate("alice")

	resp := h.roundtrip(Request{Type: "refresh_session", SessionID: start.SessionID})
	if resp.Success {
		t.Error("refresh_session authorized a pending session")
	}
	if resp.Status != auth.StatusPending {
		t.Errorf("status = %q, want %q", resp.Status, auth.StatusPending)
	}
	if resp.ErrorCode != "SESSION_NOT_ACTIVE" {
		t.Errorf("error_code = %q, want SESSION_NOT_ACTIVE", resp.ErrorCode)
	}
}

// TestUnknownSessionIsNotAuthorized covers a forged or stale session ID.
func TestUnknownSessionIsNotAuthorized(t *testing.T) {
	h := newHarness(t)

	resp := h.check("0000000000000000deadbeef00000000")
	if resp.Success {
		t.Error("an unknown session ID was reported as authorized")
	}
	if resp.Status != auth.StatusError {
		t.Errorf("status = %q, want %q", resp.Status, auth.StatusError)
	}
	if resp.ErrorCode != "SESSION_NOT_FOUND" {
		t.Errorf("error_code = %q, want SESSION_NOT_FOUND", resp.ErrorCode)
	}
}

// TestAbandonedFlowsDoNotExhaustSessionLimit covers the lockout bug: pending
// device flows used to count toward max_concurrent_sessions, so three closed
// terminals locked the account out until the cleanup ticker ran.
func TestAbandonedFlowsDoNotExhaustSessionLimit(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Authentication.MaxConcurrentSessions = 2
	})

	for i := 0; i < 5; i++ {
		resp := h.authenticate("alice")
		if resp.Status != auth.StatusPending {
			t.Fatalf("attempt %d: status = %q (%s), want pending — abandoned flows are consuming session slots",
				i+1, resp.Status, resp.ErrorMessage)
		}
	}
}

// TestConcurrentAuthCapIsEnforced checks that max_concurrent_auths bounds
// in-flight device flows broker-wide.
func TestConcurrentAuthCapIsEnforced(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Security.RateLimiting.MaxConcurrentAuths = 2
		// Take the per-user eviction out of the picture: it would keep recycling
		// alice's oldest flow and the global cap would never be reached.
		c.Mapper.Rules[0].LocalUser = "{{ .Login }}"
	})

	// Distinct users so per-user eviction does not apply.
	for _, user := range []string{"u1", "u2"} {
		if resp := h.authenticate(user); resp.Status != auth.StatusPending {
			t.Fatalf("%s: status = %q, want pending", user, resp.Status)
		}
	}

	resp := h.authenticate("u3")
	if resp.Status != auth.StatusError {
		t.Errorf("status = %q, want %q once the concurrent-auth cap is reached", resp.Status, auth.StatusError)
	}
	if resp.ErrorCode != "AUTH_LIMIT_REACHED" {
		t.Errorf("error_code = %q, want AUTH_LIMIT_REACHED", resp.ErrorCode)
	}
}

// TestPerUserPendingFlowsAreBounded checks that a user opening many terminals
// always gets a working prompt in the newest one, while old flows are evicted.
func TestPerUserPendingFlowsAreBounded(t *testing.T) {
	h := newHarness(t)

	var ids []string
	for i := 0; i < 5; i++ {
		resp := h.authenticate("alice")
		if resp.Status != auth.StatusPending {
			t.Fatalf("attempt %d: status = %q, want pending", i+1, resp.Status)
		}
		ids = append(ids, resp.SessionID)
	}

	// The newest flow is always usable.
	if resp := h.check(ids[len(ids)-1]); resp.Status != auth.StatusPending {
		t.Errorf("newest session status = %q, want pending", resp.Status)
	}

	// The oldest were evicted rather than accumulating without bound.
	evicted := 0
	for _, id := range ids {
		if h.check(id).ErrorCode == "SESSION_NOT_FOUND" {
			evicted++
		}
	}
	if evicted == 0 {
		t.Error("no pending flows were evicted; per-user pending state is unbounded")
	}
}
