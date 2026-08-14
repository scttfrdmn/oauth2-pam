package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
)

// fakeProvider is a second, deliberately non-GitHub implementation of
// provider.Provider. It exists to prove the abstraction is real: the broker,
// the mapper, and the session machinery drive it end to end without any GitHub
// type being involved, and it asserts flat "group" claims (the OIDC shape)
// rather than orgs and teams.
//
// It also wraps its sentinel errors with context, which is what a real
// implementation does and what the poll loop must tolerate.
type fakeProvider struct {
	name string

	mu         sync.Mutex
	authorized bool
	pollErr    error
	identity   *provider.Identity
	revoked    []string

	// flows counts issued device codes and polls records how many times each was
	// polled. Together they let a test observe that a poller stopped — the only
	// external evidence that a cancelled flow is no longer talking to the
	// provider.
	flows int
	polls map[string]int
	// codeLifetime is how long an issued device code stays valid at the provider.
	// Deliberately much longer than any login, like github.com's 15 minutes.
	codeLifetime time.Duration

	// identityGate, when non-nil, holds GetIdentity until it is closed, and
	// identityCtxErr records what the poll context said once it was released. A
	// completed flow really can stall here — GetIdentity retries two seconds
	// apart, and the mapper's NSS lookup takes no context at all — and holding
	// that window open is the only way a test outside the broker can arrange for a
	// flow to finish after its own deadline.
	identityGate   chan struct{}
	identityCtxErr error

	// startDelay is how long StartDeviceFlow takes to answer. A real one is an
	// HTTPS round trip, and a test that wants concurrent Authenticate calls to
	// actually overlap has to make it cost something.
	startDelay time.Duration
}

func newFakeProvider(name string) *fakeProvider {
	f := &fakeProvider{name: name, polls: make(map[string]int), codeLifetime: 15 * time.Minute}
	f.identity = &provider.Identity{
		Provider: name,
		Type:     f.Type(),
		Subject:  "8f14e45f", // an opaque OIDC-style sub, not a GitHub numeric id
		Login:    "alice",
		Name:     "Alice Example",
		Email:    "alice@example.com",
	}
	f.identity.AddClaim(provider.ClaimGroup, "platform-team", "staff")
	return f
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Type() string { return "acme-sso" }

func (f *fakeProvider) StartDeviceFlow(context.Context) (*provider.DeviceFlow, error) {
	f.mu.Lock()
	f.flows++
	code := fmt.Sprintf("device-code-%s-%d", f.name, f.flows)
	lifetime := f.codeLifetime
	delay := f.startDelay
	f.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}

	return &provider.DeviceFlow{
		DeviceCode:      code,
		UserCode:        "ABCD-1234",
		DeviceURL:       "https://sso.acme.example/device",
		ExpiresAt:       time.Now().Add(lifetime),
		PollingInterval: 1,
	}, nil
}

func (f *fakeProvider) PollDeviceAuthorization(_ context.Context, deviceCode string) (*provider.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls[deviceCode]++
	if f.pollErr != nil {
		return nil, fmt.Errorf("acme-sso poll: %w", f.pollErr)
	}
	if !f.authorized {
		return nil, fmt.Errorf("acme-sso poll: %w", provider.ErrAuthorizationPending)
	}
	return &provider.Token{
		AccessToken: fakeAccessToken,
		TokenType:   "bearer",
		Scope:       "openid profile groups",
		Fingerprint: fakeTokenFingerprint(fakeAccessToken),
	}, nil
}

// fakeAccessToken is the token this provider issues. Short and obviously fake, so
// a log line containing any of it is recognisable as a leak.
const fakeAccessToken = "acme-token"

// fakeTokenFingerprint produces what provider.Token.Fingerprint is specified to
// carry: hex(sha256(token)[:16]), the same value pkg/provider/github and
// TokenManager compute, which is what lets a session be lined up with its stored
// token in an audit trail.
//
// Computed rather than written out, and deliberately not the old
// "acme-to...ken" — that elision is the format this field used to have, and it
// carried bytes of the live secret. A fixture imitating it teaches the next
// reader an obsolete and unsafe shape.
func fakeTokenFingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:16])
}

func (f *fakeProvider) GetIdentity(ctx context.Context, _ *provider.Token) (*provider.Identity, error) {
	f.mu.Lock()
	gate := f.identityGate
	f.mu.Unlock()

	// Waited on outside the lock: pollCount and authorize are what a test uses
	// while the flow is held here.
	if gate != nil {
		<-gate
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.identityCtxErr = ctx.Err()
	return f.identity, nil
}

func (f *fakeProvider) RevokeAccessToken(_ context.Context, accessToken string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, accessToken)
	return nil
}

func (f *fakeProvider) authorize() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorized = true
}

func (f *fakeProvider) failWith(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pollErr = err
}

// blockIdentity holds every GetIdentity call until the returned func is called,
// so a test can choose when a flow that is already approved at the provider
// finishes at the broker.
func (f *fakeProvider) blockIdentity() (release func()) {
	gate := make(chan struct{})
	f.mu.Lock()
	f.identityGate = gate
	f.mu.Unlock()
	return func() { close(gate) }
}

// identityContextErr reports the state of the poll context as GetIdentity last
// saw it, which is how a test observes whether the flow's deadline reached the
// work rather than only the session record.
func (f *fakeProvider) identityContextErr() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.identityCtxErr
}

// pollCount reports how many times the nth issued device code (1-based) has been
// polled. A count that stops rising is how a test sees a poller shut down.
func (f *fakeProvider) pollCount(n int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polls[fmt.Sprintf("device-code-%s-%d", f.name, n)]
}

// brokerConfig is a minimal valid config whose only mapper rule matches a flat
// "group" claim — the neutral form, with nothing GitHub-shaped in it.
func brokerConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Server: config.ServerConfig{SocketPath: filepath.Join(t.TempDir(), "broker.sock")},
		Authentication: config.AuthenticationConfig{
			TokenLifetime:         time.Hour,
			RefreshThreshold:      time.Minute,
			MaxConcurrentSessions: 10,
		},
		Mapper: config.MapperConfig{
			Rules: []config.MappingRule{{
				Match:     config.MatchCriteria{Claims: map[string]string{provider.ClaimGroup: "platform-team"}},
				LocalUser: "alice",
			}},
		},
		Audit: config.AuditConfig{Enabled: false},
	}
}

func startBroker(t *testing.T, cfg *config.Config, providers ...provider.Provider) *Broker {
	t.Helper()
	b, err := NewBrokerWithProviders(cfg, providers)
	if err != nil {
		t.Fatalf("NewBrokerWithProviders: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := b.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = b.Stop() })
	return b
}

// awaitStatus polls CheckSession until the status is no longer pending.
func awaitStatus(t *testing.T, b *Broker, sessionID string) *AuthResponse {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := b.CheckSession(sessionID)
		if err != nil {
			t.Fatalf("CheckSession: %v", err)
		}
		if resp.Status != StatusPending {
			return resp
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("session %s never left %q", sessionID, StatusPending)
	return nil
}

// awaitPollerExit waits for a session's polling goroutine to finish. The poller
// drops its cancel entry as its last act, so this is how a test knows the flow
// reached its conclusion — including a conclusion that changes nothing, which no
// session field records and no sleep can be trusted to cover.
func awaitPollerExit(t *testing.T, b *Broker, sessionID string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		b.sessionMutex.RLock()
		_, polling := b.pollCancel[sessionID]
		b.sessionMutex.RUnlock()
		if !polling {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the poller for session %s never finished", sessionID)
}

// TestNonGitHubProviderAuthenticatesEndToEnd is the validation for the provider
// interface: a provider the broker has never heard of, asserting a claim GitHub
// does not have, authenticates a login through the ordinary path.
func TestNonGitHubProviderAuthenticatesEndToEnd(t *testing.T) {
	fake := newFakeProvider("acme")
	b := startBroker(t, brokerConfig(t), fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if start.Status != StatusPending || start.Success {
		t.Fatalf("status = %q, success = %v; want pending and false", start.Status, start.Success)
	}
	if start.DeviceURL != "https://sso.acme.example/device" {
		t.Errorf("device_url = %q, want the provider's own URL", start.DeviceURL)
	}

	fake.authorize()

	resp := awaitStatus(t, b, start.SessionID)
	if resp.Status != StatusAuthorized || !resp.Success {
		t.Fatalf("status = %q, success = %v, error = %q; want authorized",
			resp.Status, resp.Success, resp.ErrorMessage)
	}
	if resp.UserID != "alice" {
		t.Errorf("user_id = %q, want alice", resp.UserID)
	}
	if resp.Metadata["provider"] != "acme" {
		t.Errorf("metadata.provider = %q, want acme", resp.Metadata["provider"])
	}
}

// A pending error wrapped with context must not be mistaken for an operational
// failure — the interface permits wrapping, and mistaking it would fail a login
// that is merely still waiting for the user.
func TestWrappedSentinelErrorsAreRecognized(t *testing.T) {
	fake := newFakeProvider("acme")
	fake.failWith(provider.ErrAccessDenied)
	b := startBroker(t, brokerConfig(t), fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	resp := awaitStatus(t, b, start.SessionID)
	if resp.Status != StatusDenied {
		t.Errorf("status = %q, want %q — a wrapped ErrAccessDenied was not recognized",
			resp.Status, StatusDenied)
	}
}

func TestRequestSelectsProviderByName(t *testing.T) {
	first := newFakeProvider("first")
	second := newFakeProvider("second")
	b := startBroker(t, brokerConfig(t), first, second)

	// No name: the first configured provider.
	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got := start.Metadata["provider"]; got != "first" {
		t.Errorf("default provider = %q, want first", got)
	}

	// Named: exactly that one.
	start, err = b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh", Provider: "second"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got := start.Metadata["provider"]; got != "second" {
		t.Errorf("named provider = %q, want second", got)
	}
}

// A request naming a provider that is not configured must fail, not fall back to
// the default: a client that asked for one identity source and got another would
// be authenticated against something nobody chose.
func TestUnknownProviderNameIsRefused(t *testing.T) {
	b := startBroker(t, brokerConfig(t), newFakeProvider("acme"))

	resp, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh", Provider: "nope"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.Success || resp.ErrorCode != "NO_PROVIDER" {
		t.Errorf("success = %v, error_code = %q; want a NO_PROVIDER refusal", resp.Success, resp.ErrorCode)
	}
	if resp.SessionID != "" {
		t.Errorf("session_id = %q, want no session created", resp.SessionID)
	}
}

func TestDuplicateProviderNamesAreRejected(t *testing.T) {
	cfg := brokerConfig(t)
	if _, err := NewBrokerWithProviders(cfg, []provider.Provider{
		newFakeProvider("acme"), newFakeProvider("acme"),
	}); err == nil {
		t.Fatal("NewBrokerWithProviders accepted two providers with the same name")
	}
}
