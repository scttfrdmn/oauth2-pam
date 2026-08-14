package auth

import (
	"testing"
	"time"

	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
)

// Regression tests for four defects found by reproducing them against a running
// broker. Each one names the observable symptom rather than the mechanism, so
// they keep their meaning if the implementation moves.

// TestGlobalConcurrentAuthCapIsReachableForOneUser pins the cap-before-evict
// ordering.
//
// max_concurrent_auths is the broker-wide bound on polling goroutines, but it
// used to be consulted *after* per-user eviction. Eviction holds one username's
// pending count at maxPendingFlowsPerUser, so the global count never climbed and
// the cap was unreachable from a single account: measured with a cap of 10, 30
// requests were all accepted and the goroutine count went from 7 to 40.
func TestGlobalConcurrentAuthCapIsReachableForOneUser(t *testing.T) {
	cfg := brokerConfig(t)
	cfg.Security.RateLimiting.MaxConcurrentAuths = 3
	b := startBroker(t, cfg, newFakeProvider("acme"))

	var accepted, refused int
	for i := 0; i < 8; i++ {
		resp, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
		if err != nil {
			t.Fatalf("Authenticate %d: %v", i, err)
		}
		switch resp.ErrorCode {
		case "":
			accepted++
		case "AUTH_LIMIT_REACHED":
			refused++
		default:
			t.Fatalf("Authenticate %d: unexpected error_code %q", i, resp.ErrorCode)
		}
	}

	if accepted != 3 {
		t.Errorf("accepted %d requests, want exactly the cap of 3", accepted)
	}
	if refused != 5 {
		t.Errorf("refused %d requests, want 5 — the cap was not reachable for one username", refused)
	}
}

// TestEvictedPendingFlowStopsPollingTheProvider pins poller cancellation.
//
// A device flow evicted to make room for a newer one used to leave its goroutine
// polling the provider until the device code expired — 15 minutes at github.com —
// with nothing tracking it: countPendingFlows sees sessions, and the session was
// already gone. The evidence a test can see is the provider traffic itself.
func TestEvictedPendingFlowStopsPollingTheProvider(t *testing.T) {
	fake := newFakeProvider("acme")
	b := startBroker(t, brokerConfig(t), fake)

	// maxPendingFlowsPerUser is 3, so the fourth request evicts the first.
	for i := 0; i < maxPendingFlowsPerUser+1; i++ {
		if _, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"}); err != nil {
			t.Fatalf("Authenticate %d: %v", i, err)
		}
	}

	// Let the survivors poll for a while. The fake issues 1s intervals.
	time.Sleep(2500 * time.Millisecond)

	evicted := fake.pollCount(1)
	newest := fake.pollCount(maxPendingFlowsPerUser + 1)
	if newest == 0 {
		t.Fatalf("the surviving flow never polled; the test cannot distinguish a stopped poller")
	}

	time.Sleep(1500 * time.Millisecond)

	if after := fake.pollCount(1); after != evicted {
		t.Errorf("evicted flow polled %d more times after eviction (%d then %d); its goroutine was not cancelled",
			after-evicted, evicted, after)
	}
	if after := fake.pollCount(maxPendingFlowsPerUser + 1); after <= newest {
		t.Errorf("surviving flow stopped polling (%d then %d); cancellation hit the wrong session", newest, after)
	}
}

// TestExpiredFlowIsFinalAndStopsPolling covers both halves of
// authentication.device_flow_timeout: the broker gives up on its own schedule
// rather than the provider's, and an expiry it has already reported to a client
// is not revisited.
//
// The second half is the visible symptom of a lost update: the poller used to
// write back a whole snapshot of the session, so a flow that completed after the
// session had expired resurrected it as authorized. Reproduced before the fix as
// "check_session at t+4s → expired, at t+10s → authorized", leaving a live
// 8-hour session holding a real provider token and attached to no login. This
// test asserts the outcome from outside; the compare-and-set that guarantees it
// is exercised arm by arm in
// TestActivateSessionRefusesUnlessStillTheSamePendingSession, because once the
// poller is cancelled promptly there is no longer a reliable way to schedule a
// completion after the expiry from out here.
func TestExpiredFlowIsFinalAndStopsPolling(t *testing.T) {
	cfg := brokerConfig(t)
	cfg.Authentication.DeviceFlowTimeout = 2500 * time.Millisecond
	fake := newFakeProvider("acme") // issues 15-minute device codes
	b := startBroker(t, cfg, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if want := 3 * time.Second; time.Until(start.ExpiresAt) > want {
		t.Errorf("expires_at is %s away, want under %s — the provider's code lifetime is not the broker's deadline",
			time.Until(start.ExpiresAt).Round(time.Millisecond), want)
	}

	resp := awaitStatus(t, b, start.SessionID)
	if resp.Status != StatusExpired {
		t.Fatalf("status = %q, want %q", resp.Status, StatusExpired)
	}
	pollsAtExpiry := fake.pollCount(1)

	// The user approves at the provider, late. Nothing may come of it.
	fake.authorize()
	time.Sleep(2 * time.Second)

	again, err := b.CheckSession(start.SessionID)
	if err != nil {
		t.Fatalf("CheckSession: %v", err)
	}
	if again.Status != StatusExpired || again.Success {
		t.Errorf("status = %q, success = %v after a late approval; want the expiry to stand",
			again.Status, again.Success)
	}
	if after := fake.pollCount(1); after != pollsAtExpiry {
		t.Errorf("expired flow polled %d more times (%d then %d); its goroutine outlived the session",
			after-pollsAtExpiry, pollsAtExpiry, after)
	}
}

// TestActivateSessionRefusesUnlessStillTheSamePendingSession exercises the
// compare-and-set directly, because it is the only place a session becomes
// authorized and every refusal arm is a way a login could otherwise be granted
// to a session nobody is waiting on.
func TestActivateSessionRefusesUnlessStillTheSamePendingSession(t *testing.T) {
	b := startBroker(t, brokerConfig(t), newFakeProvider("acme"))

	created := time.Now()
	newPending := func(id string) *Session {
		s := &Session{
			ID:                 id,
			RequestedLocalUser: "alice",
			CreatedAt:          created,
			ExpiresAt:          created.Add(time.Minute),
			Status:             StatusPending,
		}
		b.setSession(s)
		return s
	}

	t.Run("still pending", func(t *testing.T) {
		newPending("ok")
		if !b.activateSession("ok", created, func(s *Session) { s.IsActive = true; s.Status = StatusAuthorized }) {
			t.Fatal("activateSession refused an unchanged pending session")
		}
		if got := b.getSession("ok"); got.Status != StatusAuthorized {
			t.Errorf("status = %q, want the mutation applied", got.Status)
		}
	})

	t.Run("gone", func(t *testing.T) {
		if b.activateSession("missing", created, func(*Session) {}) {
			t.Error("activateSession activated a session that no longer exists")
		}
	})

	t.Run("already terminal", func(t *testing.T) {
		s := newPending("expired")
		s.Status = StatusExpired
		if b.activateSession("expired", created, func(*Session) {}) {
			t.Error("activateSession resurrected an expired session as authorized")
		}
	})

	t.Run("already active", func(t *testing.T) {
		s := newPending("active")
		s.IsActive = true
		if b.activateSession("active", created, func(*Session) {}) {
			t.Error("activateSession re-activated an already active session")
		}
	})

	t.Run("id reused by a newer session", func(t *testing.T) {
		newPending("reused")
		if b.activateSession("reused", created.Add(-time.Second), func(*Session) {}) {
			t.Error("activateSession accepted a stale CreatedAt; a finished flow could activate a different session")
		}
	})
}

// TestTerminalStatusIsNotOverwritten pins the other half of "the answer a client
// already got is final". Cancelling a poller makes its in-flight provider and
// mapper calls fail, and those failures arrive at failSession — which would
// otherwise rewrite a session the client had already been told was "expired" or
// "denied" as "error", changing the reason after the fact.
func TestTerminalStatusIsNotOverwritten(t *testing.T) {
	b := startBroker(t, brokerConfig(t), newFakeProvider("acme"))

	for _, terminal := range []string{StatusDenied, StatusExpired} {
		b.setSession(&Session{
			ID:           terminal,
			CreatedAt:    time.Now(),
			ExpiresAt:    time.Now().Add(time.Minute),
			Status:       terminal,
			ErrorMessage: "the original reason",
		})

		b.failSession(terminal, StatusError, "a later, unrelated failure")

		got := b.getSession(terminal)
		if got == nil {
			t.Fatalf("%s: failSession removed a terminal session", terminal)
		}
		if got.Status != terminal || got.ErrorMessage != "the original reason" {
			t.Errorf("%s: status = %q, message = %q; want the first outcome to stand",
				terminal, got.Status, got.ErrorMessage)
		}
	}
}

// TestEmptyRequestedUserIsDenied is the broker half of the fail-closed fix. The
// IPC layer refuses an authenticate with no user_id, and this is why that is not
// the only defence: the guard "mapped local user == requested local user" used to
// be skipped when the requested user was empty, so a request naming no account
// activated as whatever the identity happened to map to. Reproduced before the
// fix as user_id:"" returning authorized with user_id:"alice".
func TestEmptyRequestedUserIsDenied(t *testing.T) {
	fake := newFakeProvider("acme")
	fake.authorize()
	b := startBroker(t, brokerConfig(t), fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	resp := awaitStatus(t, b, start.SessionID)
	if resp.Status != StatusDenied {
		t.Fatalf("status = %q, want %q; user_id = %q", resp.Status, StatusDenied, resp.UserID)
	}
	if resp.UserID != "" {
		t.Errorf("user_id = %q on a denied response, want empty", resp.UserID)
	}
}

// Compile-time reminder that the fake still satisfies the interface the broker
// drives; the poll-counting changes above touch its method set.
var _ provider.Provider = (*fakeProvider)(nil)
