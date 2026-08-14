package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

// TestConcurrentAuthenticateDoesNotOvershootTheAuthCap is the other half of the
// cap, and the half a sequential test cannot see.
//
// The caps were read under RLock, the lock released, the device flow started, and
// the session inserted only then — so every request in flight decided against a
// session map containing none of the others. Measured before the fix: 40
// concurrent calls against a cap of 3 accepted 17.
//
// One username per caller, so per-user eviction cannot hold the pending count
// down and hide the overshoot the way it did in
// TestGlobalConcurrentAuthCapIsReachableForOneUser. StartDeviceFlow is given a
// delay because the window is exactly the provider round trip: with an instant
// provider the calls barely overlap and the unfixed code can look correct.
func TestConcurrentAuthenticateDoesNotOvershootTheAuthCap(t *testing.T) {
	const (
		limit   = 3
		callers = 40
	)

	cfg := brokerConfig(t)
	cfg.Security.RateLimiting.MaxConcurrentAuths = limit
	fake := newFakeProvider("acme")
	fake.startDelay = 20 * time.Millisecond
	b := startBroker(t, cfg, fake)

	var mu sync.Mutex
	var accepted, refused int
	var unexpected []string

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		user := fmt.Sprintf("user%02d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, err := b.Authenticate(&AuthRequest{UserID: user, LoginType: "ssh"})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				unexpected = append(unexpected, err.Error())
			case resp.ErrorCode == "":
				accepted++
			case resp.ErrorCode == "AUTH_LIMIT_REACHED":
				refused++
			default:
				unexpected = append(unexpected, resp.ErrorCode)
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(unexpected) > 0 {
		t.Fatalf("unexpected outcomes: %v", unexpected)
	}
	if accepted != limit {
		t.Errorf("%d of %d concurrent requests were accepted against a cap of %d", accepted, callers, limit)
	}
	if refused != callers-limit {
		t.Errorf("%d requests were refused, want %d", refused, callers-limit)
	}

	// The reply count and the broker's own state have to agree: a request that was
	// told yes holds a pending flow, and it is the flows that cost a goroutine and
	// provider traffic.
	b.sessionMutex.RLock()
	pending := b.countPendingFlowsLocked()
	b.sessionMutex.RUnlock()
	if pending != accepted {
		t.Errorf("%d pending flows for %d accepted requests; the count the cap is enforced on is not the state that resulted",
			pending, accepted)
	}
}

// TestCapacityRefusalsAreErrorsNotDenials pins the status both capacity refusals
// carry, in one test, because the way #84 happened is that the two refusals were
// written in different places and each was self-consistent: reserveSession built
// its SESSION_LIMIT_REACHED reply by hand with StatusDenied while
// AUTH_LIMIT_REACHED went through errorResponse.
//
// A capacity refusal is a statement about the broker's load — the broker declined
// to try — and StatusDenied is a decision about the identity. The difference is
// not cosmetic: the reference client maps "denied" to PAM_AUTH_ERR and an "error"
// to PAM_AUTHINFO_UNAVAIL, so a user who merely hit their session cap was told
// their identity had been refused and the rest of the PAM stack never ran.
func TestCapacityRefusalsAreErrorsNotDenials(t *testing.T) {
	assertCapacityRefusal := func(t *testing.T, resp *AuthResponse, code string) {
		t.Helper()
		if resp.ErrorCode != code {
			t.Fatalf("error_code = %q, want %q", resp.ErrorCode, code)
		}
		if resp.Status == StatusDenied {
			t.Errorf("%s arrived as status %q; a capacity refusal is about the broker's load, not about the user",
				code, resp.Status)
		}
		if resp.Status != StatusError {
			t.Errorf("%s: status = %q, want %q", code, resp.Status, StatusError)
		}
		if resp.Success {
			t.Errorf("%s: success = true on a refusal", code)
		}
		if resp.UserID != "" {
			t.Errorf("%s: user_id = %q on a refusal, want empty", code, resp.UserID)
		}
		if resp.SessionID != "" {
			t.Errorf("%s: session_id = %q, want no session created", code, resp.SessionID)
		}
	}

	t.Run("SESSION_LIMIT_REACHED", func(t *testing.T) {
		cfg := brokerConfig(t)
		cfg.Authentication.MaxConcurrentSessions = 1
		b := startBroker(t, cfg, newFakeProvider("acme"))

		// One established session, which is what the per-user cap counts; pending
		// flows are counted separately and deliberately do not fill it.
		b.setSession(&Session{
			ID:                 "established",
			RequestedLocalUser: "alice",
			LocalUser:          "alice",
			CreatedAt:          time.Now(),
			ExpiresAt:          time.Now().Add(time.Hour),
			Status:             StatusAuthorized,
			IsActive:           true,
		})

		resp, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		assertCapacityRefusal(t, resp, "SESSION_LIMIT_REACHED")
	})

	t.Run("AUTH_LIMIT_REACHED", func(t *testing.T) {
		cfg := brokerConfig(t)
		cfg.Security.RateLimiting.MaxConcurrentAuths = 1
		b := startBroker(t, cfg, newFakeProvider("acme"))

		// Distinct usernames: per-user eviction would otherwise recycle alice's own
		// pending flow and the global cap would never be reached.
		if first, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"}); err != nil {
			t.Fatalf("Authenticate: %v", err)
		} else if first.Status != StatusPending {
			t.Fatalf("first request: status = %q, want %q", first.Status, StatusPending)
		}

		resp, err := b.Authenticate(&AuthRequest{UserID: "bob", LoginType: "ssh"})
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		assertCapacityRefusal(t, resp, "AUTH_LIMIT_REACHED")
	})
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
// test asserts the outcome from outside for a flow nobody ever approves; the
// compare-and-set that guarantees it is exercised arm by arm in
// TestActivateSessionRefusesUnlessStillTheSamePendingSession, and end to end for
// a flow that really does complete late in
// TestLateApprovalDoesNotActivateAnExpiredFlow.
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

// TestLateApprovalDoesNotActivateAnExpiredFlow is the end-to-end coverage the
// test above could not give, and the reason it could not is the defect: a flow
// that completes after the broker's deadline was activated anyway, and the
// activation rewrote ExpiresAt to the session lifetime, so nothing afterwards
// could tell it had been late. Measured before the fix as a session activated
// with expires_at an hour past the flow deadline, answering status="authorized"
// success=true and counting against max_concurrent_sessions.
//
// The window is opened by holding GetIdentity, which is a window the real code
// has: the identity fetch retries two seconds apart and the mapper's NSS lookup
// takes no context and no timeout, so on an LDAP or SSSD host it is bounded by
// nothing this project controls.
//
// Nothing polls check_session while the deadline passes, deliberately. A poll
// would mark the session expired itself, and then the compare-and-set would
// refuse on the status — which was always checked — rather than on the expiry,
// which was not. This test has to reach activation with the session still
// pending or it proves nothing.
func TestLateApprovalDoesNotActivateAnExpiredFlow(t *testing.T) {
	cfg := brokerConfig(t)
	// Comfortably longer than the fake's 1s polling interval, so the first poll
	// happens before the deadline and the flow is already inside GetIdentity when
	// the deadline passes. A timeout shorter than the interval would let the poll
	// loop notice the deadline before reaching any of the work, which is the case
	// TestExpiredFlowIsFinalAndStopsPolling already covers.
	cfg.Authentication.DeviceFlowTimeout = 1500 * time.Millisecond
	fake := newFakeProvider("acme")
	fake.authorize() // approved at the provider from the first poll
	release := fake.blockIdentity()
	b := startBroker(t, cfg, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	deadline := start.ExpiresAt

	// Let the flow reach GetIdentity and stall there until well past the deadline.
	time.Sleep(2500 * time.Millisecond)
	release()
	awaitPollerExit(t, b, start.SessionID)

	// The deadline has to reach the work, not only the session record: without it
	// on the context, a stalled provider or mapper call runs to completion however
	// long that takes, because the poll loop's select is not re-entered until it
	// returns.
	if err := fake.identityContextErr(); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the poll context reported %v after the flow's deadline passed, want context.DeadlineExceeded", err)
	}

	if live := b.getSession(start.SessionID); live != nil && (live.IsActive || live.Status == StatusAuthorized) {
		t.Errorf("a flow approved %s after its deadline became an active session (status=%q active=%v expires_at=%s, deadline was %s)",
			time.Since(deadline).Round(time.Millisecond), live.Status, live.IsActive, live.ExpiresAt, deadline)
	}

	resp, err := b.CheckSession(start.SessionID)
	if err != nil {
		t.Fatalf("CheckSession: %v", err)
	}
	if resp.Success || resp.Status == StatusAuthorized {
		t.Errorf("check_session says status=%q success=%v user_id=%q for a flow that expired before it was approved",
			resp.Status, resp.Success, resp.UserID)
	}
	if resp.Status != StatusExpired {
		t.Errorf("status = %q, want %q", resp.Status, StatusExpired)
	}

	// The access token the late completion fetched must not be left behind either:
	// a refused activation that keeps its credential is the same live-token-with-
	// no-login outcome by another route.
	b.tokenManager.tokenStore.mutex.RLock()
	tokens := len(b.tokenManager.tokenStore.tokens)
	b.tokenManager.tokenStore.mutex.RUnlock()
	if tokens != 0 {
		t.Errorf("%d token(s) remain in the store after a refused activation, want none", tokens)
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

	t.Run("past its own deadline", func(t *testing.T) {
		s := newPending("late")
		s.ExpiresAt = time.Now().Add(-time.Second)
		if b.activateSession("late", created, func(*Session) {}) {
			t.Error("activateSession activated a flow whose deadline had passed; the mutation rewrites ExpiresAt, so nothing downstream can tell")
		}
	})

	t.Run("exactly at its deadline is over", func(t *testing.T) {
		s := newPending("boundary")
		s.ExpiresAt = time.Now()
		if b.activateSession("boundary", created, func(*Session) {}) {
			t.Error("activateSession activated a flow at its deadline; the deadline is when the broker has stopped waiting")
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
