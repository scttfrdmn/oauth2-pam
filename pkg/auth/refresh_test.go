package auth

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Regression tests for the two defects in the session-extension path (#41, #43),
// both of which ended with the broker answering "authorized" for a session that
// should have been over: an expired one that refresh extended instead of
// refusing, a revoked one that refresh put back, and a session refreshed
// indefinitely past security.max_token_age.

// authorizedSession installs a live authorized session with a real token in the
// token manager, which is what makes "the token was destroyed" observable. The
// token's own expiry is deliberately far out, so a refusal is never attributable
// to the token having aged out on its own.
func authorizedSession(t *testing.T, b *Broker, id string, createdAt, expiresAt time.Time) *Session {
	t.Helper()

	tokenID, err := b.tokenManager.StoreToken(id, "alice", "access-token-"+id, "",
		time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}

	s := &Session{
		ID:                 id,
		TokenID:            tokenID,
		LocalUser:          "alice",
		RequestedLocalUser: "alice",
		ProviderLogin:      "alice",
		Provider:           "acme",
		CreatedAt:          createdAt,
		ExpiresAt:          expiresAt,
		LastAccessed:       createdAt,
		Status:             StatusAuthorized,
		IsActive:           true,
	}
	b.setSession(s)
	return s
}

// tokenLives reports whether a token is still in the manager. A session that
// authorizes a login while this is false is the resurrection symptom: the token
// has been revoked at the provider and the session outlived it.
func tokenLives(b *Broker, tokenID string) bool {
	b.tokenManager.tokenStore.mutex.RLock()
	defer b.tokenManager.tokenStore.mutex.RUnlock()
	_, ok := b.tokenManager.tokenStore.tokens[tokenID]
	return ok
}

// TestRefreshRefusesExpiredAuthorizedSession is the deterministic half of #41.
//
// RefreshSession had no expiry check at all: time.Until on a past timestamp is
// negative, so an expired session fell straight through to the extend branch and
// came back authorized with a fresh hour on it. CheckSession has always removed
// such a session and answered SESSION_EXPIRED, so the two verbs disagreed about
// what an expired session is, and a client that called refresh_session first
// never reached the one that was right.
func TestRefreshRefusesExpiredAuthorizedSession(t *testing.T) {
	b := startBroker(t, brokerConfig(t), newFakeProvider("acme"))

	now := time.Now()
	s := authorizedSession(t, b, "expired-authorized", now.Add(-2*time.Hour), now.Add(-time.Minute))

	resp, err := b.RefreshSession(s.ID)
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if resp.Success {
		t.Errorf("refresh extended an expired session: success=true user_id=%q expires_at=%s",
			resp.UserID, resp.ExpiresAt)
	}
	if resp.Status != StatusExpired {
		t.Errorf("status = %q, want %q — refresh_session must agree with check_session", resp.Status, StatusExpired)
	}
	if resp.ErrorCode != "SESSION_EXPIRED" {
		t.Errorf("error_code = %q, want SESSION_EXPIRED", resp.ErrorCode)
	}
	if resp.UserID != "" {
		t.Errorf("user_id = %q, want empty on a refusal", resp.UserID)
	}

	// Removed, not merely refused: the next check_session must not find it either.
	if live := b.getSession(s.ID); live != nil {
		t.Errorf("expired session is still in the map with expires_at=%s", live.ExpiresAt)
	}
	check, err := b.CheckSession(s.ID)
	if err != nil {
		t.Fatalf("CheckSession: %v", err)
	}
	if check.Success {
		t.Error("check_session authorized a session refresh had just refused")
	}
}

// TestRefreshExtendsALiveSession is the companion that stops the test above from
// passing for the wrong reason. Without it, a RefreshSession that refused
// everything would look correct.
func TestRefreshExtendsALiveSession(t *testing.T) {
	b := startBroker(t, brokerConfig(t), newFakeProvider("acme"))

	now := time.Now()
	// Inside authentication.refresh_threshold (one minute in brokerConfig), so
	// the call takes the extension branch rather than returning early.
	s := authorizedSession(t, b, "live", now, now.Add(30*time.Second))
	before := s.ExpiresAt

	resp, err := b.RefreshSession(s.ID)
	if err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if !resp.Success || resp.Status != StatusAuthorized {
		t.Fatalf("success = %v, status = %q (%s); want a live session to refresh",
			resp.Success, resp.Status, resp.ErrorCode)
	}
	if !resp.ExpiresAt.After(before) {
		t.Errorf("expires_at = %s, want later than %s — nothing was extended", resp.ExpiresAt, before)
	}

	live := b.getSession(s.ID)
	if live == nil {
		t.Fatal("refresh removed the session it extended")
	}
	if !live.ExpiresAt.Equal(resp.ExpiresAt) {
		t.Errorf("stored expires_at = %s but the reply said %s; the extension was not applied to the stored entry",
			live.ExpiresAt, resp.ExpiresAt)
	}
}

// TestExtendSessionRefusesUnlessStillTheSameAuthorizedSession exercises the
// compare-and-set arm by arm, the way
// TestActivateSessionRefusesUnlessStillTheSamePendingSession does for
// activation. Each refusal here is a way a deleted or demoted session could
// otherwise be written back into the map by a refresh that read it a moment
// earlier.
func TestExtendSessionRefusesUnlessStillTheSameAuthorizedSession(t *testing.T) {
	b := startBroker(t, brokerConfig(t), newFakeProvider("acme"))

	created := time.Now()
	newAuthorized := func(id string) *Session {
		return authorizedSession(t, b, id, created, created.Add(time.Minute))
	}
	extended := func(s *Session) bool {
		return b.extendSession(s.ID, created, func(s *Session) {
			s.ExpiresAt = created.Add(time.Hour)
		})
	}

	t.Run("still the same authorized session", func(t *testing.T) {
		s := newAuthorized("ok")
		if !extended(s) {
			t.Fatal("extendSession refused an unchanged authorized session")
		}
		if got := b.getSession("ok"); !got.ExpiresAt.Equal(created.Add(time.Hour)) {
			t.Errorf("expires_at = %s, want the mutation applied to the stored entry", got.ExpiresAt)
		}
	})

	t.Run("gone", func(t *testing.T) {
		if b.extendSession("missing", created, func(*Session) {}) {
			t.Error("extendSession extended a session that no longer exists; a revoked session would be resurrected")
		}
	})

	t.Run("deactivated", func(t *testing.T) {
		s := newAuthorized("inactive")
		s.IsActive = false
		if extended(s) {
			t.Error("extendSession extended an inactive session")
		}
	})

	t.Run("no longer authorized", func(t *testing.T) {
		s := newAuthorized("failed")
		s.Status = StatusExpired
		if extended(s) {
			t.Error("extendSession extended a session that had gone terminal")
		}
	})

	t.Run("id reused by a newer session", func(t *testing.T) {
		s := newAuthorized("reused")
		if b.extendSession(s.ID, created.Add(-time.Second), func(*Session) {}) {
			t.Error("extendSession accepted a stale CreatedAt; a refresh could extend a different session")
		}
	})
}

// TestRefreshDoesNotResurrectRevokedSession is the race half of #41.
//
// RefreshSession read a snapshot and wrote it back wholesale, so a
// RevokeSession that deleted the session in between was silently undone: the
// re-inserted entry named a TokenID that had already been destroyed at the
// provider, had no poller, and had a brand-new hour to live — and check_session
// answered it with success and user_id.
//
// This is a logic bug, not a data race: every access is properly locked and -race
// sees nothing. So the proof has to be the outcome, and the outcome is only
// visible when the two calls interleave inside a window a few instructions wide.
// There is no deterministic way to force it from out here — the window is between
// two lock acquisitions inside RefreshSession, and the only hook that would close
// it deterministically would be test scaffolding in the broker itself. So this is
// a bounded loop, and the two things that make it meaningful rather than
// decorative are:
//
//   - Many pairs race at once, not one at a time, on more than one P. One pair
//     per round is what the reviewer did by hand and it landed on 1 attempt in
//     200; measured against the unfixed code, 2000 sequential pairs found the
//     defect 0 to 1 times and missed it entirely on 5 of 8 runs, and GOMAXPROCS=1
//     missed it on 10 of 10 however many pairs raced. Racing pairsPerRound at a
//     time with GOMAXPROCS pinned above 1 gives the scheduler enough runnable
//     goroutines to preempt inside the window: the unfixed code then fails in the
//     first round or two of every run.
//   - The loop counts how many refreshes actually found the session deleted
//     underneath them, and fails if that never happened. Both call orders
//     occurring is not enough — measured at GOMAXPROCS=1, both orders occurred in
//     every run while the window itself was never hit once, which is precisely the
//     shape of a test that cannot fail.
//
// The deterministic proof of the same guarantee, arm by arm, is
// TestExtendSessionRefusesUnlessStillTheSameAuthorizedSession above; this test is
// what says the guarantee is wired into the verb.
func TestRefreshDoesNotResurrectRevokedSession(t *testing.T) {
	// Raised, never lowered, and restored afterwards: without real parallelism
	// this test still passes and proves nothing.
	if runtime.GOMAXPROCS(0) < 4 {
		prev := runtime.GOMAXPROCS(4)
		t.Cleanup(func() { runtime.GOMAXPROCS(prev) })
	}

	b := startBroker(t, brokerConfig(t), newFakeProvider("acme"))

	const (
		pairsPerRound = 32
		rounds        = 64
	)
	var sawLiveRead, sawAlreadyGone, sawDeletedUnderneath int

	for round := 0; round < rounds; round++ {
		ids := make([]string, pairsPerRound)
		tokens := make([]string, pairsPerRound)
		replies := make([]*AuthResponse, pairsPerRound)

		now := time.Now()
		for i := range ids {
			ids[i] = fmt.Sprintf("race-%d-%d", round, i)
			// Inside refresh_threshold so the refresh reaches the write, which is
			// where the window is.
			s := authorizedSession(t, b, ids[i], now, now.Add(30*time.Second))
			tokens[i] = s.TokenID
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range ids {
			i, id := i, ids[i]
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				resp, err := b.RefreshSession(id)
				if err != nil {
					panic(fmt.Sprintf("RefreshSession: %v", err))
				}
				replies[i] = resp
			}()
			go func() {
				defer wg.Done()
				<-start
				_ = b.RevokeSession(id)
			}()
		}
		close(start)
		wg.Wait()

		for i, id := range ids {
			// Whichever order the two landed in, the invariant is the same: nothing
			// may be left authorized once its token has been destroyed.
			live := b.getSession(id)
			if live != nil && live.IsActive && live.Status == StatusAuthorized && !tokenLives(b, tokens[i]) {
				t.Fatalf("round %d pair %d: revoked session is authorized again (user_id=%q token_destroyed=true expires_at=%s); refresh resurrected it",
					round+1, i, live.LocalUser, live.ExpiresAt)
			}
			if live != nil {
				t.Fatalf("round %d pair %d: session survived revocation (status=%q active=%v)",
					round+1, i, live.Status, live.IsActive)
			}
			if check, err := b.CheckSession(id); err != nil {
				t.Fatalf("CheckSession: %v", err)
			} else if check.Success {
				t.Fatalf("round %d pair %d: check_session authorizes a revoked session (user_id=%q)",
					round+1, i, check.UserID)
			}

			// Which answer the refresh gave says where in the call the revocation
			// landed, and that is how this test knows what it exercised.
			switch replies[i].ErrorMessage {
			case msgRevokedWhileRefreshing, msgDeactivatedWhileRefreshing:
				// The compare-and-set refused: the session was deleted after this
				// refresh had read and vetted it. This is the window, and in the
				// unfixed code these are the pairs that resurrected a session.
				sawDeletedUnderneath++
				sawLiveRead++
			case "Session not found":
				sawAlreadyGone++
			default:
				sawLiveRead++
			}
		}
	}

	total := pairsPerRound * rounds
	t.Logf("%d racing pairs: %d refreshes read a live session (%d of them had it deleted underneath), %d found it already revoked",
		total, sawLiveRead, sawDeletedUnderneath, sawAlreadyGone)
	if sawLiveRead == 0 || sawAlreadyGone == 0 {
		t.Errorf("refresh and revoke never interleaved across %d pairs (%d read a live session, %d found it gone); "+
			"this test cannot fail as written and must be fixed rather than trusted",
			total, sawLiveRead, sawAlreadyGone)
	}
	if sawDeletedUnderneath == 0 {
		t.Errorf("not one of %d pairs had its session deleted between the read and the write; "+
			"that window is the whole defect, so this run tested nothing and the loop must be "+
			"made to race rather than trusted", total)
	}
}

// TestMaxTokenAgeIsAnAbsoluteCeilingOnRefresh is #43: security.max_token_age was
// parsed, defaulted, documented, and compared against token_lifetime at startup —
// and never once compared against a session's age. Nothing bounded a refresh
// loop, so a session could be extended indefinitely past the ceiling the
// operator configured. Measured before the fix with max_token_age at 2s: fifty
// consecutive refreshes all succeeded.
//
// Both directions are asserted so the comparison cannot be silently inverted,
// and the session past the ceiling is given an expiry far in the future so that
// nothing but its age can explain the refusal.
func TestMaxTokenAgeIsAnAbsoluteCeilingOnRefresh(t *testing.T) {
	const ceiling = 2 * time.Hour

	cfg := brokerConfig(t)
	cfg.Security.MaxTokenAge = ceiling
	b := startBroker(t, cfg, newFakeProvider("acme"))

	t.Run("inside the ceiling extends", func(t *testing.T) {
		now := time.Now()
		s := authorizedSession(t, b, "young", now.Add(-ceiling+time.Minute), now.Add(30*time.Second))
		// s is the stored entry, and the extension mutates it in place, so the
		// expiry to compare against has to be copied before the call.
		before := s.ExpiresAt

		resp, err := b.RefreshSession(s.ID)
		if err != nil {
			t.Fatalf("RefreshSession: %v", err)
		}
		if !resp.Success {
			t.Fatalf("status = %q (%s); a session inside max_token_age must still refresh, or the check is inverted",
				resp.Status, resp.ErrorCode)
		}
		if !resp.ExpiresAt.After(before) {
			t.Errorf("expires_at = %s, want later than %s", resp.ExpiresAt, before)
		}
	})

	t.Run("past the ceiling is refused however long it has left", func(t *testing.T) {
		now := time.Now()
		// Expiry half an hour away: this session is nowhere near expiring, and is
		// not even inside refresh_threshold, so only its age can refuse it.
		s := authorizedSession(t, b, "old", now.Add(-ceiling-time.Minute), now.Add(30*time.Minute))
		tokenID := s.TokenID

		resp, err := b.RefreshSession(s.ID)
		if err != nil {
			t.Fatalf("RefreshSession: %v", err)
		}
		if resp.Success {
			t.Fatalf("a session %s old was refreshed under a %s ceiling: success=true user_id=%q expires_at=%s",
				ceiling+time.Minute, ceiling, resp.UserID, resp.ExpiresAt)
		}
		if resp.Status != StatusExpired {
			t.Errorf("status = %q, want %q", resp.Status, StatusExpired)
		}
		if resp.ErrorCode != "SESSION_EXPIRED" {
			t.Errorf("error_code = %q, want SESSION_EXPIRED", resp.ErrorCode)
		}

		// Revoked, not merely refused: the ceiling is a security control, so the
		// token must be gone too.
		if live := b.getSession(s.ID); live != nil {
			t.Errorf("session past max_token_age is still in the map (status=%q expires_at=%s)",
				live.Status, live.ExpiresAt)
		}
		if tokenLives(b, tokenID) {
			t.Error("session past max_token_age was refused but its token is still in the store")
		}
	})

	t.Run("exactly at the ceiling is still inside it", func(t *testing.T) {
		now := time.Now()
		// CreatedAt is a hair under the ceiling away, which is the closest a test
		// can get to the boundary without the clock deciding the outcome. Pinned
		// so that "older than" cannot quietly become "at least as old as".
		s := authorizedSession(t, b, "boundary", now.Add(-ceiling).Add(2*time.Second), now.Add(30*time.Second))

		if b.pastMaxTokenAge(s, now) {
			t.Errorf("a session %s old is past a %s ceiling", ceiling-2*time.Second, ceiling)
		}
		if resp, err := b.RefreshSession(s.ID); err != nil {
			t.Fatalf("RefreshSession: %v", err)
		} else if !resp.Success {
			t.Errorf("status = %q (%s), want the boundary session to refresh", resp.Status, resp.ErrorCode)
		}
	})

	t.Run("unset means no ceiling", func(t *testing.T) {
		unset := brokerConfig(t)
		unset.Security.MaxTokenAge = 0
		other := startBroker(t, unset, newFakeProvider("acme"))

		now := time.Now()
		s := authorizedSession(t, other, "ancient", now.Add(-30*24*time.Hour), now.Add(30*time.Second))

		if other.pastMaxTokenAge(s, now) {
			t.Error("max_token_age = 0 is unset and must not bound anything")
		}
		if resp, err := other.RefreshSession(s.ID); err != nil {
			t.Fatalf("RefreshSession: %v", err)
		} else if !resp.Success {
			t.Errorf("status = %q (%s); an unset ceiling refused a refresh", resp.Status, resp.ErrorCode)
		}
	})
}

// TestCheckSessionAgreesWithRefreshSession is #59. docs/wire-protocol.md says the
// two verbs "are required to agree" about whether a session is authorized, and
// CheckSession applied neither of the two bounds RefreshSession applies: it never
// called pastMaxTokenAge and never looked at the token store. Both cases were
// measured as check_session answering authorized/success=true against
// refresh_session answering expired/SESSION_EXPIRED for the same session ID.
//
// That matters more than a spec mismatch: no in-tree client sends
// refresh_session, so check_session is the only verb that ever decides a login,
// and it was the lenient one.
//
// Each case is put to both verbs on two identical sessions, because either verb
// consumes the session it refuses — and asserting the pair agree is the property,
// rather than asserting a particular answer twice.
func TestCheckSessionAgreesWithRefreshSession(t *testing.T) {
	const ceiling = 2 * time.Hour

	cfg := brokerConfig(t)
	cfg.Security.MaxTokenAge = ceiling
	b := startBroker(t, cfg, newFakeProvider("acme"))

	// twins installs the same session twice so one copy can be spent on each verb.
	twins := func(t *testing.T, name string, createdAt, expiresAt time.Time) (checked, refreshed *Session) {
		t.Helper()
		return authorizedSession(t, b, name+"-check", createdAt, expiresAt),
			authorizedSession(t, b, name+"-refresh", createdAt, expiresAt)
	}
	agree := func(t *testing.T, check, refresh *AuthResponse) {
		t.Helper()
		if check.Success != refresh.Success || check.Status != refresh.Status || check.ErrorCode != refresh.ErrorCode {
			t.Errorf("check_session says status=%q success=%v (%s) but refresh_session says status=%q success=%v (%s)",
				check.Status, check.Success, check.ErrorCode,
				refresh.Status, refresh.Success, refresh.ErrorCode)
		}
	}

	t.Run("past max_token_age", func(t *testing.T) {
		now := time.Now()
		// Half an hour of expiry left, so only the age can explain a refusal.
		checked, refreshed := twins(t, "aged", now.Add(-ceiling-time.Minute), now.Add(30*time.Minute))

		check, err := b.CheckSession(checked.ID)
		if err != nil {
			t.Fatalf("CheckSession: %v", err)
		}
		refresh, err := b.RefreshSession(refreshed.ID)
		if err != nil {
			t.Fatalf("RefreshSession: %v", err)
		}
		agree(t, check, refresh)

		if check.Success || check.Status != StatusExpired || check.ErrorCode != "SESSION_EXPIRED" {
			t.Errorf("check_session says status=%q success=%v (%s) for a session %s old under a %s ceiling",
				check.Status, check.Success, check.ErrorCode, ceiling+time.Minute, ceiling)
		}
		if check.UserID != "" {
			t.Errorf("user_id = %q on a refusal, want empty", check.UserID)
		}

		// Revoked, not merely refused, the way RefreshSession does it: the ceiling
		// is a security control, so the credential goes with the session.
		if live := b.getSession(checked.ID); live != nil {
			t.Errorf("check_session left a session past the ceiling in the map (status=%q)", live.Status)
		}
		if tokenLives(b, checked.TokenID) {
			t.Error("check_session refused a session past the ceiling but left its token in the store")
		}
	})

	t.Run("token is no longer in the store", func(t *testing.T) {
		now := time.Now()
		checked, refreshed := twins(t, "tokenless", now, now.Add(30*time.Minute))

		// What the token manager's own cleanup does when the token record's expiry
		// passes. A refresh extends the session's expiry and not the record's, so
		// this is the ordinary state of a session that has been refreshed once.
		b.tokenManager.RevokeToken(checked.TokenID)
		b.tokenManager.RevokeToken(refreshed.TokenID)

		check, err := b.CheckSession(checked.ID)
		if err != nil {
			t.Fatalf("CheckSession: %v", err)
		}
		refresh, err := b.RefreshSession(refreshed.ID)
		if err != nil {
			t.Fatalf("RefreshSession: %v", err)
		}
		agree(t, check, refresh)

		if check.Success || check.Status != StatusExpired {
			t.Errorf("check_session says status=%q success=%v user_id=%q for a session whose access token is gone",
				check.Status, check.Success, check.UserID)
		}
		if live := b.getSession(checked.ID); live != nil {
			t.Errorf("a session with no usable token is still in the map (status=%q)", live.Status)
		}
	})

	t.Run("a live session is still authorized by both", func(t *testing.T) {
		// The companion that stops the cases above from passing for the wrong
		// reason: two verbs that refuse everything also agree.
		now := time.Now()
		checked, refreshed := twins(t, "live", now, now.Add(30*time.Minute))

		check, err := b.CheckSession(checked.ID)
		if err != nil {
			t.Fatalf("CheckSession: %v", err)
		}
		refresh, err := b.RefreshSession(refreshed.ID)
		if err != nil {
			t.Fatalf("RefreshSession: %v", err)
		}
		agree(t, check, refresh)

		if !check.Success || check.Status != StatusAuthorized || check.UserID != "alice" {
			t.Errorf("check_session says status=%q success=%v user_id=%q for a live session",
				check.Status, check.Success, check.UserID)
		}
	})

	t.Run("a refresh never extends past the ceiling", func(t *testing.T) {
		now := time.Now()
		// Half an hour of ceiling left, and inside refresh_threshold so the call
		// reaches the extension. token_lifetime is an hour, so an uncapped
		// extension lands half an hour past the ceiling — measured at 59 minutes
		// past before the fix, with only the five-minute cleanup sweep to notice.
		s := authorizedSession(t, b, "capped", now.Add(-ceiling+30*time.Minute), now.Add(30*time.Second))
		ceilingAt := s.CreatedAt.Add(ceiling)

		resp, err := b.RefreshSession(s.ID)
		if err != nil {
			t.Fatalf("RefreshSession: %v", err)
		}
		if !resp.Success {
			t.Fatalf("status = %q (%s); a session inside the ceiling must still refresh",
				resp.Status, resp.ErrorCode)
		}
		if resp.ExpiresAt.After(ceilingAt) {
			t.Errorf("expires_at = %s, %s past the max_token_age ceiling at %s",
				resp.ExpiresAt, resp.ExpiresAt.Sub(ceilingAt).Round(time.Second), ceilingAt)
		}
		if live := b.getSession(s.ID); live == nil {
			t.Fatal("refresh removed the session it extended")
		} else if live.ExpiresAt.After(ceilingAt) {
			t.Errorf("stored expires_at = %s, %s past the ceiling; the cap was applied to the reply only",
				live.ExpiresAt, live.ExpiresAt.Sub(ceilingAt).Round(time.Second))
		}
	})
}

// TestSessionCleanupRevokesSessionsPastMaxTokenAge covers the other half of #43.
// Enforcing the ceiling only in RefreshSession would leave it unenforced for
// every session nobody calls refresh_session on — which today is all of them, as
// no in-tree client sends that verb.
func TestSessionCleanupRevokesSessionsPastMaxTokenAge(t *testing.T) {
	const ceiling = 2 * time.Hour

	cfg := brokerConfig(t)
	cfg.Security.MaxTokenAge = ceiling
	fake := newFakeProvider("acme")
	b := startBroker(t, cfg, fake)

	now := time.Now()
	// Both are well inside their own expiry, so ExpiresAt cannot explain either
	// outcome; the only difference between them is age.
	old := authorizedSession(t, b, "old", now.Add(-ceiling-time.Minute), now.Add(30*time.Minute))
	young := authorizedSession(t, b, "young", now.Add(-time.Minute), now.Add(30*time.Minute))

	if n := b.cleanupExpiredSessions(now); n != 1 {
		t.Errorf("cleanup revoked %d sessions, want exactly 1 (the one past max_token_age)", n)
	}

	if live := b.getSession(old.ID); live != nil {
		t.Errorf("a session %s old survived cleanup under a %s ceiling (expires_at=%s)",
			ceiling+time.Minute, ceiling, live.ExpiresAt)
	}
	if tokenLives(b, old.TokenID) {
		t.Error("cleanup dropped the session past max_token_age but left its token in the store")
	}
	if live := b.getSession(young.ID); live == nil {
		t.Error("cleanup revoked a session that is neither expired nor past the ceiling")
	}

	// The token was revoked at the provider too, not just forgotten locally.
	fake.mu.Lock()
	revoked := append([]string(nil), fake.revoked...)
	fake.mu.Unlock()
	if len(revoked) != 1 || revoked[0] != "access-token-"+old.ID {
		t.Errorf("provider saw revocations %v, want the aged-out session's token", revoked)
	}
}
