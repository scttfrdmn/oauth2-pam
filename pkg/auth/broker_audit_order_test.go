package auth

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
	"github.com/scttfrdmn/oauth2-pam/pkg/security"
)

// Two invariants about the audit record of an access decision, both from the
// round-4 review:
//
//   - #87: the record is in front of a sink *before* the grant exists. The old
//     order activated the session and withdrew it if the write then failed, on the
//     reasoning that the window "can only produce a session that existed for
//     microseconds". Both PAM stages are sub-millisecond socket round trips and an
//     fsync on a degraded disk is not microseconds, so a check_session landing in
//     that window got a shell that the withdrawal could not take back.
//
//   - #89: user_id on any record names a local account or is empty. A
//     provider-chosen string only ever appears in metadata.provider_login.

// all returns every event the sink was asked to write, so a test can state an
// invariant over the whole trail rather than over one record it went looking for.
func (s *recordingSink) all() []security.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]security.AuditEvent(nil), s.events...)
}

// grantObservingSink looks at the session the record is about, at the moment the
// record is handed to it. It is the only vantage point from which the order of the
// write and the grant is observable: both happen inside one poll goroutine, and
// every field either one sets has the same value by the time the flow ends.
type grantObservingSink struct {
	mu        sync.Mutex
	broker    *Broker
	sessionID string

	sawSuccess    bool
	statusAtWrite string
	activeAtWrite bool
}

func (s *grantObservingSink) attach(b *Broker, sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.broker = b
	s.sessionID = sessionID
}

func (s *grantObservingSink) Write(data []byte) error {
	var ev security.AuditEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		return err
	}
	if ev.EventType != "authentication_success" {
		return nil
	}

	s.mu.Lock()
	b, id := s.broker, s.sessionID
	s.mu.Unlock()

	// Read outside the lock above: getSession takes the broker's session mutex, and
	// this runs on the audit logger's write goroutine while the poll goroutine waits
	// for the answer. That it does not deadlock is part of what this test asserts.
	var status string
	var active bool
	if b != nil && id != "" {
		if live := b.getSession(id); live != nil {
			status, active = live.Status, live.IsActive
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sawSuccess = true
	s.statusAtWrite = status
	s.activeAtWrite = active
	return nil
}

func (s *grantObservingSink) Close() error { return nil }

func (s *grantObservingSink) observation() (seen bool, status string, active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sawSuccess, s.statusAtWrite, s.activeAtWrite
}

// TestTheAuditRecordIsWrittenBeforeTheGrantExists is the #87 regression test. The
// sink asks the broker what the session looks like while it is being asked to
// record a success: if the answer is "authorized and active", then a check_session
// arriving at that instant would have been answered with a shell, and the record
// had not landed yet.
func TestTheAuditRecordIsWrittenBeforeTheGrantExists(t *testing.T) {
	sink := &grantObservingSink{}
	fake := newFakeProvider("acme")
	fake.authorize()
	// Held so the session ID can be handed to the sink before the flow completes.
	release := fake.blockIdentity()

	b := brokerWithAuditSink(t, brokerConfig(t), sink, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	sink.attach(b, start.SessionID)
	release()

	if resp := awaitStatus(t, b, start.SessionID); resp.Status != StatusAuthorized {
		t.Fatalf("status = %q, want %q: the flow has to succeed for the ordering to be observable",
			resp.Status, StatusAuthorized)
	}

	seen, status, active := sink.observation()
	if !seen {
		t.Fatal("no authentication_success record reached the sink")
	}
	if status == StatusAuthorized || active {
		t.Errorf("while the success record was being written the session was already status=%q active=%v; "+
			"a check_session landing there would have been answered with a login the record had not yet recorded",
			status, active)
	}
	if status != StatusPending {
		t.Errorf("session status = %q while the record was written, want %q", status, StatusPending)
	}
}

// casRefusingSink removes the session at the moment the success record is written.
//
// That instant is the one window the new order leaves: the record is in front of a
// sink and the compare-and-set that grants has not run yet. It is reached directly
// rather than through RevokeSession, because RevokeSession writes an audit record
// of its own and this sink is holding the audit logger's write lock.
type casRefusingSink struct {
	*recordingSink
	broker    *Broker
	sessionID string
	fired     bool
}

func (s *casRefusingSink) Write(data []byte) error {
	if err := s.recordingSink.Write(data); err != nil {
		return err
	}

	var ev security.AuditEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		return err
	}
	if ev.EventType != "authentication_success" || s.fired {
		return nil
	}
	s.fired = true
	if s.broker != nil && s.sessionID != "" {
		s.broker.removeSession(s.sessionID)
	}
	return nil
}

// TestARecordedAuthenticationThatNeverActivatesIsCorrected covers the cost of the
// #87 ordering, which the old comment was right about even though its conclusion
// was wrong. With the record written first, the compare-and-set can still refuse —
// the session was revoked or expired while the identity was being resolved — and
// then an authentication_success is sitting in the trail describing a login that
// never took effect. Left alone it would be the last word on that session, and an
// incident reader would count a login that never happened.
func TestARecordedAuthenticationThatNeverActivatesIsCorrected(t *testing.T) {
	sink := &casRefusingSink{recordingSink: &recordingSink{}}
	fake := newFakeProvider("acme")
	fake.authorize()
	release := fake.blockIdentity()

	b := brokerWithAuditSink(t, brokerConfig(t), sink, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	sink.broker, sink.sessionID = b, start.SessionID
	release()

	awaitPollerExit(t, b, start.SessionID)

	if !sink.fired {
		t.Fatal("the sink never saw an authentication_success, so no compare-and-set refusal was arranged")
	}

	ev := sink.lastOfType("session_revoked")
	if ev == nil {
		t.Fatal("an authentication_success was recorded for a session that never activated, " +
			"and nothing corrected it: the trail's last word on this session is a login that did not happen")
	}
	if ev.Success {
		t.Error("success = true on the record of an authentication that never took effect")
	}
	if ev.UserID != "alice" {
		t.Errorf("user_id = %q, want alice; the correction has to name the same account as the record it corrects",
			ev.UserID)
	}
	if ev.SessionID != start.SessionID {
		t.Errorf("session_id = %q, want %q", ev.SessionID, start.SessionID)
	}
	if !strings.Contains(ev.ErrorMessage, "did not take effect") {
		t.Errorf("error_message = %q; it has to say that the recorded authentication did not take effect",
			ev.ErrorMessage)
	}

	// The correction is the last word, not an earlier note followed by the success.
	events := sink.all()
	if last := events[len(events)-1]; last.EventType != "session_revoked" {
		t.Errorf("the last record for this session is %q; a reader stopping at the latest record sees a granted login",
			last.EventType)
	}

	// And the credential the flow fetched is gone. A session that never activated
	// holding a live access token is a token attached to no login.
	b.tokenManager.tokenStore.mutex.RLock()
	tokens := len(b.tokenManager.tokenStore.tokens)
	b.tokenManager.tokenStore.mutex.RUnlock()
	if tokens != 0 {
		t.Errorf("%d token(s) remain after a session that never activated, want none", tokens)
	}
}

// TestIdentityRefusalIsRecordedAgainstTheRequestedAccount is half of #89. Not in
// the required org or team is the most common real refusal in a deployment, and it
// arrives on this path. It used to write an authentication_failed record with no
// user_id at all — a record naming nobody, with a session ID as the only handle on
// who had been turned away.
func TestIdentityRefusalIsRecordedAgainstTheRequestedAccount(t *testing.T) {
	sink := &recordingSink{}
	fake := newFakeProvider("acme")
	fake.authorize()
	fake.failIdentityWith(provider.ErrAccessForbidden)

	b := brokerWithAuditSink(t, brokerConfig(t), sink, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp := awaitStatus(t, b, start.SessionID); resp.Status != StatusDenied {
		t.Fatalf("status = %q, want %q for a provider-level access refusal", resp.Status, StatusDenied)
	}

	ev := sink.lastOfType("authentication_failed")
	if ev == nil {
		t.Fatal("no authentication_failed record was written for a refused login")
	}
	if ev.UserID != "alice" {
		t.Errorf("user_id = %q, want alice: the record has to name the account the login was for", ev.UserID)
	}
	if got := ev.Metadata["requested_user"]; got != "alice" {
		t.Errorf("metadata.requested_user = %v, want alice", got)
	}
	if ev.Success {
		t.Error("success = true on a refused login")
	}
	if ev.SessionID != start.SessionID {
		t.Errorf("session_id = %q, want %q", ev.SessionID, start.SessionID)
	}
}

// TestMappingFailureIsRecordedAgainstTheRequestedAccountNotTheProviderLogin is the
// other half of #89, and the one with an attacker in it.
//
// This branch built its record with UserID: identity.Login — the provider's login,
// in the field every other event uses for the local Unix account. The login is a
// string the person being refused chooses. So anyone with a provider account, no
// local account and no org membership needed, could rename themselves to root and
// make the broker write an unfilterable authentication_failed record attributing
// the failure to root; a SIEM rule counting failures per user_id — the obvious rule
// to write against this event set — would attribute them there too.
func TestMappingFailureIsRecordedAgainstTheRequestedAccountNotTheProviderLogin(t *testing.T) {
	sink := &recordingSink{}
	fake := newFakeProvider("acme")
	fake.authorize()
	// The provider's login is an account name on this host, chosen by the person
	// being refused. Set before the flow starts, so nothing reads it concurrently.
	fake.identity.Login = "root"

	cfg := brokerConfig(t)
	// No rule matches this identity, so the mapper answers ErrNoMapping — the
	// enrolled-nowhere case, which is what an unknown user hits.
	cfg.Mapper.Rules[0].Match.Claims = map[string]string{provider.ClaimGroup: "nobody-is-in-this-group"}

	b := brokerWithAuditSink(t, cfg, sink, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp := awaitStatus(t, b, start.SessionID); resp.Status != StatusDenied {
		t.Fatalf("status = %q, want %q for an identity with no local mapping", resp.Status, StatusDenied)
	}

	ev := sink.lastOfType("authentication_failed")
	if ev == nil {
		t.Fatal("no authentication_failed record was written for an unmapped identity")
	}
	if ev.UserID != "alice" {
		t.Errorf("user_id = %q, want alice", ev.UserID)
	}
	if got := ev.Metadata["provider_login"]; got != "root" {
		t.Errorf("metadata.provider_login = %v, want root: the provider's login is real information and belongs in the record", got)
	}

	// The invariant, stated over the whole trail rather than over the one record
	// this test went looking for: a provider-chosen string never lands in user_id.
	for _, e := range sink.all() {
		if e.UserID == "root" {
			t.Errorf("event %q has user_id = %q, a name the person being refused chose; "+
				"provider logins belong in metadata.provider_login", e.EventType, e.UserID)
		}
	}
}
