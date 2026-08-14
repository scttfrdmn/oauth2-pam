package auth

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
	"github.com/scttfrdmn/oauth2-pam/pkg/security"
)

// The audit trail is part of the grant, not a report about it. These tests cover
// the two halves of that (#69): a record that cannot be written must not leave a
// login granted, and a record that is written must say what actually happened.

// brokenSink is an audit output that accepts nothing — a full disk, or a syslog
// socket that has gone away.
type brokenSink struct {
	mu       sync.Mutex
	attempts int
}

func (s *brokenSink) Write([]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	return errors.New("no space left on device")
}

func (s *brokenSink) Close() error { return nil }

func (s *brokenSink) writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

// recordingSink keeps every event a sink was asked to write, so a test can assert
// on the record rather than on the call that produced it.
type recordingSink struct {
	mu     sync.Mutex
	events []security.AuditEvent
}

func (s *recordingSink) Write(data []byte) error {
	var ev security.AuditEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}

func (s *recordingSink) Close() error { return nil }

// lastOfType returns the most recent event of the given type, or nil.
func (s *recordingSink) lastOfType(eventType string) *security.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].EventType == eventType {
			ev := s.events[i]
			return &ev
		}
	}
	return nil
}

// brokerWithAuditSink starts a broker whose audit logger writes to sink and
// nothing else. The logger is installed before Start, so it is the one the broker
// starts and stops.
func brokerWithAuditSink(t *testing.T, cfg *config.Config, sink security.AuditOutput, providers ...provider.Provider) *Broker {
	t.Helper()
	cfg.Audit = config.AuditConfig{Enabled: true}

	b, err := NewBrokerWithProviders(cfg, providers)
	if err != nil {
		t.Fatalf("NewBrokerWithProviders: %v", err)
	}
	logger, err := security.NewAuditLoggerWithOutputs(cfg.Audit, sink)
	if err != nil {
		t.Fatalf("NewAuditLoggerWithOutputs: %v", err)
	}
	b.auditLogger = logger

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := b.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = b.Stop() })
	return b
}

// TestUnwritableAuditRecordFailsTheLogin is the point of LogAuthEventErr existing.
//
// authentication_success sits on the one path in the broker that hands out an
// authenticated session. It used to be logged with LogAuthEvent, which reports a
// write failure to the process log and returns nothing, so a host that had run out
// of disk granted logins and recorded none of them — the audit trail missing
// exactly the records an incident would be reconstructed from, and every login
// looking normal from the outside.
//
// A refused login on a broken sink is the deliberate trade: an operator whose audit
// sink is full has an outage either way, and the version of that outage where
// people are still let in unrecorded is the worse one.
func TestUnwritableAuditRecordFailsTheLogin(t *testing.T) {
	sink := &brokenSink{}
	fake := newFakeProvider("acme")
	fake.authorize()
	b := brokerWithAuditSink(t, brokerConfig(t), sink, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	resp := awaitStatus(t, b, start.SessionID)
	if resp.Success || resp.Status == StatusAuthorized {
		t.Fatalf("status = %q, success = %v, user_id = %q: a login was granted with no audit record of it",
			resp.Status, resp.Success, resp.UserID)
	}
	if resp.Status != StatusError {
		t.Errorf("status = %q, want %q — the sink failed, which is an operational failure and not a decision about the user",
			resp.Status, StatusError)
	}
	if resp.UserID != "" {
		t.Errorf("user_id = %q on a refused login, want empty", resp.UserID)
	}
	if sink.writes() == 0 {
		t.Error("the sink was never written to; the test cannot distinguish a refused write from an unattempted one")
	}

	// The session must not be left active either: check_session is not the only
	// reader of the session map, and an active session is what refresh_session and
	// the concurrency caps count.
	if live := b.getSession(start.SessionID); live != nil && (live.IsActive || live.Status == StatusAuthorized) {
		t.Errorf("session is status=%q active=%v after the audit write failed", live.Status, live.IsActive)
	}

	// And the credential the flow fetched must be gone: a withdrawn grant that
	// keeps its access token is a live token attached to no login.
	b.tokenManager.tokenStore.mutex.RLock()
	tokens := len(b.tokenManager.tokenStore.tokens)
	b.tokenManager.tokenStore.mutex.RUnlock()
	if tokens != 0 {
		t.Errorf("%d token(s) remain after a withdrawn grant, want none", tokens)
	}
}

// TestAuthenticationSuccessIsRecordedWhenTheSinkWorks is the control for the test
// above: the same path with a working sink still grants the login and still writes
// the record naming who was let in. Without this, "the login failed" would be an
// equally good outcome for a broker that never granted anything.
func TestAuthenticationSuccessIsRecordedWhenTheSinkWorks(t *testing.T) {
	sink := &recordingSink{}
	fake := newFakeProvider("acme")
	fake.authorize()
	b := brokerWithAuditSink(t, brokerConfig(t), sink, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	resp := awaitStatus(t, b, start.SessionID)
	if !resp.Success || resp.Status != StatusAuthorized {
		t.Fatalf("status = %q, success = %v; want the login granted", resp.Status, resp.Success)
	}

	ev := sink.lastOfType("authentication_success")
	if ev == nil {
		t.Fatal("no authentication_success record was written for a granted login")
	}
	if !ev.Success || ev.UserID != "alice" {
		t.Errorf("record: success = %v, user_id = %q; want true and alice", ev.Success, ev.UserID)
	}
}

// TestRevokedPendingSessionIsNotAuditedAsASuccessNamingNobody covers the other
// half of #69: what a record says has to match what happened.
//
// RevokeSession emitted session_revoked with Success: true and UserID "" for a
// session that had never completed its device flow — LocalUser is only ever written
// by activateSession — which reads as "someone's session was revoked successfully"
// and names nobody. An incident review cannot correlate that with anything, and it
// looks like a settled fact rather than a gap.
func TestRevokedPendingSessionIsNotAuditedAsASuccessNamingNobody(t *testing.T) {
	sink := &recordingSink{}
	fake := newFakeProvider("acme") // never authorized: the flow stays pending
	b := brokerWithAuditSink(t, brokerConfig(t), sink, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := b.RevokeSession(start.SessionID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	ev := sink.lastOfType("session_revoked")
	if ev == nil {
		t.Fatal("no session_revoked record was written")
	}
	if ev.UserID != "" {
		t.Errorf("user_id = %q for a session that never authenticated anyone, want empty", ev.UserID)
	}
	if ev.Success {
		t.Error("success = true on a record that names no user; that is a claim about an identity the broker never had")
	}
	if ev.ErrorMessage == "" {
		t.Error("success is false with no explanation, which reads as a failed revocation")
	}
	if got := ev.Metadata["session_status"]; got != StatusPending {
		t.Errorf("metadata.session_status = %v, want %q — the record should say what was revoked", got, StatusPending)
	}
	if got := ev.Metadata["requested_user"]; got != "alice" {
		t.Errorf("metadata.requested_user = %v, want alice; the account the login asked for is the only correlatable value there is", got)
	}
	if ev.SessionID != start.SessionID {
		t.Errorf("session_id = %q, want %q", ev.SessionID, start.SessionID)
	}
}

// The control: revoking a session that really did authenticate someone still
// records a success, and still names them. The fix above must not have been "stop
// claiming success" everywhere.
func TestRevokedAuthorizedSessionIsAuditedAsASuccessNamingTheUser(t *testing.T) {
	sink := &recordingSink{}
	fake := newFakeProvider("acme")
	fake.authorize()
	b := brokerWithAuditSink(t, brokerConfig(t), sink, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp := awaitStatus(t, b, start.SessionID); resp.Status != StatusAuthorized {
		t.Fatalf("status = %q, want %q", resp.Status, StatusAuthorized)
	}

	if err := b.RevokeSession(start.SessionID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	ev := sink.lastOfType("session_revoked")
	if ev == nil {
		t.Fatal("no session_revoked record was written")
	}
	if !ev.Success {
		t.Error("success = false for the revocation of an authorized session")
	}
	if ev.UserID != "alice" {
		t.Errorf("user_id = %q, want alice", ev.UserID)
	}
	if got := ev.Metadata["session_status"]; got != StatusAuthorized {
		t.Errorf("metadata.session_status = %v, want %q", got, StatusAuthorized)
	}
	if ev.ErrorMessage != "" {
		t.Errorf("error_message = %q on a clean revocation, want none", ev.ErrorMessage)
	}
}

// A cleanup sweep revokes whatever has run out of time, pending flows included, so
// it is the path that produced these records in bulk without anyone calling
// revoke_session.
func TestExpiredPendingSessionSweptByCleanupIsAuditedTruthfully(t *testing.T) {
	sink := &recordingSink{}
	b := brokerWithAuditSink(t, brokerConfig(t), sink, newFakeProvider("acme"))

	b.setSession(&Session{
		ID:                 "stale",
		RequestedLocalUser: "alice",
		Provider:           "acme",
		CreatedAt:          time.Now().Add(-time.Hour),
		ExpiresAt:          time.Now().Add(-time.Minute),
		Status:             StatusPending,
	})

	if n := b.cleanupExpiredSessions(time.Now()); n != 1 {
		t.Fatalf("cleanupExpiredSessions revoked %d sessions, want 1", n)
	}

	ev := sink.lastOfType("session_revoked")
	if ev == nil {
		t.Fatal("no session_revoked record was written by the cleanup sweep")
	}
	if ev.Success || ev.UserID != "" {
		t.Errorf("success = %v, user_id = %q for a swept pending flow; want false and empty",
			ev.Success, ev.UserID)
	}
}
