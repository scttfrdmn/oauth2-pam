package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/scttfrdmn/oauth2-pam/pkg/security"
)

// A login refused because its record could not be written — #91.
//
// #87 put the authentication_success in front of the sinks before the grant exists,
// and refused the login when the write failed. Both halves are right, and together
// they left a case nobody owned: the write can fail *and* leave the record readable.
// Every sink is attempted whatever the earlier ones did, so a broken file output
// among several returns an error while syslog holds the record.
//
// failSession, which is what refuses the login, writes no audit record at all. So
// the trail's last word on the session was an authentication_success — same
// user_id, same auth_method, same session_id as a real grant — for a login that
// never happened. During a disk-full incident that is a burst of apparently
// successful authentications at the moment nobody could log in.
//
// The two tests below are the pair. Which one applies depends only on whether a
// sink kept the record, which is exactly what security.RecordMayHaveLanded reports.

// TestARefusedLoginCorrectsTheRecordASinkKept is the ordinary multi-sink config:
// audit.outputs naming a file and a syslog, and the audit filesystem full.
func TestARefusedLoginCorrectsTheRecordASinkKept(t *testing.T) {
	broken := &brokenSink{}
	kept := &recordingSink{}
	fake := newFakeProvider("acme")
	fake.authorize()

	b := brokerWithAuditSinks(t, brokerConfig(t), []security.AuditOutput{broken, kept}, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	resp := awaitStatus(t, b, start.SessionID)
	if resp.Success || resp.Status == StatusAuthorized {
		t.Fatalf("status = %q success = %v: a login was granted although its record could not be written",
			resp.Status, resp.Success)
	}
	if resp.Status != StatusError {
		t.Errorf("status = %q, want %q", resp.Status, StatusError)
	}

	// The premise: one sink refused the record and the other kept it. Without both
	// halves this test is asserting nothing.
	if broken.writes() == 0 {
		t.Fatal("the failing sink was never written to")
	}
	if kept.lastOfType("authentication_success") == nil {
		t.Fatal("the healthy sink has no authentication_success, so there is no retained record to correct")
	}

	ev := kept.lastOfType("session_revoked")
	if ev == nil {
		t.Fatal("the login was refused and the success record a sink kept was never corrected: " +
			"the trail's last word on this session is a login that did not happen")
	}
	if ev.Success {
		t.Error("success = true on the record of an authentication that was refused")
	}
	if ev.UserID != "alice" {
		t.Errorf("user_id = %q, want alice: the correction has to name the account the record it corrects named",
			ev.UserID)
	}
	if ev.SessionID != start.SessionID {
		t.Errorf("session_id = %q, want %q", ev.SessionID, start.SessionID)
	}
	if !strings.Contains(ev.ErrorMessage, "did not take effect") {
		t.Errorf("error_message = %q; it has to say the recorded authentication did not take effect",
			ev.ErrorMessage)
	}

	// Last word, not an aside followed by the success. A reader stopping at the most
	// recent record for this session is the reader this is for.
	events := kept.all()
	if last := events[len(events)-1]; last.EventType != "session_revoked" {
		t.Errorf("the last record for this session is %q; a reader stopping there sees a granted login",
			last.EventType)
	}
}

// TestARefusedLoginWritesNoCorrectionWhenNoSinkKeptTheRecord is the control, and it
// is not a formality: a correction for a record that does not exist is its own false
// record. A session_revoked describing the withdrawal of a login the trail never
// claimed reads, to anything counting revocations, as a session that existed.
//
// This is the single-sink case TestUnwritableAuditRecordFailsTheLogin already
// covers from the other side, asserted here on the record rather than the response.
func TestARefusedLoginWritesNoCorrectionWhenNoSinkKeptTheRecord(t *testing.T) {
	// A sink that refuses every write, and records what it was asked to write. The
	// broker cannot tell it apart from brokenSink; the test can.
	refusing := &refusingRecordingSink{recordingSink: &recordingSink{}}
	fake := newFakeProvider("acme")
	fake.authorize()

	b := brokerWithAuditSinks(t, brokerConfig(t), []security.AuditOutput{refusing}, fake)

	start, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	resp := awaitStatus(t, b, start.SessionID)
	if resp.Status != StatusError {
		t.Fatalf("status = %q, want %q", resp.Status, StatusError)
	}
	if refusing.lastOfType("authentication_success") == nil {
		t.Fatal("no authentication_success was offered to the sink; the test is not on the path it means to be")
	}
	if ev := refusing.lastOfType("session_revoked"); ev != nil {
		t.Errorf("a correction was written for a record no sink accepted: %q", ev.ErrorMessage)
	}
}

// errNoSpace is the failure every sink in these tests reports: the audit
// filesystem is full, which is the case the whole mechanism exists for.
var errNoSpace = errors.New("no space left on device")

// refusingRecordingSink keeps every record it is offered and refuses all of them.
type refusingRecordingSink struct {
	*recordingSink
}

func (s *refusingRecordingSink) Write(data []byte) error {
	_ = s.recordingSink.Write(data)
	return errNoSpace
}
