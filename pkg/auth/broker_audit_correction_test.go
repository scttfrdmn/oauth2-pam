package auth

import (
	"errors"
	"fmt"
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
// Which of the tests below applies depends only on whether a sink kept the record,
// which is exactly what security.RecordMayHaveLanded reports. The first two are the
// two ways a sink keeps it — one healthy sink among several, and the single shipped
// file sink whose fsync is what failed (#94) — and the third is the only case in
// which there is nothing to correct: a sink that reports taking no part of it.

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

// TestARefusedLoginCorrectsARecordTheOnlySinkKept is the single-sink case, which is
// the configuration configs/example.yaml ships: one audit.outputs entry, type file,
// with stdout and syslog commented out.
//
// It was the multi-sink case above that made the correction look like it needed a
// second, healthy sink to write to. It does not, and #94 is what that assumption
// cost: fileOutput.Write hands the bytes to the kernel and then fsyncs, and a full
// filesystem with delayed allocation — along with quotas, I/O errors, and an NFS
// server that takes the write and not the commit — is reported by the fsync, with the
// whole record in the file and readable by anything tailing it. The sink returns an
// error and keeps the record, and this test used to assert that no correction was
// written in exactly that case.
//
// The correction's own write fails too, for the same reason, and lands for the same
// reason. A reader tailing the log, or reading the file once space is freed, sees it.
func TestARefusedLoginCorrectsARecordTheOnlySinkKept(t *testing.T) {
	// Keeps every record it is offered and reports failure, saying nothing about
	// whether the bytes landed — the shape of fileOutput.Write when the write
	// succeeded and the fsync did not. The broker cannot tell it apart from
	// brokenSink; the test can.
	kept := &retainingBrokenSink{recordingSink: &recordingSink{}}
	fake := newFakeProvider("acme")
	fake.authorize()

	b := brokerWithAuditSinks(t, brokerConfig(t), []security.AuditOutput{kept}, fake)

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
		t.Fatalf("status = %q, want %q", resp.Status, StatusError)
	}
	if kept.lastOfType("authentication_success") == nil {
		t.Fatal("no authentication_success reached the sink; the test is not on the path it means to be")
	}

	ev := kept.lastOfType("session_revoked")
	if ev == nil {
		t.Fatal("the login was refused and the success record the sink kept was never corrected: " +
			"on the single-file configuration example.yaml ships, every refusal during a disk-full " +
			"incident leaves an authentication_success as the trail's last word")
	}
	if ev.Success {
		t.Error("success = true on the record of an authentication that was refused")
	}
	if ev.UserID != "alice" {
		t.Errorf("user_id = %q, want alice", ev.UserID)
	}
	if ev.SessionID != start.SessionID {
		t.Errorf("session_id = %q, want %q", ev.SessionID, start.SessionID)
	}
	if !strings.Contains(ev.ErrorMessage, "did not take effect") {
		t.Errorf("error_message = %q; it has to say the recorded authentication did not take effect",
			ev.ErrorMessage)
	}
}

// TestARefusedLoginWritesNoCorrectionWhenTheSinkTookNoneOfTheRecord is the control,
// and it is not a formality: a correction for a record that does not exist is its own
// false record. A session_revoked describing the withdrawal of a login the trail
// never claimed reads, to anything counting revocations, as a session that existed.
//
// The sink here reports what only a sink can know — that its write took no bytes, so
// no part of the record is anywhere a reader could find it — by joining
// security.ErrRecordNotLanded to its error. Its recording of what it was offered is
// the test's instrumentation, not a claim that the bytes are readable.
func TestARefusedLoginWritesNoCorrectionWhenTheSinkTookNoneOfTheRecord(t *testing.T) {
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
		t.Errorf("a correction was written for a record the sink reported taking none of: %q", ev.ErrorMessage)
	}
}

// errNoSpace is the failure every sink in these tests reports: the audit
// filesystem is full, which is the case the whole mechanism exists for.
var errNoSpace = errors.New("no space left on device")

// retainingBrokenSink keeps every record it is offered and reports failure without
// saying whether the bytes landed.
type retainingBrokenSink struct {
	*recordingSink
}

func (s *retainingBrokenSink) Write(data []byte) error {
	_ = s.recordingSink.Write(data)
	return errNoSpace
}

// refusingRecordingSink took no part of the record, and says so.
type refusingRecordingSink struct {
	*recordingSink
}

func (s *refusingRecordingSink) Write(data []byte) error {
	_ = s.recordingSink.Write(data)
	return fmt.Errorf("%w: %w", errNoSpace, security.ErrRecordNotLanded)
}
