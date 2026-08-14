package security

import (
	"sync"
	"testing"
	"time"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

// The sinks a config can name have two ways to fail, and only one of them was
// covered anywhere. failingOutput in audit_test.go models the first: the write is
// refused and the refusal comes back. These tests model the second (#87): the
// write is accepted and never comes back. fileOutput.Write ends in an fsync, which
// blocks indefinitely on a hard NFS mount that has become unreachable;
// syslogOutput.Write blocks the same way on a stream /dev/log whose peer has
// stopped reading.
//
// The distinction matters because of who is waiting. LogAuthEventErr exists so
// that a caller holding a grant open can refuse the login when the record does not
// land — and a caller that never gets an answer never refuses anything. Without a
// deadline, an unreachable log server turned the fail-closed guarantee into its
// opposite: the broker blocked in the audit write, and every outcome downstream of
// that answer was simply never reached.

// stallingOutput accepts a write and then holds it until it is released.
type stallingOutput struct {
	release chan struct{}
	once    sync.Once

	mu     sync.Mutex
	writes int
}

func newStallingOutput() *stallingOutput {
	return &stallingOutput{release: make(chan struct{})}
}

func (o *stallingOutput) Write([]byte) error {
	o.mu.Lock()
	o.writes++
	o.mu.Unlock()
	<-o.release
	return nil
}

func (o *stallingOutput) Close() error { return nil }

// attempts reports how many records were handed to this sink. It is how a test
// tells a record that was refused from one that was never offered.
func (o *stallingOutput) attempts() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.writes
}

// unblock lets every held and future write through. Idempotent, because the
// cleanup below always calls it and some tests call it first.
func (o *stallingOutput) unblock() {
	o.once.Do(func() { close(o.release) })
}

// stalledLogger returns a logger whose only sink stalls, with a deadline short
// enough to wait out in a test.
//
// The sink is unblocked before Stop, not after: Stop takes writeMu to close the
// outputs and the goroutine stuck in Write is holding it, so a cleanup in the
// other order would hang the test binary rather than fail it. That ordering
// requirement is the honest cost of the design — see writeEvent.
func stalledLogger(t *testing.T, timeout time.Duration) (*AuditLogger, *stallingOutput) {
	t.Helper()

	sink := newStallingOutput()
	al, err := NewAuditLoggerWithOutputs(config.AuditConfig{Enabled: true}, sink)
	if err != nil {
		t.Fatalf("NewAuditLoggerWithOutputs: %v", err)
	}
	al.testWriteTimeout = timeout

	t.Cleanup(func() {
		sink.unblock()
		_ = al.Stop()
	})
	return al, sink
}

func accessDecision(user string) AuditEvent {
	return AuditEvent{EventType: "authentication_success", UserID: user, Success: true}
}

// TestAStalledSinkFailsTheRecordRatherThanWaitingOnIt: the deadline is the whole
// point. A caller that is about to grant a login must get an answer about the
// record, and "the sink has not come back" has to arrive as an error rather than
// as silence.
func TestAStalledSinkFailsTheRecordRatherThanWaitingOnIt(t *testing.T) {
	const timeout = 100 * time.Millisecond
	al, sink := stalledLogger(t, timeout)

	start := time.Now()
	err := al.LogAuthEventErr(accessDecision("alice"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("LogAuthEventErr reported success for a record no sink has accepted; " +
			"a caller deciding whether to grant a login on this answer would grant it")
	}
	if elapsed < timeout {
		t.Errorf("returned after %s, before the %s deadline; the record may not have been offered at all",
			elapsed, timeout)
	}
	// Two seconds is far below auditWriteTimeout and far above the deadline this
	// logger was given, so it distinguishes "the deadline was enforced" from "the
	// hardcoded five seconds elapsed".
	if elapsed > 2*time.Second {
		t.Errorf("returned after %s; the configured deadline of %s was not what ended the wait",
			elapsed, timeout)
	}
	if n := sink.attempts(); n != 1 {
		t.Errorf("the sink saw %d writes, want 1; the test cannot tell a stalled write from an unattempted one", n)
	}
}

// TestOnceTheSinksHaveStalledLaterRecordsFailImmediately: nothing can abort an
// fsync in progress, so after the deadline fires that goroutine is still stuck,
// still holding writeMu. Without the stalled flag every later record would queue
// behind it and wait out the full deadline again — five seconds each, serialized,
// on the authentication path — to arrive at the same answer.
func TestOnceTheSinksHaveStalledLaterRecordsFailImmediately(t *testing.T) {
	const timeout = 200 * time.Millisecond
	al, sink := stalledLogger(t, timeout)

	if err := al.LogAuthEventErr(accessDecision("alice")); err == nil {
		t.Fatal("the first record did not fail; the rest of this test assumes the sinks are known stalled")
	}

	start := time.Now()
	err := al.LogAuthEventErr(accessDecision("bob"))
	elapsed := time.Since(start)

	if err == nil {
		t.Error("a record was reported written while the sinks are known not to be draining")
	}
	// The load-bearing assertion, and the one that does not depend on timing: the
	// second record was never handed to a sink that has already failed to take one.
	if n := sink.attempts(); n != 1 {
		t.Errorf("the sink saw %d writes, want 1; the second record queued behind a write that has not returned", n)
	}
	if elapsed >= timeout {
		t.Errorf("the second record took %s, at least as long as the %s deadline; it waited rather than failing fast",
			elapsed, timeout)
	}
}

// TestASinkThatComesBackClearsTheStall is the other half: a mount that recovers
// must not leave the audit trail permanently refused. The stalled state names the
// write that overran, so it stops being true as soon as that write comes back and
// the next record is written normally.
func TestASinkThatComesBackClearsTheStall(t *testing.T) {
	al, sink := stalledLogger(t, 100*time.Millisecond)

	if err := al.LogAuthEventErr(accessDecision("alice")); err == nil {
		t.Fatal("the first record did not fail; the rest of this test assumes the sinks are known stalled")
	}

	sink.unblock()

	deadline := time.Now().Add(5 * time.Second)
	for al.sinksStalled() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if al.sinksStalled() {
		t.Fatal("the sink returned but the logger is still refusing records")
	}

	if err := al.LogAuthEventErr(accessDecision("bob")); err != nil {
		t.Errorf("LogAuthEventErr = %v on a sink that is working again, want nil", err)
	}
	if n := sink.attempts(); n != 2 {
		t.Errorf("the sink saw %d writes, want 2", n)
	}
}
