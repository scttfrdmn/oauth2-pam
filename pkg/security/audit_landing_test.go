package security

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

// What a failed audit write actually tells the caller — #91.
//
// LogAuthEventErr's error was read by the broker as "no sink has this record", and
// it never meant that. Two of the three ways a write fails leave the record
// readable: every sink is attempted whatever the earlier ones did, so one broken
// output among several returns an error while the healthy ones hold the record; and
// a write that overran its deadline is still running, with fileOutput.Write having
// written the bytes before it reached the fsync it is stuck in.
//
// The caller refuses the login on that error. So on those two paths the trail keeps
// an authentication_success — byte-identical to a real grant — for a login that was
// refused, unless the caller is told the difference and corrects it.
//
// audit_test.go's TestAWriteFailureOnACriticalEventReachesTheCaller asserts the
// first half of this (err != nil while working.writes == 1) and frames the retained
// record as the desirable property, which it is. These tests are about the fact it
// leaves the caller needing.

func loggerWithSinks(t *testing.T, outputs ...AuditOutput) *AuditLogger {
	t.Helper()
	al, err := NewAuditLoggerWithOutputs(config.AuditConfig{Enabled: true}, outputs...)
	if err != nil {
		t.Fatalf("NewAuditLoggerWithOutputs: %v", err)
	}
	t.Cleanup(func() { _ = al.Stop() })
	return al
}

func criticalEvent() AuditEvent {
	return AuditEvent{EventType: "authentication_success", UserID: "alice", Success: true}
}

// TestAPartiallyWrittenRecordSaysSoToTheCaller: the ordinary multi-sink config —
// audit.outputs with a file and a syslog entry — and the audit filesystem fills.
// Every login now fails, correctly, and every one of them leaves a success record in
// syslog. A SIEM watching that stream sees a burst of successful authentications at
// the moment nobody could log in.
func TestAPartiallyWrittenRecordSaysSoToTheCaller(t *testing.T) {
	sinkErr := errors.New("no space left on device")
	broken := &failingOutput{err: sinkErr}
	working := &failingOutput{}
	al := loggerWithSinks(t, broken, working)

	err := al.LogAuthEventErr(criticalEvent())
	if err == nil {
		t.Fatal("LogAuthEventErr reported success for a record one sink refused")
	}
	if working.writes != 1 {
		t.Fatalf("the healthy sink saw %d writes, want 1: without a retained record there is nothing to report",
			working.writes)
	}
	if !RecordMayHaveLanded(err) {
		t.Errorf("err = %v reports the record as unwritten, but a sink accepted it; "+
			"a caller refusing the login on this error leaves that success as the trail's last word", err)
	}
	if !errors.Is(err, sinkErr) {
		t.Errorf("err = %v, want it to wrap the sink's error", err)
	}
}

// TestARecordNoSinkAcceptedIsNotReportedAsPossiblyLanded is the control. If the
// answer were "may have landed" whatever happened, the caller would write a
// correction for a record that does not exist — a session_revoked describing the
// withdrawal of a login the trail never claimed, which is its own false record.
func TestARecordNoSinkAcceptedIsNotReportedAsPossiblyLanded(t *testing.T) {
	t.Run("every sink refused it", func(t *testing.T) {
		al := loggerWithSinks(t,
			&failingOutput{err: errors.New("no space left on device")},
			&failingOutput{err: errors.New("connection refused")})

		err := al.LogAuthEventErr(criticalEvent())
		if err == nil {
			t.Fatal("LogAuthEventErr reported success for a record no sink accepted")
		}
		if RecordMayHaveLanded(err) {
			t.Errorf("err = %v claims the record may be readable; no sink accepted it", err)
		}
	})

	t.Run("it was never marshalled", func(t *testing.T) {
		al := loggerWithSinks(t, &failingOutput{})

		event := criticalEvent()
		// A channel has no JSON encoding. Metadata is map[string]interface{} and this
		// is the one failure that happens before any sink is reached.
		event.Metadata = map[string]interface{}{"unencodable": make(chan int)}

		err := al.LogAuthEventErr(event)
		if err == nil {
			t.Fatal("LogAuthEventErr reported success for an event it could not marshal")
		}
		if RecordMayHaveLanded(err) {
			t.Errorf("err = %v claims the record may be readable; it was never serialized", err)
		}
	})

	t.Run("the sinks had already stalled", func(t *testing.T) {
		al, sink := stalledLogger(t, 50*time.Millisecond)

		if err := al.LogAuthEventErr(criticalEvent()); err == nil {
			t.Fatal("the first record was accepted despite the sink never returning")
		}
		err := al.LogAuthEventErr(criticalEvent())
		if err == nil {
			t.Fatal("a record was accepted while the sinks were known not to be draining")
		}
		if sink.attempts() != 1 {
			t.Fatalf("the sink saw %d writes, want 1: the second record was offered to it after all",
				sink.attempts())
		}
		if RecordMayHaveLanded(err) {
			t.Errorf("err = %v claims the record may be readable; it was refused before any sink saw it", err)
		}
	})
}

// TestAStalledWriteSaysTheRecordMayHaveLanded is the case #87 was filed for, and the
// reason the answer cannot be inferred from "the caller got an error".
//
// Nothing aborts a write in progress. fileOutput.Write writes and then syncs, so on
// the motivating scenario — an fsync on a degraded disk or an unreachable hard NFS
// mount — the bytes are in the file, and readable by anything tailing it, some time
// before the deadline the caller gave up at.
func TestAStalledWriteSaysTheRecordMayHaveLanded(t *testing.T) {
	al, sink := stalledLogger(t, 50*time.Millisecond)

	err := al.LogAuthEventErr(criticalEvent())
	if err == nil {
		t.Fatal("LogAuthEventErr reported success for a write that never returned")
	}
	if sink.attempts() != 1 {
		t.Fatalf("the sink saw %d writes, want 1", sink.attempts())
	}
	if !RecordMayHaveLanded(err) {
		t.Errorf("err = %v reports the record as unwritten, but the write it timed out on is still running "+
			"and the sink already has the bytes", err)
	}
}

// boundaryOutput accepts writes and takes a settable time over them, so a test can
// aim them at the deadline.
type boundaryOutput struct {
	mu       sync.Mutex
	delay    time.Duration
	inFlight int
}

func (o *boundaryOutput) Write([]byte) error {
	o.mu.Lock()
	o.inFlight++
	delay := o.delay
	o.mu.Unlock()

	time.Sleep(delay)

	o.mu.Lock()
	o.inFlight--
	o.mu.Unlock()
	return nil
}

func (o *boundaryOutput) Close() error { return nil }

func (o *boundaryOutput) setDelay(d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.delay = d
}

func (o *boundaryOutput) quiet() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.inFlight == 0
}

// TestAWriteReturningAsItsDeadlineFiresDoesNotWedgeTheStalledFlag.
//
// The stalled flag is set by the deadline and cleared by the write that overran it.
// A write that returns in the same instant its deadline fires used to be declared
// stalled *after* it had cleared the flag — and a refused write spawns no goroutine
// to clear it, so the flag stayed set and every record after it was refused for the
// life of the process. Fail-closed forever is a broker that grants no logins at all,
// out of one write that was a few microseconds late.
//
// The interleaving cannot be forced from outside, so this aims a few hundred writes
// at the boundary and then asserts the invariant on a quiescent logger, where the
// answer is not a matter of timing: with no write outstanding, nothing is stalled.
func TestAWriteReturningAsItsDeadlineFiresDoesNotWedgeTheStalledFlag(t *testing.T) {
	const timeout = 2 * time.Millisecond

	sink := &boundaryOutput{}
	al := loggerWithSinks(t, sink)
	al.testWriteTimeout = timeout

	// Straddling rather than matching the deadline: sleep granularity is coarse
	// enough that only some of these land on the wrong side of it.
	jitter := []time.Duration{timeout - 200*time.Microsecond, timeout, timeout + 200*time.Microsecond}
	for i := 0; i < 300; i++ {
		sink.setDelay(jitter[i%len(jitter)])
		_ = al.LogAuthEventErr(criticalEvent())
	}

	sink.setDelay(0)
	deadline := time.Now().Add(2 * time.Second)
	for !sink.quiet() {
		if time.Now().After(deadline) {
			t.Fatal("a write was still outstanding two seconds after the last one was issued")
		}
		time.Sleep(time.Millisecond)
	}

	if al.stalled.Load() {
		t.Error("no write is outstanding and the logger still considers its sinks stalled; " +
			"every later record will be refused for the life of the process")
	}
	if err := al.LogAuthEventErr(criticalEvent()); err != nil {
		t.Errorf("a record offered to an idle, healthy sink was refused: %v", err)
	}
}
