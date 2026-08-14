//go:build unix

package security

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestAFifoAuditPathIsRefused. The other half of the regular-file check, and the
// worse half operationally: a critical record is written and fsynced on the login's
// own goroutine, so a FIFO with nothing reading it does not lose the record — it
// blocks the login, and every login after it, for as long as the pipe is full.
//
// Tagged unix because mkfifo is; the check it exercises is not.
func TestAFifoAuditPathIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}

	// Behind a timeout because the failure mode of removing O_NONBLOCK is a hang, not
	// a wrong answer: an open of a FIFO for writing waits for a reader, and there is
	// no deadline anywhere between here and NewAuditLogger's caller. A test that hung
	// would take the whole package down with the 10-minute panic and name the wrong
	// test as the cause.
	done := make(chan error, 1)
	go func() { done <- startWithAuditPath(t, path) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the broker started with its audit trail pointed at a FIFO")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("err = %v, which does not say why a FIFO is not a sink", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("opening the FIFO blocked: the open is waiting for a reader, so a broker configured " +
			"this way never finishes starting")
	}
}
