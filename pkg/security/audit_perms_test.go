package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

// The audit sink's own file checks — #106.
//
// pkg/config and pkg/enrollment each have symlink and permission tests for their
// files. pkg/security had none, which is the other half of why this open went seven
// rounds without O_NOFOLLOW: every test here uses t.TempDir(), and a directory this
// process just created is never the directory the check is about.
//
// These go through NewAuditLogger rather than calling openAuditFile, because the
// statement worth making is about the broker: a sink it cannot trust stops it
// starting, rather than being accepted and quietly keeping nothing.

// startWithAuditPath builds a logger writing to path and returns the error.
func startWithAuditPath(t *testing.T, path string) error {
	t.Helper()
	al, err := NewAuditLogger(config.AuditConfig{
		Enabled: true,
		Outputs: []config.AuditOutput{{Type: "file", Path: path}},
	})
	if err == nil {
		t.Cleanup(func() { _ = al.Stop() })
	}
	return err
}

// TestASymlinkedAuditPathIsRefused. A link to /dev/null is the case that matters:
// every write to it succeeds, so LogAuthEventErr returns nil, every login is
// granted, and there is no trail. The fail-closed guarantee is satisfied vacuously,
// and nothing downstream can tell.
func TestASymlinkedAuditPathIsRefused(t *testing.T) {
	for name, target := range map[string]string{
		"a link to /dev/null":      os.DevNull,
		"a link to another file":   "", // filled in below, inside this test's dir
		"a link to nothing at all": "/nonexistent/audit.log",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if target == "" {
				target = filepath.Join(dir, "real.log")
				if err := os.WriteFile(target, nil, 0600); err != nil {
					t.Fatalf("write target: %v", err)
				}
			}
			link := filepath.Join(dir, "audit.log")
			if err := os.Symlink(target, link); err != nil {
				t.Fatalf("symlink: %v", err)
			}

			err := startWithAuditPath(t, link)
			if err == nil {
				t.Fatal("the broker started with a symlinked audit path; a link to /dev/null makes " +
					"every record appear written and keeps none")
			}
			// The message has to name the actual problem. O_NOFOLLOW reports ELOOP, whose
			// text describes a symbolic-link loop that is not there, and an operator
			// debugging that message looks for the wrong thing.
			if !strings.Contains(err.Error(), "symlink") {
				t.Errorf("err = %v, which does not say the path is a symlink", err)
			}
		})
	}
}

// TestAnAuditPathThatKeepsNothingIsRefused: /dev/null named directly, with no
// symlink involved. O_NOFOLLOW says nothing about this one — it is the regular-file
// check that does, and without it the sink is the same vacuous success.
func TestAnAuditPathThatKeepsNothingIsRefused(t *testing.T) {
	if _, err := os.Stat(os.DevNull); err != nil {
		t.Skipf("no %s on this platform", os.DevNull)
	}
	err := startWithAuditPath(t, os.DevNull)
	if err == nil {
		t.Fatal("the broker started with its audit trail pointed at /dev/null")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("err = %v, which does not say why a device is not a sink", err)
	}
}

// TestAnAuditFileOtherUsersCanWriteIsRefused. Write on the trail is the authority to
// forge or erase the record of an access decision, which outranks a start-up failure
// the operator can fix with one chmod.
func TestAnAuditFileOtherUsersCanWriteIsRefused(t *testing.T) {
	for name, mode := range map[string]os.FileMode{
		"group-writable": 0o660,
		"world-writable": 0o666,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			if err := os.WriteFile(path, nil, mode); err != nil {
				t.Fatalf("write: %v", err)
			}
			// WriteFile applies the umask, so the bits under test have to be set after it.
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			err := startWithAuditPath(t, path)
			if err == nil {
				t.Fatalf("the broker started with a %04o audit file", mode)
			}
			if !strings.Contains(err.Error(), "writable by group or other") {
				t.Errorf("err = %v, which does not say the mode is the problem", err)
			}
		})
	}
}

// TestAnAuditDirectoryOtherUsersCanWriteIsRefused. The directory is checked before
// the file is created, because this is the one open in the tree that creates its
// file: a name in a directory somebody else can write is a name they can get to
// first.
func TestAnAuditDirectoryOtherUsersCanWriteIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	path := filepath.Join(dir, "audit.log")
	err := startWithAuditPath(t, path)
	if err == nil {
		t.Fatal("the broker started with its audit file in a world-writable directory")
	}
	if !strings.Contains(err.Error(), "writable by group or other") {
		t.Errorf("err = %v, which does not say the directory is the problem", err)
	}
	// And it refused before creating anything: a file created in a directory this
	// process has decided it does not trust is a file it should not have made.
	if _, statErr := os.Lstat(path); statErr == nil {
		t.Error("the audit file was created in the directory that was then rejected")
	}
}

// TestAnOrdinaryAuditPathIsAccepted is the control, and it is the assertion that
// keeps this from being a fix that refuses real installations. Three shapes an
// operator really has:
//
//   - the shipped one: a fresh 0750 directory and a file that does not exist yet;
//   - a file already there from a previous run;
//   - a 0640 file, group-readable so that an operators group can tail it. Read is
//     deliberately allowed — refusing it would refuse every login on the host,
//     because a critical record that cannot be written denies the login it
//     describes, and an outage is a worse answer to a disclosure than the
//     disclosure.
func TestAnOrdinaryAuditPathIsAccepted(t *testing.T) {
	t.Run("a path that does not exist yet", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o750); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if err := startWithAuditPath(t, filepath.Join(dir, "audit.log")); err != nil {
			t.Fatalf("the shipped shape was refused: %v", err)
		}
	})

	for name, mode := range map[string]os.FileMode{
		"an existing 0600 file": 0o600,
		"an existing 0640 file": 0o640,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			if err := os.WriteFile(path, []byte("{}\n"), mode); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			if err := startWithAuditPath(t, path); err != nil {
				t.Fatalf("a %04o audit file was refused: %v", mode, err)
			}
		})
	}
}

// TestAStickyDirectoryIsAccepted: /tmp is 1777 and shared, and the sticky bit is why
// that is not a hole — with it set, only a file's owner may rename or unlink it.
// What it does not stop is another user creating a name the broker has not created
// yet, which is what O_NOFOLLOW and the regular-file check cover; the two tests
// above are the ones that hold for a relocated path under /tmp.
func TestAStickyDirectoryIsAccepted(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := startWithAuditPath(t, filepath.Join(dir, "audit.log")); err != nil {
		t.Fatalf("a sticky shared directory was refused: %v", err)
	}
}
