package security

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Opening the audit file the way every other file in this tree is opened — #106.
//
// Before this, newFileOutput was the only open in the tree with no O_NOFOLLOW, no
// mode check and no directory check: pkg/config/secrets.go, pkg/config/config.go
// and pkg/enrollment/store.go all have the three. It was also the only one that
// *creates* a file, as root.
//
// What the three buy here is specific to what this sink is for. A symlink at
// cfg.Path pointing at /dev/null makes every critical write succeed, so
// LogAuthEventErr returns nil, the login is granted, and the trail is empty — the
// fail-closed guarantee satisfied vacuously, which is the one failure mode of an
// audit sink that nothing downstream can detect. O_CREAT|O_APPEND as root through
// an unfollowed symlink is also an append to a file of somebody else's choosing;
// records are single-line JSON so line injection into a file like cron.d is not
// available, but disk-fill is.
//
// The reach is narrow under the shipped packaging — configs/systemd's
// LogsDirectory is root:root 0750, and only root can plant a symlink in it, and
// root can rewrite broker.yaml anyway. The check is here because "only root can do
// it" was not accepted as an answer for the client secret, the mapper script or the
// enrollment file, and an audit trail that can be silently voided is not the field
// to start accepting it for.

// auditFileMask is the permission bits the audit file may not have: write for
// group or other.
//
// Read is deliberately absent, which is where this differs from pkg/config's rule
// for a client secret (0o077) and matches pkg/enrollment's for the enrollment file
// (0o022). A group-readable trail is a disclosure — it names local accounts,
// provider logins and email addresses — but refusing to open one would refuse every
// login on the host, because a critical record that cannot be written denies the
// login it describes. Fail-closed makes an over-strict check on this path an
// outage, and an outage is a worse answer to a disclosure than the disclosure.
// Write is not a disclosure: it is the authority to forge or erase the record of an
// access decision.
const auditFileMask fs.FileMode = 0o022

// auditDirMask is the permission bits the directory holding the audit file may not
// have. The same bits, for the stronger reason pkg/enrollment gives: a directory is
// write authority over every name in it, so a writable directory means the file can
// be replaced — or, since this open creates, that the name can be a symlink before
// the broker ever gets there.
const auditDirMask fs.FileMode = 0o022

// openAuditFile opens (creating if needed) the audit file at path, refusing a
// symlink, a non-regular file, a file another local user could write, and a
// directory another local user could write.
//
// The directory is checked first and by name, before the open, because this is the
// one path in the tree that creates its file: checking afterwards would mean
// creating a file in a directory this process has just decided it does not trust.
func openAuditFile(path string) (*os.File, error) {
	if err := checkAuditDirPerms(filepath.Dir(path)); err != nil {
		return nil, err
	}

	// O_NOFOLLOW refuses a symlink in the same syscall as the open, rather than
	// leaving a window in which one could appear between a check and the open (#96,
	// #106). With O_CREAT the window matters more here than anywhere else: the file
	// need not exist yet, so the name is one somebody else could reach first.
	//
	// O_NONBLOCK is for the FIFO case and is explained where it is defined — without
	// it, a FIFO at this path hangs the open and the regular-file check below never
	// runs.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|oNoFollow|oNonBlock, 0600) // #nosec G304 -- path comes from the broker's own root-owned config
	if err != nil {
		// Both flags report something other than what they refused: O_NOFOLLOW gives
		// ELOOP, whose message describes a symbolic-link loop that is not there, and
		// O_NONBLOCK on a readerless FIFO gives ENXIO, "device not configured". An
		// operator debugging either message looks for the wrong thing, so say what is
		// actually wrong. Lstat, not Stat: a symlink has to be reported as itself.
		if fi, lerr := os.Lstat(path); lerr == nil {
			if fi.Mode()&fs.ModeSymlink != 0 {
				return nil, auditSymlinkError(path)
			}
			if !fi.Mode().IsRegular() {
				return nil, notARegularAuditFileError(path, fi.Mode())
			}
		}
		return nil, fmt.Errorf("open audit file %s: %w", path, err)
	}

	// Stat the open descriptor, not the path: what was checked has to be the same
	// inode that is then written to, and a stat by name can be answered by one file
	// and the writes served by another.
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat audit file %s: %w", path, err)
	}
	if err := checkAuditFilePerms(path, info); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// checkAuditFilePerms refuses an audit file that is not a regular file, or that
// another local user could write.
//
// Non-regular is its own case and not a pedantic one: a FIFO at this path blocks
// the first critical write until something opens the read end, and since a critical
// record is written on the login's own goroutine that is a login that never
// returns. A character device — /dev/null being the obvious one — accepts every
// write and keeps nothing, which is the vacuous fail-closed above.
func checkAuditFilePerms(path string, info fs.FileInfo) error {
	// Reachable when info came from Lstat; never when it came from a descriptor
	// opened with O_NOFOLLOW. Kept for the same reason the other two copies keep it:
	// the mode and owner that matter for a symlink would be the target's, and the
	// target can be changed, by whoever owns the directory holding the link, without
	// touching anything this function looked at.
	if info.Mode()&fs.ModeSymlink != 0 {
		return auditSymlinkError(path)
	}
	if !info.Mode().IsRegular() {
		return notARegularAuditFileError(path, info.Mode())
	}
	if perm := info.Mode().Perm(); perm&auditFileMask != 0 {
		return fmt.Errorf("%s is writable by group or other (mode %04o), so they can forge or erase "+
			"the record of an access decision; run: chmod 640 %s", path, perm, path)
	}
	// Ownership matters as much as the mode: a 0600 file owned by someone else is a
	// trail that user can rewrite whenever they like.
	if uid, ok := fileOwner(info); ok {
		if euid := os.Geteuid(); uid != 0 && uid != uint32(euid) { // #nosec G115 -- a uid fits a uid
			return fmt.Errorf("%s is owned by uid %d, which is neither root nor this process "+
				"(uid %d), so that user can rewrite the audit trail; run: chown root %s",
				path, uid, euid, path)
		}
	}
	return nil
}

// checkAuditDirPerms refuses a directory another local user could write to, and so
// could put a symlink or a device at the audit file's name before the broker opens
// it, or replace the file afterwards.
func checkAuditDirPerms(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat audit directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory, so %s cannot be created in it", dir, dir)
	}
	perm := info.Mode().Perm()
	// The sticky bit is the exception, and it is the reason /tmp can be shared: with
	// it set, only the owner of a file may rename or unlink it, which is the attack
	// the mode is being checked for. It does not stop another user creating a *new*
	// name — which is why O_NOFOLLOW and the regular-file check above are what
	// actually cover a relocated path under /tmp, and this exemption is not a hole.
	if perm&auditDirMask != 0 && info.Mode()&fs.ModeSticky == 0 {
		return fmt.Errorf("%s is writable by group or other (mode %04o), so the audit file in it can "+
			"be replaced whatever its own mode is; run: chmod 750 %s", dir, perm, dir)
	}
	// A directory owned by another user is writable by them whatever its mode says,
	// because they can chmod it.
	if uid, ok := fileOwner(info); ok {
		if euid := os.Geteuid(); uid != 0 && uid != uint32(euid) { // #nosec G115 -- a uid fits a uid
			return fmt.Errorf("%s is owned by uid %d, which is neither root nor this process "+
				"(uid %d), so that user can replace the audit file in it; run: chown root %s",
				dir, uid, euid, dir)
		}
	}
	return nil
}

// notARegularAuditFileError is shared by the two places that can notice: the open
// itself, when O_NONBLOCK turned a FIFO into an error, and the check on the open
// descriptor for everything that opens successfully. One message, so an operator
// gets the same explanation either way.
func notARegularAuditFileError(path string, mode fs.FileMode) error {
	return fmt.Errorf("%s is not a regular file (mode %s); an audit sink has to be a file that "+
		"keeps what is written to it — a device accepts records and discards them, which makes "+
		"every login appear audited and leaves no trail, and a FIFO blocks the login whose record "+
		"it is until something reads the other end", path, mode)
}

func auditSymlinkError(path string) error {
	return fmt.Errorf("%s is a symlink; name the file itself, so that the file whose permissions "+
		"are checked is the file the records are written to — a link to /dev/null makes every "+
		"write succeed and keeps no trail, which is the one audit failure nothing downstream "+
		"can detect", path)
}
