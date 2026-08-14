package enrollment

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// enrollmentFileMask is the permission bits the enrollment file may not have:
// write for group or other.
//
// Read is deliberately not on the list, and this is where the rule differs from
// the one pkg/config applies to a client secret. A group-readable enrollment file
// is a disclosure — it says which local account belongs to which provider
// identity, which is what aiming a device-flow phish at the right person needs —
// but refusing to load one would lock every enrolled user out of a host whose
// operator had chmodded it 0640, and an outage is a worse answer to a disclosure
// than the disclosure. Write is not a disclosure: it is the whole of tier 0's
// authority.
const enrollmentFileMask fs.FileMode = 0o022

// enrollmentDirMask is the permission bits the directory holding the enrollment
// file may not have. Same bits as the file's, and for a stronger reason: a
// directory is write authority over every name in it.
const enrollmentDirMask fs.FileMode = 0o022

// checkPerms refuses an enrollment file that another local user could rewrite.
//
// This is the same check pkg/config makes before reading a client secret, for a
// stronger version of the same reason. Tier 0 is the most authoritative mapping
// tier: it decides which provider identity owns which local account. So whoever
// can write this file chooses who logs in as whom — a 0620 file lets any member
// of its group add a record pointing their own provider login at anybody's Unix
// account, and the login that follows is indistinguishable from a real one.
//
// Save writes 0600 and owns the file, so a file that fails this check was put
// there or changed by something else, and that is exactly the case worth
// refusing.
func checkPerms(path string, info fs.FileInfo) error {
	// Reachable when info came from Lstat; never when it came from a descriptor
	// opened with O_NOFOLLOW. A symlink is refused rather than followed because the
	// mode and owner that matter would be the target's, and the target can be
	// changed — by whoever owns the directory holding the link — without touching
	// anything this check looked at (#96).
	if info.Mode()&fs.ModeSymlink != 0 {
		return symlinkError(path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&enrollmentFileMask != 0 {
		return fmt.Errorf("%s is writable by group or other (mode %04o), so they can choose which "+
			"provider identity owns a local account; run: chmod 600 %s", path, perm, path)
	}
	// Ownership matters as much as the mode: a 0600 file owned by someone else is
	// an enrollment file that user can rewrite whenever they like, which makes
	// them the one deciding who logs in as whom.
	if uid, ok := fileOwner(info); ok {
		if euid := os.Geteuid(); uid != 0 && uid != uint32(euid) { // #nosec G115 -- a uid fits a uid
			return fmt.Errorf("%s is owned by uid %d, which is neither root nor this process "+
				"(uid %d), so that user can rewrite the enrollments; run: chown root %s",
				path, uid, euid, path)
		}
	}
	// And the directory matters as much as the file, by the same argument as
	// pkg/config makes about a client secret: a 0600 root-owned file in a directory
	// another user can write cannot be modified, but it can be renamed out of the
	// way and replaced.
	//
	// The mode and owner checks above stop them installing a file of their own —
	// what they cannot forge is root's ownership. What the directory check stops is
	// the rollback (#96): with write access to the directory, an earlier root-owned
	// copy of this very file is theirs to put back. An operator's
	// enrolled-users.yaml.bak alongside it is enough, and it restores an enrollment
	// that was deliberately removed, or one that pointed a provider identity at a
	// different local account. Nothing above can tell that file from the current one,
	// because in every respect it checks it is the same file.
	return checkDirPerms(filepath.Dir(path))
}

// checkDirPerms refuses a directory another local user could write to, and so could
// replace the enrollment file inside.
func checkDirPerms(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	perm := info.Mode().Perm()
	// The sticky bit is the exception, and it is the reason /tmp can be shared: with
	// it set, only the owner of a file may rename or unlink it, which is exactly the
	// attack the mode is being checked for.
	if perm&enrollmentDirMask != 0 && info.Mode()&fs.ModeSticky == 0 {
		return fmt.Errorf("%s is writable by group or other (mode %04o), so the enrollment file in "+
			"it can be replaced with an older copy whatever its own mode is; run: chmod 750 %s",
			dir, perm, dir)
	}
	// A directory owned by another user is writable by them whatever its mode says,
	// because they can chmod it.
	if uid, ok := fileOwner(info); ok {
		if euid := os.Geteuid(); uid != 0 && uid != uint32(euid) { // #nosec G115 -- a uid fits a uid
			return fmt.Errorf("%s is owned by uid %d, which is neither root nor this process "+
				"(uid %d), so that user can replace the enrollment file in it; run: chown root %s",
				dir, uid, euid, dir)
		}
	}
	return nil
}

func symlinkError(path string) error {
	return fmt.Errorf("%s is a symlink; name the file itself, so that the file whose "+
		"permissions are checked is the file that is read", path)
}
