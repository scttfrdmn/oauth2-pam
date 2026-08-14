package enrollment

import (
	"fmt"
	"io/fs"
	"os"
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
	return nil
}
