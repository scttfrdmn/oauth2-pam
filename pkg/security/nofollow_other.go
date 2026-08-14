//go:build !unix

package security

// oNoFollow has no equivalent on this platform, so the open cannot refuse a symlink
// and the checks in checkAuditFilePerms are all there is: enough to reject a symlink
// already in place, not enough to win a race against one appearing between the check
// and the write. The broker is the counterpart of a PAM module and only ever runs on
// unix; this exists so the package still builds elsewhere, as fileowner_other.go
// does.
const oNoFollow = 0

// oNonBlock likewise has no equivalent here. A platform without O_NONBLOCK is a
// platform without the FIFO semantics that make it necessary.
const oNonBlock = 0
