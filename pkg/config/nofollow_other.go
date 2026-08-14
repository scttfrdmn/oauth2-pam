//go:build !unix

package config

// oNoFollow has no equivalent on this platform, so an open cannot refuse a
// symlink and the Lstat in checkPerms is all there is: enough to reject a
// symlink that is already in place, not enough to win a race against one
// appearing between the check and the read. The broker is the counterpart of a
// PAM module and only ever runs on unix; this exists so the package still
// builds elsewhere, as fileowner_other.go does.
const oNoFollow = 0
