//go:build unix

package security

import "syscall"

// oNoFollow makes an open fail rather than follow a symlink at the last path
// component. There is no portable spelling of it in the os package, for the same
// reason fileOwner needs a build-tagged file: not every platform has it.
//
// This is the third copy of these two lines — pkg/config has one for its secret
// files and pkg/enrollment one for the enrollment file. The masks the three
// packages apply genuinely differ (0o077 for a secret, 0o022 for the other two), so
// the checks are not one function with a parameter, but the syscall flag is. A
// fourth copy would be the point at which to extract an internal package; three,
// each two lines, is cheaper than a new dependency edge between packages that
// currently have none.
const oNoFollow = syscall.O_NOFOLLOW

// oNonBlock makes an open of a FIFO return rather than wait for a peer.
//
// It is here for one case, and the case is not hypothetical: an open of a FIFO for
// writing blocks until something opens the read end, so a FIFO at the audit path
// would hang the open — inside NewAuditLogger, before the broker has a socket, with
// no timeout anywhere. Without this flag the regular-file check in
// checkAuditFilePerms could never run on a FIFO, because the open it is meant to
// vet never returns.
//
// On a regular file the flag has no effect, which is what makes it safe to leave set
// for the lifetime of the descriptor: POSIX defines O_NONBLOCK's meaning for FIFOs,
// sockets and some devices, and regular-file reads and writes ignore it.
const oNonBlock = syscall.O_NONBLOCK
