//go:build freebsd

package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

// FreeBSD spells it LOCAL_PEERCRED too, with its own xucred layout; x/sys/unix
// hides the difference.
const peerCredsSupported = true

// peerUID returns the UID of the process that connected to a Unix socket, and
// whether that UID could be determined at all.
func peerUID(conn net.Conn) (uint32, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	f, err := uc.File()
	if err != nil {
		return 0, false
	}
	// uc.File() dups the descriptor; closing the copy leaves the connection open.
	defer func() { _ = f.Close() }()
	cred, err := unix.GetsockoptXucred(int(f.Fd()), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, false
	}
	return cred.Uid, true
}
