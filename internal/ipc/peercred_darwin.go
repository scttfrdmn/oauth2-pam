//go:build darwin

package ipc

import (
	"net"

	"golang.org/x/sys/unix"
)

// Darwin has no SO_PEERCRED. LOCAL_PEERCRED returns an xucred, which carries the
// effective UID of the peer at the time the socket was connected.
const peerCredsSupported = true

// peerUID returns the UID of the process that connected to a Unix socket, and
// whether that UID could be determined at all.
//
// The broker is not deployed on macOS — the PAM module is Linux-only — but it
// runs there for development, and a rate limiter that silently lumps every
// developer's requests into one bucket makes local testing lie about production.
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
