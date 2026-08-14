//go:build linux

package ipc

import (
	"net"
	"syscall"
)

// peerCredsSupported records whether this platform can identify the process on
// the other end of a Unix socket. Logged once at startup, because a broker whose
// rate limiter cannot tell its callers apart should say so rather than look like
// one that can.
const peerCredsSupported = true

// peerUID returns the UID of the process that connected to a Unix socket, and
// whether that UID could be determined at all. The rate limiter buckets by the
// result; see unknownPeerKey for what happens when ok is false.
func peerUID(conn net.Conn) (uint32, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	f, err := uc.File()
	if err != nil {
		return 0, false
	}
	// uc.File() dups the descriptor, so this Close releases only the copy; the
	// connection itself is unaffected and the error has nowhere useful to go.
	defer func() { _ = f.Close() }()
	ucred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return 0, false
	}
	return ucred.Uid, true
}
