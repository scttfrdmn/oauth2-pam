//go:build linux

package ipc

import (
	"net"
	"syscall"
)

// peerUID returns the UID of the process that connected to a Unix socket.
// Used by the rate limiter to enforce per-user limits.
func peerUID(conn net.Conn) uint32 {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0
	}
	f, err := uc.File()
	if err != nil {
		return 0
	}
	defer f.Close()
	ucred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return 0
	}
	return ucred.Uid
}
