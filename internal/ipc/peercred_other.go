//go:build !linux

package ipc

import "net"

// peerUID returns 0 on non-Linux platforms.
// All callers share a single rate-limit bucket (UID 0).
func peerUID(_ net.Conn) uint32 { return 0 }
