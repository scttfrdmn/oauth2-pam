//go:build !linux && !darwin && !freebsd

package ipc

import "net"

// No peer-credential mechanism on this platform, so the rate limiter cannot tell
// two callers apart. It falls back to one shared bucket and the broker says so at
// startup — see unknownPeerBucket.
const peerCredsSupported = false

// peerUID cannot identify the peer here, and says so rather than guessing.
//
// It used to return 0 unconditionally on every non-Linux platform, which meant
// every unidentifiable caller was attributed to root: both under-limited (one
// bucket for all of them) and mislabelled in the logs.
func peerUID(_ net.Conn) (uint32, bool) { return 0, false }
