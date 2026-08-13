package ipc

import (
	"math"
	"sync"
	"time"
)

// unknownPeerBucket is the bucket every caller whose UID could not be determined
// shares. (uid_t)-1 is not a valid UID on any supported platform, so it cannot
// collide with a real one — unlike 0, which is root's actual UID and which this
// code used to hand to unidentifiable peers.
//
// Sharing one bucket is a deliberate trade: it over-limits (one slow caller can
// exhaust the window for all of them) rather than under-limits. Peer credentials
// are available on every platform the broker is deployed on, so in practice this
// bucket stays empty; see peerCredsSupported.
const unknownPeerBucket uint32 = math.MaxUint32

// rateLimiter is a per-caller sliding-window counter.
// Callers are identified by their Unix UID, obtained from the socket's peer
// credentials; those that cannot be identified share unknownPeerBucket.
type rateLimiter struct {
	mu      sync.Mutex
	windows map[uint32]*rateWindow
	maxRPM  int
}

type rateWindow struct {
	count   int
	resetAt time.Time
}

func newRateLimiter(maxRPM int) *rateLimiter {
	if maxRPM <= 0 {
		maxRPM = 60
	}
	return &rateLimiter{
		windows: make(map[uint32]*rateWindow),
		maxRPM:  maxRPM,
	}
}

// allow returns true if the caller identified by uid is within the rate limit.
func (rl *rateLimiter) allow(uid uint32) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	w, ok := rl.windows[uid]
	if !ok || now.After(w.resetAt) {
		rl.windows[uid] = &rateWindow{count: 1, resetAt: now.Add(time.Minute)}
		return true
	}
	if w.count >= rl.maxRPM {
		return false
	}
	w.count++
	return true
}

// evict removes stale windows to prevent unbounded map growth.
// Call periodically (e.g. from a background goroutine).
func (rl *rateLimiter) evict() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for uid, w := range rl.windows {
		if now.After(w.resetAt) {
			delete(rl.windows, uid)
		}
	}
}
