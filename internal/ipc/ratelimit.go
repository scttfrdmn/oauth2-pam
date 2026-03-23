package ipc

import (
	"sync"
	"time"
)

// rateLimiter is a per-caller sliding-window counter.
// Callers are identified by their Unix UID (obtained via SO_PEERCRED on Linux;
// UID 0 is used as a shared bucket on other platforms).
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
