package ipc

import (
	"strconv"
	"sync"
	"time"
)

// unknownPeerKey is the bucket every caller whose UID could not be determined
// shares. It is deliberately not a numeric UID string, so it cannot collide
// with a real caller — unlike "0", which is root's actual UID and which this
// code used to hand to unidentifiable peers.
//
// Sharing one bucket is a deliberate trade: it over-limits (one slow caller can
// exhaust the window for all of them) rather than under-limits. Peer credentials
// are available on every platform the broker is deployed on, so in practice this
// bucket stays empty; see peerCredsSupported.
const unknownPeerKey = "uid:unknown"

// callerKey is the rate-limit bucket for a connection's peer.
//
// Note what this can and cannot bound. Every PAM caller on the host is sshd
// running as root, so in a real deployment every authenticate request lands in
// bucket "uid:0" — this limits the host, not an individual attacker. It is a
// backstop against a runaway or looping client, not the control that stops a
// remote flood; sshd's MaxStartups bounds concurrent pre-auth connections, and
// the broker's own max_concurrent_auths and per-user pending-flow cap bound the
// work each one can create. See the rate_limiting notes in configs/example.yaml.
func callerKey(uid uint32, known bool) string {
	if !known {
		return unknownPeerKey
	}
	return "uid:" + strconv.FormatUint(uint64(uid), 10)
}

// sessionKey is the rate-limit bucket for operations on an existing session.
//
// Polling is bucketed per session rather than per caller because a poll's cost
// is attributable to one login, and because the per-caller bucket cannot
// separate two logins that are both sshd. Charging polls to "uid:0" made one
// in-progress login consume the whole host's budget: at a 5s interval a single
// login spends 12 requests a minute, so a handful of concurrent logins hit the
// default ceiling and the next poll came back RATE_LIMITED, which the module
// treated as terminal and the login died.
func sessionKey(sessionID string) string {
	return "session:" + sessionID
}

// rateLimiter is a per-key sliding-window counter.
type rateLimiter struct {
	mu      sync.Mutex
	windows map[string]*rateWindow
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
		windows: make(map[string]*rateWindow),
		maxRPM:  maxRPM,
	}
}

// allow returns true if the given bucket is within the rate limit.
func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	w, ok := rl.windows[key]
	if !ok || now.After(w.resetAt) {
		rl.windows[key] = &rateWindow{count: 1, resetAt: now.Add(time.Minute)}
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
	for key, w := range rl.windows {
		if now.After(w.resetAt) {
			delete(rl.windows, key)
		}
	}
}
