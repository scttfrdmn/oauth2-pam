package ipc

import (
	"fmt"
	"testing"
	"time"
)

// windowCount is the number of live map entries, read under the lock.
func (rl *rateLimiter) windowCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.windows)
}

// stale ages a key's window so it counts as elapsed, instead of sleeping a minute.
func (rl *rateLimiter) stale(t *testing.T, key string) {
	t.Helper()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	w, ok := rl.windows[key]
	if !ok {
		t.Fatalf("no window for key %q to age", key)
	}
	w.resetAt = time.Now().Add(-time.Second)
}

// TestRateLimiterRefusesNewKeysAtTheCap is the boundary in both directions: the
// last key that fits is admitted, the first that does not is refused, and the
// refusal does not leave an entry behind. Without a cap this limiter allocates a
// window for every key it is ever shown, which is how an invented session ID
// bought permanent broker memory.
func TestRateLimiterRefusesNewKeysAtTheCap(t *testing.T) {
	const keyCap = 4
	rl := newBoundedRateLimiter(10, keyCap)

	for i := 0; i < keyCap; i++ {
		key := fmt.Sprintf("session:%d", i)
		if !rl.allow(key) {
			t.Fatalf("key %d of %d denied, want allowed below the cap", i+1, keyCap)
		}
	}
	if got := rl.windowCount(); got != keyCap {
		t.Fatalf("windows = %d after %d distinct keys, want %d", got, keyCap, keyCap)
	}

	if rl.allow("session:one-too-many") {
		t.Error("a new key was admitted at the cap; the map still grows without bound")
	}
	if got := rl.windowCount(); got != keyCap {
		t.Errorf("windows = %d after a refused key, want %d — the refusal allocated anyway", got, keyCap)
	}
}

// TestRateLimiterCapDoesNotRefuseAKeyItAlreadyHolds: the cap must bound growth,
// not start failing established buckets. A full map is not a reason to refuse an
// in-flight login's next poll.
func TestRateLimiterCapDoesNotRefuseAKeyItAlreadyHolds(t *testing.T) {
	const keyCap = 2
	rl := newBoundedRateLimiter(10, keyCap)

	if !rl.allow("session:a") || !rl.allow("session:b") {
		t.Fatal("filling the map to the cap was refused")
	}
	if rl.allow("session:c") {
		t.Fatal("a third key was admitted at a cap of 2")
	}

	// session:a is established, so it keeps its budget while the map is full.
	for i := 0; i < 5; i++ {
		if !rl.allow("session:a") {
			t.Fatalf("request %d for an established key was refused because the map is full", i+2)
		}
	}
	// And its own per-minute limit still applies: 6 of 10 spent above.
	for i := 0; i < 4; i++ {
		if !rl.allow("session:a") {
			t.Fatalf("request %d for an established key was refused below maxRPM", i+7)
		}
	}
	if rl.allow("session:a") {
		t.Error("an established key exceeded maxRPM")
	}
}

// TestRateLimiterCapEvictsStaleWindowsBeforeRefusing: reaching the cap is usually
// a sign the map is full of expired windows, so the honest room is taken first.
// Otherwise the cap would wedge the limiter shut until the next eviction tick.
func TestRateLimiterCapEvictsStaleWindowsBeforeRefusing(t *testing.T) {
	const keyCap = 3
	rl := newBoundedRateLimiter(10, keyCap)

	for i := 0; i < keyCap; i++ {
		if !rl.allow(fmt.Sprintf("session:%d", i)) {
			t.Fatalf("key %d denied below the cap", i)
		}
	}
	if rl.allow("session:blocked") {
		t.Fatal("a new key was admitted with the map full of live windows")
	}

	rl.stale(t, "session:1")

	if !rl.allow("session:new") {
		t.Error("a new key was refused although a stale window could have made room")
	}
	if got := rl.windowCount(); got > keyCap {
		t.Errorf("windows = %d, want at most the cap %d", got, keyCap)
	}
	rl.mu.Lock()
	_, staleStillThere := rl.windows["session:1"]
	rl.mu.Unlock()
	if staleStillThere {
		t.Error("the stale window survived; room was made some other way")
	}
}

// TestRateLimiterRenewalDoesNotConsumeCapacity: an existing key whose window has
// elapsed is renewed in place. It does not grow the map, so the cap must not
// refuse it even when the map is full.
func TestRateLimiterRenewalDoesNotConsumeCapacity(t *testing.T) {
	rl := newBoundedRateLimiter(1, 1)

	if !rl.allow("session:a") {
		t.Fatal("first request denied")
	}
	if rl.allow("session:a") {
		t.Fatal("second request in the same window allowed")
	}

	rl.stale(t, "session:a")

	if !rl.allow("session:a") {
		t.Error("a renewal was refused by the key cap, though it allocates nothing")
	}
	if got := rl.windowCount(); got != 1 {
		t.Errorf("windows = %d after a renewal, want 1", got)
	}
}

// TestRateLimiterWithoutACapIsUnbounded pins that the caller limiter is
// unaffected: its key space is the host's UIDs, so a cap there could only refuse
// a real caller.
func TestRateLimiterWithoutACapIsUnbounded(t *testing.T) {
	rl := newRateLimiter(10)
	if rl.maxKeys != 0 {
		t.Fatalf("newRateLimiter set maxKeys = %d, want 0 (unbounded)", rl.maxKeys)
	}
	for i := 0; i < 500; i++ {
		if !rl.allow(fmt.Sprintf("uid:%d", i)) {
			t.Fatalf("uncapped limiter refused key %d", i)
		}
	}
	if got := rl.windowCount(); got != 500 {
		t.Errorf("windows = %d, want 500", got)
	}
}

func TestBoundedRateLimiterNormalisesItsArguments(t *testing.T) {
	rl := newBoundedRateLimiter(0, -1)
	if rl.maxRPM != 60 {
		t.Errorf("maxRPM = %d, want the 60 default", rl.maxRPM)
	}
	if rl.maxKeys != 0 {
		t.Errorf("maxKeys = %d, want 0 for a negative cap", rl.maxKeys)
	}
}

// TestRateLimiterHasLiveWindow covers the predicate allowRequest uses to tell an
// established bucket from one it is about to allocate. Getting this wrong in
// either direction is a live bug: true for an unknown key means an invented
// session ID is never charged, false for a known one means every poll is.
func TestRateLimiterHasLiveWindow(t *testing.T) {
	rl := newRateLimiter(10)

	if rl.hasLiveWindow("session:a") {
		t.Error("hasLiveWindow is true for a key never seen")
	}
	if !rl.allow("session:a") {
		t.Fatal("first request denied")
	}
	if !rl.hasLiveWindow("session:a") {
		t.Error("hasLiveWindow is false for a key that has a live window")
	}

	rl.stale(t, "session:a")
	if rl.hasLiveWindow("session:a") {
		t.Error("hasLiveWindow is true for an elapsed window, which allow() must reallocate")
	}
	// Asking must not itself allocate.
	if got := rl.windowCount(); got != 1 {
		t.Errorf("windows = %d, want 1: hasLiveWindow allocated", got)
	}
	if rl.hasLiveWindow("session:never-seen") {
		t.Error("hasLiveWindow is true for a second unknown key")
	}
	if got := rl.windowCount(); got != 1 {
		t.Errorf("windows = %d after asking about an unknown key, want 1", got)
	}
}
