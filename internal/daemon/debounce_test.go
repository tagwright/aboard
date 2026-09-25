// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pendingCount reports how many keys are waiting to flush. It is the coalescing
// invariant the tests below assert against (N rapid events for one key leave
// exactly one pending entry, not N), and it is used only by those tests, so it
// lives here rather than in the production file the deadcode gate roots at.
func (d *debouncer) pendingCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pending)
}

// TestDebounceCoalescesBurst proves a rapid burst for one service collapses to a
// single flush carrying the LATEST container id, which is how a force-recreate's
// die-plus-start settles into one reconcile of the live container.
func TestDebounceCoalescesBurst(t *testing.T) {
	var flushes int32
	var mu sync.Mutex
	var lastKey, lastID string

	deb := newDebouncer(30*time.Millisecond, func(key, id string) {
		atomic.AddInt32(&flushes, 1)
		mu.Lock()
		lastKey, lastID = key, id
		mu.Unlock()
	})

	deb.observe("nutrition", "id-old")
	deb.observe("nutrition", "id-mid")
	deb.observe("nutrition", "id-new")

	// Inside the window: exactly one pending entry, no flush yet.
	if got := deb.pendingCount(); got != 1 {
		t.Fatalf("pending = %d during burst, want 1 (coalesced)", got)
	}
	if got := atomic.LoadInt32(&flushes); got != 0 {
		t.Fatalf("flushes = %d during window, want 0", got)
	}

	time.Sleep(120 * time.Millisecond)

	if got := atomic.LoadInt32(&flushes); got != 1 {
		t.Fatalf("flushes = %d after window, want exactly 1", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if lastKey != "nutrition" || lastID != "id-new" {
		t.Fatalf("flushed (%s,%s), want (nutrition,id-new): the latest id must win", lastKey, lastID)
	}
}

// TestDebounceSeparateKeys proves distinct services debounce independently: two
// keys yield two pending entries and two flushes.
func TestDebounceSeparateKeys(t *testing.T) {
	var flushes int32
	deb := newDebouncer(20*time.Millisecond, func(_, _ string) {
		atomic.AddInt32(&flushes, 1)
	})

	deb.observe("app-a", "a")
	deb.observe("app-b", "b")

	if got := deb.pendingCount(); got != 2 {
		t.Fatalf("pending = %d, want 2 distinct keys", got)
	}
	time.Sleep(100 * time.Millisecond)
	if got := atomic.LoadInt32(&flushes); got != 2 {
		t.Fatalf("flushes = %d, want 2", got)
	}
}

// TestDebounceFlushNowFiresPending proves the graceful-shutdown flush: flushNow
// fires every pending key immediately with its LATEST id, bypassing the quiet
// window, and empties the pending set, so a settled-but-not-yet-elapsed change is
// reconciled rather than dropped on the way out. A long window guarantees the
// timer cannot fire on its own inside the test, so any flush observed is flushNow.
func TestDebounceFlushNowFiresPending(t *testing.T) {
	var flushes int32
	var mu sync.Mutex
	fired := map[string]string{}

	deb := newDebouncer(10*time.Second, func(key, id string) {
		atomic.AddInt32(&flushes, 1)
		mu.Lock()
		fired[key] = id
		mu.Unlock()
	})

	deb.observe("app-a", "a-old")
	deb.observe("app-a", "a-new") // coalesces; latest id must win
	deb.observe("app-b", "b1")

	if got := deb.pendingCount(); got != 2 {
		t.Fatalf("pending = %d before flush, want 2", got)
	}

	deb.flushNow()

	if got := atomic.LoadInt32(&flushes); got != 2 {
		t.Fatalf("flushes = %d after flushNow, want 2 (both pending keys fired)", got)
	}
	if got := deb.pendingCount(); got != 0 {
		t.Fatalf("pending = %d after flushNow, want 0 (drained)", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if fired["app-a"] != "a-new" {
		t.Fatalf("flushed app-a with id %q, want a-new (the latest id must win)", fired["app-a"])
	}
	if fired["app-b"] != "b1" {
		t.Fatalf("flushed app-b with id %q, want b1", fired["app-b"])
	}
}

// TestDebounceFlushNowAfterStopIsNoop proves a stray flushNow after stop cannot
// resurrect work into a closing queue: once stopped, flushNow fires nothing.
func TestDebounceFlushNowAfterStopIsNoop(t *testing.T) {
	var flushes int32
	deb := newDebouncer(10*time.Second, func(_, _ string) {
		atomic.AddInt32(&flushes, 1)
	})
	deb.observe("app", "id")
	deb.stop()
	deb.flushNow()
	if got := atomic.LoadInt32(&flushes); got != 0 {
		t.Fatalf("flushes = %d, want 0 (flushNow after stop must be a no-op)", got)
	}
}

// TestDebounceStopDropsPending proves shutdown discards in-flight debounces
// rather than firing a burst into a closing queue.
func TestDebounceStopDropsPending(t *testing.T) {
	var flushes int32
	deb := newDebouncer(20*time.Millisecond, func(_, _ string) {
		atomic.AddInt32(&flushes, 1)
	})
	deb.observe("app", "id")
	deb.stop()
	time.Sleep(60 * time.Millisecond)
	if got := atomic.LoadInt32(&flushes); got != 0 {
		t.Fatalf("flushes = %d after stop, want 0 (pending dropped)", got)
	}
	if got := deb.pendingCount(); got != 0 {
		t.Fatalf("pending = %d after stop, want 0", got)
	}
}
