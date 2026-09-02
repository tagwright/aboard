// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
