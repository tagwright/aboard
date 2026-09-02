// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"sync"
	"time"
)

// debouncer coalesces rapid lifecycle events per stable service identity into a
// single deferred flush. A `docker compose up --force-recreate` fires a die and
// then a start for the same service within milliseconds, and acting on each raw
// event would thrash Authentik objects (create, detach, re-create) for what is
// really one settled change. The debouncer waits for a quiet window to elapse
// with no further event for a key, then fires once with the most recent
// container id observed for that key.
//
// It is deliberately simple and independently testable: observe records the
// latest id and (re)arms a per-key timer; the pending map holds exactly one
// entry per in-flight key, so coalescing is observable without waiting on a
// clock. onFlush is invoked from a timer goroutine, so it must be safe to call
// without a context (it enqueues onto the serial queue, which supplies the
// worker's context when the job actually runs).
type debouncer struct {
	window  time.Duration
	onFlush func(key, id string)

	mu      sync.Mutex
	timers  map[string]*time.Timer
	pending map[string]string
	stopped bool
}

// newDebouncer builds a debouncer with the given quiet window and flush callback.
func newDebouncer(window time.Duration, onFlush func(key, id string)) *debouncer {
	return &debouncer{
		window:  window,
		onFlush: onFlush,
		timers:  map[string]*time.Timer{},
		pending: map[string]string{},
	}
}

// observe records a lifecycle event for key naming container id, coalescing it
// with any other event for the same key inside the quiet window. The latest id
// wins, so a force-recreate's start (the live container) supersedes the die's
// dead one. Each observe resets the key's timer, so the flush fires only once
// the churn settles.
func (d *debouncer) observe(key, id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return
	}
	d.pending[key] = id
	if t := d.timers[key]; t != nil {
		t.Stop()
	}
	d.timers[key] = time.AfterFunc(d.window, func() { d.fire(key) })
}

// fire flushes one key: it reads and clears the pending id under the lock, then
// invokes onFlush outside the lock so the callback can enqueue freely. A key
// with no pending entry (a stopped or already-fired timer) is a no-op.
func (d *debouncer) fire(key string) {
	d.mu.Lock()
	id, ok := d.pending[key]
	if !ok || d.stopped {
		d.mu.Unlock()
		return
	}
	delete(d.pending, key)
	delete(d.timers, key)
	d.mu.Unlock()

	d.onFlush(key, id)
}

// pendingCount reports how many keys are waiting to flush. It is the coalescing
// invariant a test asserts against: N rapid events for one key leave exactly one
// pending entry, not N.
func (d *debouncer) pendingCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pending)
}

// flushNow fires every pending key immediately, bypassing the timers. It gives a
// test a deterministic way to drain the debouncer without sleeping on the clock,
// and it is used at shutdown by stop's callers only through the timers.
func (d *debouncer) flushNow() {
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		return
	}
	keys := make([]string, 0, len(d.pending))
	ids := make([]string, 0, len(d.pending))
	for k, id := range d.pending {
		keys = append(keys, k)
		ids = append(ids, id)
	}
	for _, k := range keys {
		if t := d.timers[k]; t != nil {
			t.Stop()
		}
		delete(d.timers, k)
		delete(d.pending, k)
	}
	d.mu.Unlock()

	for i, k := range keys {
		d.onFlush(k, ids[i])
	}
}

// stop halts every armed timer and blocks further observes. Pending entries are
// dropped, not flushed: shutdown discards in-flight debounces rather than firing
// a burst of reconciles into a closing queue.
func (d *debouncer) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopped = true
	for k, t := range d.timers {
		if t != nil {
			t.Stop()
		}
		delete(d.timers, k)
	}
	d.pending = map[string]string{}
}
