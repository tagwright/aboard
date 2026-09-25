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

// flushNow fires every pending key immediately, bypassing the quiet-window
// timers, and clears the pending set. It is the graceful-shutdown counterpart to
// stop: Run calls it before stop (daemon.go), so a change that has settled but
// whose window has not yet elapsed is reconciled rather than dropped on the way
// out. Each pending key's timer is stopped under the lock so it cannot also fire,
// and onFlush is invoked outside the lock (as fire does) so it can enqueue
// freely. A no-op once stopped, so a stray call after stop cannot resurrect work.
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

// stop halts every armed timer and blocks further observes. Any entries STILL
// pending are dropped, not flushed. Graceful shutdown flushes first (Run calls
// flushNow, then stop), so by the time stop runs the pending set is normally
// empty; the drop here is the backstop for anything that arrived in between and
// the guard that blocks a late observe from arming a new timer into a closing
// queue.
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
