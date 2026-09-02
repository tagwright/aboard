// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestWorkerSerializesReconciles is the load-bearing correctness proof for this
// chunk. The embedded outpost's providers list is a SHARED object: every
// forward-auth reconcile reads the list, appends its own provider pk, and PATCHes
// the whole list back. If two reconciles ran concurrently, both would read the
// old list and the second PATCH would clobber the first's freshly-added
// membership, silently un-attaching an app that still looks configured.
//
// The daemon routes EVERY Authentik-touching operation through the single serial
// worker, so this test pushes two jobs and proves the worker never runs a second
// while the first is in flight: the second does not even start until the first
// returns, and the observed peak concurrency is exactly one.
func TestWorkerSerializesReconciles(t *testing.T) {
	q := newWorkQueue()

	var active int32
	var peak int32
	entered := make(chan string, 2)
	release := make(chan struct{})

	mkJob := func(key string) job {
		return job{key: key, run: func(_ context.Context) {
			n := atomic.AddInt32(&active, 1)
			for {
				old := atomic.LoadInt32(&peak)
				if n <= old || atomic.CompareAndSwapInt32(&peak, old, n) {
					break
				}
			}
			entered <- key
			<-release // block this reconcile "in flight"
			atomic.AddInt32(&active, -1)
		}}
	}

	q.push(mkJob("app-a"))
	q.push(mkJob("app-b"))

	d := &Daemon{queue: q}
	done := make(chan struct{})
	go func() {
		d.runWorker(context.Background())
		close(done)
	}()

	// The first reconcile starts.
	first := <-entered

	// While it is blocked in flight, the second reconcile MUST NOT start: that is
	// the shared-outpost hazard. Prove it does not by seeing no second entry.
	select {
	case second := <-entered:
		t.Fatalf("two reconciles ran concurrently (%s and %s): the shared outpost providers list would be clobbered", first, second)
	case <-time.After(75 * time.Millisecond):
	}

	// Release the first; only now may the second run.
	release <- struct{}{}
	second := <-entered
	release <- struct{}{}

	// Drain and stop the worker.
	q.close()
	<-done

	if first == second {
		t.Fatalf("expected two distinct jobs to run, both were %q", first)
	}
	if got := atomic.LoadInt32(&peak); got != 1 {
		t.Fatalf("peak concurrency was %d, must be 1 for serialized reconciles", got)
	}
}

// TestWorkQueueCoalescesByKey proves the per-key coalescing on top of the serial
// execution: a second push for a key already waiting replaces the pending job
// (latest wins) rather than enqueuing a duplicate, so a burst of events for one
// service does not pile up duplicate reconciles.
func TestWorkQueueCoalescesByKey(t *testing.T) {
	q := newWorkQueue()

	var ran []string
	q.push(job{key: "app-a", run: func(context.Context) { ran = append(ran, "a1") }})
	q.push(job{key: "app-a", run: func(context.Context) { ran = append(ran, "a2") }})
	q.push(job{key: "app-b", run: func(context.Context) { ran = append(ran, "b1") }})

	if got := q.depth(); got != 2 {
		t.Fatalf("depth = %d, want 2 (app-a coalesced, app-b distinct)", got)
	}
	if keys := q.queuedKeys(); len(keys) != 2 || keys[0] != "app-a" || keys[1] != "app-b" {
		t.Fatalf("queued keys = %v, want [app-a app-b] in first-seen order", keys)
	}

	// Drain: app-a must run its LATEST closure (a2), not a1.
	j1, _ := q.pop()
	j1.run(context.Background())
	j2, _ := q.pop()
	j2.run(context.Background())

	if len(ran) != 2 || ran[0] != "a2" || ran[1] != "b1" {
		t.Fatalf("ran = %v, want [a2 b1] (latest-wins coalescing, FIFO order)", ran)
	}
}
