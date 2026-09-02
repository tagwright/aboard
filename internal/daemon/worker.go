// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"sync"
)

// fullPassKey is the reserved queue key for the boot/full reconcile pass. It is
// out of the service-name space (a leading NUL no service label can carry) so a
// full pass never coalesces with a per-service sync.
const fullPassKey = "\x00fullpass"

// job is one unit of serial work. Every Authentik-touching operation is a job,
// and the single worker runs jobs one at a time, which is the whole point: two
// forward-auth reconciles must never overlap, or the second's outpost-providers
// PATCH clobbers the first's freshly-added membership (see the package doc). run
// receives the worker's context so a job stops when the daemon shuts down.
type job struct {
	// key is the coalescing identity: a stable service name, or fullPassKey. A
	// job pushed for a key already waiting REPLACES it, so the latest state wins
	// and rapid churn collapses to one run.
	key string

	// run performs the work. It is invoked exactly once, on the worker goroutine,
	// never concurrently with another run.
	run func(ctx context.Context)
}

// workQueue is a coalescing FIFO with a single consumer. It is the mechanism
// behind serial reconciles: one goroutine calls pop in a loop and runs each job
// to completion before popping the next, so no two jobs ever execute at once.
// Per-key coalescing sits on top: a push for a key already queued overwrites the
// pending job rather than appending a second, so a burst of events for one
// service does not pile up duplicate reconciles.
type workQueue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	order   []string
	pending map[string]job
	closed  bool
}

// newWorkQueue builds an empty queue.
func newWorkQueue() *workQueue {
	q := &workQueue{pending: map[string]job{}}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// push enqueues j, coalescing by key. If a job for j.key is already waiting, it
// is replaced with j (latest wins) and the queue does not grow; otherwise j is
// appended at the back. A push to a closed queue is dropped.
func (q *workQueue) push(j job) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	if _, ok := q.pending[j.key]; !ok {
		q.order = append(q.order, j.key)
	}
	q.pending[j.key] = j
	q.cond.Signal()
}

// pop returns the oldest waiting job, blocking until one is available or the
// queue is closed. The second return is false only when the queue is closed and
// drained, which is the single worker's signal to exit.
func (q *workQueue) pop() (job, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.order) == 0 && !q.closed {
		q.cond.Wait()
	}
	if len(q.order) == 0 {
		return job{}, false
	}
	key := q.order[0]
	q.order = q.order[1:]
	j := q.pending[key]
	delete(q.pending, key)
	return j, true
}

// close marks the queue closed and wakes every waiter. Jobs already waiting are
// still drained by pop before it reports false.
func (q *workQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.cond.Broadcast()
}

// depth reports how many distinct keys are waiting. It exists for tests and
// status, and takes the lock so it is safe to call concurrently.
func (q *workQueue) depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.order)
}

// queuedKeys returns the waiting keys in FIFO order, for tests.
func (q *workQueue) queuedKeys() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := append([]string(nil), q.order...)
	return out
}

// runWorker is the SINGLE serial consumer. It pops and runs jobs one at a time
// until the queue is closed and drained or the context is cancelled. Because
// there is exactly one runWorker goroutine and it runs each job to completion
// before the next, every reconcile is serialized against every other reconcile,
// which closes the shared-outpost-list hazard the package doc describes.
func (d *Daemon) runWorker(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		j, ok := d.queue.pop()
		if !ok {
			return
		}
		j.run(ctx)
	}
}
