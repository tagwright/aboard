// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/spec"
)

// waitFor polls cond until it is true or the deadline passes, so a test does not
// race the daemon's own goroutines. It returns whether cond became true.
func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// TestShutdownFlushesPendingReconcile is the graceful-shutdown proof for the
// flushNow wiring: a change that has settled but whose debounce window has not
// yet elapsed is reconciled on the way out, not dropped.
//
// The setup isolates the flush from the boot full pass: the container is
// inspectable (so the flushed sync can reconcile it) but absent from the listing
// (so the boot full pass reconciles nothing). The debounce window is 30s, far
// longer than the test, so the pending entry can only fire via the shutdown
// flush, never on its own. Before ctx is cancelled, nothing has reconciled;
// after, exactly the flushed service has.
func TestShutdownFlushesPendingReconcile(t *testing.T) {
	rt := newFakeRuntime()
	c := runtime.Container{
		Name:    "nutrition",
		Service: "nutrition",
		Image:   "example/nutrition",
		State:   "running",
		Labels: map[string]string{
			"aboard.enable": "true",
			"aboard.host":   "nutrition.example.org",
		},
	}
	rt.inspectByID["live-id"] = c
	// containers stays empty: the boot full pass has nothing to reconcile, so any
	// reconcile observed is the shutdown flush's.

	rec := &fakeReconciler{}
	d, err := New(Config{
		Runtime:        rt,
		Reconciler:     rec,
		Notifier:       &capturingNotifier{},
		Config:         testConfig(),
		DebounceWindow: 30 * time.Second, // never fires on its own inside the test
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	// A lifecycle event lands the service in the debouncer as pending.
	rt.events <- runtime.Event{
		Type:   runtime.EventStart,
		ID:     "live-id",
		Name:   "nutrition",
		Labels: map[string]string{composeServiceLabel: "nutrition"},
	}

	if !waitFor(func() bool { return d.deb.pendingCount() == 1 }, 3*time.Second) {
		cancel()
		<-runErr
		t.Fatalf("event never became pending in the debouncer")
	}

	// Nothing has fired yet: the window is 30s and the boot pass had no containers.
	if got := rec.reconciledSlugs(); len(got) != 0 {
		cancel()
		<-runErr
		t.Fatalf("reconciled %v before shutdown, want none (the pending change must not have fired)", got)
	}

	// Shutdown flushes the pending change instead of dropping it.
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}

	got := rec.reconciledSlugs()
	if len(got) != 1 || got[0] != "nutrition" {
		t.Fatalf("reconciled = %v after shutdown, want [nutrition]: the pending change was dropped, not flushed", got)
	}
}

// enabledContainer builds a healthy, opted-in forward-auth container that
// reconciles cleanly, one per distinct service name/host.
func enabledContainer(svc string) runtime.Container {
	return runtime.Container{
		Name:    svc,
		Service: svc,
		Image:   "example/" + svc,
		State:   "running",
		Labels: map[string]string{
			"aboard.enable": "true",
			"aboard.host":   svc + ".example.org",
		},
	}
}

// delayingReconciler makes each reconcile take a fixed, ctx-respecting delay,
// standing in for a HEALTHY but non-instant backend call. It is how a multi-job
// drain takes real (small, injected) time while every individual job still
// completes well within the stall window, which is the exact shape the old blind
// global deadline punished. It records reconciled slugs like fakeReconciler.
type delayingReconciler struct {
	fakeReconciler
	delay time.Duration
}

func (r *delayingReconciler) Reconcile(ctx context.Context, s spec.Spec) (*reconcile.Result, error) {
	select {
	case <-time.After(r.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return r.fakeReconciler.Reconcile(ctx, s)
}

// blockingReconciler hangs in Reconcile until its context is cancelled, standing
// in for a stuck Authentik REST call (a reconcile that makes NO progress) so the
// stall watchdog can be exercised. It respects ctx so the watchdog's cancel
// actually unblocks it, and it records the ctx error it observed so a test can
// assert the WORKER context was the thing cancelled.
type blockingReconciler struct {
	fakeReconciler
	entered chan struct{}

	mu     sync.Mutex
	ctxErr error
}

func (b *blockingReconciler) Reconcile(ctx context.Context, _ spec.Spec) (*reconcile.Result, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	b.mu.Lock()
	b.ctxErr = ctx.Err()
	b.mu.Unlock()
	return nil, ctx.Err()
}

func (b *blockingReconciler) observedCtxErr() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ctxErr
}

// TestShutdownDrainProgressNotPunished is acceptance criterion 1: a HEALTHY
// backlog whose TOTAL drain time exceeds the stall window (so a single blind
// deadline of that size, the old design's shape, would have guillotined it
// mid-flight), but where each individual job completes well within the stall
// window, drains EVERY job and cancels nothing. This is the core proof that
// progress is no longer punished.
func TestShutdownDrainProgressNotPunished(t *testing.T) {
	const backlog = 12

	rt := newFakeRuntime()
	for i := 0; i < backlog; i++ {
		rt.inspectByID[fmt.Sprintf("live-%d", i)] = enabledContainer(fmt.Sprintf("svc%d", i))
	}
	// rt.containers stays empty: the boot full pass reconciles nothing, so every
	// reconcile observed is a drained backlog job, not the boot pass.

	rec := &delayingReconciler{delay: 15 * time.Millisecond}
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d, err := New(Config{
		Runtime:        rt,
		Reconciler:     rec,
		Notifier:       &capturingNotifier{},
		Config:         testConfig(),
		Logger:         logger,
		DebounceWindow: 30 * time.Second, // the pending set only flushes on shutdown
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// One healthy job (15ms) sits far inside the stall window, so a steady stream
	// of completions keeps resetting it; the ceiling is far away so only progress
	// governs this test.
	d.shutdownStall = 100 * time.Millisecond
	d.shutdownCeiling = 10 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	// Land every backlog service in the debouncer as pending. The 30s window means
	// none fire on their own; they exist only to be flushed at shutdown.
	for i := 0; i < backlog; i++ {
		svc := fmt.Sprintf("svc%d", i)
		rt.events <- runtime.Event{
			Type:   runtime.EventStart,
			ID:     fmt.Sprintf("live-%d", i),
			Name:   svc,
			Labels: map[string]string{composeServiceLabel: svc},
		}
	}
	if !waitFor(func() bool { return d.deb.pendingCount() == backlog }, 3*time.Second) {
		cancel()
		<-runErr
		t.Fatalf("only %d of %d events became pending in the debouncer", d.deb.pendingCount(), backlog)
	}
	if got := rec.reconciledSlugs(); len(got) != 0 {
		cancel()
		<-runErr
		t.Fatalf("reconciled %v before shutdown, want none (the backlog must not have fired early)", got)
	}

	start := time.Now()
	cancel() // shutdown: flush the whole backlog onto the queue, then drain it

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
	elapsed := time.Since(start)

	// Every job drained: a healthy, progressing backlog is not punished.
	if got := rec.reconciledSlugs(); len(got) != backlog {
		t.Fatalf("drained %d of %d backlog jobs; a healthy backlog must drain in FULL: %v", len(got), backlog, got)
	}
	// Nothing was cancelled, by either bound.
	if s := logBuf.String(); strings.Contains(s, "cancelling in-flight reconcile") {
		t.Fatalf("the drain cancelled the worker on a HEALTHY backlog; progress was punished. log:\n%s", s)
	}
	// The whole drain outlasted the stall window: a single blind deadline of that
	// size (the old shape) would have cut this backlog off, but progress-awareness
	// let it finish.
	if elapsed < d.shutdownStall {
		t.Fatalf("drain finished in %s, not longer than the %s stall window: the test never actually exceeded a single-deadline bound", elapsed, d.shutdownStall)
	}
}

// TestShutdownDrainStallCancelsHungReconcile is acceptance criterion 2: a
// reconcile that HANGS (blocks indefinitely, making no progress) is cancelled
// roughly one stall-window after it wedges, and shutdown then completes. It
// asserts the WORKER context was cancelled and Run returned, and that the cancel
// was the STALL path, not the absolute ceiling.
func TestShutdownDrainStallCancelsHungReconcile(t *testing.T) {
	rt := newFakeRuntime()
	rt.inspectByID["live-id"] = enabledContainer("nutrition")

	rec := &blockingReconciler{entered: make(chan struct{}, 1)}
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d, err := New(Config{
		Runtime:        rt,
		Reconciler:     rec,
		Notifier:       &capturingNotifier{},
		Config:         testConfig(),
		Logger:         logger,
		DebounceWindow: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A short stall window so the hang is cut quickly; the ceiling is far away so
	// the STALL path, not the ceiling, must be what fires.
	d.shutdownStall = 120 * time.Millisecond
	d.shutdownCeiling = 10 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	rt.events <- runtime.Event{
		Type:   runtime.EventStart,
		ID:     "live-id",
		Name:   "nutrition",
		Labels: map[string]string{composeServiceLabel: "nutrition"},
	}
	if !waitFor(func() bool { return d.deb.pendingCount() == 1 }, 3*time.Second) {
		cancel()
		<-runErr
		t.Fatalf("event never became pending in the debouncer")
	}

	start := time.Now()
	cancel() // shutdown: flush -> the reconcile hangs -> the stall watchdog must unwedge it

	// The hung reconcile actually started (so a stall, not a no-op, is what we cut).
	select {
	case <-rec.entered:
	case <-time.After(3 * time.Second):
		cancel()
		<-runErr
		t.Fatal("the flushed reconcile never entered; the test did not exercise a hang")
	}

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return: a hung reconcile wedged shutdown, the stall watchdog did not fire")
	}
	elapsed := time.Since(start)

	// The worker context was the thing cancelled (the reconcile saw it).
	if got := rec.observedCtxErr(); got != context.Canceled {
		t.Fatalf("worker ctx err = %v, want context.Canceled: the stall watchdog must cancel the WORKER context", got)
	}
	// It was the stall path, cut promptly, not the far-off ceiling and not the old
	// fixed 10s deadline.
	if !waitForLog(logBuf, "shutdown drain stalled", 2*time.Second) {
		t.Fatalf("expected the stall-cancel warning; log was:\n%s", logBuf.String())
	}
	if s := logBuf.String(); strings.Contains(s, "absolute ceiling") {
		t.Fatalf("the ceiling fired on a hung reconcile; the stall path should have cut it first. log:\n%s", s)
	}
	// Roughly one stall window: at least the window (a timer cannot fire early) and
	// well short of the ceiling / the old 10s deadline.
	if elapsed < d.shutdownStall-20*time.Millisecond {
		t.Fatalf("shutdown took %s, less than the %s stall window: the watchdog cut before a real stall elapsed", elapsed, d.shutdownStall)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("shutdown took %s, far longer than one stall window: the hang was not cut promptly", elapsed)
	}
}

// TestShutdownDrainCeilingCapsPathologicalStream is acceptance criterion 3: the
// absolute ceiling caps a pathological worker that keeps "completing" trivial
// work forever (which keeps resetting the stall window so the stall path never
// fires). The worker is cancelled at the ceiling, not left to run without bound.
//
// The pathological stream is fault-injected at the progress seam: a job whose run
// loops emitting the worker's completion signal until its context is cancelled,
// exactly modelling a reconcile stuck in a tight loop that reports micro-progress
// but never ends. The stall window never fires (progress keeps resetting it); the
// absolute ceiling, which is never reset, is the only thing that can stop it.
func TestShutdownDrainCeilingCapsPathologicalStream(t *testing.T) {
	rt := newFakeRuntime()

	rec := &fakeReconciler{}
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d, err := New(Config{
		Runtime:    rt,
		Reconciler: rec,
		Notifier:   &capturingNotifier{},
		Config:     testConfig(),
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The stream reports progress every 8ms, far inside the 60ms stall window, so
	// the stall path can NEVER fire; the 150ms ceiling is the only bound that can.
	d.shutdownStall = 60 * time.Millisecond
	d.shutdownCeiling = 150 * time.Millisecond

	// A job that keeps completing trivial work forever, until the worker context is
	// cancelled. Each tick emits the worker's own progress signal, so the drain's
	// stall window is perpetually reset.
	started := make(chan struct{})
	var startOnce sync.Once
	var sawCancel struct {
		mu  sync.Mutex
		hit bool
	}
	d.queue.push(job{
		key: "\x00pathological",
		run: func(ctx context.Context) {
			tick := time.NewTicker(8 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					sawCancel.mu.Lock()
					sawCancel.hit = true
					sawCancel.mu.Unlock()
					return
				case <-tick.C:
					startOnce.Do(func() { close(started) })
					d.signalJobDone() // "completed" trivial work: resets the stall window
				}
			}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	// Make sure the pathological stream is actually running before shutdown, so the
	// drain measures its progress from the start of the ceiling window.
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		cancel()
		<-runErr
		t.Fatal("the pathological stream never started emitting progress")
	}

	start := time.Now()
	cancel() // shutdown: the stream keeps resetting the stall, only the ceiling can cut it

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return: the ceiling did not cap a stream that keeps completing trivial jobs")
	}
	elapsed := time.Since(start)

	// The worker context was cancelled at the ceiling (the stream saw it and left).
	sawCancel.mu.Lock()
	hit := sawCancel.hit
	sawCancel.mu.Unlock()
	if !hit {
		t.Fatal("the pathological stream was never cancelled: the ceiling did not cancel the worker context")
	}
	// It was the ceiling path, not the stall path (progress kept the stall alive).
	if !waitForLog(logBuf, "absolute ceiling", 2*time.Second) {
		t.Fatalf("expected the ceiling-cancel warning; log was:\n%s", logBuf.String())
	}
	if s := logBuf.String(); strings.Contains(s, "shutdown drain stalled") {
		t.Fatalf("the stall path fired, but progress should have kept it reset; only the ceiling should cut this. log:\n%s", s)
	}
	// The ceiling actually held it that long (a timer cannot fire early) and no
	// longer than a small margin past it.
	if elapsed < d.shutdownCeiling-20*time.Millisecond {
		t.Fatalf("shutdown took %s, less than the %s ceiling: the cap fired early", elapsed, d.shutdownCeiling)
	}
	if elapsed > d.shutdownCeiling+2*time.Second {
		t.Fatalf("shutdown took %s, far past the %s ceiling: the cap did not hold the line", elapsed, d.shutdownCeiling)
	}
}

// TestSingleRemovalClearsSlugStickyError proves the clearSlug wiring on a single
// removal, ISOLATED from the batch retainSlugs. The follow-up container listing
// fails, so refreshFromList returns before retainSlugs ever runs; the removed
// slug's sticky error is therefore cleared only if the per-slug clearSlug fired.
func TestSingleRemovalClearsSlugStickyError(t *testing.T) {
	rt := newFakeRuntime()
	rt.inspectErr["dead-id"] = errors.New("no such container")
	rt.listErr = errors.New("socket gone") // refreshFromList returns before retainSlugs

	rec := &fakeReconciler{}
	d := newTestDaemon(t, rt, rec, &capturingNotifier{})

	// The slug had a standing sticky error, and the daemon knows the key->slug map
	// (as it would after having reconciled the now-removed container).
	errIssue := discovery.Issue{Severity: discovery.SeverityError, Code: "unwired-middleware", Message: "no middleware"}
	d.sticky.replaceSlug("nutrition", "nutrition", []discovery.Issue{errIssue}, time.Now())
	d.rememberSlug("nutrition", "nutrition")
	if d.sticky.count() != 1 {
		t.Fatalf("setup: sticky count = %d, want 1", d.sticky.count())
	}

	d.syncKey(context.Background(), "nutrition", "dead-id")

	if d.sticky.count() != 0 {
		t.Fatalf("single removal did not clear the removed slug's sticky error; count = %d. "+
			"The batch retainSlugs never ran (listing failed), so only the per-slug clearSlug could clear it", d.sticky.count())
	}
	if _, ok := d.lookupSlug("nutrition"); ok {
		t.Fatalf("single removal must forget the key->slug mapping")
	}
}

// TestOptOutClearsSlugStickyError proves the same per-slug clear on the other
// single-removal shape: a container that stays up but drops aboard.enable. It too
// is isolated from retainSlugs by failing the follow-up listing, and it exercises
// that the removed slug comes from the key->slug index (discovery leaves sp.Slug
// empty for a disabled container).
func TestOptOutClearsSlugStickyError(t *testing.T) {
	rt := newFakeRuntime()
	optedOut := runtime.Container{
		Name:    "nutrition",
		Service: "nutrition",
		Image:   "example/nutrition",
		State:   "running",
		Labels:  map[string]string{}, // aboard.enable gone: opted out
	}
	rt.inspectByID["live-id"] = optedOut
	rt.listErr = errors.New("socket gone") // isolate from retainSlugs

	rec := &fakeReconciler{}
	d := newTestDaemon(t, rt, rec, &capturingNotifier{})

	errIssue := discovery.Issue{Severity: discovery.SeverityError, Code: "unwired-middleware", Message: "no middleware"}
	d.sticky.replaceSlug("nutrition", "nutrition", []discovery.Issue{errIssue}, time.Now())
	d.rememberSlug("nutrition", "nutrition")

	d.syncKey(context.Background(), "nutrition", "live-id")

	if d.sticky.count() != 0 {
		t.Fatalf("opting out did not clear the slug's sticky error; count = %d (only the per-slug clearSlug could, retainSlugs never ran)", d.sticky.count())
	}
	if got := rec.reconciledSlugs(); len(got) != 0 {
		t.Fatalf("an opted-out container must not be reconciled; got %v", got)
	}
}

// TestSingleRemovalBatchRetainStillClears is the regression guard for the batch
// path: with the listing HEALTHY, a removal still clears the removed slug through
// retainSlugs over the enabled set, exactly as before the per-slug clear was
// added. The two paths coexist.
func TestSingleRemovalBatchRetainStillClears(t *testing.T) {
	rt := newFakeRuntime()
	rt.inspectErr["dead-id"] = errors.New("no such container")
	rt.containers = nil // healthy listing, no enabled containers remain

	rec := &fakeReconciler{}
	d := newTestDaemon(t, rt, rec, &capturingNotifier{})

	errIssue := discovery.Issue{Severity: discovery.SeverityError, Code: "unwired-middleware", Message: "no middleware"}
	// A DIFFERENT slug than the removed key, with no key mapping: the per-slug
	// clear cannot touch it, so only retainSlugs (the batch path) can drop it.
	d.sticky.replaceSlug("stale", "stale", []discovery.Issue{errIssue}, time.Now())
	if d.sticky.count() != 1 {
		t.Fatalf("setup: sticky count = %d, want 1", d.sticky.count())
	}

	d.syncKey(context.Background(), "some-other-key", "dead-id")

	if d.sticky.count() != 0 {
		t.Fatalf("batch retainSlugs must still clear a slug no longer enabled; count = %d", d.sticky.count())
	}
}
