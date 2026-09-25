// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"errors"
	"log/slog"
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

// blockingReconciler hangs in Reconcile until its context is cancelled, standing
// in for a stuck Authentik REST call so the bounded-drain deadline can be
// exercised. It respects ctx so the deadline's cancel actually unblocks it.
type blockingReconciler struct {
	fakeReconciler
	entered chan struct{}
}

func (b *blockingReconciler) Reconcile(ctx context.Context, _ spec.Spec) (*reconcile.Result, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestShutdownDrainBoundedByDeadline proves the graceful flush cannot wedge
// shutdown: if a flushed reconcile hangs, the drain deadline cancels the worker
// and Run still returns. Without the bound, a stuck reconcile would block Run
// forever.
func TestShutdownDrainBoundedByDeadline(t *testing.T) {
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
	d.shutdownDrain = 150 * time.Millisecond // short deadline for the test

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
	cancel() // shutdown: flush -> the reconcile hangs -> the deadline must unwedge it

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return: a hung reconcile wedged shutdown, the drain deadline did not fire")
	}

	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("shutdown took %s, far longer than the drain deadline: the bound did not apply", elapsed)
	}
	if !waitForLog(logBuf, "shutdown drain exceeded deadline", 2*time.Second) {
		t.Fatalf("expected the deadline-exceeded warning to be logged; log was:\n%s", logBuf.String())
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
