// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tagwright/core/runtime/runtimetest"
)

// TestRun_InjectedWatchFailureSurfaces is aboard's Level 2 wiring test for the
// ratified suite Testing Standard: it drives aboard through its real production
// entry seam, run(Deps), with the canonical fake runtime
// (core/runtime/runtimetest), injects a failure on a runtime operation the
// control loop genuinely hits (the socket-watch subscription), and asserts that
// failure SURFACES in the daemon's log rather than being silently swallowed.
//
// The fault knob is Faults.Watch. aboard's foreground is the socket watch
// (watch.go): runLoop subscribes through rt.Watch, and a subscription error is
// delivered on Watch's error channel. watchOnce logs it on aboard's own logger
// as "runtime watch error" before reconnecting. That log record is aboard's
// durable, observable failure signal for a runtime-layer fault, and it is what
// this test asserts on. (List failures surface only through the beacon notifier,
// whose assertion is a separate fast-follow, and Inspect failures are the
// deliberate Fork 8 KEEP path, not a failure; the watch subscription is the one
// runtime seam whose fault surfaces on aboard's log.)
//
// Without the injected Faults.Watch this test would prove only the happy path,
// which the suite audit found is where the fake tier misses every real bug; the
// standard forbids a double with no error knob for exactly that reason.
func TestRun_InjectedWatchFailureSurfaces(t *testing.T) {
	rt := runtimetest.New()
	// The injected failure: the socket-watch subscription fails on demand. This
	// is the knob the standard requires a wiring test to trip.
	injected := errors.New("injected watch subscription failure")
	rt.Faults.Watch = injected

	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	deps := Deps{
		Runtime:    rt,
		Reconciler: &fakeReconciler{},
		Notifier:   &capturingNotifier{},
		Config:     testConfig(),
		Logger:     logger,
		Clock:      rt.Clock.Now, // fake clock drives the loop deterministically
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- run(ctx, deps) }()

	if !waitForLog(logBuf, injected.Error(), 10*time.Second) {
		cancel()
		<-done
		t.Fatalf("injected watch failure did not surface: no daemon log carried %q within timeout (a silent swallow)", injected)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned an unexpected error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after ctx cancel")
	}

	got := logBuf.String()
	if !strings.Contains(got, "runtime watch error") {
		t.Fatalf("injected watch failure did not surface as a watch-error log record; log was:\n%s", got)
	}
	if !strings.Contains(got, injected.Error()) {
		t.Fatalf("watch-error log did not carry the injected error %q; log was:\n%s", injected, got)
	}
}

// waitForLog polls the buffer until it contains want, returning true, or false
// after timeout.
func waitForLog(b *syncBuffer, want string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), want) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return strings.Contains(b.String(), want)
}

// syncBuffer is a mutex-guarded bytes.Buffer: the daemon writes log lines from
// its own goroutines while the test reads them, so both sides must serialize on
// the same lock (bytes.Buffer is not safe for concurrent use).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
