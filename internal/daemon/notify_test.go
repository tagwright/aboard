// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/tagwright/beacon"
	"github.com/tagwright/beacon/beacontest"

	"github.com/tagwright/core/runtime/runtimetest"
)

// TestRun_ListFailureAlertsOperator is the additive notifier assertion for the
// one alert-contracted failure path aboard surfaces ONLY through the beacon
// notifier: a failed container listing. fullPass (the boot/full reconcile pass)
// calls rt.List, and on error it fires an Error-level alert and returns without
// propagating the error anywhere else. runtimetest cannot see that surface (it
// is neither an error return nor a log assertion the Level 2 test covers), so
// this test uses the shared beacontest capturing beacon to prove the operator
// alert actually fires end to end.
//
// It complements, and does not replace, TestRun_InjectedWatchFailureSurfaces:
// the run record / log stays the primary surface, and this notify assertion is
// added only because a swallowed List alert is exactly the "failed to alert an
// operator" bug class the standard closes.
func TestRun_ListFailureAlertsOperator(t *testing.T) {
	rt := runtimetest.New()
	// The injected failure: listing the fleet fails on demand. aboard's only
	// reaction is the operator alert, so a swallow here is silent.
	injected := errors.New("injected list failure")
	rt.Faults.List = injected

	notifier, capture := beacontest.New(beacon.LevelInfo)

	deps := Deps{
		Runtime:    rt,
		Reconciler: &fakeReconciler{},
		Notifier:   notifier,
		Config:     testConfig(),
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:      rt.Clock.Now,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- run(ctx, deps) }()

	fired := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if capture.Contains(beacon.LevelError, "list containers failed") {
			fired = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after ctx cancel")
	}

	if !fired {
		t.Fatalf("aboard's List-failure alert did not fire: no Error-level notification about the failed listing was captured (a silent swallow of the notifier-only surface). captured: %+v", capture.Notifications())
	}
	if !capture.Contains(beacon.LevelError, injected.Error()) {
		t.Fatalf("the List-failure alert did not carry the underlying error %q; captured: %+v", injected, capture.Notifications())
	}
}
