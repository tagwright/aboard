// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/spec"
)

// newTestDaemon builds a Daemon over the given fakes for the sync-path tests.
func newTestDaemon(t *testing.T, rt Runtime, rec Reconciler, notifier Notifier) *Daemon {
	t.Helper()
	d, err := New(Config{
		Runtime:    rt,
		Reconciler: rec,
		Notifier:   notifier,
		Config:     testConfig(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

// TestRemovalKeepsObjectsAsOrphans is the Fork 8 KEEP proof: a die/destroy event
// that leaves no live container for the service must NOT tear anything down. The
// removed container's aboard-owned objects become orphans, surfaced for the
// digest, and Teardown is never called from the daemon.
func TestRemovalKeepsObjectsAsOrphans(t *testing.T) {
	rt := newFakeRuntime()
	// The service's container is gone: Inspect by the last-seen id errors, and the
	// listing has no enabled container for it.
	rt.inspectErr["dead-id"] = errors.New("no such container")
	rt.containers = nil

	rec := &fakeReconciler{
		orphans: []reconcile.Orphan{
			{Slug: "gitea", Kind: spec.ProviderOIDC, ProviderPK: 7, AppPK: "app-gitea"},
			{Slug: "whoami", Kind: spec.ProviderForwardAuth, ProviderPK: 3, AppPK: "app-whoami"},
		},
	}
	d := newTestDaemon(t, rt, rec, &capturingNotifier{})

	d.syncKey(context.Background(), "gitea", "dead-id")

	if calls := rec.teardowns(); len(calls) != 0 {
		t.Fatalf("Teardown was called %v on a removal event: Fork 8 KEEP forbids the daemon from tearing down", calls)
	}
	orphans := d.snapshotOrphans()
	if len(orphans) != 2 {
		t.Fatalf("orphan set has %d entries, want 2 (the removed objects must surface as orphans)", len(orphans))
	}
	// OIDC (live credential) is listed first by Orphans; the daemon preserves it.
	if orphans[0].Kind != spec.ProviderOIDC {
		t.Fatalf("first orphan kind = %v, want OIDC (live credentials first)", orphans[0].Kind)
	}
}

// TestStartReconcilesContainer proves the positive path: an inspectable, opted-in
// container is reconciled, and no teardown ever happens.
func TestStartReconcilesContainer(t *testing.T) {
	rt := newFakeRuntime()
	c := runtime.Container{
		Name:    "nutrition",
		Service: "nutrition",
		Image:   "example/nutrition",
		State:   "running",
		Labels: map[string]string{
			"aboard.enable": "true",
			"aboard.host":   "nutrition.natecalvert.org",
		},
	}
	rt.inspectByID["live-id"] = c
	rt.containers = []runtime.Container{c}

	rec := &fakeReconciler{}
	d := newTestDaemon(t, rt, rec, &capturingNotifier{})

	d.syncKey(context.Background(), "nutrition", "live-id")

	if got := rec.reconciledSlugs(); len(got) != 1 || got[0] != "nutrition" {
		t.Fatalf("reconciled = %v, want [nutrition]", got)
	}
	if calls := rec.teardowns(); len(calls) != 0 {
		t.Fatalf("Teardown was called %v on a reconcile: the daemon never tears down", calls)
	}
}

// TestFullPassReconcilesEnabledOnly proves the boot pass reconciles opted-in
// containers, skips the un-opted-in and self-excluded ones, and detects the fleet
// catch-all once.
func TestFullPassReconcilesEnabledOnly(t *testing.T) {
	rt := newFakeRuntime()
	rt.containers = []runtime.Container{
		{
			Name: "nutrition", Service: "nutrition", Image: "example/nutrition",
			Labels: map[string]string{"aboard.enable": "true", "aboard.host": "nutrition.natecalvert.org"},
		},
		{
			Name: "plain", Service: "plain", Image: "example/plain",
			Labels: map[string]string{}, // not opted in
		},
		{
			Name: "authentik-server", Service: "authentik-server", Image: "ghcr.io/goauthentik/server:2025.6.4",
			// even if mislabeled opted-in, self-exclusion wins
			Labels: map[string]string{
				"aboard.enable": "true",
				"traefik.http.routers.ak-outpost.rule": "HostRegexp(`^.+\\.natecalvert\\.org$`) && PathPrefix(`/outpost.goauthentik.io/`)",
			},
		},
	}
	rec := &fakeReconciler{}
	d := newTestDaemon(t, rt, rec, &capturingNotifier{})

	d.fullPass(context.Background())

	got := rec.reconciledSlugs()
	if len(got) != 1 || got[0] != "nutrition" {
		t.Fatalf("reconciled = %v, want only [nutrition] (plain not opted in, authentik self-excluded)", got)
	}
	if !d.fleetCallbackPresent() {
		t.Fatalf("fleet catch-all not detected during the full pass")
	}
}
