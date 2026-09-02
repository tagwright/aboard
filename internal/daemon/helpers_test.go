// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"errors"
	"sync"

	"github.com/tagwright/beacon"
	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/spec"
)

// fakeRuntime is an in-memory Runtime: it serves a fixed container listing, a
// per-id inspect table (with per-id errors to simulate a gone container), and a
// caller-supplied event/error channel pair for Watch. No socket, no Docker.
type fakeRuntime struct {
	mu          sync.Mutex
	containers  []runtime.Container
	inspectByID map[string]runtime.Container
	inspectErr  map[string]error
	events      chan runtime.Event
	errs        chan error
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		inspectByID: map[string]runtime.Container{},
		inspectErr:  map[string]error{},
		events:      make(chan runtime.Event, 8),
		errs:        make(chan error, 1),
	}
}

func (f *fakeRuntime) List(_ context.Context) ([]runtime.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]runtime.Container, len(f.containers))
	copy(out, f.containers)
	return out, nil
}

func (f *fakeRuntime) Inspect(_ context.Context, id string) (runtime.Container, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.inspectErr[id]; err != nil {
		return runtime.Container{}, err
	}
	c, ok := f.inspectByID[id]
	if !ok {
		return runtime.Container{}, errors.New("fake: no such container " + id)
	}
	return c, nil
}

func (f *fakeRuntime) Watch(_ context.Context) (<-chan runtime.Event, <-chan error) {
	return f.events, f.errs
}

// fakeReconciler records what it reconciled and torn down, returns a canned
// orphan set, and exposes an onReconcile hook the serialization test uses to
// block a reconcile in flight.
type fakeReconciler struct {
	mu            sync.Mutex
	reconciled    []string
	teardownCalls []string
	orphans       []reconcile.Orphan
	onReconcile   func(s spec.Spec)
}

func (f *fakeReconciler) Reconcile(_ context.Context, s spec.Spec) (*reconcile.Result, error) {
	if f.onReconcile != nil {
		f.onReconcile(s)
	}
	f.mu.Lock()
	f.reconciled = append(f.reconciled, s.Slug)
	f.mu.Unlock()
	return &reconcile.Result{Slug: s.Slug, Provider: s.Provider, Attached: true}, nil
}

func (f *fakeReconciler) Orphans(_ context.Context, _ []string) ([]reconcile.Orphan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]reconcile.Orphan, len(f.orphans))
	copy(out, f.orphans)
	return out, nil
}

func (f *fakeReconciler) Teardown(_ context.Context, slug string) error {
	f.mu.Lock()
	f.teardownCalls = append(f.teardownCalls, slug)
	f.mu.Unlock()
	return nil
}

func (f *fakeReconciler) reconciledSlugs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reconciled...)
}

func (f *fakeReconciler) teardowns() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.teardownCalls...)
}

// capturingNotifier records every Notification for assertions.
type capturingNotifier struct {
	mu    sync.Mutex
	notes []beacon.Notification
}

func (c *capturingNotifier) Notify(_ context.Context, n beacon.Notification) error {
	c.mu.Lock()
	c.notes = append(c.notes, n)
	c.mu.Unlock()
	return nil
}

// testConfig is a minimal but coherent config for discovery and the verifier.
func testConfig() *config.Config {
	cfg := &config.Config{
		Proxy:   config.ProxyTraefik,
		Outpost: config.DefaultOutpost,
		Flows:   config.Flows{Authorization: "authz", Invalidation: "inval"},
		Traefik: config.Traefik{Middleware: config.DefaultMiddleware, Version: 3},
	}
	cfg.Globals.DigestSchedule = "daily"
	return cfg
}
