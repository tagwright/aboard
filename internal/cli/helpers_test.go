// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"bytes"
	"context"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/reconcile"
)

// testConfig builds a valid, defaults-applied config for the read-only CLI passes.
// It mirrors a minimal aboard.yml under proxy: traefik so discovery, the verifier,
// and render all have what they need.
func testConfig() *config.Config {
	return &config.Config{
		Authentik: config.Authentik{
			URL:       "http://authentik-server:9000",
			PublicURL: "https://auth.natecalvert.org",
			Token:     "aboard-api-token",
		},
		Flows: config.Flows{
			Authorization: "default-authorization-flow",
			Invalidation:  "default-invalidation-flow",
		},
		Outpost: "authentik Embedded Outpost",
		OIDC:    config.OIDC{SigningKey: "authentik Self-signed Certificate"},
		Proxy:   config.ProxyTraefik,
		Traefik: config.Traefik{Middleware: "authentik@docker", Version: 3},
	}
}

// container builds a core Container with the given name and labels.
func container(name string, labels map[string]string) runtime.Container {
	return runtime.Container{Name: name, Labels: labels}
}

// fakeLister is an in-memory containerLister: it returns a canned slice, so the
// CLI's list-and-audit passes run with no socket.
type fakeLister struct {
	containers []runtime.Container
	err        error
}

func (f *fakeLister) List(context.Context) ([]runtime.Container, error) {
	return f.containers, f.err
}

// fakeReconciler is an in-memory orphanReconciler. It returns a canned orphan set
// and RECORDS every Teardown call, which is what lets the prune confirmation gate
// be proven: a gate that holds means teardowns stays empty.
type fakeReconciler struct {
	orphans     []reconcile.Orphan
	orphansErr  error
	teardowns   []string
	teardownErr error
}

func (f *fakeReconciler) Orphans(context.Context, []string) ([]reconcile.Orphan, error) {
	return f.orphans, f.orphansErr
}

func (f *fakeReconciler) Teardown(_ context.Context, slug string) error {
	f.teardowns = append(f.teardowns, slug)
	return f.teardownErr
}

// newTestUI builds a colour-off ui over a buffer for output assertions.
func newTestUI() (ui, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return ui{w: buf, color: false}, buf
}
