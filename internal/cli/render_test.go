// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/tagwright/core/runtime"
)

// TestRunRenderService_ProtectedRouter proves render emits the middleware line for
// a service whose router is declared protected, from a known label set.
func TestRunRenderService_ProtectedRouter(t *testing.T) {
	l := &fakeLister{containers: []runtime.Container{
		container("wiki", map[string]string{
			"aboard.enable":                         "true",
			"aboard.host":                           "wiki.example.com",
			"traefik.http.routers.wiki.rule":        "Host(`wiki.example.com`)",
			"traefik.http.routers.wiki.middlewares": "authentik@docker",
		}),
	}}

	u, buf := newTestUI()
	if err := runRenderService(context.Background(), testConfig(), l, "wiki", u); err != nil {
		t.Fatalf("runRenderService: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "aboard render wiki") {
		t.Errorf("expected the render header for wiki, got:\n%s", out)
	}
	if !strings.Contains(out, "traefik.http.routers.wiki.middlewares=authentik@docker") {
		t.Errorf("expected the middleware line for the protected router, got:\n%s", out)
	}
}

// TestRunRenderService_NotFound proves render errors when no enabled container
// matches the named service.
func TestRunRenderService_NotFound(t *testing.T) {
	l := &fakeLister{containers: []runtime.Container{
		container("other", map[string]string{"aboard.enable": "true", "aboard.host": "other.example.com"}),
	}}
	u, _ := newTestUI()
	err := runRenderService(context.Background(), testConfig(), l, "missing", u)
	if err == nil {
		t.Fatalf("expected an error for a missing service")
	}
	if !strings.Contains(err.Error(), "no aboard-enabled container found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestRunRenderSetup_EmitsMiddlewareAndCatchAll proves --setup prints the shared
// middleware definition and the fleet catch-all callback router.
func TestRunRenderSetup_EmitsMiddlewareAndCatchAll(t *testing.T) {
	u, buf := newTestUI()
	runRenderSetup(testConfig(), u)
	out := buf.String()
	if !strings.Contains(out, "forwardauth.address") {
		t.Errorf("expected the shared forward-auth middleware definition, got:\n%s", out)
	}
	if !strings.Contains(out, "aboard-outpost.rule") {
		t.Errorf("expected the fleet catch-all callback router, got:\n%s", out)
	}
	// Version 3 config selects the anchored Go-regexp HostRegexp spelling.
	if !strings.Contains(out, "HostRegexp") {
		t.Errorf("expected a HostRegexp catch-all rule, got:\n%s", out)
	}
}
