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

// TestRunRenderService_SAMLMetadataURL proves render for a SAML app prints the
// IdP metadata URL (the analog of the OIDC discovery URL) and no Traefik output,
// since SAML has no proxy half.
func TestRunRenderService_SAMLMetadataURL(t *testing.T) {
	l := &fakeLister{containers: []runtime.Container{
		container("kimai", map[string]string{
			"aboard.enable":        "true",
			"aboard.provider":      "saml",
			"aboard.saml.acs":      "https://kimai.example.com/auth/saml/acs",
			"aboard.saml.audience": "https://kimai.example.com",
		}),
	}}

	u, buf := newTestUI()
	if err := runRenderService(context.Background(), testConfig(), l, "kimai", u); err != nil {
		t.Fatalf("runRenderService: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "https://auth.natecalvert.org/application/saml/kimai/metadata/") {
		t.Errorf("expected the composed IdP metadata URL, got:\n%s", out)
	}
	if !strings.Contains(out, "https://kimai.example.com/auth/saml/acs") {
		t.Errorf("expected the ACS URL reminder, got:\n%s", out)
	}
	// SAML has no Traefik half, so no middleware/callback labels are emitted.
	if strings.Contains(out, "middlewares=") || strings.Contains(out, "PathPrefix") {
		t.Errorf("SAML render must emit no Traefik labels, got:\n%s", out)
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
