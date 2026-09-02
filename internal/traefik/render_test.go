// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package traefik

import (
	"strings"
	"testing"

	"github.com/tagwright/aboard/internal/config"
)

func TestRenderServiceMixedHost(t *testing.T) {
	// The travels mixed-host case with no fleet catch-all: render must emit the
	// protected router's middleware line AND a full callback block at a priority
	// above the app routers, pointed at authentik-server.
	cfg := testCfg()
	sp := faSpec("travels", "travels.natecalvert.org", "travels-admin")
	res := Verify(cfg, sp, travelsMixed(), false)
	out := RenderService(cfg, sp, res)

	wantContains := []string{
		"traefik.http.routers.travels-admin.middlewares=authentik@docker",
		"traefik.http.routers.travels-outpost.rule=Host(`travels.natecalvert.org`) && PathPrefix(`/outpost.goauthentik.io/`)",
		"traefik.http.routers.travels-outpost.middlewares=authentik@docker",
		"traefik.http.routers.travels-outpost.priority=20",
		"traefik.http.services.authentik-svc.loadbalancer.server.url=http://authentik-server:9000",
	}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("render missing %q\n---\n%s", w, out)
		}
	}
	// The callback priority (20) must be above the highest app-router priority (10).
	if !strings.Contains(out, ".priority=20") {
		t.Errorf("callback priority should be 20, above admin 10\n%s", out)
	}
	// Never writes files, and never a stray emoji: the output is compose YAML.
	if strings.ContainsAny(out, "–—") {
		t.Error("render output contains an en or em dash")
	}
}

func TestRenderServiceWholeHostNoCallback(t *testing.T) {
	cfg := testCfg()
	sp := faSpec("whoami", "whoami.example.com")
	res := Verify(cfg, sp, whoamiWholeHost(), false)
	out := RenderService(cfg, sp, res)

	if !strings.Contains(out, "traefik.http.routers.whoami.middlewares=authentik@docker") {
		t.Errorf("render missing whoami middleware line\n%s", out)
	}
	if strings.Contains(out, "outpost.goauthentik.io") {
		t.Errorf("whole host should not render a callback block\n%s", out)
	}
}

func TestRenderServiceFleetCatchAll(t *testing.T) {
	cfg := testCfg()
	sp := faSpec("travels", "travels.natecalvert.org", "travels-admin")
	res := Verify(cfg, sp, travelsMixed(), true) // fleet catch-all present
	out := RenderService(cfg, sp, res)

	if strings.Contains(out, "travels-outpost.rule") {
		t.Errorf("fleet catch-all present: no per-app callback block should render\n%s", out)
	}
	if !strings.Contains(out, "catch-all") {
		t.Errorf("expected a note about the fleet catch-all\n%s", out)
	}
}

func TestRenderSetupV3(t *testing.T) {
	cfg := testCfg()
	cfg.Traefik.Version = 3
	out := RenderSetup(cfg)

	// The shared middleware definition matches traefik/docker-compose.yml.
	wantMw := []string{
		"traefik.http.middlewares.authentik.forwardauth.address=http://authentik-server:9000/outpost.goauthentik.io/auth/traefik",
		"traefik.http.middlewares.authentik.forwardauth.trustForwardHeader=true",
		"traefik.http.middlewares.authentik.forwardauth.authResponseHeaders=X-authentik-username",
		"traefik.http.middlewares.authentik.forwardauth.maxResponseBodySize=4194304",
	}
	for _, w := range wantMw {
		if !strings.Contains(out, w) {
			t.Errorf("setup missing middleware line %q\n%s", w, out)
		}
	}

	// v3 HostRegexp is standard Go (RE2) regexp, anchored, dots escaped.
	if !strings.Contains(out, "HostRegexp(`^[a-z0-9-]+\\.natecalvert\\.org$`)") {
		t.Errorf("v3 setup missing Go-regexp HostRegexp\n%s", out)
	}
	if strings.Contains(out, "{subdomain") {
		t.Errorf("v3 setup must not use v2 named-group HostRegexp syntax\n%s", out)
	}
	if !strings.Contains(out, "PathPrefix(`/outpost.goauthentik.io/`)") {
		t.Errorf("catch-all rule missing the outpost PathPrefix\n%s", out)
	}
}

func TestRenderSetupV2(t *testing.T) {
	cfg := testCfg()
	cfg.Traefik.Version = 2
	out := RenderSetup(cfg)

	// v2 HostRegexp uses the {name:pattern} named-group template syntax.
	if !strings.Contains(out, "HostRegexp(`{subdomain:[a-z0-9-]+}.natecalvert.org`)") {
		t.Errorf("v2 setup missing named-group HostRegexp\n%s", out)
	}
	if strings.Contains(out, "^[a-z0-9-]+\\.") {
		t.Errorf("v2 setup must not use v3 Go-regexp HostRegexp syntax\n%s", out)
	}
}

func TestRenderSetupV2V3Differ(t *testing.T) {
	// The load-bearing version split: the same fleet, two Traefik majors, two
	// different HostRegexp spellings.
	cfg := testCfg()
	cfg.Traefik.Version = 2
	v2 := RenderSetup(cfg)
	cfg.Traefik.Version = 3
	v3 := RenderSetup(cfg)
	if v2 == v3 {
		t.Fatal("v2 and v3 setup output are identical, HostRegexp syntax must differ")
	}
}

func TestRenderSetupProxyNone(t *testing.T) {
	cfg := testCfg()
	cfg.Proxy = config.ProxyNone
	out := RenderSetup(cfg)
	if !strings.Contains(out, "proxy is none") {
		t.Errorf("proxy none setup should be a no-op note, got\n%s", out)
	}
}

func TestFleetDomainDerivation(t *testing.T) {
	cfg := testCfg()
	cfg.Authentik.PublicURL = "https://auth.natecalvert.org"
	d, guessed := fleetDomain(cfg)
	if d != "natecalvert.org" {
		t.Errorf("fleetDomain = %q, want natecalvert.org", d)
	}
	if !guessed {
		t.Error("a derived domain should be flagged guessed")
	}

	cfg.Authentik.PublicURL = ""
	d, guessed = fleetDomain(cfg)
	if d != "fleet.example.com" || !guessed {
		t.Errorf("empty public_url: got %q guessed=%v, want placeholder", d, guessed)
	}
}
