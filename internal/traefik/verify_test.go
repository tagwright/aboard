// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package traefik

import (
	"testing"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/spec"
)

// testCfg is a proxy: traefik config with the fleet defaults the verifier reads.
func testCfg() *config.Config {
	c := &config.Config{}
	c.Authentik.URL = "http://authentik-server:9000"
	c.Authentik.PublicURL = "https://auth.natecalvert.org"
	c.Proxy = config.ProxyTraefik
	c.Traefik.Middleware = "authentik@docker"
	c.Traefik.Version = 3
	return c
}

// faSpec builds an enabled forward-auth Spec for host with the given protected
// router names (aboard.traefik.routers).
func faSpec(name, host string, routers ...string) *spec.Spec {
	return &spec.Spec{
		Enable:   true,
		Name:     name,
		Slug:     name,
		Title:    name,
		Provider: spec.ProviderForwardAuth,
		Host:     host,
		ForwardAuth: spec.ForwardAuthSpec{
			TraefikRouters: routers,
		},
	}
}

// whoamiWholeHost is the hero demo: one router on one host, carrying the
// middleware.
func whoamiWholeHost() map[string]string {
	return map[string]string{
		"traefik.http.routers.whoami.rule":        "Host(`whoami.example.com`)",
		"traefik.http.routers.whoami.middlewares": "authentik@docker",
	}
}

// travelsMixed is the grammar's worked example (c): a public router beside a
// protected admin router, one host, no per-app callback router.
func travelsMixed() map[string]string {
	return map[string]string{
		"traefik.http.routers.travels.rule":              "Host(`travels.natecalvert.org`)",
		"traefik.http.routers.travels.priority":          "1",
		"traefik.http.routers.travels-admin.rule":        "Host(`travels.natecalvert.org`) && PathPrefix(`/admin`)",
		"traefik.http.routers.travels-admin.middlewares": "authentik@docker",
		"traefik.http.routers.travels-admin.priority":    "10",
	}
}

// travelsFull is the live travels compose: the mixed pair plus the outpost
// callback router at priority 20, pointed at authentik-svc.
func travelsFull() map[string]string {
	m := travelsMixed()
	m["traefik.http.routers.travels-outpost.rule"] = "Host(`travels.natecalvert.org`) && PathPrefix(`/outpost.goauthentik.io/`)"
	m["traefik.http.routers.travels-outpost.middlewares"] = "authentik@docker"
	m["traefik.http.routers.travels-outpost.service"] = "authentik-svc"
	m["traefik.http.routers.travels-outpost.priority"] = "20"
	m["traefik.http.services.travels-svc.loadbalancer.server.port"] = "5000"
	m["traefik.http.services.authentik-svc.loadbalancer.server.url"] = "http://authentik-server:9000"
	return m
}

// codes collects the finding codes from a result, for assertion.
func codes(res VerifyResult) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.Code)
	}
	return out
}

func hasCode(res VerifyResult, code string) bool {
	for _, c := range codes(res) {
		if c == code {
			return true
		}
	}
	return false
}

func TestVerify(t *testing.T) {
	cfg := testCfg()

	cases := []struct {
		name              string
		sp                *spec.Spec
		labels            map[string]string
		fleetCallback     bool
		wantFindings      []string // exact set (order-independent) expected
		wantCallbackReq   bool
		wantCallbackSat   bool
		wantSkipped       bool
		wantProtected     []string
	}{
		{
			name:            "whole-host all wired, no findings, no callback",
			sp:              faSpec("whoami", "whoami.example.com"),
			labels:          whoamiWholeHost(),
			wantFindings:    nil,
			wantCallbackReq: false,
			wantCallbackSat: true,
			wantProtected:   []string{"whoami"},
		},
		{
			name:            "protected router missing middleware is a sticky unwired error",
			sp:              faSpec("whoami", "whoami.example.com"),
			labels:          map[string]string{"traefik.http.routers.whoami.rule": "Host(`whoami.example.com`)"},
			wantFindings:    []string{CodeUnwiredMiddleware},
			wantCallbackReq: false, // the sole router is protected, not a deliberate public one
			wantProtected:   []string{"whoami"},
		},
		{
			name:            "mixed host, no callback router, callback required and sticky",
			sp:              faSpec("travels", "travels.natecalvert.org", "travels-admin"),
			labels:          travelsMixed(),
			wantFindings:    []string{CodeMissingCallback},
			wantCallbackReq: true,
			wantCallbackSat: false,
			wantProtected:   []string{"travels-admin"},
		},
		{
			name:            "mixed host satisfied by container callback router",
			sp:              faSpec("travels", "travels.natecalvert.org", "travels-admin"),
			labels:          travelsFull(),
			wantFindings:    nil,
			wantCallbackReq: true,
			wantCallbackSat: true,
			wantProtected:   []string{"travels-admin"},
		},
		{
			name:            "mixed host satisfied by fleet catch-all",
			sp:              faSpec("travels", "travels.natecalvert.org", "travels-admin"),
			labels:          travelsMixed(),
			fleetCallback:   true,
			wantFindings:    nil,
			wantCallbackReq: true,
			wantCallbackSat: true,
			wantProtected:   []string{"travels-admin"},
		},
		{
			name:            "aboard.traefik.routers names a nonexistent router is an error",
			sp:              faSpec("travels", "travels.natecalvert.org", "does-not-exist"),
			labels:          travelsMixed(),
			wantFindings:    []string{CodeRouterUnknown, CodeMissingCallback},
			wantCallbackReq: true,
			wantProtected:   nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := Verify(cfg, c.sp, c.labels, c.fleetCallback)

			if res.Skipped != c.wantSkipped {
				t.Fatalf("Skipped = %v, want %v (reason %q)", res.Skipped, c.wantSkipped, res.Reason)
			}
			if got := codes(res); !sameSet(got, c.wantFindings) {
				t.Errorf("findings = %v, want %v", got, c.wantFindings)
			}
			if res.CallbackRequired != c.wantCallbackReq {
				t.Errorf("CallbackRequired = %v, want %v", res.CallbackRequired, c.wantCallbackReq)
			}
			if len(c.wantFindings) == 0 && res.CallbackSatisfied != c.wantCallbackSat {
				t.Errorf("CallbackSatisfied = %v, want %v", res.CallbackSatisfied, c.wantCallbackSat)
			}
			if !sameSet(res.ProtectedRouters, c.wantProtected) {
				t.Errorf("ProtectedRouters = %v, want %v", res.ProtectedRouters, c.wantProtected)
			}
		})
	}
}

func TestVerifyCallbackPriorityTooLow(t *testing.T) {
	// A callback router exists but sits at or below the public router's priority,
	// so it does not win the callback path. Public priority 5, callback 5.
	cfg := testCfg()
	labels := map[string]string{
		"traefik.http.routers.app.rule":               "Host(`app.example.com`)",
		"traefik.http.routers.app.priority":           "5",
		"traefik.http.routers.app-admin.rule":         "Host(`app.example.com`) && PathPrefix(`/admin`)",
		"traefik.http.routers.app-admin.middlewares":  "authentik@docker",
		"traefik.http.routers.app-cb.rule":            "Host(`app.example.com`) && PathPrefix(`/outpost.goauthentik.io/`)",
		"traefik.http.routers.app-cb.middlewares":     "authentik@docker",
		"traefik.http.routers.app-cb.priority":        "5",
	}
	sp := faSpec("app", "app.example.com", "app-admin")
	res := Verify(cfg, sp, labels, false)
	if !hasCode(res, CodeCallbackPriority) {
		t.Errorf("want callback-priority finding, got %v", codes(res))
	}
	if res.CallbackSatisfied {
		t.Error("CallbackSatisfied = true, want false (callback under-prioritized)")
	}
}

func TestVerifyCallbackPriorityComputed(t *testing.T) {
	// The suggested callback priority sits above every router on the host: travels
	// (1) and travels-admin (10) give 20, matching the live travels compose.
	cfg := testCfg()
	sp := faSpec("travels", "travels.natecalvert.org", "travels-admin")
	res := Verify(cfg, sp, travelsMixed(), false)
	if res.CallbackPriority != 20 {
		t.Errorf("CallbackPriority = %d, want 20 (above admin priority 10)", res.CallbackPriority)
	}
}

func TestVerifyProxyNoneSkips(t *testing.T) {
	cfg := testCfg()
	cfg.Proxy = config.ProxyNone
	res := Verify(cfg, faSpec("whoami", "whoami.example.com"), whoamiWholeHost(), false)
	if !res.Skipped || res.HasError() {
		t.Errorf("proxy none: Skipped=%v findings=%v, want skipped no-op", res.Skipped, codes(res))
	}
}

func TestVerifyOIDCSkips(t *testing.T) {
	cfg := testCfg()
	sp := faSpec("gitea", "git.natecalvert.org")
	sp.Provider = spec.ProviderOIDC
	res := Verify(cfg, sp, map[string]string{
		"traefik.http.routers.gitea.rule": "Host(`git.natecalvert.org`)",
	}, false)
	if !res.Skipped {
		t.Errorf("OIDC provider: Skipped=%v, want skipped (no Traefik half)", res.Skipped)
	}
}

func TestVerifyDefaultProtectsEveryHostRouter(t *testing.T) {
	// Without aboard.traefik.routers, the default protected set is every
	// host-matching non-callback router, so a bare public router beside a
	// protected one is flagged as unwired (its bareness is not declared
	// deliberate). This is why aboard.traefik.routers exists.
	cfg := testCfg()
	sp := faSpec("travels", "travels.natecalvert.org") // no named routers
	res := Verify(cfg, sp, travelsMixed(), false)
	if !hasCode(res, CodeUnwiredMiddleware) {
		t.Errorf("want unwired-middleware for the bare travels router, got %v", codes(res))
	}
	if !sameSet(res.ProtectedRouters, []string{"travels", "travels-admin"}) {
		t.Errorf("ProtectedRouters = %v, want both routers", res.ProtectedRouters)
	}
}

// sameSet reports whether a and b hold the same elements, ignoring order and
// nil-vs-empty.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
	}
	for _, v := range seen {
		if v != 0 {
			return false
		}
	}
	return true
}

// ensure discovery.Issue stays the finding type (compile-time guard).
var _ = []discovery.Issue(nil)
