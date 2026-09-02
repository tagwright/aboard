// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package traefik

import (
	"reflect"
	"testing"
)

func TestParseRouters(t *testing.T) {
	// The travels full compose shape: public router, protected admin router, and
	// the outpost callback router, plus the two service definitions.
	labels := travelsFull()

	routers := ParseRouters(labels)
	if len(routers) != 3 {
		t.Fatalf("parsed %d routers, want 3 (%v)", len(routers), routerNames(routers))
	}

	pub := routers["travels"]
	if pub == nil {
		t.Fatal("travels router not parsed")
	}
	if got := pub.Hosts; !reflect.DeepEqual(got, []string{"travels.natecalvert.org"}) {
		t.Errorf("travels hosts = %v, want [travels.natecalvert.org]", got)
	}
	if pub.HasPath {
		t.Error("travels HasPath = true, want false (bare Host rule)")
	}
	if pub.HasMiddleware("authentik@docker") {
		t.Error("travels carries middleware, want none (public router)")
	}
	if pub.EffectivePriority() != 1 {
		t.Errorf("travels priority = %d, want 1", pub.EffectivePriority())
	}
	if pub.IsCallback() {
		t.Error("travels IsCallback = true, want false")
	}

	admin := routers["travels-admin"]
	if !admin.HasPath {
		t.Error("travels-admin HasPath = false, want true (PathPrefix /admin)")
	}
	if !admin.HasMiddleware("authentik@docker") {
		t.Error("travels-admin should carry the middleware")
	}
	if admin.IsCallback() {
		t.Error("travels-admin IsCallback = true, want false")
	}

	cb := routers["travels-outpost"]
	if !cb.IsCallback() {
		t.Error("travels-outpost IsCallback = false, want true (PathPrefix /outpost.goauthentik.io/)")
	}
	if cb.EffectivePriority() != 20 {
		t.Errorf("travels-outpost priority = %d, want 20", cb.EffectivePriority())
	}
	if cb.Service != "authentik-svc" {
		t.Errorf("travels-outpost service = %q, want authentik-svc", cb.Service)
	}
}

func TestEffectivePriorityDefault(t *testing.T) {
	// No explicit priority: Traefik defaults to the rule length.
	labels := map[string]string{
		"traefik.http.routers.x.rule": "Host(`x.example.com`)",
	}
	r := ParseRouters(labels)["x"]
	if got, want := r.EffectivePriority(), len("Host(`x.example.com`)"); got != want {
		t.Errorf("default priority = %d, want rule length %d", got, want)
	}
}

func TestIsCallbackRuleShapes(t *testing.T) {
	cases := []struct {
		rule string
		want bool
	}{
		{"Host(`h`) && PathPrefix(`/outpost.goauthentik.io/`)", true},
		{"Host(`h`) && PathPrefix(`/admin`)", false},
		{"Host(`h`)", false},
	}
	for _, c := range cases {
		if got := isCallbackRule(c.rule); got != c.want {
			t.Errorf("isCallbackRule(%q) = %v, want %v", c.rule, got, c.want)
		}
	}
}

func routerNames(m map[string]*Router) []string {
	var out []string
	for n := range m {
		out = append(out, n)
	}
	return out
}
