// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"testing"

	"github.com/tagwright/core/runtime"
)

// TestDetectFleetCallback covers the fleet catch-all detection over label maps: a
// broad HostRegexp callback router satisfies the mixed-host rule fleet-wide, a
// per-app literal-Host callback does not, and a fleet with no callback router
// yields false.
func TestDetectFleetCallback(t *testing.T) {
	fleetCatchAll := runtime.Container{
		Name:  "authentik-server",
		Image: "ghcr.io/goauthentik/server:2025.6.4",
		Labels: map[string]string{
			"traefik.http.routers.ak-outpost.rule": "HostRegexp(`^.+\\.natecalvert\\.org$`) && PathPrefix(`/outpost.goauthentik.io/`)",
		},
	}
	perAppCallback := runtime.Container{
		Name:  "travels",
		Image: "example/travels",
		Labels: map[string]string{
			"traefik.http.routers.travels-outpost.rule": "Host(`travels.natecalvert.org`) && PathPrefix(`/outpost.goauthentik.io/`)",
		},
	}
	plainApp := runtime.Container{
		Name:  "whoami",
		Image: "traefik/whoami",
		Labels: map[string]string{
			"traefik.http.routers.whoami.rule": "Host(`whoami.natecalvert.org`)",
		},
	}

	cases := []struct {
		name  string
		conts []runtime.Container
		want  bool
	}{
		{"fleet HostRegexp catch-all present", []runtime.Container{plainApp, fleetCatchAll}, true},
		{"only a per-app literal-Host callback", []runtime.Container{perAppCallback, plainApp}, false},
		{"no callback router at all", []runtime.Container{plainApp}, false},
		{"empty fleet", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectFleetCallback(tc.conts); got != tc.want {
				t.Fatalf("detectFleetCallback = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSelfExclusion covers the defensive skip: aboard never acts on the Authentik
// containers it drives or on its own container, whatever their labels say.
func TestSelfExclusion(t *testing.T) {
	cases := []struct {
		name string
		c    runtime.Container
		want bool
	}{
		{"authentik server by image", runtime.Container{Image: "ghcr.io/goauthentik/server:2025.6.4", Service: "authentik-server"}, true},
		{"authentik worker by service", runtime.Container{Image: "someregistry/thing", Service: "authentik-worker"}, true},
		{"aboard itself by image", runtime.Container{Image: "tagwright/aboard:latest", Service: "aboard"}, true},
		{"ordinary app is not excluded", runtime.Container{Image: "example/nutrition", Service: "nutrition"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSelfExcluded(tc.c); got != tc.want {
				t.Fatalf("isSelfExcluded = %v, want %v", got, tc.want)
			}
		})
	}
}
