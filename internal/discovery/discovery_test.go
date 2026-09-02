// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package discovery

import (
	"reflect"
	"testing"

	"github.com/tagwright/aboard/internal/config"
)

// traefikProxy is a minimal config with the Traefik proxy on, the default fleet.
func traefikProxy() *config.Config {
	return &config.Config{Proxy: config.ProxyTraefik}
}

// noneProxy is a minimal config with the proxy off (a Caddy or nginx fleet).
func noneProxy() *config.Config {
	return &config.Config{Proxy: config.ProxyNone}
}

// hostRule is the single-router label set that infers one host, so a table case
// that is not exercising host inference still resolves a host.
func hostRule(h string) map[string]string {
	return map[string]string{"traefik.http.routers.app.rule": "Host(`" + h + "`)"}
}

// with merges extra labels onto a base map, returning a new map.
func with(base map[string]string, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func hasCode(issues []Issue, code string) bool {
	for _, i := range issues {
		if i.Code == code {
			return true
		}
	}
	return false
}

func TestDiscoverNotEnabled(t *testing.T) {
	// Absent enable, no other aboard labels: inert, no warning.
	sp, issues := Discover(traefikProxy(), Input{ContainerName: "svc", Labels: hostRule("svc.example.com")})
	if sp.Enable {
		t.Error("Enable should be false when aboard.enable is absent")
	}
	if len(issues) != 0 {
		t.Errorf("no aboard labels means no issues, got %v", issues)
	}
}

func TestDiscoverEnableFalseAlone(t *testing.T) {
	// A lone aboard.enable=false is a deliberate disable, not unarmed.
	_, issues := Discover(traefikProxy(), Input{ContainerName: "svc",
		Labels: with(hostRule("svc.example.com"), map[string]string{"aboard.enable": "false"})})
	if len(issues) != 0 {
		t.Errorf("lone enable=false must not warn, got %v", issues)
	}
}

func TestDiscoverUnarmed(t *testing.T) {
	// aboard.* labels present without the gate: declared-but-unarmed warning.
	sp, issues := Discover(traefikProxy(), Input{ContainerName: "svc",
		Labels: map[string]string{"aboard.groups": "staff"}})
	if sp.Enable {
		t.Error("Enable should be false")
	}
	if !hasCode(issues, CodeUnarmed) {
		t.Errorf("want unarmed warning, got %v", issues)
	}
	if HasError(issues) {
		t.Errorf("unarmed is a warning, not an error: %v", issues)
	}
}

func TestDiscoverTable(t *testing.T) {
	base := hostRule("app.example.com")
	en := func(extra map[string]string) map[string]string {
		return with(base, with(map[string]string{"aboard.enable": "true"}, extra))
	}

	cases := []struct {
		name    string
		cfg     *config.Config
		labels  map[string]string
		wantErr string // an expected error code, "" for none
	}{
		{"minimal ok", traefikProxy(), en(nil), ""},
		{"unknown suffix", traefikProxy(), en(map[string]string{"aboard.grops": "x"}), CodeUnknownSuffix},
		{"saml rejected", traefikProxy(), en(map[string]string{"aboard.provider": "saml"}), CodeSAMLReserved},
		{"provider invalid", traefikProxy(), en(map[string]string{"aboard.provider": "ldap"}), CodeProviderInvalid},
		{"require invalid", traefikProxy(), en(map[string]string{"aboard.require": "some"}), CodeRequireInvalid},
		{"slug invalid", traefikProxy(), en(map[string]string{"aboard.slug": "Bad_Slug"}), CodeSlugInvalid},
		{"users reserved", traefikProxy(), en(map[string]string{"aboard.users": "nate"}), CodeReserved},
		{"saml subns reserved", traefikProxy(), en(map[string]string{"aboard.saml.metadata": "x"}), CodeReserved},
		{"caddy reserved", traefikProxy(), en(map[string]string{"aboard.caddy.foo": "x"}), CodeReserved},

		// Typed sub-namespace under the wrong provider.
		{"oidc key under forwardauth", traefikProxy(),
			en(map[string]string{"aboard.oidc.redirect": "https://app.example.com/cb"}), CodeWrongProvider},
		{"outpost under oidc", traefikProxy(),
			en(map[string]string{"aboard.provider": "oidc", "aboard.outpost": "remote",
				"aboard.oidc.redirect": "https://app.example.com/cb", "aboard.oidc.secret": "s"}), CodeWrongProvider},
		{"traefik.routers under oidc", traefikProxy(),
			en(map[string]string{"aboard.provider": "oidc", "aboard.traefik.routers": "r",
				"aboard.oidc.redirect": "https://app.example.com/cb", "aboard.oidc.secret": "s"}), CodeWrongProvider},

		// proxy: none forbids aboard.traefik.*.
		{"traefik under proxy none", noneProxy(),
			en(map[string]string{"aboard.traefik.routers": "r"}), CodeProxyNoneTraefik},

		// OIDC required-field rules.
		{"oidc missing redirect", traefikProxy(),
			en(map[string]string{"aboard.provider": "oidc", "aboard.oidc.secret": "s"}), CodeOIDCRedirectMissing},
		{"oidc confidential missing secret", traefikProxy(),
			en(map[string]string{"aboard.provider": "oidc", "aboard.oidc.redirect": "https://app.example.com/cb"}), CodeOIDCSecretMissing},
		{"oidc public forbids secret", traefikProxy(),
			en(map[string]string{"aboard.provider": "oidc", "aboard.oidc.client": "public",
				"aboard.oidc.redirect": "https://app.example.com/cb", "aboard.oidc.secret": "s"}), CodeOIDCSecretForbidden},
		{"oidc redirect not absolute", traefikProxy(),
			en(map[string]string{"aboard.provider": "oidc", "aboard.oidc.secret": "s",
				"aboard.oidc.redirect": "/relative/path"}), CodeOIDCRedirectInvalid},
		{"oidc client invalid", traefikProxy(),
			en(map[string]string{"aboard.provider": "oidc", "aboard.oidc.secret": "s",
				"aboard.oidc.client": "hybrid", "aboard.oidc.redirect": "https://app.example.com/cb"}), CodeClientInvalid},
		{"oidc public ok", traefikProxy(),
			en(map[string]string{"aboard.provider": "oidc", "aboard.oidc.client": "public",
				"aboard.oidc.redirect": "https://app.example.com/cb"}), ""},

		// csv and indexed escape both present.
		{"indexed conflict", traefikProxy(),
			en(map[string]string{"aboard.provider": "oidc", "aboard.oidc.secret": "s",
				"aboard.oidc.redirect": "https://app.example.com/a", "aboard.oidc.redirect.0": "https://app.example.com/b"}), CodeIndexedConflict},
		{"indexed non-integer", traefikProxy(),
			en(map[string]string{"aboard.provider": "oidc", "aboard.oidc.secret": "s",
				"aboard.oidc.redirect.x": "https://app.example.com/b"}), CodeIndexedInvalid},

		// Host.
		{"explicit host scheme", traefikProxy(),
			en(map[string]string{"aboard.host": "https://app.example.com"}), CodeHostInvalid},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, issues := Discover(c.cfg, Input{ContainerName: "app", Labels: c.labels})
			if c.wantErr == "" {
				if HasError(issues) {
					t.Fatalf("want no error, got %v", issues)
				}
				return
			}
			if !hasCode(issues, c.wantErr) {
				t.Fatalf("want code %q, got %v", c.wantErr, issues)
			}
		})
	}
}

func TestDiscoverGroupsThreeState(t *testing.T) {
	base := with(hostRule("app.example.com"), map[string]string{"aboard.enable": "true"})

	// Unset: use the fleet default, GroupsSet false.
	sp, _ := Discover(traefikProxy(), Input{ContainerName: "app", Labels: base})
	if sp.GroupsSet {
		t.Error("groups unset must leave GroupsSet false")
	}

	// Explicit none: GroupsSet true, empty, GroupsNone true.
	sp, _ = Discover(traefikProxy(), Input{ContainerName: "app",
		Labels: with(base, map[string]string{"aboard.groups": "none"})})
	if !sp.GroupsSet || !sp.GroupsNone() || len(sp.Groups) != 0 {
		t.Errorf("groups=none: GroupsSet=%v GroupsNone=%v Groups=%v", sp.GroupsSet, sp.GroupsNone(), sp.Groups)
	}

	// A list: GroupsSet true, GroupsNone false.
	sp, _ = Discover(traefikProxy(), Input{ContainerName: "app",
		Labels: with(base, map[string]string{"aboard.groups": "admins, staff"})})
	if !sp.GroupsSet || sp.GroupsNone() || !reflect.DeepEqual(sp.Groups, []string{"admins", "staff"}) {
		t.Errorf("groups list: GroupsSet=%v GroupsNone=%v Groups=%v", sp.GroupsSet, sp.GroupsNone(), sp.Groups)
	}
}

func TestDiscoverCosmeticSetFlags(t *testing.T) {
	base := with(hostRule("app.example.com"), map[string]string{"aboard.enable": "true"})

	// Absent: untouched, no set flags.
	sp, _ := Discover(traefikProxy(), Input{ContainerName: "app", Labels: base})
	if sp.LaunchSet || sp.IconSet || sp.DescriptionSet {
		t.Error("absent cosmetic labels must leave set flags false")
	}

	// Present: managed.
	sp, _ = Discover(traefikProxy(), Input{ContainerName: "app", Labels: with(base, map[string]string{
		"aboard.launch":      "none",
		"aboard.icon":        "https://cdn.example.com/i.png",
		"aboard.description": "An app",
	})})
	if !sp.LaunchSet || !sp.LaunchNone {
		t.Errorf("launch=none: LaunchSet=%v LaunchNone=%v", sp.LaunchSet, sp.LaunchNone)
	}
	if !sp.IconSet || sp.Icon != "https://cdn.example.com/i.png" {
		t.Errorf("icon: IconSet=%v Icon=%q", sp.IconSet, sp.Icon)
	}
	if !sp.DescriptionSet || sp.Description != "An app" {
		t.Errorf("description: DescriptionSet=%v Description=%q", sp.DescriptionSet, sp.Description)
	}
}

func TestDiscoverIndexedRedirectEscape(t *testing.T) {
	// The indexed escape carries one literal value per label, even one with a
	// comma, and assembles in index order.
	labels := with(hostRule("app.example.com"), map[string]string{
		"aboard.enable":          "true",
		"aboard.provider":        "oidc",
		"aboard.oidc.secret":     "gitea-secret",
		"aboard.oidc.redirect.1": "https://app.example.com/second",
		"aboard.oidc.redirect.0": "https://app.example.com/first",
	})
	sp, issues := Discover(traefikProxy(), Input{ContainerName: "app", Labels: labels})
	if HasError(issues) {
		t.Fatalf("unexpected error: %v", issues)
	}
	want := []string{"https://app.example.com/first", "https://app.example.com/second"}
	if !reflect.DeepEqual(sp.OIDC.Redirect, want) {
		t.Errorf("redirect = %v, want %v", sp.OIDC.Redirect, want)
	}
}
