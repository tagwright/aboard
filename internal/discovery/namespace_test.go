// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package discovery

import "testing"

func TestStripPrefix(t *testing.T) {
	cases := []struct {
		key    string
		suffix string
		ok     bool
	}{
		{"aboard.enable", "enable", true},
		{"tagwright.auth.enable", "enable", true},
		{"aboard.oidc.redirect", "oidc.redirect", true},
		{"tagwright.auth.oidc.redirect", "oidc.redirect", true},
		{"aboard.", "", false},          // empty suffix is not a label
		{"tagwright.auth.", "", false},  // empty suffix is not a label
		{"traefik.http.routers.x.rule", "", false},
		{"tagwright.backup.enable", "", false}, // a different tool's namespace
		{"com.docker.compose.service", "", false},
	}
	for _, c := range cases {
		suffix, ok := stripPrefix(c.key)
		if ok != c.ok || suffix != c.suffix {
			t.Errorf("stripPrefix(%q) = (%q, %v), want (%q, %v)", c.key, suffix, ok, c.suffix, c.ok)
		}
	}
}

func TestMergeNamespacesConflict(t *testing.T) {
	// Same suffix under both prefixes with DIFFERENT values is an error.
	norm, issues := mergeNamespaces(map[string]string{
		"aboard.title":         "One",
		"tagwright.auth.title": "Two",
	})
	if !HasError(issues) {
		t.Fatalf("different values across prefixes must conflict, got %v", issues)
	}
	if issues[0].Code != CodeConflict {
		t.Errorf("code = %q, want %q", issues[0].Code, CodeConflict)
	}
	// The first-seen value (sorted key order: aboard.* sorts before tagwright.*)
	// is kept so the rest of discovery can still run.
	if norm["title"] != "One" {
		t.Errorf("kept value = %q, want %q", norm["title"], "One")
	}
}

func TestMergeNamespacesSameValueHarmless(t *testing.T) {
	// Same suffix under both prefixes with the SAME value is harmless.
	norm, issues := mergeNamespaces(map[string]string{
		"aboard.enable":         "true",
		"tagwright.auth.enable": "true",
	})
	if len(issues) != 0 {
		t.Fatalf("identical values must not conflict, got %v", issues)
	}
	if norm["enable"] != "true" {
		t.Errorf("enable = %q, want true", norm["enable"])
	}
}

func TestMergeNamespacesIgnoresForeign(t *testing.T) {
	norm, issues := mergeNamespaces(map[string]string{
		"aboard.enable":       "true",
		"traefik.enable":      "true",
		"some.other.label":    "x",
		"tagwright.backup.tag": "y",
	})
	if len(issues) != 0 {
		t.Fatalf("foreign labels must be ignored, got %v", issues)
	}
	if len(norm) != 1 || norm["enable"] != "true" {
		t.Errorf("norm = %v, want only {enable: true}", norm)
	}
}
