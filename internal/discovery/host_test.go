// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package discovery

import "testing"

func TestValidateExplicitHost(t *testing.T) {
	cases := []struct {
		host string
		ok   bool
	}{
		{"app.example.com", true},
		{"nutrition.natecalvert.org", true},
		{"https://app.example.com", false}, // scheme
		{"app.example.com/admin", false},   // path
		{"app.example.com:8080", false},    // port
		{"app example.com", false},         // whitespace
		{"", false},                        // empty
	}
	for _, c := range cases {
		iss := validateExplicitHost(c.host)
		if (iss == nil) != c.ok {
			t.Errorf("validateExplicitHost(%q): ok=%v, want %v (issue=%v)", c.host, iss == nil, c.ok, iss)
		}
		if iss != nil && iss.Code != CodeHostInvalid {
			t.Errorf("validateExplicitHost(%q) code = %q, want %q", c.host, iss.Code, CodeHostInvalid)
		}
	}
}

func TestInferHostSingle(t *testing.T) {
	labels := map[string]string{
		"traefik.http.routers.whoami.rule": "Host(`whoami.example.com`)",
	}
	host, iss := inferHost(labels)
	if iss != nil {
		t.Fatalf("unexpected issue: %v", iss)
	}
	if host != "whoami.example.com" {
		t.Errorf("host = %q, want whoami.example.com", host)
	}
}

func TestInferHostMultipleRoutersOneHost(t *testing.T) {
	// The travels pattern: several routers, one distinct host, with a Host() &&
	// PathPrefix() combined matcher. Inference counts DISTINCT hosts, so it works.
	labels := map[string]string{
		"traefik.http.routers.travels.rule":       "Host(`travels.natecalvert.org`)",
		"traefik.http.routers.travels-admin.rule": "Host(`travels.natecalvert.org`) && PathPrefix(`/admin`)",
	}
	host, iss := inferHost(labels)
	if iss != nil {
		t.Fatalf("unexpected issue: %v", iss)
	}
	if host != "travels.natecalvert.org" {
		t.Errorf("host = %q, want travels.natecalvert.org", host)
	}
}

func TestInferHostAmbiguous(t *testing.T) {
	labels := map[string]string{
		"traefik.http.routers.a.rule": "Host(`a.example.com`)",
		"traefik.http.routers.b.rule": "Host(`b.example.com`)",
	}
	_, iss := inferHost(labels)
	if iss == nil || iss.Code != CodeHostAmbiguous {
		t.Fatalf("want host-ambiguous, got %v", iss)
	}
}

func TestInferHostZero(t *testing.T) {
	labels := map[string]string{
		"traefik.enable": "true",
	}
	_, iss := inferHost(labels)
	if iss == nil || iss.Code != CodeHostMissing {
		t.Fatalf("want host-missing, got %v", iss)
	}
}

func TestInferHostRegexp(t *testing.T) {
	// Any HostRegexp/HostSNI is unparseable as a literal, an error even if it is
	// the only matcher.
	labels := map[string]string{
		"traefik.http.routers.x.rule": "HostRegexp(`^.+\\.example\\.com$`)",
	}
	_, iss := inferHost(labels)
	if iss == nil || iss.Code != CodeHostAmbiguous {
		t.Fatalf("want host-ambiguous for HostRegexp, got %v", iss)
	}
}
