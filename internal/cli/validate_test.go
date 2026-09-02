// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/tagwright/core/runtime"
)

// TestRunValidate_CleanFleetNoError proves a fleet of valid labels reports no
// error and exits zero (hasError false).
func TestRunValidate_CleanFleetNoError(t *testing.T) {
	l := &fakeLister{containers: []runtime.Container{
		container("app-good", map[string]string{
			"aboard.enable": "true",
			"aboard.host":   "good.example.com",
			"traefik.http.routers.good.rule":        "Host(`good.example.com`)",
			"traefik.http.routers.good.middlewares": "authentik@docker",
		}),
	}}

	u, buf := newTestUI()
	hasError, err := runValidate(context.Background(), testConfig(), l, u)
	if err != nil {
		t.Fatalf("runValidate: %v", err)
	}
	if hasError {
		t.Fatalf("clean fleet reported an error:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "no errors") {
		t.Errorf("expected a no-errors verdict, got:\n%s", buf.String())
	}
}

// TestRunValidate_ErrorExitsNonzero proves a container with a discovery Error
// makes validate report hasError true (the nonzero-exit signal), and that the
// offending code is printed.
func TestRunValidate_ErrorExitsNonzero(t *testing.T) {
	l := &fakeLister{containers: []runtime.Container{
		container("app-good", map[string]string{
			"aboard.enable": "true",
			"aboard.host":   "good.example.com",
		}),
		container("app-bad", map[string]string{
			"aboard.enable":   "true",
			"aboard.host":     "bad.example.com",
			"aboard.provider": "bogus",
		}),
	}}

	u, buf := newTestUI()
	hasError, err := runValidate(context.Background(), testConfig(), l, u)
	if err != nil {
		t.Fatalf("runValidate: %v", err)
	}
	if !hasError {
		t.Fatalf("expected hasError=true for an invalid provider, output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "provider-invalid") {
		t.Errorf("expected the provider-invalid code in output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "errors found") {
		t.Errorf("expected an errors-found verdict:\n%s", buf.String())
	}
}

// TestRunValidate_SkipsSelfExcluded proves the IdP aboard drives is never reported
// on, even if it were labelled: self-exclusion is defence in depth.
func TestRunValidate_SkipsSelfExcluded(t *testing.T) {
	authentik := container("authentik-server", map[string]string{
		"aboard.enable": "true",
		"aboard.host":   "auth.example.com",
	})
	authentik.Image = "ghcr.io/goauthentik/server:2025.6.4"

	l := &fakeLister{containers: []runtime.Container{authentik}}
	u, buf := newTestUI()
	hasError, err := runValidate(context.Background(), testConfig(), l, u)
	if err != nil {
		t.Fatalf("runValidate: %v", err)
	}
	if hasError {
		t.Fatalf("self-excluded container should not produce an error")
	}
	if !strings.Contains(buf.String(), "no aboard-labelled containers found") {
		t.Errorf("expected the empty-fleet summary, got:\n%s", buf.String())
	}
}
