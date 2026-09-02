// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/spec"
)

// TestRunStatus_ReportsAppsAndOrphans proves the read-only report lists an enabled
// application, its slug, and the orphan set with OIDC called out as live
// credentials. It never calls Teardown.
func TestRunStatus_ReportsAppsAndOrphans(t *testing.T) {
	l := &fakeLister{containers: []runtime.Container{
		container("wiki", map[string]string{
			"aboard.enable":                         "true",
			"aboard.host":                           "wiki.example.com",
			"traefik.http.routers.wiki.rule":        "Host(`wiki.example.com`)",
			"traefik.http.routers.wiki.middlewares": "authentik@docker",
		}),
	}}
	rec := &fakeReconciler{orphans: []reconcile.Orphan{
		{Slug: "grafana", Kind: spec.ProviderOIDC, ProviderPK: 7, AppPK: "app-grafana"},
	}}

	u, buf := newTestUI()
	if err := runStatus(context.Background(), testConfig(), l, rec, u); err != nil {
		t.Fatalf("runStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Enabled applications") || !strings.Contains(out, "wiki") {
		t.Errorf("expected the enabled app wiki, got:\n%s", out)
	}
	if !strings.Contains(out, "Orphans") || !strings.Contains(out, "grafana") {
		t.Errorf("expected the grafana orphan, got:\n%s", out)
	}
	if !strings.Contains(out, "live client credentials") {
		t.Errorf("expected OIDC orphan flagged as live credentials, got:\n%s", out)
	}
	if len(rec.teardowns) != 0 {
		t.Fatalf("status must never delete, but Teardown was called: %v", rec.teardowns)
	}
}
