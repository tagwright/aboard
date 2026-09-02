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

// twoOrphans is a canned orphan set: one OIDC (live credentials) and one proxy.
// The Orphans contract orders OIDC first, so the fake mirrors that.
func twoOrphans() []reconcile.Orphan {
	return []reconcile.Orphan{
		{Slug: "grafana", Kind: spec.ProviderOIDC, ProviderPK: 7, AppPK: "app-grafana"},
		{Slug: "wiki", Kind: spec.ProviderForwardAuth, ProviderPK: 3, AppPK: "app-wiki"},
	}
}

// emptyFleet is a lister with no enabled containers, so every owned object is an
// orphan.
func emptyFleet() *fakeLister {
	return &fakeLister{containers: []runtime.Container{}}
}

// TestRunPrune_DefaultDoesNotDeleteWithoutConfirmation is the security-critical
// gate: with neither --yes nor --dry-run, a "no" answer (here an empty reader,
// which is EOF) must delete NOTHING.
func TestRunPrune_DefaultDoesNotDeleteWithoutConfirmation(t *testing.T) {
	rec := &fakeReconciler{orphans: twoOrphans()}
	u, buf := newTestUI()

	err := runPrune(context.Background(), testConfig(), emptyFleet(), rec, pruneOptions{}, strings.NewReader(""), u)
	if err != nil {
		t.Fatalf("runPrune: %v", err)
	}
	if len(rec.teardowns) != 0 {
		t.Fatalf("SECURITY: prune deleted %v without confirmation", rec.teardowns)
	}
	if !strings.Contains(buf.String(), "aborted: nothing deleted") {
		t.Errorf("expected an aborted message, got:\n%s", buf.String())
	}
}

// TestRunPrune_DefaultNoAnswerDoesNotDelete proves an explicit "n" also deletes
// nothing.
func TestRunPrune_DefaultNoAnswerDoesNotDelete(t *testing.T) {
	rec := &fakeReconciler{orphans: twoOrphans()}
	u, _ := newTestUI()

	err := runPrune(context.Background(), testConfig(), emptyFleet(), rec, pruneOptions{}, strings.NewReader("n\n"), u)
	if err != nil {
		t.Fatalf("runPrune: %v", err)
	}
	if len(rec.teardowns) != 0 {
		t.Fatalf("SECURITY: prune deleted %v on a no answer", rec.teardowns)
	}
}

// TestRunPrune_ConfirmedDeletes proves an explicit "y" deletes every orphan, OIDC
// first.
func TestRunPrune_ConfirmedDeletes(t *testing.T) {
	rec := &fakeReconciler{orphans: twoOrphans()}
	u, buf := newTestUI()

	err := runPrune(context.Background(), testConfig(), emptyFleet(), rec, pruneOptions{}, strings.NewReader("y\n"), u)
	if err != nil {
		t.Fatalf("runPrune: %v", err)
	}
	if got, want := rec.teardowns, []string{"grafana", "wiki"}; !equalStrings(got, want) {
		t.Fatalf("expected teardowns %v, got %v", want, got)
	}
	if !strings.Contains(buf.String(), "pruned 2 orphan(s)") {
		t.Errorf("expected a pruned summary, got:\n%s", buf.String())
	}
}

// TestRunPrune_YesSkipsPrompt proves --yes deletes without consulting the reader.
func TestRunPrune_YesSkipsPrompt(t *testing.T) {
	rec := &fakeReconciler{orphans: twoOrphans()}
	u, _ := newTestUI()

	// A reader that would answer "no" if read: --yes must not read it.
	err := runPrune(context.Background(), testConfig(), emptyFleet(), rec, pruneOptions{Yes: true}, strings.NewReader("n\n"), u)
	if err != nil {
		t.Fatalf("runPrune: %v", err)
	}
	if len(rec.teardowns) != 2 {
		t.Fatalf("expected --yes to delete both orphans, got %v", rec.teardowns)
	}
}

// TestRunPrune_DryRunNeverDeletes proves --dry-run prints the plan and deletes
// nothing, even when --yes is also set (dry-run wins).
func TestRunPrune_DryRunNeverDeletes(t *testing.T) {
	rec := &fakeReconciler{orphans: twoOrphans()}
	u, buf := newTestUI()

	err := runPrune(context.Background(), testConfig(), emptyFleet(), rec, pruneOptions{Yes: true, DryRun: true}, strings.NewReader("y\n"), u)
	if err != nil {
		t.Fatalf("runPrune: %v", err)
	}
	if len(rec.teardowns) != 0 {
		t.Fatalf("SECURITY: dry-run deleted %v", rec.teardowns)
	}
	if !strings.Contains(buf.String(), "dry run: nothing deleted") {
		t.Errorf("expected a dry-run message, got:\n%s", buf.String())
	}
}

// TestRunPrune_CallsOutOIDCFirst proves the plan flags OIDC providers as live
// credentials, distinctly from proxy orphans.
func TestRunPrune_CallsOutOIDCFirst(t *testing.T) {
	rec := &fakeReconciler{orphans: twoOrphans()}
	u, buf := newTestUI()

	_ = runPrune(context.Background(), testConfig(), emptyFleet(), rec, pruneOptions{DryRun: true}, strings.NewReader(""), u)
	out := buf.String()
	if !strings.Contains(out, "LIVE client credentials") {
		t.Errorf("expected OIDC orphans called out as live credentials, got:\n%s", out)
	}
}

// TestRunPrune_NoOrphans proves prune is a clean no-op when nothing is orphaned.
func TestRunPrune_NoOrphans(t *testing.T) {
	rec := &fakeReconciler{orphans: nil}
	u, buf := newTestUI()

	err := runPrune(context.Background(), testConfig(), emptyFleet(), rec, pruneOptions{}, strings.NewReader(""), u)
	if err != nil {
		t.Fatalf("runPrune: %v", err)
	}
	if len(rec.teardowns) != 0 {
		t.Fatalf("expected no teardowns, got %v", rec.teardowns)
	}
	if !strings.Contains(buf.String(), "no orphans") {
		t.Errorf("expected a no-orphans message, got:\n%s", buf.String())
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
