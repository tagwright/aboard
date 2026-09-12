// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tagwright/courier"

	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/spec"
)

// Fix 2: a newly-detected orphan that is STILL attached to the outpost fires an
// immediate Error-level beacon alert, rather than waiting silently for the daily
// digest. A renamed-away app left attached is the exact collision that turned
// fatal, so its detection must surface the moment it appears.
func TestRefreshOrphans_AttachedOrphanAlertsImmediately(t *testing.T) {
	rec := &fakeReconciler{orphans: []reconcile.Orphan{
		{Slug: "fantasy-old", Kind: spec.ProviderForwardAuth, ProviderPK: 9, Attached: true},
	}}
	capture := &capturingNotifier{}

	d, err := New(Config{
		Runtime:    newFakeRuntime(),
		Reconciler: rec,
		Notifier:   capture,
		Config:     testConfig(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	d.refreshOrphans(context.Background(), nil)

	capture.mu.Lock()
	defer capture.mu.Unlock()
	found := false
	for _, n := range capture.notes {
		if n.Level == courier.LevelError && strings.Contains(n.Title, "attached to outpost") {
			found = true
		}
	}
	if !found {
		t.Fatalf("an attached orphan must fire an immediate Error alert; got %+v", capture.notes)
	}
}

// The de-dup negative fixture: an orphan already in the previous set is NOT
// re-alerted on the next scan, so a standing orphan does not spam the operator on
// every refresh.
func TestRefreshOrphans_KnownOrphanNotReAlerted(t *testing.T) {
	rec := &fakeReconciler{orphans: []reconcile.Orphan{
		{Slug: "fantasy-old", Kind: spec.ProviderForwardAuth, ProviderPK: 9, Attached: true},
	}}
	capture := &capturingNotifier{}
	d, err := New(Config{
		Runtime:    newFakeRuntime(),
		Reconciler: rec,
		Notifier:   capture,
		Config:     testConfig(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	d.refreshOrphans(context.Background(), nil) // first sight: one alert
	d.refreshOrphans(context.Background(), nil) // same orphan: no new alert

	capture.mu.Lock()
	defer capture.mu.Unlock()
	alerts := 0
	for _, n := range capture.notes {
		if strings.Contains(n.Title, "attached to outpost") {
			alerts++
		}
	}
	if alerts != 1 {
		t.Fatalf("a known orphan must alert once, not on every scan; got %d alerts", alerts)
	}
}

// Fix 4: the digest carries the CONFIRMED section (what aboard last wrote to
// Authentik and whether the go-live was confirmed) and flags an orphan still
// attached to the outpost, so a reader cannot mistake discovered for live.
func TestComposeDigest_ConfirmedSectionAndAttachedOrphan(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	orphans := []reconcile.Orphan{
		{Slug: "fantasy-old", Kind: spec.ProviderForwardAuth, ProviderPK: 9, Attached: true},
	}
	applied := []appliedView{
		{Slug: "whoami", Provider: spec.ProviderForwardAuth, Attached: false, When: now},
	}

	n := composeDigest(nil, orphans, applied, now)

	if !strings.Contains(n.Body, "STILL ATTACHED") {
		t.Errorf("digest must flag an attached orphan as a collision risk:\n%s", n.Body)
	}
	if !strings.Contains(n.Body, "Last confirmed Authentik writes") {
		t.Errorf("digest must carry the confirmed-state section:\n%s", n.Body)
	}
	if !strings.Contains(n.Body, "NOT confirmed live") {
		t.Errorf("an unverified go-live must read as NOT confirmed live, not as success:\n%s", n.Body)
	}
}
