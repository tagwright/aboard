// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"testing"
	"time"

	"github.com/tagwright/aboard/internal/discovery"
)

// TestStickyReplaceAndRetain proves the sticky-set lifecycle: a first error is
// newly-added, a persisting error keeps its FirstSeen, a fixed error clears, and
// a slug that leaves the enabled set is dropped by retention.
func TestStickyReplaceAndRetain(t *testing.T) {
	s := newStickySet()
	t0 := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)

	errIssue := discovery.Issue{Severity: discovery.SeverityError, Code: "unwired-middleware", Message: "no middleware"}
	warnIssue := discovery.Issue{Severity: discovery.SeverityWarning, Code: "binding-removed", Message: "removed a binding"}

	// First sighting: the error is newly-added, the warning is not sticky.
	added := s.replaceSlug("nutrition", "nutrition", []discovery.Issue{errIssue, warnIssue}, t0)
	if len(added) != 1 || added[0].Code != "unwired-middleware" {
		t.Fatalf("first replace added = %v, want the one error", added)
	}
	if s.count() != 1 {
		t.Fatalf("sticky count = %d, want 1 (warning must not be sticky)", s.count())
	}

	// Same error persists at t1: not newly-added, FirstSeen preserved.
	added = s.replaceSlug("nutrition", "nutrition", []discovery.Issue{errIssue}, t1)
	if len(added) != 0 {
		t.Fatalf("persisting error should not be newly-added, got %v", added)
	}
	if got := s.list()[0].FirstSeen; !got.Equal(t0) {
		t.Fatalf("FirstSeen = %v, want the original %v", got, t0)
	}

	// Error fixed: replacing with no errors clears the slug.
	added = s.replaceSlug("nutrition", "nutrition", nil, t1)
	if len(added) != 0 || s.count() != 0 {
		t.Fatalf("clearing a fixed error should empty the set, count = %d", s.count())
	}

	// Retention drops a slug no longer enabled.
	s.replaceSlug("gone", "gone", []discovery.Issue{errIssue}, t1)
	s.replaceSlug("kept", "kept", []discovery.Issue{errIssue}, t1)
	s.retainSlugs([]string{"kept"})
	list := s.list()
	if len(list) != 1 || list[0].Slug != "kept" {
		t.Fatalf("after retain, sticky = %v, want only [kept]", list)
	}
}
