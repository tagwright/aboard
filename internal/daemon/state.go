// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"sort"
	"sync"
	"time"

	"github.com/tagwright/aboard/internal/discovery"
)

// stickyEntry is one security-affecting error held until it is fixed. The
// architecture makes these sticky because a skipped container may be an app that
// is now open, or one whose access rule never landed, and letting that scroll off
// the operator's attention is unacceptable for a security tool. An entry names
// the service, slug, code, and message only, never a secret value.
type stickyEntry struct {
	Service   string
	Slug      string
	Code      string
	Message   string
	FirstSeen time.Time
	LastSeen  time.Time
}

// stickySet is the daemon's sticky-error state, keyed by slug then code. It is
// the digest's memory: reconcile updates a slug's entries in one shot
// (replaceSlug), a clean reconcile clears them, and a removed container's slug is
// dropped when it leaves the enabled set (retainSlugs). There is no datastore;
// this lives only in memory and is rebuilt from the fleet on restart.
type stickySet struct {
	mu     sync.Mutex
	bySlug map[string]map[string]stickyEntry
}

// newStickySet builds an empty set.
func newStickySet() *stickySet {
	return &stickySet{bySlug: map[string]map[string]stickyEntry{}}
}

// replaceSlug makes the given error issues the complete sticky set for slug: a
// code no longer present is cleared (the gate was fixed), a code still present
// keeps its original FirstSeen (so the digest can show how long it has been
// broken), and a code not seen before is returned as newly-added so the caller
// can fire an immediate alert. Only SeverityError issues are sticky; warnings and
// infos are transient and never enter the set.
func (s *stickySet) replaceSlug(slug, service string, issues []discovery.Issue, now time.Time) []stickyEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.bySlug[slug]
	next := map[string]stickyEntry{}
	var added []stickyEntry
	for _, is := range issues {
		if is.Severity != discovery.SeverityError {
			continue
		}
		e := stickyEntry{
			Service:   service,
			Slug:      slug,
			Code:      is.Code,
			Message:   is.Message,
			FirstSeen: now,
			LastSeen:  now,
		}
		if prev, ok := old[is.Code]; ok {
			e.FirstSeen = prev.FirstSeen
		} else {
			added = append(added, e)
		}
		next[is.Code] = e
	}

	if len(next) == 0 {
		delete(s.bySlug, slug)
	} else {
		s.bySlug[slug] = next
	}
	return added
}

// clearSlug drops every sticky entry for slug. Used when a slug's container is
// gone and its errors can no longer be acted on from labels.
func (s *stickySet) clearSlug(slug string) {
	s.mu.Lock()
	delete(s.bySlug, slug)
	s.mu.Unlock()
}

// retainSlugs drops every slug not in keep. It runs after an orphan recompute:
// a slug with no enabled container can no longer be fixed by editing labels, so
// its stale sticky errors are cleared and the orphan surfacing takes over.
func (s *stickySet) retainSlugs(keep []string) {
	set := make(map[string]struct{}, len(keep))
	for _, k := range keep {
		set[k] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for slug := range s.bySlug {
		if _, ok := set[slug]; !ok {
			delete(s.bySlug, slug)
		}
	}
}

// list returns every sticky entry in a stable order (by slug, then code), for
// the digest.
func (s *stickySet) list() []stickyEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []stickyEntry
	for _, byCode := range s.bySlug {
		for _, e := range byCode {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Slug != out[j].Slug {
			return out[i].Slug < out[j].Slug
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// count reports the total number of sticky entries.
func (s *stickySet) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, byCode := range s.bySlug {
		n += len(byCode)
	}
	return n
}
