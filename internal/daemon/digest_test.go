// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/tagwright/beacon"

	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/spec"
)

// TestComposeDigestOrdersAndCounts proves the digest assembly: sticky errors lead
// the body, orphaned OIDC providers (live credentials) are listed before
// orphaned proxy providers, the level escalates to error, and the fields carry
// machine-readable counts.
func TestComposeDigestOrdersAndCounts(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	sticky := []stickyEntry{
		{Service: "nutrition", Slug: "nutrition", Code: "unwired-middleware", Message: "router carries no forward-auth middleware", FirstSeen: now, LastSeen: now},
	}
	orphans := []reconcile.Orphan{
		{Slug: "gitea", Kind: spec.ProviderOIDC},
		{Slug: "whoami", Kind: spec.ProviderForwardAuth},
	}

	n := composeDigest(sticky, orphans, now)

	if n.Level != beacon.LevelError {
		t.Fatalf("level = %v, want error (a sticky error and a live-credential orphan present)", n.Level)
	}
	if n.Fields["sticky"] != "1" || n.Fields["orphans_oidc"] != "1" || n.Fields["orphans_proxy"] != "1" {
		t.Fatalf("fields = %v, want sticky=1 orphans_oidc=1 orphans_proxy=1", n.Fields)
	}

	body := n.Body
	if !strings.Contains(body, "unwired-middleware") {
		t.Fatalf("body missing the sticky error:\n%s", body)
	}
	oidcAt := strings.Index(body, "Orphaned OIDC providers")
	proxyAt := strings.Index(body, "Orphaned proxy providers")
	if oidcAt < 0 || proxyAt < 0 {
		t.Fatalf("body missing an orphan section:\n%s", body)
	}
	if oidcAt > proxyAt {
		t.Fatalf("OIDC orphan section must precede the proxy section (live credentials first):\n%s", body)
	}
	// Sticky section must precede the orphan sections.
	stickyAt := strings.Index(body, "Sticky errors")
	if stickyAt < 0 || stickyAt > oidcAt {
		t.Fatalf("sticky section must lead the body:\n%s", body)
	}
}

// TestComposeDigestClean proves a clean fleet is an info heartbeat, not an alarm.
func TestComposeDigestClean(t *testing.T) {
	n := composeDigest(nil, nil, time.Unix(0, 0).UTC())
	if n.Level != beacon.LevelInfo {
		t.Fatalf("level = %v, want info for a clean fleet", n.Level)
	}
	if !strings.Contains(n.Body, "Nothing to report") {
		t.Fatalf("clean digest body should say nothing to report:\n%s", n.Body)
	}
}

// TestComposeDigestProxyOnlyIsWarning proves an orphan set of only inert proxy
// providers is a warning, not an error.
func TestComposeDigestProxyOnlyIsWarning(t *testing.T) {
	orphans := []reconcile.Orphan{{Slug: "whoami", Kind: spec.ProviderForwardAuth}}
	n := composeDigest(nil, orphans, time.Unix(0, 0).UTC())
	if n.Level != beacon.LevelWarning {
		t.Fatalf("level = %v, want warning for proxy-only orphans", n.Level)
	}
}

// TestParseSchedule covers the cadence keywords, a bare duration, the empty
// default, and the loud-disable on an unknown value.
func TestParseSchedule(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 24 * time.Hour},
		{"daily", 24 * time.Hour},
		{"Hourly", time.Hour},
		{"weekly", 7 * 24 * time.Hour},
		{"15m", 15 * time.Minute},
		{"nonsense", 0},
		{"-5m", 0},
	}
	for _, tc := range cases {
		if got := parseSchedule(tc.in); got != tc.want {
			t.Fatalf("parseSchedule(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
