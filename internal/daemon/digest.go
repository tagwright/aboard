// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tagwright/courier"

	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/spec"
)

// runDigest fires the daily digest on the parsed cadence. The digest re-emits the
// sticky errors and the orphan set until they are fixed, so a broken gate or a
// live-credential orphan does not scroll out of the operator's attention. It is a
// hand-composed courier.Notification sent through the same Notify path as an
// immediate alert, because beacon v0.1.0 has no digest-shaped report method (its
// Report is health telemetry); this mirrors the sibling tools' digest wiring
// exactly rather than inventing a second notification path.
func (d *Daemon) runDigest(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	d.log.Info("aboard digest scheduled", "interval", interval.String())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.SendDigest(ctx)
		}
	}
}

// SendDigest composes and sends one digest immediately from the current sticky
// and orphan state. It is exported so the CLI's `aboard status`-adjacent commands
// (chunk 7) can trigger a digest on demand through the same path.
func (d *Daemon) SendDigest(ctx context.Context) {
	n := composeDigest(d.sticky.list(), d.snapshotOrphans(), d.snapshotApplied(), d.now())
	if d.notifier == nil {
		return
	}
	_ = d.notifier.Notify(ctx, n)
}

// composeDigest assembles the digest Notification from the sticky errors and the
// orphan set. The ordering is the architecture's: orphaned OIDC providers are
// LIVE CREDENTIALS, so they are listed first and separately from harmless
// orphaned proxy providers, and the sticky security errors lead the body. The
// level escalates by content: any sticky error or any live-credential OIDC orphan
// is an error-level digest, a proxy-only orphan set is a warning, and a clean
// fleet is an info heartbeat. Fields carry machine-readable counts.
func composeDigest(sticky []stickyEntry, orphans []reconcile.Orphan, applied []appliedView, now time.Time) courier.Notification {
	var oidc, proxy []reconcile.Orphan
	for _, o := range orphans {
		if o.Kind == spec.ProviderOIDC {
			oidc = append(oidc, o)
		} else {
			proxy = append(proxy, o)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "aboard digest %s\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "%d sticky error(s), %d orphaned OIDC provider(s), %d orphaned proxy provider(s).\n",
		len(sticky), len(oidc), len(proxy))

	if len(sticky) > 0 {
		fmt.Fprintf(&b, "\nSticky errors (security-affecting, until fixed):\n")
		for _, e := range sticky {
			fmt.Fprintf(&b, "  - [%s] %s: %s (since %s)\n",
				e.Code, e.Service, e.Message, e.FirstSeen.UTC().Format(time.RFC3339))
		}
	}

	if len(oidc) > 0 {
		fmt.Fprintf(&b, "\nOrphaned OIDC providers (LIVE credentials, prune first):\n")
		for _, o := range oidc {
			fmt.Fprintf(&b, "  - %s%s\n", o.Slug, attachedNote(o))
		}
	}

	if len(proxy) > 0 {
		fmt.Fprintf(&b, "\nOrphaned proxy providers (inert unless still attached):\n")
		for _, o := range proxy {
			fmt.Fprintf(&b, "  - %s%s\n", o.Slug, attachedNote(o))
		}
	}

	// Confirmed state: what aboard last actually WROTE to Authentik and when, and
	// whether the go-live was confirmed live. This is the CONFIRMED side of the
	// ground-truth distinction, so a reader never reads "container present" as
	// "provisioned and live".
	if len(applied) > 0 {
		fmt.Fprintf(&b, "\nLast confirmed Authentik writes (CONFIRMED, not just discovered):\n")
		for _, a := range applied {
			state := "no outpost half"
			if a.Provider == spec.ProviderForwardAuth {
				if a.Attached {
					state = "attached and served (go-live confirmed)"
				} else {
					state = "NOT confirmed live (attach unverified or stale)"
				}
			}
			fmt.Fprintf(&b, "  - %s [%s]: %s, last write %s\n",
				a.Slug, a.Provider, state, a.When.UTC().Format(time.RFC3339))
		}
	}

	if len(sticky) == 0 && len(oidc) == 0 && len(proxy) == 0 {
		b.WriteString("\nNothing to report: no sticky errors and no orphans.\n")
	}

	level := courier.LevelInfo
	switch {
	case len(sticky) > 0 || len(oidc) > 0:
		level = courier.LevelError
	case len(proxy) > 0:
		level = courier.LevelWarning
	}

	return courier.Notification{
		Title: "aboard digest",
		Body:  b.String(),
		Level: level,
		Fields: map[string]string{
			"sticky":        strconv.Itoa(len(sticky)),
			"orphans_oidc":  strconv.Itoa(len(oidc)),
			"orphans_proxy": strconv.Itoa(len(proxy)),
		},
	}
}

// attachedNote flags an orphan that is STILL in the outpost's providers list, the
// dangerous kind: it keeps claiming its external_host and can collide with a new
// app on the same host. An unattached orphan gets no note.
func attachedNote(o reconcile.Orphan) string {
	if o.Attached {
		return " (STILL ATTACHED to the outpost, collision risk, prune now)"
	}
	return ""
}

// parseSchedule turns the ABOARD_DIGEST_SCHEDULE cadence into a tick interval,
// mirroring the sibling tools: the named keywords daily, hourly, and weekly, or a
// bare Go duration. An empty value is daily. An unrecognized value returns zero,
// which Run reports and treats as disabling the digest loudly rather than
// silently.
func parseSchedule(s string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "daily":
		return 24 * time.Hour
	case "hourly":
		return time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return 0
}
