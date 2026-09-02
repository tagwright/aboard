// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"

	"github.com/tagwright/beacon"
	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/spec"
	"github.com/tagwright/aboard/internal/traefik"
)

// fullPass is the boot/full reconcile pass and the only place aboard reconciles
// the whole fleet at once. It runs on the serial worker, so its reconciles are
// serialized against every per-container sync like everything else. It detects
// the fleet catch-all once, reconciles every enabled container, and computes the
// orphan set. Per the suite's per-container isolation rule, one container's error
// never aborts the pass: each is processed independently.
func (d *Daemon) fullPass(ctx context.Context) {
	containers, err := d.rt.List(ctx)
	if err != nil {
		d.notify(ctx, beacon.LevelError, "aboard: list containers failed", err.Error())
		return
	}

	d.setFleetCallback(detectFleetCallback(containers))

	var enabled []string
	for _, c := range containers {
		if slug, ok := d.processContainer(ctx, c); ok {
			enabled = append(enabled, slug)
		}
	}

	d.refreshOrphans(ctx, enabled)
	d.log.Info("full reconcile pass complete",
		"enabled", len(enabled),
		"sticky", d.sticky.count(),
		"orphans", len(d.snapshotOrphans()))
}

// syncKey reconciles or retires one service after its lifecycle churn has
// settled (debounce.go). It inspects the container the debouncer last saw for the
// key:
//
//   - Inspect succeeds and the container is opted in: reconcile it.
//   - Inspect fails (the container is gone) or the container is no longer opted
//     in: this is a REMOVAL. Under Fork 8 KEEP, aboard tears down NOTHING. It
//     only recomputes the orphan set, so the removed container's aboard-owned
//     objects surface as orphans in status and the digest. Teardown is never
//     called here; it is `aboard prune` only.
//
// Either way it ends by recomputing the orphan set from a fresh listing, so a
// now-enabled slug drops out of the orphans and a now-removed one enters, and the
// fleet catch-all finding is refreshed in case the catch-all container changed.
func (d *Daemon) syncKey(ctx context.Context, key, id string) {
	c, err := d.rt.Inspect(ctx, id)
	if err != nil {
		// The container the debouncer last saw is gone. KEEP: recompute orphans,
		// never tear down. The slug's stale sticky errors are cleared by the
		// retainSlugs step inside refreshFromList.
		d.log.Info("container gone, keeping aboard objects as orphans (Fork 8 KEEP)", "service", key)
		d.refreshFromList(ctx)
		return
	}

	d.processContainer(ctx, c)
	d.refreshFromList(ctx)
}

// processContainer runs the per-container pipeline: discover the desired state
// from labels, reconcile Authentik when the state is clean, audit the Traefik
// wiring, and route the findings to sticky state and immediate alerts. It returns
// the slug and true when the container is opted in (so a caller can collect the
// enabled-slug set for the orphan scan), and "" / false otherwise.
//
// Self-exclusion is enforced first: aboard never acts on the Authentik
// containers it drives or on its own container, defense in depth over the enable
// gate (fleet.go isSelfExcluded).
func (d *Daemon) processContainer(ctx context.Context, c runtime.Container) (string, bool) {
	if isSelfExcluded(c) {
		return "", false
	}

	sp, issues := discovery.Discover(d.cfg, inputFrom(c))
	service := sp.Name

	if !sp.Enable {
		// Not opted in. The only interesting issue here is the declared-but-unarmed
		// warning (aboard.* labels present without aboard.enable), which is a
		// transient alert, not sticky. There is nothing to reconcile.
		d.notifyTransient(ctx, service, issues)
		return "", false
	}

	all := append([]discovery.Issue(nil), issues...)

	// Only reconcile when discovery produced no error: a container with any error
	// is skip-and-alert, never acted on (the security-critical rule).
	if !discovery.HasError(issues) {
		res, rerr := d.reconciler.Reconcile(ctx, sp)
		if res != nil {
			all = append(all, res.Issues...)
			d.recordApplied(sp, res)
		}
		if rerr != nil {
			d.log.Warn("reconcile returned an error", "service", service, "slug", sp.Slug, "err", rerr.Error())
		}

		// Audit the proxy half. The verifier is a pure label check independent of
		// the Authentik outcome, so it runs whenever the proxy is Traefik and the
		// provider has a forward-auth half.
		if d.cfg.Proxy == config.ProxyTraefik && sp.Provider == spec.ProviderForwardAuth {
			vr := traefik.Verify(d.cfg, &sp, c.Labels, d.fleetCallbackPresent())
			all = append(all, vr.Findings...)
		}
	}

	// Replace this slug's sticky set with the current errors: a fixed error drops
	// out, a persistent one keeps its FirstSeen, a new one is returned for an
	// immediate alert. Then fire the transient (warning/info) notifications.
	added := d.sticky.replaceSlug(sp.Slug, service, all, d.now())
	d.notifySticky(ctx, added)
	d.notifyTransient(ctx, service, all)

	return sp.Slug, true
}

// refreshFromList recomputes the read-only aggregate state from a fresh listing
// without reconciling: the fleet catch-all finding, the enabled-slug set, the
// sticky retention, and the orphan set. It is the removal and post-sync path, and
// it never touches Authentik except through the read-only orphan scan.
func (d *Daemon) refreshFromList(ctx context.Context) {
	containers, err := d.rt.List(ctx)
	if err != nil {
		d.notify(ctx, beacon.LevelError, "aboard: list containers failed", err.Error())
		return
	}
	d.setFleetCallback(detectFleetCallback(containers))

	var enabled []string
	for _, c := range containers {
		if isSelfExcluded(c) {
			continue
		}
		sp, _ := discovery.Discover(d.cfg, inputFrom(c))
		if sp.Enable {
			enabled = append(enabled, sp.Slug)
		}
	}
	d.refreshOrphans(ctx, enabled)
}

// refreshOrphans clears stale sticky errors for slugs no longer enabled, then
// recomputes the orphan set over the enabled slugs and stores it. The orphan scan
// is read-only (it lists Authentik applications and checks the ownership marker),
// so it is safe to run on the serial worker without contending with a reconcile.
// Orphans() returns OIDC providers (live credentials) first, which the digest
// preserves.
func (d *Daemon) refreshOrphans(ctx context.Context, enabledSlugs []string) {
	d.sticky.retainSlugs(enabledSlugs)

	orphans, err := d.reconciler.Orphans(ctx, enabledSlugs)
	if err != nil {
		d.notify(ctx, beacon.LevelError, "aboard: orphan scan failed", err.Error())
		return
	}
	d.setOrphans(orphans)
}

// notifySticky fires an immediate error alert for each newly-added sticky error,
// so a freshly-broken gate is not left to wait for the daily digest.
func (d *Daemon) notifySticky(ctx context.Context, added []stickyEntry) {
	for _, e := range added {
		d.notify(ctx, beacon.LevelError, "aboard: "+e.Code, e.Service+": "+e.Message)
	}
}

// notifyTransient fires the non-error (warning, info) issues immediately. These
// never enter the sticky set: a binding-removed warning or an adopted info is a
// one-time notice, not a standing problem.
func (d *Daemon) notifyTransient(ctx context.Context, service string, issues []discovery.Issue) {
	for _, is := range issues {
		if is.Severity == discovery.SeverityError {
			continue
		}
		d.notify(ctx, levelForSeverity(is.Severity), "aboard: "+is.Code, service+": "+is.Message)
	}
}

// levelForSeverity maps a discovery severity to a beacon level.
func levelForSeverity(s discovery.Severity) beacon.Level {
	switch s {
	case discovery.SeverityError:
		return beacon.LevelError
	case discovery.SeverityWarning:
		return beacon.LevelWarning
	default:
		return beacon.LevelInfo
	}
}

// notify sends a Notification through the beacon seam, tolerating a nil notifier
// (the sibling tools' nil-tolerant helper). No secret value ever reaches here:
// every title and body is built from codes, names, and messages that the lower
// packages guarantee are secret-free.
func (d *Daemon) notify(ctx context.Context, level beacon.Level, title, body string) {
	if d.notifier == nil {
		return
	}
	_ = d.notifier.Notify(ctx, beacon.Notification{
		Title: title,
		Body:  body,
		Level: level,
	})
}
