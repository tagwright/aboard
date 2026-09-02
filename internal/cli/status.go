// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"context"
	"sort"

	"github.com/spf13/cobra"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/daemon"
	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/spec"
	"github.com/tagwright/aboard/internal/traefik"
)

// newStatusCmd wires "aboard status": a READ-ONLY report. It lists the enabled
// containers and the applications they map to, the current orphan set (aboard-
// owned Authentik objects with no matching enabled container, OIDC providers first
// because they are live credentials), and the sticky findings from a fresh
// discovery-and-verify pass. It reads Authentik only through the orphan scan's
// application listing, and it never writes.
func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Read-only report of owned applications, findings, and orphans",
		Long: `status reports what aboard sees right now: the enabled containers and the
Authentik applications they map to, the sticky findings from a fresh label and
Traefik audit, and the orphan set (owned objects with no enabled container).
Orphaned OIDC providers, which are live credentials, are listed first. status
reads Authentik but never writes.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			rt := newRuntime()
			defer rt.Close()

			rec, err := newReconciler(cfg)
			if err != nil {
				return err
			}
			return runStatus(cmd.Context(), cfg, rt, rec, newUI(cmd.OutOrStdout()))
		},
	}
}

// appView is one enabled container's discovered application, with the findings
// from its label and Traefik audit. status prints it and prune reuses the slug.
type appView struct {
	service  string
	slug     string
	provider spec.ProviderType
	host     string
	findings []discovery.Issue
}

// discoverEnabled lists containers and returns, for every enabled and non-excluded
// one, its appView (with discovery plus Traefik-verify findings) and the parallel
// slug set. It is the shared read-only pass behind status and prune. It touches no
// Authentik: discovery and the verifier are both pure.
func discoverEnabled(ctx context.Context, cfg *config.Config, lister containerLister) ([]appView, []string, error) {
	containers, err := lister.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	fleetCallback := daemon.DetectFleetCallback(containers)

	var (
		apps  []appView
		slugs []string
	)
	for _, c := range containers {
		if daemon.IsSelfExcluded(c) {
			continue
		}
		sp, issues := discovery.Discover(cfg, daemon.InputFrom(c))
		if !sp.Enable {
			continue
		}

		findings := append([]discovery.Issue(nil), issues...)
		if !discovery.HasError(issues) && cfg.Proxy == config.ProxyTraefik && sp.Provider == spec.ProviderForwardAuth {
			vr := traefik.Verify(cfg, &sp, c.Labels, fleetCallback)
			findings = append(findings, vr.Findings...)
		}

		apps = append(apps, appView{
			service:  sp.Name,
			slug:     sp.Slug,
			provider: sp.Provider,
			host:     sp.Host,
			findings: findings,
		})
		slugs = append(slugs, sp.Slug)
	}

	sort.SliceStable(apps, func(i, j int) bool { return apps[i].service < apps[j].service })
	return apps, slugs, nil
}

// runStatus renders the read-only report. The orphan scan is the only Authentik
// call, and it is a listing. A fake reconciler and colour-off ui make it testable
// without a live IdP.
func runStatus(ctx context.Context, cfg *config.Config, lister containerLister, rec orphanReconciler, u ui) error {
	apps, slugs, err := discoverEnabled(ctx, cfg, lister)
	if err != nil {
		return err
	}

	orphans, err := rec.Orphans(ctx, slugs)
	if err != nil {
		return err
	}

	printEnabledApps(u, apps)
	printFindings(u, apps)
	printOrphans(u, orphans)
	return nil
}

// printEnabledApps prints the enabled container to application mapping.
func printEnabledApps(u ui, apps []appView) {
	u.printf("%s\n", u.bold("Enabled applications"))
	if len(apps) == 0 {
		u.printf("  %s\n", u.dim("none: no container carries aboard.enable=true"))
		return
	}
	for _, a := range apps {
		host := a.host
		if host == "" {
			host = "?"
		}
		u.printf("  %s  %s  %s  %s\n",
			a.service,
			u.cyan(a.slug),
			u.dim("["+string(a.provider)+"]"),
			u.dim(host))
	}
}

// printFindings prints the sticky-style findings grouped by service. Silent when
// the fleet is clean.
func printFindings(u ui, apps []appView) {
	var withFindings []appView
	for _, a := range apps {
		if len(a.findings) > 0 {
			withFindings = append(withFindings, a)
		}
	}
	if len(withFindings) == 0 {
		return
	}

	u.printf("\n%s\n", u.bold("Findings"))
	for _, a := range withFindings {
		u.printf("  %s\n", u.bold(a.service))
		for _, is := range a.findings {
			u.printf("    %s  %s: %s\n", severityLabel(u, is.Severity), is.Code, is.Message)
		}
	}
}

// printOrphans prints the orphan set, OIDC providers (live credentials) called out
// first and distinctly from harmless proxy orphans. The Orphans result is already
// ordered OIDC-first.
func printOrphans(u ui, orphans []reconcile.Orphan) {
	u.printf("\n%s\n", u.bold("Orphans"))
	if len(orphans) == 0 {
		u.printf("  %s\n", u.dim("none: every owned application maps to an enabled container"))
		return
	}
	for _, o := range orphans {
		if o.Kind == spec.ProviderOIDC {
			u.printf("  %s  %s  %s\n",
				u.red("OIDC "),
				u.cyan(o.Slug),
				u.red("live client credentials, rotate on removal"))
		} else {
			u.printf("  %s  %s  %s\n",
				u.yellow("proxy"),
				u.cyan(o.Slug),
				u.dim("forward-auth provider, no standing credential"))
		}
	}
}
