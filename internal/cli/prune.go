// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/spec"
)

// pruneOptions are the two gates on the only destructive command. Both default
// off, so the safe path (prompt, then delete only owned orphans on an explicit
// yes) is what runs when neither flag is given.
type pruneOptions struct {
	// Yes skips the interactive prompt for automation. It still deletes only the
	// computed orphan set, and never with DryRun also set.
	Yes bool

	// DryRun prints the plan and exits without deleting anything, and wins over
	// Yes: a dry run never deletes.
	DryRun bool
}

// newPruneCmd wires "aboard prune", the tool's ONLY delete path (Fork 8 KEEP: the
// daemon never deletes, so a removed container's owned objects survive as orphans
// until a human runs this). It is treated security-first: it computes the orphan
// set, prints exactly what WOULD be deleted with OIDC providers (live credentials)
// called out first, and then REQUIRES confirmation before any delete. The default
// is an interactive y/N prompt, --yes skips it for automation, and --dry-run
// prints and exits without deleting. Only aboard-owned objects are ever touched:
// reconcile.Teardown refuses a hand-made object by its ownership marker.
func newPruneCmd() *cobra.Command {
	var opts pruneOptions

	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Delete orphaned aboard-owned Authentik objects (guarded by confirmation)",
		Long: `prune deletes the orphan set: aboard-owned Authentik applications and
providers with no matching enabled container. The daemon never deletes, so this
is the only command that does.

It always prints what would be deleted, with orphaned OIDC providers (live client
credentials) called out first. By default it then asks for confirmation before
deleting anything. Use --dry-run to print the plan and stop, or --yes to skip the
prompt for automation. Only aboard-owned objects are ever deleted: a hand-made
Authentik object has no aboard ownership marker and teardown refuses to touch it.`,
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
			return runPrune(cmd.Context(), cfg, rt, rec, opts, cmd.InOrStdin(), newUI(cmd.OutOrStdout()))
		},
	}

	cmd.Flags().BoolVar(&opts.Yes, "yes", false, "skip the confirmation prompt (for automation)")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "print what would be deleted and exit without deleting")
	return cmd
}

// runPrune is the testable core of the destructive command. The confirmation gate
// is the security-critical property: with neither --yes nor --dry-run, it deletes
// NOTHING until confirm reads an explicit yes. A fake reconciler records whether
// Teardown was ever called, which is what proves the gate.
func runPrune(ctx context.Context, cfg *config.Config, lister containerLister, rec orphanReconciler, opts pruneOptions, in io.Reader, u ui) error {
	_, slugs, err := discoverEnabled(ctx, cfg, lister)
	if err != nil {
		return err
	}

	orphans, err := rec.Orphans(ctx, slugs)
	if err != nil {
		return err
	}

	if len(orphans) == 0 {
		u.printf("%s\n", u.dim("no orphans: every owned application maps to an enabled container, nothing to prune"))
		return nil
	}

	printPrunePlan(u, orphans)

	if opts.DryRun {
		u.printf("\n%s\n", u.dim("dry run: nothing deleted"))
		return nil
	}

	if !opts.Yes {
		if !confirmPrune(in, u, len(orphans)) {
			u.printf("\n%s\n", u.bold("aborted: nothing deleted"))
			return nil
		}
	}

	return deleteOrphans(ctx, rec, orphans, u)
}

// printPrunePlan prints the objects prune WOULD delete, OIDC providers (live
// credentials) first and distinctly. The Orphans result is already OIDC-first.
func printPrunePlan(u ui, orphans []reconcile.Orphan) {
	oidc := 0
	for _, o := range orphans {
		if o.Kind == spec.ProviderOIDC {
			oidc++
		}
	}

	u.printf("%s\n", u.bold(fmt.Sprintf("%d orphan(s) would be deleted:", len(orphans))))
	if oidc > 0 {
		u.printf("  %s\n", u.red(fmt.Sprintf("%d of these are OIDC providers with LIVE client credentials.", oidc)))
	}
	for _, o := range orphans {
		if o.Kind == spec.ProviderOIDC {
			u.printf("  %s  %s  %s\n",
				u.red("OIDC "),
				u.cyan(o.Slug),
				u.red("application + OAuth2 provider (live credentials)"))
		} else {
			u.printf("  %s  %s  %s\n",
				u.yellow("proxy"),
				u.cyan(o.Slug),
				u.dim("application + forward-auth provider, detached from the outpost first"))
		}
	}
}

// confirmPrune prints the prompt and reads one line. It returns true only on an
// explicit "y" or "yes" (case-insensitive). EOF, a blank line, or anything else is
// a No, so the safe default (do not delete) holds whenever confirmation is not
// clearly given.
func confirmPrune(in io.Reader, u ui, n int) bool {
	u.printf("\nDelete %d aboard-owned object(s)? This cannot be undone. Type y to confirm [y/N]: ", n)
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return answer == "y" || answer == "yes"
}

// deleteOrphans tears each orphan down, OIDC first (the input order). Per the
// suite's per-object isolation, one failure does not stop the rest: it reports the
// error and continues, then returns a non-nil error if any delete failed so the
// process exits nonzero.
func deleteOrphans(ctx context.Context, rec orphanReconciler, orphans []reconcile.Orphan, u ui) error {
	var failed int
	for _, o := range orphans {
		if err := rec.Teardown(ctx, o.Slug); err != nil {
			failed++
			u.printf("  %s  %s: %s\n", u.red("FAILED"), o.Slug, err.Error())
			continue
		}
		u.printf("  %s  %s\n", u.green("deleted"), o.Slug)
	}

	if failed > 0 {
		return fmt.Errorf("prune: %d of %d object(s) failed to delete", failed, len(orphans))
	}
	u.printf("\n%s\n", u.bold(fmt.Sprintf("pruned %d orphan(s)", len(orphans))))
	return nil
}
