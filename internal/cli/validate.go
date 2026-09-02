// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"context"
	"errors"
	"sort"

	"github.com/spf13/cobra"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/daemon"
	"github.com/tagwright/aboard/internal/discovery"
)

// errValidationFailed is the sentinel a validate run returns when any container
// carries a discovery Error, so the process exits nonzero. Its message is empty
// and errors are silenced at the root, so the human sees the grouped report, not
// a duplicate one-line error.
var errValidationFailed = errors.New("")

// newValidateCmd wires "aboard validate": a DRY RUN that checks every container's
// aboard.* labels against the loaded config and prints the issues, grouped by
// container, with a colour-coded severity. It never calls Authentik and never
// writes anything, so it is the safe "check my labels before I deploy" command. It
// exits nonzero when any container has an Error.
func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Dry-run check of every container's aboard labels (no Authentik, no writes)",
		Long: `validate reads each container's aboard.* labels, validates them against the
loaded aboard.yml exactly as the daemon's discovery pass would, and prints every
error and warning grouped by container. It makes no call to Authentik and writes
nothing. Exit status is nonzero if any container has an error.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			rt := newRuntime()
			defer rt.Close()

			hasError, err := runValidate(cmd.Context(), cfg, rt, newUI(cmd.OutOrStdout()))
			if err != nil {
				return err
			}
			if hasError {
				return errValidationFailed
			}
			return nil
		},
	}
}

// validateItem is one container's validation outcome, held so the report is
// printed in a stable, service-sorted order regardless of listing order.
type validateItem struct {
	service string
	enabled bool
	issues  []discovery.Issue
}

// runValidate lists containers, discovers each (skipping the always-excluded IdP
// and aboard itself), and prints the grouped issue report. It returns whether any
// container carried an Error. It is the testable core: a fake lister and a
// colour-off ui let it run with no socket.
func runValidate(ctx context.Context, cfg *config.Config, lister containerLister, u ui) (bool, error) {
	containers, err := lister.List(ctx)
	if err != nil {
		return false, err
	}

	items := make([]validateItem, 0, len(containers))
	for _, c := range containers {
		if daemon.IsSelfExcluded(c) {
			continue
		}
		sp, issues := discovery.Discover(cfg, daemon.InputFrom(c))
		// Nothing to say about a container that is not opted in and raised no
		// issue (the common case for most of the fleet): stay quiet.
		if !sp.Enable && len(issues) == 0 {
			continue
		}
		items = append(items, validateItem{service: sp.Name, enabled: sp.Enable, issues: issues})
	}

	sort.SliceStable(items, func(i, j int) bool { return items[i].service < items[j].service })

	anyError := false
	enabledCount := 0
	for _, it := range items {
		if it.enabled {
			enabledCount++
		}
		if discovery.HasError(it.issues) {
			anyError = true
		}
		printContainerIssues(u, it.service, it.enabled, it.issues)
	}

	printValidateSummary(u, len(items), enabledCount, anyError)
	return anyError, nil
}

// printContainerIssues prints one container's header and its issues, each with a
// colour-coded severity label. A clean enabled container is reported as OK.
func printContainerIssues(u ui, service string, enabled bool, issues []discovery.Issue) {
	state := "enabled"
	if !enabled {
		state = "not enabled"
	}
	u.printf("%s  %s\n", u.bold(service), u.dim("("+state+")"))

	if len(issues) == 0 {
		u.printf("  %s labels valid\n", u.green("OK"))
		return
	}
	for _, is := range issues {
		u.printf("  %s  %s: %s\n", severityLabel(u, is.Severity), is.Code, is.Message)
	}
}

// printValidateSummary prints the closing count line.
func printValidateSummary(u ui, total, enabled int, anyError bool) {
	if total == 0 {
		u.printf("%s\n", u.dim("no aboard-labelled containers found"))
		return
	}
	verdict := u.green("no errors")
	if anyError {
		verdict = u.red("errors found")
	}
	u.printf("\n%s: %d container(s) checked, %d enabled, %s\n",
		u.bold("validate"), total, enabled, verdict)
}

// severityLabel renders a discovery severity as a fixed-width, colour-coded label.
func severityLabel(u ui, sev discovery.Severity) string {
	if sev == discovery.SeverityError {
		return u.red("ERROR  ")
	}
	return u.yellow("WARNING")
}
