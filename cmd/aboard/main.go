// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Command aboard is the label-driven single-sign-on companion for Authentik.
// It reads aboard.* labels on a container and reconciles the matching state
// inside Authentik (an Application, a Provider, the access bindings, and the
// embedded-outpost attachment) over Authentik's REST API, then audits the
// container's Traefik forward-auth wiring. It drives Authentik, it never
// rebuilds the IdP.
//
// This is the repo skeleton. Only the version subcommand is wired. The
// reconcile, Authentik REST, Traefik audit, and discovery logic land in later
// phases.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/tagwright/aboard/internal/version"

	// aboard is a tagwright suite tool. It builds on the shared runtime
	// abstraction (core) and the suite notifier (beacon), the same way berm
	// and ballast do. The reconcile, discovery, and alert wiring that use them
	// land in later phases; the blank imports pin the suite dependency now so
	// the module graph is stable from the skeleton on.
	_ "github.com/tagwright/beacon"
	_ "github.com/tagwright/core/runtime"

	// aboard.yml (the fleet config: API token path, default outpost, default
	// groups) is parsed with the suite's YAML library. The loader lands in a
	// later phase; the blank import pins the dependency now.
	_ "gopkg.in/yaml.v3"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd builds the aboard command tree. Cobra gives the root a "--version"
// flag automatically because Version is set, templated to match the "version"
// subcommand.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "aboard",
		Short:         "Label-driven single sign-on companion for Authentik",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
	}
	root.SetVersionTemplate("aboard {{.Version}}\n")

	root.AddCommand(newVersionCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the aboard version",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Printf("aboard %s\n", version.Version)
			return nil
		},
	}
}
