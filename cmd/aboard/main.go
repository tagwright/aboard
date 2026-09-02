// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Command aboard is the label-driven single-sign-on companion for Authentik.
// It reads aboard.* labels on a container and reconciles the matching state
// inside Authentik (an Application, a Provider, the access bindings, and the
// embedded-outpost attachment) over Authentik's REST API, then audits the
// container's Traefik forward-auth wiring. It drives Authentik, it never
// rebuilds the IdP.
//
// The full CLI surface (status, render, prune, validate) lands in a later phase.
// The daemon subcommand here is the event-driven control loop's entry point: it
// wires the socket watch to discovery, the reconciler, the Traefik verifier, and
// beacon, and runs until interrupted.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/daemon"
	"github.com/tagwright/aboard/internal/version"
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
	root.AddCommand(newDaemonCmd())
	return root
}

// newDaemonCmd wires `aboard daemon`, the event-driven control loop. It resolves
// the config path, installs a SIGINT/SIGTERM-cancelled context, and hands off to
// daemon.Serve, which does the full wiring and blocks until interrupted. The
// heavier CLI surface (status, render, prune, validate) is a later phase; this is
// the one command the daemon needs.
func newDaemonCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the label-driven reconcile-and-audit control loop",
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			path := configPath
			if path == "" {
				path = config.ResolveConfigPath()
			}
			return daemon.Serve(ctx, path, logger)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to aboard.yml (default: ABOARD_CONFIG, ./aboard.yml, then /etc/aboard/aboard.yml)")
	return cmd
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
