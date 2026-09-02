// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Package cli builds aboard's Cobra command tree and is the CLI's only entry
// point: cmd/aboard/main.go calls Execute and does nothing else.
//
// The command tree:
//
//	aboard daemon              run the label-driven reconcile-and-audit loop
//	aboard status              read-only report of owned apps and orphans
//	aboard render <service>    print the Traefik labels for one service
//	aboard render --setup      print the once-per-fleet Traefik pieces
//	aboard prune               delete orphaned aboard-owned objects (guarded)
//	aboard validate            dry-run label check, no Authentik, no writes
//	aboard version             print the build version
//
// Every subcommand except version reads the same aboard.yml, resolved from the
// persistent --config flag or config.ResolveConfigPath. The commands are thin:
// they load config, build the small set of collaborators they need (a container
// lister, and for status and prune an Authentik-backed reconciler), and delegate
// to the internal packages that already own the real work. None of the network
// or socket I/O lives in the command logic itself, which is what lets validate,
// render, and the prune confirmation gate be unit-tested over fakes.
package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/daemon"
	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/secret"
	"github.com/tagwright/aboard/internal/version"
)

// cfgPath backs the root command's persistent --config flag. A cobra command is
// a long-lived singleton, so a package-level var bound by pflag is the idiomatic
// way to thread a persistent flag to every subcommand's RunE.
var cfgPath string

// containerLister is the read-only slice of the runtime the CLI's list-and-audit
// passes need. *runtime.DockerRuntime satisfies it, and a test injects a fake, so
// the commands' logic runs without a socket.
type containerLister interface {
	List(ctx context.Context) ([]runtime.Container, error)
}

// orphanReconciler is the narrow slice of the reconciler status and prune drive:
// compute the orphan set, and tear one owned object down. *reconcile.Reconciler
// satisfies it, and a test injects a fake, so the prune confirmation gate is
// proven without a live Authentik.
type orphanReconciler interface {
	Orphans(ctx context.Context, enabledSlugs []string) ([]reconcile.Orphan, error)
	Teardown(ctx context.Context, slug string) error
}

// Compile-time proof the real types satisfy the seams.
var (
	_ containerLister  = (*runtime.DockerRuntime)(nil)
	_ orphanReconciler = (*reconcile.Reconciler)(nil)
)

// Execute builds the command tree and runs it against os.Args.
func Execute() error {
	return newRootCmd().Execute()
}

// newRootCmd builds the root "aboard" command and attaches every subcommand.
// Cobra adds its own "completion" and "help" subcommands, and (because Version is
// set) a "--version" flag, automatically.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "aboard",
		Short: "Label-driven single sign-on companion for Authentik",
		Long: `aboard lets a container declare by label that it should join the fleet's
single sign-on, and reconciles the matching state inside Authentik over
Authentik's REST API, then audits the container's Traefik forward-auth wiring.
It drives Authentik, it never rebuilds the IdP.`,
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.SetVersionTemplate("aboard {{.Version}}\n")

	root.PersistentFlags().StringVar(&cfgPath, "config", "",
		"path to aboard.yml (default: ABOARD_CONFIG, ./aboard.yml, then /etc/aboard/aboard.yml)")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newDaemonCmd())
	root.AddCommand(newValidateCmd())
	root.AddCommand(newRenderCmd())
	root.AddCommand(newStatusCmd())
	root.AddCommand(newPruneCmd())
	return root
}

// newVersionCmd prints the same "aboard <version>" line the auto-generated
// "aboard --version" flag prints.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the aboard version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "aboard %s\n", version.Version)
			return nil
		},
	}
}

// newDaemonCmd wires "aboard daemon", the event-driven control loop. It resolves
// the config path, installs a SIGINT/SIGTERM-cancelled context, and hands off to
// daemon.Serve, which does the full wiring and blocks until interrupted.
func newDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Run the label-driven reconcile-and-audit control loop",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return daemon.Serve(ctx, resolvedConfigPath(), logger)
		},
	}
}

// resolvedConfigPath is the --config value, or the standard resolution chain when
// the flag is unset. Every subcommand loads config through it, so the flag and the
// env/working-dir/etc fallback behave identically across the tree.
func resolvedConfigPath() string {
	if cfgPath != "" {
		return cfgPath
	}
	return config.ResolveConfigPath()
}

// loadConfig loads and validates aboard.yml from the resolved path. Every command
// that reads config starts here, so an invalid config fails the same way everywhere.
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(resolvedConfigPath())
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// newRuntime opens the read-only container socket. aboard reads the socket, it
// never writes it. The caller closes it.
func newRuntime() *runtime.DockerRuntime {
	return runtime.NewDocker(daemon.DefaultDockerSocket)
}

// newReconciler builds the Authentik-backed reconciler status and prune drive: the
// secret resolver, the REST client (token resolved by NAME), and the reconciler
// over them, exactly as the daemon builds them.
func newReconciler(cfg *config.Config) (*reconcile.Reconciler, error) {
	resolve := secret.FileEnvResolver(cfg.Globals.SecretsDir)
	client, err := authentik.FromConfig(cfg, resolve)
	if err != nil {
		return nil, err
	}
	return reconcile.New(client, cfg, resolve), nil
}

// ANSI colour codes. The suite uses ANSI for emphasis and never emojis. Colour is
// applied only when writing to a terminal (see newUI), so piped and captured
// output, and every test assertion, stays plain.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiGreen  = "\x1b[32m"
	ansiCyan   = "\x1b[36m"
	ansiDim    = "\x1b[2m"
)

// ui is a thin output helper carrying the destination writer and whether colour
// is on. Threading it through the run functions keeps the commands testable: a
// test builds a ui over a bytes.Buffer with colour off and asserts on plain text.
type ui struct {
	w     io.Writer
	color bool
}

// newUI builds a ui over w, enabling colour only when w is a terminal and NO_COLOR
// is unset.
func newUI(w io.Writer) ui {
	return ui{w: w, color: isTerminal(w)}
}

func (u ui) printf(format string, a ...any) { fmt.Fprintf(u.w, format, a...) }
func (u ui) print(s string)                 { fmt.Fprint(u.w, s) }

// wrap applies an ANSI code around s only when colour is on.
func (u ui) wrap(code, s string) string {
	if !u.color {
		return s
	}
	return code + s + ansiReset
}

func (u ui) red(s string) string    { return u.wrap(ansiRed, s) }
func (u ui) yellow(s string) string { return u.wrap(ansiYellow, s) }
func (u ui) green(s string) string  { return u.wrap(ansiGreen, s) }
func (u ui) cyan(s string) string   { return u.wrap(ansiCyan, s) }
func (u ui) bold(s string) string   { return u.wrap(ansiBold, s) }
func (u ui) dim(s string) string    { return u.wrap(ansiDim, s) }

// isTerminal reports whether w is an interactive terminal, so colour and prompts
// are only used where a human is watching. It stats the underlying file's mode for
// the char-device bit, which needs no extra dependency, and honours NO_COLOR.
func isTerminal(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
