// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/secret"
)

// Serve is the CLI-facing entry point the `aboard daemon` command calls. It does
// the full wiring the injectable New leaves to its caller: load and validate the
// config, build the secret resolver, build the Authentik REST client (token
// resolved by NAME), build the reconciler, build the log-floored beacon notifier,
// open the runtime socket, then construct and Run the daemon. It blocks until ctx
// is cancelled.
//
// The seams that Run needs are all constructed here from real implementations;
// tests bypass Serve and call New over fakes instead, which is why the socket and
// network I/O all live in this thin wrapper and none of it in New.
func Serve(ctx context.Context, configPath string, logger *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	resolve := secret.FileEnvResolver(cfg.Globals.SecretsDir)

	client, err := authentik.FromConfig(cfg, resolve)
	if err != nil {
		return err
	}
	rec := reconcile.New(client, cfg, resolve)

	notifier, err := BuildNotifier(cfg, resolve)
	if err != nil {
		return fmt.Errorf("daemon: build notifier: %w", err)
	}

	// The container socket the config selects (docker or podman), read-only.
	// aboard reads the socket, it never writes it.
	rt, err := BuildRuntime(cfg)
	if err != nil {
		return err
	}
	defer rt.Close()

	return run(ctx, Deps{
		Runtime:    rt,
		Reconciler: rec,
		Notifier:   notifier,
		Config:     cfg,
		Logger:     logger,
		Clock:      time.Now,
	})
}

// Deps carries run's collaborators. It is the testable seam (the ratified suite
// Testing Standard), mirroring ballast's daemon.Deps: Serve builds Deps from the
// config file and the environment, then hands off to run; a wiring test builds
// Deps directly with fakes (a core/runtime/runtimetest Runtime, a fake
// reconciler, a fake clock) and calls run to drive the real socket-watch and
// reconcile loop with an injected failure, asserting it surfaces rather than
// passing silently.
//
// Every field here is a collaborator the production path constructs from config
// and a test substitutes: the runtime (the socket watch/list/inspect seam), the
// reconciler (the Authentik driver aboard reconciles through), the notifier, and
// the loop's clock. Config is the loaded aboard.yml run threads through to the
// daemon. DebounceWindow and DigestSchedule are test-only overrides; Serve
// leaves both at their zero value, so production timing is unchanged.
type Deps struct {
	Runtime    Runtime
	Reconciler Reconciler
	Notifier   Notifier
	Config     *config.Config
	Logger     *slog.Logger
	Clock      func() time.Time // loop/debounce clock; nil defaults to time.Now

	DebounceWindow time.Duration
	DigestSchedule string
}

// run builds the daemon from d and drives its control loop until ctx is
// cancelled. It is the production seam Serve hands off to and the seam a wiring
// test drives with fakes. It is behavior-preserving: it constructs and runs
// exactly what Serve constructed and ran inline before, now routed through Deps.
func run(ctx context.Context, d Deps) error {
	dmn, err := New(Config{
		Runtime:        d.Runtime,
		Reconciler:     d.Reconciler,
		Notifier:       d.Notifier,
		Config:         d.Config,
		Logger:         d.Logger,
		Now:            d.Clock,
		DebounceWindow: d.DebounceWindow,
		DigestSchedule: d.DigestSchedule,
	})
	if err != nil {
		return err
	}
	return dmn.Run(ctx)
}

// errRequired builds the "a X is required" construction error New returns for a
// missing seam.
func errRequired(what string) error {
	return fmt.Errorf("daemon: %s is required", what)
}
