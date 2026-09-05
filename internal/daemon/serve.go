// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"fmt"
	"log/slog"

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

	d, err := New(Config{
		Runtime:    rt,
		Reconciler: rec,
		Notifier:   notifier,
		Config:     cfg,
		Logger:     logger,
	})
	if err != nil {
		return err
	}
	return d.Run(ctx)
}

// errRequired builds the "a X is required" construction error New returns for a
// missing seam.
func errRequired(what string) error {
	return fmt.Errorf("daemon: %s is required", what)
}
