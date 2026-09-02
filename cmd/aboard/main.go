// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Command aboard is the label-driven single-sign-on companion for Authentik.
// It reads aboard.* labels on a container and reconciles the matching state
// inside Authentik (an Application, a Provider, the access bindings, and the
// embedded-outpost attachment) over Authentik's REST API, then audits the
// container's Traefik forward-auth wiring. It drives Authentik, it never
// rebuilds the IdP.
//
// The command tree (daemon, status, render, prune, validate, version) lives in
// internal/cli. This entry point calls Execute and does nothing else.
package main

import (
	"os"

	"github.com/tagwright/aboard/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
