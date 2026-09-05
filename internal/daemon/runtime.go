// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"fmt"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/config"
)

// DefaultPodmanSocket is the rootful Podman system-service socket BuildRuntime
// dials for runtime "podman" when no socket override is configured (podman.socket
// enabled at the system level). A rootless Podman deployment uses
// $XDG_RUNTIME_DIR/podman/podman.sock instead: set ABOARD_SOCKET (or socket: in
// aboard.yml) to that path. aboard reads the socket, it never writes to it.
const DefaultPodmanSocket = "/run/podman/podman.sock"

// BuildRuntime constructs the core runtime adapter cfg selects: Docker (the
// default) or Podman, both talking to a Docker Engine API-compatible socket
// through github.com/tagwright/core. It is the single place the daemon and every
// CLI command open a socket, so the two can never drift apart on runtime
// selection. A socket override (config.Socket, from ABOARD_SOCKET or aboard.yml)
// wins; otherwise the per-runtime conventional default is used. An unknown
// runtime is a construction error, so an out-of-enum value fails closed rather
// than silently defaulting to Docker.
func BuildRuntime(cfg *config.Config) (runtime.Runtime, error) {
	switch cfg.Runtime {
	case config.RuntimeDocker:
		return runtime.NewDocker(runtimeSocket(cfg, DefaultDockerSocket)), nil
	case config.RuntimePodman:
		return runtime.NewPodman(runtimeSocket(cfg, DefaultPodmanSocket)), nil
	default:
		return nil, fmt.Errorf("daemon: unknown runtime %q, want %q or %q",
			cfg.Runtime, config.RuntimeDocker, config.RuntimePodman)
	}
}

// runtimeSocket resolves the API socket path for the selected runtime: the
// explicit override when set, otherwise the per-runtime conventional default.
func runtimeSocket(cfg *config.Config, def string) string {
	if cfg.Socket != "" {
		return cfg.Socket
	}
	return def
}
