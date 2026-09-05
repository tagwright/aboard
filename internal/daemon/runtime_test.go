// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"testing"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/config"
)

// TestBuildRuntimeSelectsDocker proves the default runtime and an explicit
// "docker" both build the Docker adapter.
func TestBuildRuntimeSelectsDocker(t *testing.T) {
	rt, err := BuildRuntime(&config.Config{Runtime: config.RuntimeDocker})
	if err != nil {
		t.Fatalf("BuildRuntime docker: %v", err)
	}
	if _, ok := rt.(*runtime.DockerRuntime); !ok {
		t.Errorf("runtime docker: got %T, want *runtime.DockerRuntime", rt)
	}
}

// TestBuildRuntimeSelectsPodman proves "podman" builds the Podman adapter.
func TestBuildRuntimeSelectsPodman(t *testing.T) {
	rt, err := BuildRuntime(&config.Config{Runtime: config.RuntimePodman})
	if err != nil {
		t.Fatalf("BuildRuntime podman: %v", err)
	}
	if _, ok := rt.(*runtime.PodmanRuntime); !ok {
		t.Errorf("runtime podman: got %T, want *runtime.PodmanRuntime", rt)
	}
}

// TestBuildRuntimeUnknownFailsClosed proves an out-of-enum runtime is a
// construction error, never a silent fall back to Docker.
func TestBuildRuntimeUnknownFailsClosed(t *testing.T) {
	rt, err := BuildRuntime(&config.Config{Runtime: "containerd"})
	if err == nil {
		t.Fatalf("BuildRuntime containerd: want error, got nil")
	}
	if rt != nil {
		t.Errorf("BuildRuntime containerd: want nil runtime, got %T", rt)
	}
}

// TestRuntimeSocketDefaultsPerRuntime proves an unset socket resolves to the
// per-runtime conventional default passed in.
func TestRuntimeSocketDefaultsPerRuntime(t *testing.T) {
	if got := runtimeSocket(&config.Config{}, DefaultDockerSocket); got != DefaultDockerSocket {
		t.Errorf("docker default socket: got %q, want %q", got, DefaultDockerSocket)
	}
	if got := runtimeSocket(&config.Config{}, DefaultPodmanSocket); got != DefaultPodmanSocket {
		t.Errorf("podman default socket: got %q, want %q", got, DefaultPodmanSocket)
	}
}

// TestRuntimeSocketOverrideWins proves an explicit socket overrides the
// per-runtime default for either runtime.
func TestRuntimeSocketOverrideWins(t *testing.T) {
	const custom = "/run/user/1000/podman/podman.sock"
	if got := runtimeSocket(&config.Config{Socket: custom}, DefaultDockerSocket); got != custom {
		t.Errorf("socket override over docker default: got %q, want %q", got, custom)
	}
	if got := runtimeSocket(&config.Config{Socket: custom}, DefaultPodmanSocket); got != custom {
		t.Errorf("socket override over podman default: got %q, want %q", got, custom)
	}
}
