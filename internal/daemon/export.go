// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/traefik"
)

// The CLI's read-only passes (validate, render, status, prune) reuse the exact
// self-exclusion, fleet-callback detection, and Input construction the daemon's
// event loop uses, so there is ONE source of truth for each. Self-exclusion in
// particular is a security property (aboard must never enrol the IdP it drives),
// and a second copy in the cli package could drift from this one. These are thin
// re-exports of the unexported helpers, not new logic.

// InputFrom builds a discovery.Input for a container, matching the daemon's own
// per-container hand-off.
func InputFrom(c runtime.Container) discovery.Input { return inputFrom(c) }

// IsSelfExcluded reports whether a container must never be acted on regardless of
// its labels: the Authentik containers aboard drives, and aboard's own container.
func IsSelfExcluded(c runtime.Container) bool { return isSelfExcluded(c) }

// DetectFleetCallback reports whether any container carries a fleet-wide catch-all
// outpost callback router, which satisfies the mixed-host callback rule fleet-wide.
func DetectFleetCallback(containers []runtime.Container) bool {
	return detectFleetCallback(containers)
}

// DetectGroupsHeader reports whether the forward-auth middleware definition among
// the containers carries X-authentik-groups in its authResponseHeaders, the
// fleet scan the status pass reuses so it agrees with the daemon.
func DetectGroupsHeader(containers []runtime.Container, middlewareRef string) traefik.GroupsHeaderState {
	return detectGroupsHeader(containers, middlewareRef)
}
