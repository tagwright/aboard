// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"strings"

	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/traefik"
)

// composeServiceLabel is the Docker Compose service-name label, the stable
// identity aboard keys debounce and alerts off, matching discovery's own ladder.
const composeServiceLabel = "com.docker.compose.service"

// detectFleetCallback scans every container's Traefik router labels for a FLEET
// catch-all callback router: a router whose rule carries the outpost callback
// PathPrefix AND matches broadly (a HostRegexp for the fleet's domains rather
// than a single literal Host tied to one app). When such a router exists, the
// verifier's per-container mixed-host callback demand is satisfied fleet-wide, so
// no per-app callback router is ever needed again (grammar Fork 6, "The Traefik
// side"; architecture "Embedded outpost discovery").
//
// It reuses the traefik package's structural callback recognition (IsCallback)
// and discovery's HostRegexp detection (RuleHasHostRegexp) rather than
// re-parsing, so the daemon and the verifier agree on what a callback router is.
// A per-app callback router (callback PathPrefix with a literal Host) is
// deliberately NOT a fleet catch-all: it protects one host, and treating it as
// fleet-wide would wrongly suppress the callback demand on every other host.
func detectFleetCallback(containers []runtime.Container) bool {
	for _, c := range containers {
		for _, r := range traefik.ParseRouters(c.Labels) {
			if r.IsCallback() && discovery.RuleHasHostRegexp(r.Rule) {
				return true
			}
		}
	}
	return false
}

// authentikImageMarkers are substrings of an Authentik container's image that
// mark it as the IdP aboard drives. aboard never enrolls the IdP it drives.
var authentikImageMarkers = []string{"goauthentik", "authentik"}

// aboardSelfMarkers are substrings marking aboard's own container. aboard never
// enrolls itself.
var aboardSelfMarkers = []string{"tagwright/aboard", "/aboard:", "aboard:"}

// isSelfExcluded reports whether a container must never be acted on regardless of
// its labels: the Authentik containers aboard drives, and aboard's own container.
// This is DEFENSE IN DEPTH on top of the strict opt-in gate (a container with no
// aboard.enable=true is already invisible). The architecture requires it: aboard
// should never try to enroll the IdP it drives or itself even if one of them were
// mislabeled, because that is a way to lock the fleet out of its own login.
//
// The check is by container image and service name, deliberately broad and
// documented as a heuristic. The primary protection remains the enable gate; this
// is the belt to its suspenders. An operator who truly wants to protect an
// Authentik-adjacent service can still do so, because self-exclusion keys on the
// IdP's own image markers, not on the word "auth" appearing anywhere.
func isSelfExcluded(c runtime.Container) bool {
	image := strings.ToLower(c.Image)
	for _, m := range authentikImageMarkers {
		if strings.Contains(image, m) {
			return true
		}
	}
	for _, m := range aboardSelfMarkers {
		if strings.Contains(image, m) {
			return true
		}
	}

	name := strings.ToLower(serviceIdentity(c))
	switch name {
	case "authentik", "authentik-server", "authentik-worker", "aboard":
		return true
	}
	return false
}

// serviceIdentity is the stable service name for a container: the compose
// service label, else the container name with any leading slash stripped. It is
// the key debounce and sticky state use, and it matches discovery's identity
// ladder for a container that carries no aboard.name override.
func serviceIdentity(c runtime.Container) string {
	if c.Service != "" {
		return c.Service
	}
	if v := c.Labels[composeServiceLabel]; v != "" {
		return v
	}
	return strings.TrimPrefix(c.Name, "/")
}

// inputFrom builds the discovery Input for a container: its name and full label
// map. Discovery re-derives the service identity from the labels, so this stays a
// thin, Docker-free hand-off.
func inputFrom(c runtime.Container) discovery.Input {
	return discovery.Input{
		ContainerName: strings.TrimPrefix(c.Name, "/"),
		Labels:        c.Labels,
	}
}

// serviceKeyFromEvent derives the stable debounce key for a lifecycle event. A
// core Event carries the raw actor attributes (which include the container's
// labels plus its name), so the compose service label is preferred, then the
// event name. Keying off the service, not the container id, is what lets a
// force-recreate's die (old id) and start (new id) coalesce into one change.
func serviceKeyFromEvent(ev runtime.Event) string {
	if v := ev.Labels[composeServiceLabel]; v != "" {
		return v
	}
	if ev.Name != "" {
		return strings.TrimPrefix(ev.Name, "/")
	}
	return ev.ID
}
