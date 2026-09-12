// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package reconcile

import (
	"context"
	"errors"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/spec"
)

// LiveState is the confirmed-vs-desired verdict for one enabled app. It is the
// ground-truth distinction status draws so a reader never mistakes "container
// present" (DISCOVERED from labels) for "provisioned and live" (CONFIRMED against
// Authentik). This is the meta-lesson of the naming/scratchie incident, where
// status reported apps as fine that Authentik had never provisioned.
type LiveState int

const (
	// LiveUnknown means the confirmation could not be completed (a lookup or the
	// live serve probe errored). It is neither confirmed nor proven drifted.
	LiveUnknown LiveState = iota
	// LiveConfirmed means Authentik actually has the object AND, for forward-auth,
	// the live outpost serves the host. This is the only state that proves live.
	LiveConfirmed
	// LiveDrift means the app is desired from labels but is NOT confirmed live in
	// Authentik: no provider, an unattached provider, or an attached-but-stale
	// outpost. A drift means the app is not actually serving as the labels intend.
	LiveDrift
)

// LiveCheck is one enabled app to confirm against Authentik: its desired slug,
// forward-auth host, and provider type.
type LiveCheck struct {
	Slug     string
	Host     string
	Provider spec.ProviderType
}

// LiveResult is the confirmed state of one LiveCheck plus a human-readable detail,
// never a secret.
type LiveResult struct {
	Slug   string
	State  LiveState
	Detail string
}

// ConfirmLive checks each enabled app against ACTUAL Authentik state and returns a
// per-app confirmed-vs-desired verdict. For a forward-auth app "confirmed" means
// the aboard provider exists, is attached to the embedded outpost, AND the live
// outpost serves the host; anything short of that is drift. OIDC and SAML are
// server-served with no outpost half, so confirmation is provider existence. It is
// read-only: it never writes Authentik.
func (r *Reconciler) ConfirmLive(ctx context.Context, checks []LiveCheck) ([]LiveResult, error) {
	// The embedded outpost's providers list, fetched once, for the forward-auth
	// attach check. Only needed when a forward-auth app is among the checks.
	var attached map[int]bool
	for _, c := range checks {
		if c.Provider == spec.ProviderForwardAuth {
			outpost, err := r.api.GetEmbeddedOutpost(ctx)
			if err != nil {
				if !errors.Is(err, authentik.ErrNotFound) {
					return nil, err
				}
				attached = map[int]bool{} // no embedded outpost means nothing is attached
			} else {
				attached = make(map[int]bool, len(outpost.Providers))
				for _, pk := range outpost.Providers {
					attached[pk] = true
				}
			}
			break
		}
	}

	out := make([]LiveResult, 0, len(checks))
	for _, c := range checks {
		out = append(out, r.confirmOne(ctx, c, attached))
	}
	return out, nil
}

// confirmOne resolves the live state of a single app.
func (r *Reconciler) confirmOne(ctx context.Context, c LiveCheck, attached map[int]bool) LiveResult {
	name := providerMarkerName(c.Slug)
	switch c.Provider {
	case spec.ProviderForwardAuth:
		p, err := r.api.GetProxyProviderByName(ctx, name)
		if err != nil {
			if errors.Is(err, authentik.ErrNotFound) {
				return LiveResult{Slug: c.Slug, State: LiveDrift, Detail: "no aboard provider in Authentik (never provisioned)"}
			}
			return LiveResult{Slug: c.Slug, State: LiveUnknown, Detail: "provider lookup failed: " + err.Error()}
		}
		if !attached[p.PK] {
			return LiveResult{Slug: c.Slug, State: LiveDrift, Detail: "provider exists but is NOT attached to the embedded outpost"}
		}
		serves, err := r.api.OutpostServesHost(ctx, c.Host)
		if err != nil {
			return LiveResult{Slug: c.Slug, State: LiveUnknown, Detail: "attached, but the live serve probe failed: " + err.Error()}
		}
		if !serves {
			return LiveResult{Slug: c.Slug, State: LiveDrift, Detail: "attached to the outpost but the LIVE outpost does not serve the host (stale)"}
		}
		return LiveResult{Slug: c.Slug, State: LiveConfirmed, Detail: "provider attached and served by the outpost"}
	case spec.ProviderSAML:
		if _, err := r.api.GetSAMLProviderByName(ctx, name); err != nil {
			if errors.Is(err, authentik.ErrNotFound) {
				return LiveResult{Slug: c.Slug, State: LiveDrift, Detail: "no aboard SAML provider in Authentik (never provisioned)"}
			}
			return LiveResult{Slug: c.Slug, State: LiveUnknown, Detail: "provider lookup failed: " + err.Error()}
		}
		return LiveResult{Slug: c.Slug, State: LiveConfirmed, Detail: "SAML provider present (server-served, no outpost half)"}
	default: // OIDC
		if _, err := r.api.GetOAuth2ProviderByName(ctx, name); err != nil {
			if errors.Is(err, authentik.ErrNotFound) {
				return LiveResult{Slug: c.Slug, State: LiveDrift, Detail: "no aboard OIDC provider in Authentik (never provisioned)"}
			}
			return LiveResult{Slug: c.Slug, State: LiveUnknown, Detail: "provider lookup failed: " + err.Error()}
		}
		return LiveResult{Slug: c.Slug, State: LiveConfirmed, Detail: "OIDC provider present (server-served, no outpost half)"}
	}
}
