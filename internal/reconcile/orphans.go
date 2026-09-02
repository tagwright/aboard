// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package reconcile

import (
	"context"
	"errors"
	"sort"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/spec"
)

// orphanListPageSize is the page size for the full-fleet provider listing the
// orphan scan walks. A full listing is the one place a single-item filter would
// span pages (architecture, "Authentik REST client").
const orphanListPageSize = 100

// Orphan is an aboard-owned Authentik object with no matching enabled container
// (Fork 8). It is surfaced in status and the daily digest, never deleted by
// reconcile. Kind lets the digest list OIDC orphans (live credentials) first and
// separately from harmless proxy ones. Slug is the assigned application slug the
// orphan is keyed on, empty for a dangling provider that has no application.
type Orphan struct {
	Slug       string
	Kind       spec.ProviderType
	ProviderPK int
}

// Orphans returns the aboard-owned providers whose assigned application slug is
// not in enabledSlugs. It enumerates the providers (the polymorphic
// /providers/all/ list, which unlike the application list is NOT access-filtered,
// so a non-superuser scoped token sees every owned provider) and keeps only the
// aboard-owned ones, identified by the " (aboard)" name marker: a hand-made
// object is never an orphan. Each owned provider is keyed on its
// assigned_application_slug, and one whose slug is not still enabled is an orphan.
// A provider with no application assigned (empty slug) is a dangling-provider
// orphan, which the old application-keyed scan could not see at all. The result is
// ordered OIDC first, so a caller rendering the digest surfaces live credentials
// before inert proxies.
func (r *Reconciler) Orphans(ctx context.Context, enabledSlugs []string) ([]Orphan, error) {
	provs, err := r.api.ListAllProviders(ctx, orphanListPageSize)
	if err != nil {
		return nil, err
	}

	enabled := make(map[string]bool, len(enabledSlugs))
	for _, s := range enabledSlugs {
		enabled[s] = true
	}

	var orphans []Orphan
	for _, p := range provs {
		if !isAboardProviderName(p.Name) {
			continue
		}
		if p.AssignedApplicationSlug != "" && enabled[p.AssignedApplicationSlug] {
			continue
		}
		orphans = append(orphans, Orphan{
			Slug:       p.AssignedApplicationSlug,
			Kind:       providerKindFromComponent(p.Component),
			ProviderPK: p.PK,
		})
	}

	// OIDC (live credentials) first, then by slug for a stable order.
	sort.SliceStable(orphans, func(i, j int) bool {
		if orphans[i].Kind != orphans[j].Kind {
			return orphans[i].Kind == spec.ProviderOIDC
		}
		return orphans[i].Slug < orphans[j].Slug
	})
	return orphans, nil
}

// Teardown removes an aboard-owned object explicitly, the only delete path in
// the tool: reconcile never deletes (KEEP default, Fork 8), and this runs only
// for `aboard prune`. It refuses to touch anything not aboard-owned, so a
// hand-made object is safe.
//
// The order defends against leaving a dangling live provider: detach the
// provider from the outpost FIRST (so it stops serving), then delete the
// provider, then delete the application. A failure at any step stops before the
// next, so the worst outcome is the pre-existing state, never an attached
// provider whose application is already gone. A forward-auth provider is
// detached from the embedded outpost; OIDC has no outpost step.
func (r *Reconciler) Teardown(ctx context.Context, slug string) error {
	app, err := r.api.GetApplicationBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, authentik.ErrNotFound) {
			return &Error{Code: CodeAPI, Message: "application " + slug + " does not exist"}
		}
		return err
	}

	own, err := r.resolveOwnership(ctx, *app)
	if err != nil {
		return err
	}
	if !own.owned {
		return &Error{Code: CodeAdoptConflict, Message: "application " + slug + " is not aboard-owned; teardown refuses to delete a hand-made object"}
	}

	switch own.kind {
	case spec.ProviderForwardAuth:
		if derr := r.detachFromEmbedded(ctx, own.providerPK); derr != nil {
			return derr
		}
		if derr := r.api.DeleteProxyProvider(ctx, own.providerPK); derr != nil && !errors.Is(derr, authentik.ErrNotFound) {
			return derr
		}
	case spec.ProviderSAML:
		// SAML is server-served: no outpost attach, so no detach. Just delete the
		// provider.
		if derr := r.api.DeleteSAMLProvider(ctx, own.providerPK); derr != nil && !errors.Is(derr, authentik.ErrNotFound) {
			return derr
		}
	default:
		// OIDC: no outpost step either.
		if derr := r.api.DeleteOAuth2Provider(ctx, own.providerPK); derr != nil && !errors.Is(derr, authentik.ErrNotFound) {
			return derr
		}
	}

	if derr := r.api.DeleteApplication(ctx, slug); derr != nil && !errors.Is(derr, authentik.ErrNotFound) {
		return derr
	}
	return nil
}

// detachFromEmbedded removes providerPK from the embedded outpost's providers
// list, read-modify-write, leaving every other provider in place. An absent
// embedded outpost or a provider already not in the list is a no-op.
func (r *Reconciler) detachFromEmbedded(ctx context.Context, providerPK int) error {
	outpost, err := r.api.GetEmbeddedOutpost(ctx)
	if err != nil {
		if errors.Is(err, authentik.ErrNotFound) {
			return nil
		}
		return err
	}
	if !containsInt(outpost.Providers, providerPK) {
		return nil
	}
	kept := make([]int, 0, len(outpost.Providers))
	for _, pk := range outpost.Providers {
		if pk != providerPK {
			kept = append(kept, pk)
		}
	}
	_, err = r.api.PatchOutpostProviders(ctx, outpost.PK, kept)
	return err
}
