// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package reconcile

import (
	"context"
	"errors"
	"strings"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/spec"
)

// ownerSuffix is the ownership marker (Fork 2). A provider named "<slug>
// (aboard)" is aboard's, and an Application is aboard-owned when it points at
// such a provider. The marker lives in Authentik itself, so there is no separate
// state ledger. This is the one place the marker string is defined; adoption,
// orphan detection, and teardown all route through the helpers here.
const ownerSuffix = " (aboard)"

// providerMarkerName is the derived, non-label-controlled provider name for a
// slug. It always carries ownerSuffix, which is what makes the object greppable
// as aboard's and recoverable without any aboard-local state.
func providerMarkerName(slug string) string {
	return slug + ownerSuffix
}

// isAboardProviderName reports whether a provider name carries the ownership
// marker. It is the predicate behind "aboard-owned": a provider name is aboard's
// exactly when it ends in " (aboard)".
func isAboardProviderName(name string) bool {
	return strings.HasSuffix(name, ownerSuffix)
}

// providerKindFromComponent maps an Authentik provider `component` discriminator
// to aboard's provider type. An unrecognized component (a saml or other provider
// aboard does not model) yields the empty type, which callers treat as "type
// unknown, do not assert a match".
func providerKindFromComponent(component string) spec.ProviderType {
	switch component {
	case authentik.ComponentProxyProvider:
		return spec.ProviderForwardAuth
	case authentik.ComponentOAuth2Provider:
		return spec.ProviderOIDC
	case authentik.ComponentSAMLProvider:
		return spec.ProviderSAML
	default:
		return ""
	}
}

// ownership is the result of resolving whether an application is aboard-owned
// and, if so, of which provider kind. An application is aboard-owned when its
// provider pk matches the aboard-named provider derived from its slug
// ("<slug> (aboard)"), which the authentik primitives can resolve by name (they
// expose no lookup by pk, so the marker name is the stable key).
type ownership struct {
	owned      bool
	kind       spec.ProviderType
	providerPK int
}

// resolveOwnership decides whether app is aboard-owned. It looks up the
// aboard-named provider derived from the app's slug and reports ownership only
// when the app points at the provider it found. A lookup that merely finds
// nothing (ErrNotFound) is not an error here; any other error is returned so a
// transport failure is never mistaken for "not owned".
//
// The PROXY table is consulted FIRST, and this order is load-bearing, verified
// against the live 2025.6.4 API: in Authentik a ProxyProvider is a SUBCLASS of
// OAuth2Provider, so the /providers/oauth2/ list returns proxy providers too
// (a forward-auth provider shows up on both endpoints). The /providers/proxy/
// list, by contrast, returns ONLY genuine proxy providers. So a proxy is
// identified authoritatively by the proxy endpoint, and the oauth2 endpoint is
// consulted only when no proxy of the marker name matches, at which point a hit
// there is a genuine OIDC provider. Checking oauth2 first would misread every
// aboard forward-auth provider as OIDC and spuriously flag a provider-type
// change on the next reconcile.
func (r *Reconciler) resolveOwnership(ctx context.Context, app authentik.Application) (ownership, error) {
	if app.Provider == nil {
		return ownership{}, nil
	}
	name := providerMarkerName(app.Slug)

	proxy, err := r.api.GetProxyProviderByName(ctx, name)
	if err != nil && !errors.Is(err, authentik.ErrNotFound) {
		return ownership{}, err
	}
	if proxy != nil && proxy.PK == *app.Provider {
		return ownership{owned: true, kind: spec.ProviderForwardAuth, providerPK: proxy.PK}, nil
	}

	// SAML is a clean, disjoint type: it is NOT an OAuth2Provider subclass, so it
	// never appears on the proxy or oauth2 endpoints and is resolved on its own.
	saml, err := r.api.GetSAMLProviderByName(ctx, name)
	if err != nil && !errors.Is(err, authentik.ErrNotFound) {
		return ownership{}, err
	}
	if saml != nil && saml.PK == *app.Provider {
		return ownership{owned: true, kind: spec.ProviderSAML, providerPK: saml.PK}, nil
	}

	oauth, err := r.api.GetOAuth2ProviderByName(ctx, name)
	if err != nil && !errors.Is(err, authentik.ErrNotFound) {
		return ownership{}, err
	}
	// A proxy provider is also returned by the oauth2 endpoint (subclass), so a
	// hit whose pk is the proxy we already saw is NOT a genuine OIDC provider.
	if oauth != nil && oauth.PK == *app.Provider && (proxy == nil || proxy.PK != oauth.PK) {
		return ownership{owned: true, kind: spec.ProviderOIDC, providerPK: oauth.PK}, nil
	}

	return ownership{}, nil
}
