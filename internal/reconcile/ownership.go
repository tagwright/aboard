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
// aboard-named provider derived from the app's slug in the OAuth2 table first
// (so a live-credential OIDC provider is recognized as such) and then the proxy
// table, and reports ownership only when the app points at the provider it
// found. A lookup that merely finds nothing (ErrNotFound) is not an error here;
// any other error is returned so a transport failure is never mistaken for
// "not owned".
func (r *Reconciler) resolveOwnership(ctx context.Context, app authentik.Application) (ownership, error) {
	if app.Provider == nil {
		return ownership{}, nil
	}
	name := providerMarkerName(app.Slug)

	oauth, err := r.api.GetOAuth2ProviderByName(ctx, name)
	if err != nil && !errors.Is(err, authentik.ErrNotFound) {
		return ownership{}, err
	}
	if oauth != nil && oauth.PK == *app.Provider {
		return ownership{owned: true, kind: spec.ProviderOIDC, providerPK: oauth.PK}, nil
	}

	proxy, err := r.api.GetProxyProviderByName(ctx, name)
	if err != nil && !errors.Is(err, authentik.ErrNotFound) {
		return ownership{}, err
	}
	if proxy != nil && proxy.PK == *app.Provider {
		return ownership{owned: true, kind: spec.ProviderForwardAuth, providerPK: proxy.PK}, nil
	}

	return ownership{}, nil
}
