// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package reconcile

import (
	"context"
	"testing"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/spec"
)

func TestOrphansOwnedAndNotEnabledOIDCFirst(t *testing.T) {
	f := newFake()
	// Owned forward-auth, not enabled -> orphan.
	f.proxyByName["gone (aboard)"] = &authentik.ProxyProvider{PK: 1, Name: "gone (aboard)"}
	// Owned OIDC, not enabled -> orphan, and a live credential, so listed first.
	f.oauthByName["oidcgone (aboard)"] = &authentik.OAuth2Provider{PK: 2, Name: "oidcgone (aboard)"}
	// Owned forward-auth, still enabled -> not an orphan.
	f.proxyByName["live (aboard)"] = &authentik.ProxyProvider{PK: 3, Name: "live (aboard)"}

	f.apps = []authentik.Application{
		{PK: "app-gone", Slug: "gone", Provider: intPtr(1)},
		{PK: "app-live", Slug: "live", Provider: intPtr(3)},
		{PK: "app-hand", Slug: "hand", Provider: intPtr(99)}, // hand-made, never an orphan
		{PK: "app-oidcgone", Slug: "oidcgone", Provider: intPtr(2)},
	}

	r := New(f, testConfig(), fixedResolver("unused"))
	orphans, err := r.Orphans(context.Background(), []string{"live"})
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	if len(orphans) != 2 {
		t.Fatalf("orphans = %+v, want 2 (gone, oidcgone)", orphans)
	}
	if orphans[0].Slug != "oidcgone" || orphans[0].Kind != spec.ProviderOIDC {
		t.Errorf("first orphan = %+v, want the OIDC one first", orphans[0])
	}
	if orphans[1].Slug != "gone" || orphans[1].Kind != spec.ProviderForwardAuth {
		t.Errorf("second orphan = %+v, want gone (forwardauth)", orphans[1])
	}
}

func TestTeardownOrderDetachDeleteProviderDeleteApp(t *testing.T) {
	f := newFake().withEmbedded(1, 99) // our provider 1, plus a foreign 99
	f.proxyByName["gone (aboard)"] = &authentik.ProxyProvider{PK: 1, Name: "gone (aboard)"}
	f.appBySlug["gone"] = &authentik.Application{PK: "app-gone", Slug: "gone", Provider: intPtr(1)}

	r := New(f, testConfig(), fixedResolver("unused"))
	if err := r.Teardown(context.Background(), "gone"); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	detach := f.callIndex("PatchOutpostProviders")
	delProv := f.callIndex("DeleteProxyProvider")
	delApp := f.callIndex("DeleteApplication")
	if detach < 0 || delProv < 0 || delApp < 0 {
		t.Fatalf("expected detach, delete provider, delete app to all run: %v", f.calls)
	}
	if !(detach < delProv && delProv < delApp) {
		t.Errorf("teardown order wrong: detach=%d delProv=%d delApp=%d", detach, delProv, delApp)
	}
	// Detach kept the foreign provider and dropped ours.
	if len(f.patchedOutpost) != 1 || f.patchedOutpost[0] != 99 {
		t.Errorf("outpost after detach = %v, want [99]", f.patchedOutpost)
	}
	if len(f.deletedProxyPKs) != 1 || f.deletedProxyPKs[0] != 1 {
		t.Errorf("deleted provider pks = %v, want [1]", f.deletedProxyPKs)
	}
	if len(f.deletedApps) != 1 || f.deletedApps[0] != "gone" {
		t.Errorf("deleted apps = %v, want [gone]", f.deletedApps)
	}
}

func TestTeardownRefusesHandMade(t *testing.T) {
	f := newFake().withEmbedded()
	// App points at a provider with no aboard marker -> not aboard-owned.
	f.appBySlug["hand"] = &authentik.Application{PK: "app-hand", Slug: "hand", Provider: intPtr(99)}

	r := New(f, testConfig(), fixedResolver("unused"))
	err := r.Teardown(context.Background(), "hand")
	if err == nil {
		t.Fatal("teardown must refuse a hand-made object")
	}
	if f.called("DeleteApplication") || f.called("DeleteProxyProvider") {
		t.Error("teardown must delete nothing when it refuses")
	}
}

func TestTeardownOIDCNoOutpost(t *testing.T) {
	f := newFake().withEmbedded()
	f.oauthByName["gitea (aboard)"] = &authentik.OAuth2Provider{PK: 5, Name: "gitea (aboard)"}
	f.appBySlug["gitea"] = &authentik.Application{PK: "app-gitea", Slug: "gitea", Provider: intPtr(5)}

	r := New(f, testConfig(), fixedResolver("unused"))
	if err := r.Teardown(context.Background(), "gitea"); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if f.called("PatchOutpostProviders") {
		t.Error("OIDC teardown has no outpost step")
	}
	if len(f.deletedOAuthPKs) != 1 || f.deletedOAuthPKs[0] != 5 {
		t.Errorf("deleted oauth pks = %v, want [5]", f.deletedOAuthPKs)
	}
	if len(f.deletedApps) != 1 || f.deletedApps[0] != "gitea" {
		t.Errorf("deleted apps = %v, want [gitea]", f.deletedApps)
	}
}
