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
	// The orphan scan enumerates the polymorphic provider list, keeps only the
	// " (aboard)"-named ones, and keys each on its assigned application slug. Each
	// provider appears ONCE here under its true component (a proxy provider is
	// ak-provider-proxy-form, not the oauth2 subclass form).
	f.allProviders = []authentik.AllProvider{
		// Owned forward-auth, not enabled -> orphan.
		{PK: 1, Name: "gone (aboard)", Component: authentik.ComponentProxyProvider, AssignedApplicationSlug: "gone"},
		// Owned forward-auth, still enabled -> not an orphan.
		{PK: 3, Name: "live (aboard)", Component: authentik.ComponentProxyProvider, AssignedApplicationSlug: "live"},
		// Hand-made (no aboard marker) -> never an orphan.
		{PK: 99, Name: "hand-rolled provider", Component: authentik.ComponentProxyProvider, AssignedApplicationSlug: "hand"},
		// Owned OIDC, not enabled -> orphan, and a live credential, so listed first.
		{PK: 2, Name: "oidcgone (aboard)", Component: authentik.ComponentOAuth2Provider, AssignedApplicationSlug: "oidcgone"},
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

func TestOrphansDanglingProviderNoApplication(t *testing.T) {
	f := newFake()
	// An aboard-owned provider with no application assigned (empty slug) is a
	// dangling-provider orphan, which the old application-keyed scan never saw.
	f.allProviders = []authentik.AllProvider{
		{PK: 5, Name: "dangling (aboard)", Component: authentik.ComponentOAuth2Provider, AssignedApplicationSlug: ""},
	}

	r := New(f, testConfig(), fixedResolver("unused"))
	orphans, err := r.Orphans(context.Background(), []string{"live"})
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	if len(orphans) != 1 || orphans[0].ProviderPK != 5 || orphans[0].Slug != "" {
		t.Fatalf("orphans = %+v, want one dangling orphan with empty slug", orphans)
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

func TestTeardownSAMLNoOutpost(t *testing.T) {
	f := newFake().withEmbedded()
	f.samlByName["kimai (aboard)"] = &authentik.SAMLProvider{PK: 6, Name: "kimai (aboard)"}
	f.appBySlug["kimai"] = &authentik.Application{PK: "app-kimai", Slug: "kimai", Provider: intPtr(6)}

	r := New(f, testConfig(), fixedResolver("unused"))
	if err := r.Teardown(context.Background(), "kimai"); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	// SAML is server-served: no outpost detach.
	if f.called("PatchOutpostProviders") {
		t.Error("SAML teardown has no outpost step")
	}
	if len(f.deletedSAMLPKs) != 1 || f.deletedSAMLPKs[0] != 6 {
		t.Errorf("deleted saml pks = %v, want [6]", f.deletedSAMLPKs)
	}
	if len(f.deletedApps) != 1 || f.deletedApps[0] != "kimai" {
		t.Errorf("deleted apps = %v, want [kimai]", f.deletedApps)
	}
}

func TestOrphansSAMLKind(t *testing.T) {
	f := newFake()
	f.allProviders = []authentik.AllProvider{
		{PK: 7, Name: "kimai (aboard)", Component: authentik.ComponentSAMLProvider, AssignedApplicationSlug: "kimai"},
	}

	r := New(f, testConfig(), fixedResolver("unused"))
	orphans, err := r.Orphans(context.Background(), nil)
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	if len(orphans) != 1 || orphans[0].Kind != spec.ProviderSAML {
		t.Fatalf("orphans = %+v, want one SAML orphan", orphans)
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
