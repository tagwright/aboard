// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package reconcile

import (
	"context"
	"testing"

	"github.com/tagwright/aboard/internal/authentik"
)

// #605: aboard's reconcile fake supports errOn injection, but only the
// pre-attach CreateBinding failure was exercised. These lock in that the write
// and delete failures on the IdP paths a wrong reconcile/prune would hit SURFACE
// (an error, Attached=false, no partial teardown), rather than being acked as
// success. aboard holds a write token to the identity provider, so a swallowed
// write/delete is a silent security-relevant failure.

// The attach-last go-live step failing must surface as a failed reconcile with
// Attached=false (nothing goes live on a failed attach).
func TestReconcile_AttachFailureSurfaces(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	f.errOn["PatchOutpostProviders"] = errBoom

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())
	if err == nil {
		t.Fatal("#605: a failed outpost attach did not surface (silent success on the go-live step)")
	}
	if res.Attached {
		t.Error("#605: Result.Attached must be false when the attach failed")
	}
}

// A provider-delete failure during teardown must surface AND must not proceed to
// delete the application: the provider-before-app order means a failed provider
// delete leaves both in place (a clean retry), never an app-gone/provider-left
// partial that would orphan a live provider.
func TestTeardown_ProviderDeleteFailureSurfacesAndSkipsAppDelete(t *testing.T) {
	f := newFake().withEmbedded(1)
	f.proxyByName["gone (aboard)"] = &authentik.ProxyProvider{PK: 1, Name: "gone (aboard)"}
	f.appBySlug["gone"] = &authentik.Application{PK: "app-gone", Slug: "gone", Provider: intPtr(1)}
	f.errOn["DeleteProxyProvider"] = errBoom

	r := New(f, testConfig(), fixedResolver("unused"))
	if err := r.Teardown(context.Background(), "gone"); err == nil {
		t.Fatal("#605: a failed provider delete during teardown did not surface")
	}
	if f.called("DeleteApplication") {
		t.Error("#605: the application was deleted after the provider delete FAILED -- a partial teardown (app gone, provider left)")
	}
}

// An application-delete failure (the last teardown step) must surface too.
func TestTeardown_ApplicationDeleteFailureSurfaces(t *testing.T) {
	f := newFake().withEmbedded(1)
	f.proxyByName["gone (aboard)"] = &authentik.ProxyProvider{PK: 1, Name: "gone (aboard)"}
	f.appBySlug["gone"] = &authentik.Application{PK: "app-gone", Slug: "gone", Provider: intPtr(1)}
	f.errOn["DeleteApplication"] = errBoom

	r := New(f, testConfig(), fixedResolver("unused"))
	if err := r.Teardown(context.Background(), "gone"); err == nil {
		t.Fatal("#605: a failed application delete during teardown did not surface")
	}
}
