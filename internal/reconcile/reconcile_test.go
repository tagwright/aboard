// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package reconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/spec"
)

var errBoom = errors.New("boom")

// hasIssue reports whether res carries an Issue with the given severity and code.
func hasIssue(res *Result, sev discovery.Severity, code string) bool {
	for _, i := range res.Issues {
		if i.Severity == sev && i.Code == code {
			return true
		}
	}
	return false
}

// errCode returns the reconcile Error code, or "".
func errCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestReconcileForwardAuthCreateAndAttachLast(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if !f.called("CreateProxyProvider") {
		t.Error("expected the provider to be created")
	}
	if !f.called("CreateApplication") {
		t.Error("expected the application to be created")
	}
	if !f.called("CreateBinding") {
		t.Error("expected the group binding to be created")
	}
	if !res.Attached {
		t.Error("expected the provider to be attached")
	}

	// The ordering contract: the attach happens only after the bindings.
	attach := f.callIndex("PatchOutpostProviders")
	bind := f.callIndex("CreateBinding")
	if attach < 0 || bind < 0 || attach < bind {
		t.Errorf("attach must come after bindings: bind=%d attach=%d", bind, attach)
	}
	// And after the outpost was read (read-modify-write).
	if read := f.callIndex("GetEmbeddedOutpost"); read < 0 || read > attach {
		t.Errorf("outpost must be read before it is patched: read=%d attach=%d", read, attach)
	}
}

// TestReconcileAttachSkippedOnPriorError is the ordering-contract proof: when a
// step before the attach fails, the attach never runs and nothing goes live.
func TestReconcileAttachSkippedOnPriorError(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	f.errOn["CreateBinding"] = errBoom // fail in step d, right before the attach

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())
	if err == nil {
		t.Fatal("expected an error when a pre-attach step fails")
	}
	if f.called("GetEmbeddedOutpost") {
		t.Error("outpost must not be read once a pre-attach step failed")
	}
	if f.called("PatchOutpostProviders") {
		t.Error("ATTACH RAN despite a pre-attach failure: the ordering contract is broken")
	}
	if res.Attached {
		t.Error("Result.Attached must be false on a failed reconcile")
	}
}

func TestReconcileProviderPatchWhenExists(t *testing.T) {
	f := newFake().withFlows().withEmbedded(7)
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	// An already aboard-owned app and its provider.
	f.proxyByName["whoami (aboard)"] = &authentik.ProxyProvider{PK: 7, Name: "whoami (aboard)"}
	f.appBySlug["whoami"] = &authentik.Application{PK: "app-whoami", Slug: "whoami", Provider: intPtr(7), Name: "whoami", PolicyEngineMode: "any"}

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if f.called("CreateProxyProvider") {
		t.Error("existing provider must be patched, not created")
	}
	if !f.called("PatchProxyProvider") {
		t.Error("expected the existing provider to be patched")
	}
	if !f.called("PatchApplication") {
		t.Error("expected the existing application to be patched")
	}
	if res.Adopted {
		t.Error("an already aboard-owned app is not an adoption")
	}
}

func TestReconcileOIDCCreateNoAttach(t *testing.T) {
	f := newFake().withFlows()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	f.certs["authentik Self-signed Certificate"] = &authentik.CertificateKeyPair{PK: "cert-1", Name: "authentik Self-signed Certificate"}
	f.scopes["openid"] = &authentik.ScopeMapping{PK: "sm-openid", ScopeName: "openid"}
	f.scopes["email"] = &authentik.ScopeMapping{PK: "sm-email", ScopeName: "email"}
	f.scopes["profile"] = &authentik.ScopeMapping{PK: "sm-profile", ScopeName: "profile"}
	f.scopes["offline_access"] = &authentik.ScopeMapping{PK: "sm-offline", ScopeName: "offline_access"}

	const secret40 = "0123456789012345678901234567890123456789"
	s := spec.Spec{
		Enable: true, Name: "gitea", Slug: "gitea", Title: "Gitea",
		Provider: spec.ProviderOIDC, Host: "git.example.com", Require: spec.RequireAny,
		Groups: []string{"g-admins"}, GroupsSet: true,
		OIDC: spec.OIDCSpec{
			Redirect:   []string{"https://git.example.com/callback"},
			SecretName: "gitea-secret",
			ClientKind: spec.ClientConfidential,
			Scopes:     []string{"offline_access"},
		},
	}

	r := New(f, testConfig(), fixedResolver(secret40))
	res, err := r.Reconcile(context.Background(), s)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !f.called("CreateOAuth2Provider") {
		t.Fatal("expected the OIDC provider to be created")
	}
	// OIDC has no outpost step.
	if f.called("GetEmbeddedOutpost") || f.called("PatchOutpostProviders") {
		t.Error("OIDC must not touch an outpost")
	}
	if res.Attached {
		t.Error("OIDC provider is never attached")
	}

	body := f.createdOAuth[0]
	if body.ClientType != authentik.ClientTypeConfidential {
		t.Errorf("client_type = %q, want confidential", body.ClientType)
	}
	if body.ClientSecret != secret40 {
		t.Error("the resolved client secret must be pushed inward onto the provider")
	}
	if body.SigningKey != "cert-1" {
		t.Errorf("signing_key = %q, want cert-1", body.SigningKey)
	}
	// openid, email, profile always, plus the extra.
	if len(body.PropertyMappings) != 4 {
		t.Errorf("property_mappings = %v, want 4 (openid,email,profile,offline_access)", body.PropertyMappings)
	}
	wantScope := map[string]bool{"sm-openid": true, "sm-email": true, "sm-profile": true, "sm-offline": true}
	for _, pk := range body.PropertyMappings {
		if !wantScope[pk] {
			t.Errorf("unexpected scope mapping pk %q", pk)
		}
		delete(wantScope, pk)
	}
	if len(wantScope) != 0 {
		t.Errorf("missing scope mappings: %v", wantScope)
	}
}

func TestReconcileOIDCSecretTooShortRejected(t *testing.T) {
	f := newFake().withFlows()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	f.certs["authentik Self-signed Certificate"] = &authentik.CertificateKeyPair{PK: "cert-1"}
	f.scopes["openid"] = &authentik.ScopeMapping{PK: "sm-openid"}
	f.scopes["email"] = &authentik.ScopeMapping{PK: "sm-email"}
	f.scopes["profile"] = &authentik.ScopeMapping{PK: "sm-profile"}

	s := spec.Spec{
		Enable: true, Name: "gitea", Slug: "gitea", Title: "Gitea",
		Provider: spec.ProviderOIDC, Host: "git.example.com", Require: spec.RequireAny,
		Groups: []string{"g-admins"}, GroupsSet: true,
		OIDC: spec.OIDCSpec{Redirect: []string{"https://git/cb"}, SecretName: "gitea-secret", ClientKind: spec.ClientConfidential},
	}

	r := New(f, testConfig(), fixedResolver("too-short"))
	res, err := r.Reconcile(context.Background(), s)
	if errCode(err) != CodeSecretWeak {
		t.Fatalf("err code = %q, want %q", errCode(err), CodeSecretWeak)
	}
	if f.called("CreateOAuth2Provider") {
		t.Error("a weak secret must be rejected before any provider is written")
	}
	if !hasIssue(res, discovery.SeverityError, CodeSecretWeak) {
		t.Error("expected a sticky error issue")
	}
}

func TestReconcileMissingGroupError(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	// g-admins is not registered.

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())
	if errCode(err) != CodeGroupMissing {
		t.Fatalf("err code = %q, want %q", errCode(err), CodeGroupMissing)
	}
	if f.called("CreateProxyProvider") || f.called("PatchOutpostProviders") {
		t.Error("a missing group must stop the reconcile before any write or attach")
	}
	if !hasIssue(res, discovery.SeverityError, CodeGroupMissing) {
		t.Error("expected a sticky group-missing issue")
	}
}

func TestReconcileMissingGroupCreateAndWarn(t *testing.T) {
	f := newFake().withFlows().withEmbedded()

	cfg := testConfig()
	cfg.Globals.CreateGroups = true

	r := New(f, cfg, fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(f.createdGroups) != 1 || f.createdGroups[0] != "g-admins" {
		t.Errorf("expected group g-admins to be created, got %v", f.createdGroups)
	}
	if !hasIssue(res, discovery.SeverityWarning, CodeGroupCreated) {
		t.Error("expected a create-and-warn issue")
	}
	if !res.Attached {
		t.Error("reconcile should proceed to attach after creating the group")
	}
}

func TestReconcileMissingPolicyAlwaysError(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins"}

	cfg := testConfig()
	cfg.Globals.CreateGroups = true // must NOT rescue a missing policy

	s := baseForwardSpec()
	s.Policies = []string{"mfa-required"}

	r := New(f, cfg, fixedResolver("unused"))
	_, err := r.Reconcile(context.Background(), s)
	if errCode(err) != CodePolicyMissing {
		t.Fatalf("err code = %q, want %q", errCode(err), CodePolicyMissing)
	}
	if len(f.createdGroups) != 0 {
		t.Error("a missing policy is never created")
	}
}

func TestReconcileStrictBindingRemoval(t *testing.T) {
	f := newFake().withFlows().withEmbedded(7)
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	f.proxyByName["whoami (aboard)"] = &authentik.ProxyProvider{PK: 7, Name: "whoami (aboard)"}
	f.appBySlug["whoami"] = &authentik.Application{PK: "app-whoami", Slug: "whoami", Provider: intPtr(7), Name: "whoami", PolicyEngineMode: "any"}
	// Existing bindings: the desired one, plus a stray group bound in the UI.
	f.bindings["app-whoami"] = []authentik.PolicyBinding{
		{PK: "b-admins", Group: strPtr("grp-admins"), Target: "app-whoami"},
		{PK: "b-stray", Group: strPtr("grp-stray"), Target: "app-whoami"},
	}

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(f.deletedBindings) != 1 || f.deletedBindings[0] != "b-stray" {
		t.Errorf("strict ownership must remove exactly the stray binding, deleted=%v", f.deletedBindings)
	}
	if f.called("CreateBinding") {
		t.Error("the desired binding already exists and must not be recreated")
	}
	if !hasIssue(res, discovery.SeverityWarning, CodeBindingRemoved) {
		t.Error("a strict removal must warn")
	}
}

func TestReconcileOutpostReadModifyWriteKeepsForeign(t *testing.T) {
	f := newFake().withFlows().withEmbedded(99) // a foreign provider already attached
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins"}

	r := New(f, testConfig(), fixedResolver("unused"))
	if _, err := r.Reconcile(context.Background(), baseForwardSpec()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// providerPK is 1 (first created). The patch must keep 99 and add 1.
	if len(f.patchedOutpost) != 2 || f.patchedOutpost[0] != 99 || f.patchedOutpost[1] != 1 {
		t.Errorf("outpost patch = %v, want [99 1] (foreign pk kept, ours appended)", f.patchedOutpost)
	}
}

func TestReconcileAdoptSilentNoop(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	// Hand-made app matching the labels, pointing at a non-aboard proxy provider.
	f.appBySlug["whoami"] = &authentik.Application{PK: "app-whoami", Slug: "whoami", Provider: intPtr(50), Name: "whoami", PolicyEngineMode: "any"}
	f.providerRefByPK[50] = &authentik.ProviderRef{PK: 50, Name: "whoami Provider", Component: authentik.ComponentProxyProvider}
	f.bindings["app-whoami"] = []authentik.PolicyBinding{
		{PK: "b1", Group: strPtr("grp-admins"), Target: "app-whoami"},
	}

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !res.Adopted {
		t.Error("a matching hand-made app should be adopted")
	}
	if !hasIssue(res, discovery.SeverityInfo, CodeAdopted) {
		t.Error("silent adoption emits an info issue")
	}
	// Adoption renames the pre-existing provider IN PLACE rather than creating a
	// duplicate and re-pointing: verified empirically that a create-and-repoint
	// leaves an uncleanable orphan provider attached to the outpost.
	if f.called("CreateProxyProvider") {
		t.Error("adoption must not create a new provider; it renames the existing one in place")
	}
	if f.nextProviderPK != 0 {
		t.Error("no new provider pk should be minted during an in-place adoption")
	}
	if !f.called("PatchProxyProvider") || !f.called("PatchApplication") {
		t.Error("adoption renames the existing provider and updates the app")
	}
	if got := f.patchedProxy[50].Name; got != "whoami (aboard)" {
		t.Errorf("renamed provider name = %q, want %q", got, "whoami (aboard)")
	}
	// The app must end up pointing at the SAME (renamed) provider pk 50, never a
	// freshly created one.
	if got := f.patchedApps["whoami"].Provider; got == nil || *got != 50 {
		t.Errorf("app provider = %v, want the renamed provider pk 50", got)
	}
}

func TestReconcileAdoptHandMadeTypeChangeRefused(t *testing.T) {
	// A hand-made OIDC provider (not aboard-named) where the label asks for
	// forward-auth is a provider-type change, and must be refused even with the
	// affirmation. This is the gap the by-pk type lookup closes: the ownership
	// marker alone cannot see the hand-made provider's type.
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	f.appBySlug["whoami"] = &authentik.Application{PK: "app-whoami", Slug: "whoami", Provider: intPtr(50), Name: "whoami", PolicyEngineMode: "any"}
	f.providerRefByPK[50] = &authentik.ProviderRef{PK: 50, Name: "whoami OAuth", Component: authentik.ComponentOAuth2Provider}

	s := baseForwardSpec()
	s.Adopt = true // even the affirmation must not allow a type change

	r := New(f, testConfig(), fixedResolver("unused"))
	_, err := r.Reconcile(context.Background(), s)
	if errCode(err) != CodeAdoptTypeChange {
		t.Fatalf("err code = %q, want %q", errCode(err), CodeAdoptTypeChange)
	}
	if f.called("PatchProxyProvider") || f.called("CreateProxyProvider") || f.called("PatchApplication") {
		t.Error("a refused type-change adoption must write nothing")
	}
}

func TestReconcileAdoptConflictWithoutAdopt(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	// Hand-made app whose title differs from the label.
	f.appBySlug["whoami"] = &authentik.Application{PK: "app-whoami", Slug: "whoami", Provider: intPtr(50), Name: "Old Title", PolicyEngineMode: "any"}
	f.providerRefByPK[50] = &authentik.ProviderRef{PK: 50, Name: "whoami Provider", Component: authentik.ComponentProxyProvider}
	f.bindings["app-whoami"] = []authentik.PolicyBinding{{PK: "b1", Group: strPtr("grp-admins"), Target: "app-whoami"}}

	s := baseForwardSpec()
	s.Title = "New Title"

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), s)
	if errCode(err) != CodeAdoptConflict {
		t.Fatalf("err code = %q, want %q", errCode(err), CodeAdoptConflict)
	}
	if f.called("CreateProxyProvider") || f.called("PatchApplication") || res.Attached {
		t.Error("a refused adoption must make no writes and never attach")
	}
	if !hasIssue(res, discovery.SeverityError, CodeAdoptConflict) {
		t.Error("expected a sticky adopt-conflict issue")
	}
}

func TestReconcileAdoptConflictClearedByAdopt(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	f.appBySlug["whoami"] = &authentik.Application{PK: "app-whoami", Slug: "whoami", Provider: intPtr(50), Name: "Old Title", PolicyEngineMode: "any"}
	f.providerRefByPK[50] = &authentik.ProviderRef{PK: 50, Name: "whoami Provider", Component: authentik.ComponentProxyProvider}
	f.bindings["app-whoami"] = []authentik.PolicyBinding{{PK: "b1", Group: strPtr("grp-admins"), Target: "app-whoami"}}

	s := baseForwardSpec()
	s.Title = "New Title"
	s.Adopt = true

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), s)
	if err != nil {
		t.Fatalf("Reconcile with adopt=true: %v", err)
	}
	if !res.Adopted {
		t.Error("adopt=true should clear the conflict and adopt")
	}
	if !f.called("PatchApplication") {
		t.Error("adoption should proceed to repoint and update the app")
	}
}

func TestReconcileAdoptTypeChangeNeverAdopts(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	// App owned by an aboard OIDC provider; the label now asks for forward-auth.
	f.oauthByName["whoami (aboard)"] = &authentik.OAuth2Provider{PK: 60, Name: "whoami (aboard)"}
	f.appBySlug["whoami"] = &authentik.Application{PK: "app-whoami", Slug: "whoami", Provider: intPtr(60), Name: "whoami", PolicyEngineMode: "any"}

	s := baseForwardSpec()
	s.Adopt = true // even the affirmation must not allow a type change

	r := New(f, testConfig(), fixedResolver("unused"))
	_, err := r.Reconcile(context.Background(), s)
	if errCode(err) != CodeAdoptTypeChange {
		t.Fatalf("err code = %q, want %q", errCode(err), CodeAdoptTypeChange)
	}
	if f.called("CreateProxyProvider") || f.called("PatchProxyProvider") {
		t.Error("a type change is never adopted, so no forward-auth provider is written")
	}
}
