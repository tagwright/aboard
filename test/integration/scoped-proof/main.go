// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Command scoped-proof drives the real aboard authentik client and reconciler
// against the DISPOSABLE integration Authentik using the least-privilege scoped
// service-account token, to prove aboard runs without a superuser token after the
// GetApplicationBySlug-detail-route and provider-keyed-orphan-scan changes. It is
// a manual harness, run inside the golang container on aboard-itest-net, not a
// go test. It writes only to the disposable stack and cleans up the one throwaway
// object it creates.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/reconcile"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	base := os.Getenv("AK_URL")
	if base == "" {
		base = "http://aboard-itest-server:9000"
	}
	tok, err := os.ReadFile(os.Getenv("AK_TOKEN_FILE"))
	if err != nil {
		return fmt.Errorf("read scoped token: %w", err)
	}
	cli := authentik.New(base, strings.TrimSpace(string(tok)))

	// ---- Proof 1: GetApplicationBySlug via the detail route resolves the
	// access-RESTRICTED apps the scoped user cannot launch (grp, cg, saml), plus
	// the visible ones. On the old filtered-list path grp/cg/saml were invisible
	// and reconcile would try a duplicate CreateApplication (the 0188a41 failure).
	fmt.Println("== Proof 1: GetApplicationBySlug detail route on restricted apps ==")
	for _, slug := range []string{"fa1", "grp", "cg", "saml", "oidc1", "hidden", "adopt1"} {
		app, err := cli.GetApplicationBySlug(ctx, slug)
		if err != nil {
			return fmt.Errorf("GetApplicationBySlug(%s): %w", slug, err)
		}
		if app.Slug != slug {
			return fmt.Errorf("GetApplicationBySlug(%s) returned slug %q", slug, app.Slug)
		}
		fmt.Printf("  FOUND  %-8s pk=%s provider=%v\n", app.Slug, app.PK, deref(app.Provider))
	}

	// ---- Proof 2: a genuinely absent app 404s to ErrNotFound (so reconcile still
	// creates a truly-new app rather than mistaking a transport error for absence).
	fmt.Println("== Proof 2: absent app -> ErrNotFound ==")
	if _, err := cli.GetApplicationBySlug(ctx, "definitely-not-a-real-slug-xyz"); err == nil {
		return fmt.Errorf("expected ErrNotFound for a bogus slug, got nil")
	} else if !isNotFound(err) {
		return fmt.Errorf("expected ErrNotFound, got %v", err)
	}
	fmt.Println("  OK  bogus slug returned ErrNotFound")

	// ---- Proof 3: ListAllProviders (the provider-keyed enumeration) sees every
	// aboard-owned provider, including those whose application is access-restricted
	// to the scoped user. Each carries assigned_application_slug.
	fmt.Println("== Proof 3: provider-keyed owned-app enumeration (/providers/all/) ==")
	provs, err := cli.ListAllProviders(ctx, 100)
	if err != nil {
		return fmt.Errorf("ListAllProviders: %w", err)
	}
	owned := map[string]struct{}{}
	for _, p := range provs {
		if strings.HasSuffix(p.Name, " (aboard)") {
			fmt.Printf("  OWNED  provider=%q component=%s app=%q\n", p.Name, p.Component, p.AssignedApplicationSlug)
			if p.AssignedApplicationSlug != "" {
				owned[p.AssignedApplicationSlug] = struct{}{}
			}
		}
	}
	fmt.Printf("  owned-app count = %d\n", len(owned))
	for _, want := range []string{"fa1", "grp", "cg", "saml", "oidc1"} {
		if _, ok := owned[want]; !ok {
			return fmt.Errorf("owned-app enumeration missed the restricted/expected app %q", want)
		}
	}

	// ---- Proof 4: the real Reconciler.Orphans scan on the scoped token. With
	// every owned app enabled it reports ZERO orphans (a clean no-op fleet); with
	// one owned app dropped from the enabled set it reports exactly that one, keyed
	// on the provider's assigned slug. This is the provider-keyed scan end to end.
	fmt.Println("== Proof 4: Reconciler.Orphans on the scoped token ==")
	rec := reconcile.New(cli, &config.Config{}, func(string) (string, error) { return "", nil })
	var allOwned []string
	for s := range owned {
		allOwned = append(allOwned, s)
	}
	orphansAll, err := rec.Orphans(ctx, allOwned)
	if err != nil {
		return fmt.Errorf("Orphans(all enabled): %w", err)
	}
	if len(orphansAll) != 0 {
		return fmt.Errorf("expected 0 orphans with every owned app enabled, got %+v", orphansAll)
	}
	fmt.Printf("  OK  all owned apps enabled -> 0 orphans (clean no-op fleet)\n")

	// Drop "grp" (a restricted app) from the enabled set: it must surface as an
	// orphan, proving the scan sees the restricted-app provider a superuser token
	// was previously required for.
	var minusGrp []string
	for _, s := range allOwned {
		if s != "grp" {
			minusGrp = append(minusGrp, s)
		}
	}
	orphansMinus, err := rec.Orphans(ctx, minusGrp)
	if err != nil {
		return fmt.Errorf("Orphans(minus grp): %w", err)
	}
	if len(orphansMinus) != 1 || orphansMinus[0].Slug != "grp" {
		return fmt.Errorf("expected exactly [grp] orphaned, got %+v", orphansMinus)
	}
	fmt.Printf("  OK  dropping restricted app grp -> orphan %+v\n", orphansMinus[0])

	// ---- Proof 5: writes function on the scoped RBAC role. Create a throwaway
	// aboard-owned oauth2 provider, patch it, confirm the orphan scan sees it as a
	// dangling owned provider (no app assigned), then delete it. Exercises
	// add/change/delete on oauth2provider plus the read side of the orphan path.
	fmt.Println("== Proof 5: writes (create/patch/delete) on the scoped role ==")
	authz, err := cli.GetFlowBySlug(ctx, "default-provider-authorization-implicit-consent")
	if err != nil {
		return fmt.Errorf("resolve authorization flow: %w", err)
	}
	inval, err := cli.GetFlowBySlug(ctx, "default-provider-invalidation-flow")
	if err != nil {
		return fmt.Errorf("resolve invalidation flow: %w", err)
	}
	const throwName = "aboard-itest-scoped-throwaway (aboard)"
	created, err := cli.CreateOAuth2Provider(ctx, authentik.OAuth2ProviderRequest{
		Name:              throwName,
		AuthorizationFlow: authz.PK,
		InvalidationFlow:  inval.PK,
		RedirectURIs:      []authentik.RedirectURI{{MatchingMode: authentik.MatchingModeStrict, URL: "https://throwaway.itest.local/callback"}},
		ClientType:        authentik.ClientTypeConfidential,
	})
	if err != nil {
		return fmt.Errorf("CreateOAuth2Provider (scoped write): %w", err)
	}
	fmt.Printf("  CREATE ok  pk=%d name=%q\n", created.PK, created.Name)

	if _, err := cli.PatchOAuth2Provider(ctx, created.PK, authentik.OAuth2ProviderRequest{Name: throwName}); err != nil {
		return fmt.Errorf("PatchOAuth2Provider (scoped write): %w", err)
	}
	fmt.Printf("  PATCH  ok  pk=%d\n", created.PK)

	// The throwaway is aboard-owned but has no application: the provider-keyed scan
	// must see it as a dangling orphan (empty slug), proving orphan detection sees
	// owned providers created on the scoped token.
	orphansAfterCreate, err := rec.Orphans(ctx, allOwned)
	if err != nil {
		return fmt.Errorf("Orphans(after throwaway create): %w", err)
	}
	sawThrow := false
	for _, o := range orphansAfterCreate {
		if o.ProviderPK == created.PK {
			sawThrow = true
			fmt.Printf("  ORPHAN scan saw the throwaway owned provider: %+v\n", o)
		}
	}
	if !sawThrow {
		return fmt.Errorf("orphan scan did not surface the throwaway owned provider pk=%d", created.PK)
	}

	if err := cli.DeleteOAuth2Provider(ctx, created.PK); err != nil {
		return fmt.Errorf("DeleteOAuth2Provider (scoped write): %w", err)
	}
	fmt.Printf("  DELETE ok  pk=%d (throwaway cleaned up)\n", created.PK)

	fmt.Println("\nALL SCOPED-TOKEN PROOFS PASSED")
	return nil
}

func isNotFound(err error) bool {
	return errors.Is(err, authentik.ErrNotFound)
}

func deref(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}
