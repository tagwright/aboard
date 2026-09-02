// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Package reconcile converges Authentik state to match a discovered Spec. It is
// the orchestration layer above the internal/authentik primitives: it owns the
// reconcile decisions the primitives deliberately do not (lookup-then-create-or-
// patch, the ownership marker, adoption, strict binding ownership, and the
// ordering contract), and drives Authentik entirely through those primitives.
//
// The spine of the design is the ordering contract (Fork 4, and "Must verify
// empirically" item 2 in the architecture): access bindings are reconciled
// BEFORE the provider is attached to the outpost, the attach is the moment an
// app goes live, and any failure before the attach returns with nothing
// attached. Reconcile is structured so the attach is unmistakably last and is
// unreachable once an earlier step has returned an error, which closes the
// production script's warn-and-continue group-bind hole: a failed reconcile can
// never leave an app open to every authenticated user.
//
// Secrets are handled by NAME only. An OIDC client secret is resolved inward,
// pushed onto the provider, and never logged, never read back, and never placed
// in an Issue message.
package reconcile

import (
	"context"

	"github.com/tagwright/aboard/internal/authentik"
)

// API is the narrow slice of the Authentik client the reconciler drives. It is a
// consumer-defined interface (the Go idiom): declared here, listing only the
// methods reconcile actually calls, and satisfied structurally by
// *authentik.Client without the client package knowing this interface exists.
// Tests inject an in-memory fake that records what was created, patched, and
// deleted and returns canned lookups, which is what lets the ordering contract
// and every branch be proven without a live Authentik.
type API interface {
	// Flow lookup (step a).
	GetFlowBySlug(ctx context.Context, slug string) (*authentik.Flow, error)

	// Proxy (forward-auth) provider convergence and teardown.
	GetProxyProviderByName(ctx context.Context, name string) (*authentik.ProxyProvider, error)
	CreateProxyProvider(ctx context.Context, body authentik.ProxyProviderRequest) (*authentik.ProxyProvider, error)
	PatchProxyProvider(ctx context.Context, pk int, body authentik.ProxyProviderRequest) (*authentik.ProxyProvider, error)
	DeleteProxyProvider(ctx context.Context, pk int) error

	// OAuth2 (OIDC) provider convergence and teardown.
	GetOAuth2ProviderByName(ctx context.Context, name string) (*authentik.OAuth2Provider, error)
	CreateOAuth2Provider(ctx context.Context, body authentik.OAuth2ProviderRequest) (*authentik.OAuth2Provider, error)
	PatchOAuth2Provider(ctx context.Context, pk int, body authentik.OAuth2ProviderRequest) (*authentik.OAuth2Provider, error)
	DeleteOAuth2Provider(ctx context.Context, pk int) error

	// Application convergence, listing (orphans), teardown, and the icon action.
	GetApplicationBySlug(ctx context.Context, slug string) (*authentik.Application, error)
	CreateApplication(ctx context.Context, body authentik.ApplicationRequest) (*authentik.Application, error)
	PatchApplication(ctx context.Context, slug string, body authentik.ApplicationRequest) (*authentik.Application, error)
	DeleteApplication(ctx context.Context, slug string) error
	ListApplications(ctx context.Context, pageSize int) ([]authentik.Application, error)
	SetApplicationIconURL(ctx context.Context, slug, iconURL string) error

	// Strict binding ownership (step d).
	ListBindingsForTarget(ctx context.Context, appPK string) ([]authentik.PolicyBinding, error)
	CreateBinding(ctx context.Context, body authentik.PolicyBindingRequest) (*authentik.PolicyBinding, error)
	DeleteBinding(ctx context.Context, pk string) error

	// Access resolution: groups (with the create opt-in) and existing policies.
	GetGroupByName(ctx context.Context, name string) (*authentik.Group, error)
	CreateGroup(ctx context.Context, name string) (*authentik.Group, error)
	GetPolicyByName(ctx context.Context, name string) (*authentik.Policy, error)

	// OIDC signing key and scope mappings.
	GetCertificateByName(ctx context.Context, name string) (*authentik.CertificateKeyPair, error)
	GetFirstSigningKey(ctx context.Context) (*authentik.CertificateKeyPair, error)
	GetScopeMappingByName(ctx context.Context, scopeName string) (*authentik.ScopeMapping, error)

	// Outpost attach (step e), read-modify-write on the providers list.
	GetEmbeddedOutpost(ctx context.Context) (*authentik.Outpost, error)
	GetOutpostByName(ctx context.Context, name string) (*authentik.Outpost, error)
	PatchOutpostProviders(ctx context.Context, pk string, providers []int) (*authentik.Outpost, error)
}

// Compile-time proof that the real client satisfies the seam structurally, so
// the interface can never drift from the primitives it abstracts.
var _ API = (*authentik.Client)(nil)
