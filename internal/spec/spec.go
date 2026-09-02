// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Package spec is aboard's shared desired-state domain model: the parsed,
// validated per-container view that discovery produces from the aboard.* labels
// and the reconciler consumes to converge Authentik. It is pure data, no logic
// and no Docker or Authentik imports, so both sides depend on the model without
// depending on each other.
//
// The model tracks not just values but whether a field was SET, because the
// grammar draws a hard line between a security-relevant field, which is always
// managed (absent means the default, never "leave whatever is there"), and a
// cosmetic field, which is declared-means-managed and absent-means-untouched
// (Fork 5, "Field ownership"). The "set" booleans carry that distinction to the
// reconciler.
package spec

// ProviderType is the Authentik provider a container asks for (Fork 1). The
// value strings are the operator's words from the aboard.provider label, not
// Authentik's internal ones.
type ProviderType string

const (
	// ProviderForwardAuth is an Authentik proxy provider in forward_single mode,
	// the per-app forward-auth pattern. It is the default provider type.
	ProviderForwardAuth ProviderType = "forwardauth"

	// ProviderOIDC is an Authentik OAuth2 and OpenID provider, for apps that
	// speak OIDC themselves.
	ProviderOIDC ProviderType = "oidc"

	// ProviderSAML is reserved. The enum is complete so discovery can recognize
	// the value, but parsing rejects it with a loud validation error in v1,
	// never a silent downgrade to forward-auth (Fork 1). It is not on the v1
	// reconcile path.
	ProviderSAML ProviderType = "saml"
)

// Require is the Authentik policy-engine bind mode across every binding on an
// Application (Fork 5). The default is RequireAny.
type Require string

const (
	// RequireAny means a user in any one bound group, or passing any one bound
	// policy, is admitted.
	RequireAny Require = "any"

	// RequireAll means a user must satisfy every binding: in every bound group
	// and passing every bound policy.
	RequireAll Require = "all"
)

// ClientKind is the OIDC client type (Fork 7). A confidential client requires a
// client secret, a public client forbids one.
type ClientKind string

const (
	// ClientConfidential is the default OIDC client type. It requires a client
	// secret, resolved inward-only and set on the provider every reconcile.
	ClientConfidential ClientKind = "confidential"

	// ClientPublic is for SPAs and native apps. It needs no secret and makes an
	// OIDC secret reference a validation error.
	ClientPublic ClientKind = "public"
)

// ForwardAuthSpec is the forward-auth sub-namespace of a Spec, meaningful only
// when Provider is ProviderForwardAuth. A key here under any other provider type
// is a validation error a later chunk raises (Fork 1).
type ForwardAuthSpec struct {
	// PublicPaths are unauthenticated path regexes on the provider (health
	// checks, webhooks), Authentik's skip_path_regex. From aboard.forwardauth.public.
	PublicPaths []string

	// TraefikRouters names which of the container's Traefik routers must carry
	// the forward-auth middleware, marking a deliberate public router by
	// omission. Empty means every host-matching router except a callback router.
	// From aboard.traefik.routers, meaningful only under proxy: traefik (Fork 6).
	TraefikRouters []string
}

// OIDCSpec is the OIDC sub-namespace of a Spec, meaningful only when Provider is
// ProviderOIDC. A key here under any other provider type is a validation error
// a later chunk raises (Fork 1, Fork 7).
type OIDCSpec struct {
	// Redirect are the absolute redirect URIs, strict matching, required for an
	// OIDC provider. From aboard.oidc.redirect.
	Redirect []string

	// SecretName is the NAME of the client secret, never its value. aboard
	// resolves it inward-only and sets it on the provider every reconcile,
	// never reading it back. Required for a confidential client, forbidden for a
	// public one. From aboard.oidc.secret.
	SecretName string

	// ClientID is the OIDC client id, not a secret. Defaults to the slug. From
	// aboard.oidc.id.
	ClientID string

	// ClientKind is the client type. Defaults to ClientConfidential. From
	// aboard.oidc.client.
	ClientKind ClientKind

	// Scopes are scope-mapping names ADDED to the always-present openid, email,
	// profile. From aboard.oidc.scopes.
	Scopes []string
}

// Spec is the desired Authentik state for one container, built from its
// aboard.* labels. It is the whole grammar as data: identity, provider, host,
// access, the typed provider sub-namespace, and the cosmetic library fields.
type Spec struct {
	// Enable is the aboard.enable opt-in gate. A container with Enable false is
	// invisible to the reconciler.
	Enable bool

	// Name is the stable service identity: the compose service name, or the
	// container name, overridable with aboard.name. It keys the default Slug and
	// the alert identity, and is stable across a force-recreate (Fork 2).
	Name string

	// Slug is the Authentik Application slug, the reconcile key. It defaults to
	// the sanitized Name and is overridable with aboard.slug (Fork 2).
	Slug string

	// Title is the Authentik Application display name, what users see in their
	// library. It defaults to Name verbatim, with no case-mangling (Fork 2).
	Title string

	// Provider is the selected provider type (Fork 1).
	Provider ProviderType

	// Host is the bare public hostname, aboard composes https:// in front. It is
	// explicit from aboard.host or inferred from exactly one distinct literal
	// Host() across the container's Traefik routers (Fork 3).
	Host string

	// Flow is the authorization flow override for this app. Empty means the
	// fleet default flows.authorization from aboard.yml (Fork, aboard.flow).
	Flow string

	// Adopt affirms taking ownership of a pre-existing Authentik object whose
	// state differs from these labels. From aboard.adopt (Fork 9).
	Adopt bool

	// Groups are the Authentik group names bound to the Application. Its meaning
	// is three-state, see GroupsSet and GroupsNone (Fork 5):
	//   - GroupsSet false: unset, use the fleet default defaults.groups.
	//   - GroupsSet true, Groups empty: the aboard.groups=none sentinel, no
	//     group gate (any authenticated user).
	//   - GroupsSet true, Groups non-empty: this explicit list, replacing the
	//     fleet default wholesale.
	Groups []string

	// GroupsSet reports whether the aboard.groups label was present at all,
	// distinguishing "unset, use the fleet default" from an explicit none.
	GroupsSet bool

	// Policies are EXISTING Authentik policy names bound to the Application,
	// never created. From aboard.policies (Fork 5).
	Policies []string

	// Require is the policy-engine bind mode. Defaults to RequireAny (Fork 5).
	Require Require

	// Outpost is the outpost name to attach a forward-auth provider to. Empty
	// means the fleet default outpost from aboard.yml (embedded). aboard never
	// creates outposts. From aboard.outpost (Fork 4).
	Outpost string

	// Launch is the library launch URL. LaunchSet reports whether aboard.launch
	// was present (absent means untouched, cosmetic ownership). LaunchNone
	// reports the aboard.launch=none sentinel that hides the app from the
	// library. Fork 5, "Field ownership".
	Launch     string
	LaunchNone bool
	LaunchSet  bool

	// Icon is the library icon URL. IconSet reports whether aboard.icon was
	// present. Absent means untouched, so a UI-set icon survives.
	Icon    string
	IconSet bool

	// Description is the library description. DescriptionSet reports whether
	// aboard.description was present. Absent means untouched.
	Description    string
	DescriptionSet bool

	// ForwardAuth is the forward-auth sub-namespace, meaningful only when
	// Provider is ProviderForwardAuth.
	ForwardAuth ForwardAuthSpec

	// OIDC is the OIDC sub-namespace, meaningful only when Provider is
	// ProviderOIDC.
	OIDC OIDCSpec
}

// GroupsNone reports the aboard.groups=none sentinel: the label was set but
// resolves to no groups, an explicit "no group gate, any authenticated user".
// It is distinct from GroupsSet being false, which means "use the fleet
// default". This is a data-model convenience over the three-state Groups
// convention documented on the field, not reconcile logic (Fork 5).
func (s *Spec) GroupsNone() bool {
	return s.GroupsSet && len(s.Groups) == 0
}
