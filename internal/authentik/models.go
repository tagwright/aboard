// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package authentik

// This file types only the Authentik fields aboard reads or writes. Every name
// and required-ness was checked against the OpenAPI schema for Authentik
// 2025.6.4. Response structs carry read-only server fields; request structs use
// omitempty (and pointers where a zero value is a meaningful, sendable value) so
// a PATCH sends only the fields it means to change.

// Provider-mode and client-type constants, from the schema's ProxyMode and
// ClientTypeEnum. aboard uses ForwardSingle and ClientConfidential.
const (
	ProxyModeForwardSingle = "forward_single"
	ProxyModeForwardDomain = "forward_domain"
	ProxyModeProxy         = "proxy"

	ClientTypeConfidential = "confidential"
	ClientTypePublic       = "public"

	// MatchingModeStrict is the redirect-URI matching mode aboard sets, from the
	// schema's MatchingModeEnum.
	MatchingModeStrict = "strict"

	// PolicyEngineModeAny and PolicyEngineModeAll are the two PolicyEngineMode
	// values an Application can carry.
	PolicyEngineModeAny = "any"
	PolicyEngineModeAll = "all"

	// ManagedEmbeddedOutpost is the stable managed marker of the embedded
	// outpost, verified from authentik/outposts/apps.py. aboard finds the
	// embedded outpost by this marker, never by a hardcoded pk.
	ManagedEmbeddedOutpost = "goauthentik.io/outposts/embedded"

	// ManagedScopePrefix is the prefix on Authentik's own managed OAuth2 scope
	// mappings. A scope lookup prefers a mapping whose managed marker starts with
	// this over any user-created mapping of the same scope name.
	ManagedScopePrefix = "goauthentik.io/providers/oauth2/scope-"

	// ManagedSAMLPrefix is the prefix on Authentik's own managed SAML property
	// mappings (the seven default attribute mappings: Email, Groups, Name, UPN,
	// User ID, Username, WindowsAccountname). aboard attaches every mapping whose
	// managed marker starts with this so a SAML provider's assertions carry
	// attributes, the analog of the always-present OIDC scopes.
	ManagedSAMLPrefix = "goauthentik.io/providers/saml/"

	// SpBindingPost and SpBindingRedirect are the two SpBindingEnum values a SAML
	// provider's sp_binding can carry.
	SpBindingPost     = "post"
	SpBindingRedirect = "redirect"
)

// Pagination is the wrapper metadata on every list response. next and previous
// are page NUMBERS on this Authentik version, not URLs. Verified against the
// live 2025.6.4 API: on the LAST page next is 0, not null (and previous is 0 on
// the first page), so "no next page" is next == nil OR a next that does not name
// a page strictly beyond the current one. A paginated walk must test the page
// number, not merely non-nil-ness, or it will request page 0 and get a 404
// "Invalid page." See ListApplications.
type Pagination struct {
	Next     *int `json:"next"`
	Previous *int `json:"previous"`
	Count    int  `json:"count"`
}

// Paginated is a list response: the pagination block plus the page of results.
type Paginated[T any] struct {
	Pagination Pagination `json:"pagination"`
	Results    []T        `json:"results"`
}

// Application is a core Application. Its REST lookup field is slug, not pk:
// detail routes are /api/v3/core/applications/{slug}/. provider is a nullable
// integer FK to the linked provider. meta_icon is read-only on the API and so is
// absent from ApplicationRequest.
type Application struct {
	PK               string `json:"pk"`
	Name             string `json:"name"`
	Slug             string `json:"slug"`
	Provider         *int   `json:"provider"`
	PolicyEngineMode string `json:"policy_engine_mode"`
	MetaLaunchURL    string `json:"meta_launch_url"`
	MetaIcon         string `json:"meta_icon"`
	MetaDescription  string `json:"meta_description"`
}

// ApplicationRequest is the create/patch body for an Application. Provider is a
// pointer so a link can be sent as a real integer (including nothing, when nil).
type ApplicationRequest struct {
	Name             string `json:"name,omitempty"`
	Slug             string `json:"slug,omitempty"`
	Provider         *int   `json:"provider,omitempty"`
	PolicyEngineMode string `json:"policy_engine_mode,omitempty"`
	MetaLaunchURL    string `json:"meta_launch_url,omitempty"`
	MetaDescription  string `json:"meta_description,omitempty"`
}

// FilePathRequest is the JSON body of the set_icon_url action, a single url
// (verified against the schema's FilePathRequest, which requires url). It is how
// aboard sets an application's library icon: meta_icon is read-only on
// ApplicationRequest, so a normal PATCH cannot set it, and unlike the multipart
// set_icon action this one takes a plain JSON url.
type FilePathRequest struct {
	URL string `json:"url"`
}

// ProxyProvider is a proxy (forward-auth) provider. pk is an integer. aboard
// creates it in mode forward_single.
type ProxyProvider struct {
	PK                int      `json:"pk"`
	Name              string   `json:"name"`
	AuthorizationFlow string   `json:"authorization_flow"`
	InvalidationFlow  string   `json:"invalidation_flow"`
	ExternalHost      string   `json:"external_host"`
	Mode              string   `json:"mode"`
	SkipPathRegex     string   `json:"skip_path_regex"`
	PropertyMappings  []string `json:"property_mappings"`
}

// ProxyProviderRequest is the create/patch body for a proxy provider. The
// schema requires name, authorization_flow, invalidation_flow, and external_host
// on create; omitempty lets a PATCH send a subset.
type ProxyProviderRequest struct {
	Name              string   `json:"name,omitempty"`
	AuthorizationFlow string   `json:"authorization_flow,omitempty"`
	InvalidationFlow  string   `json:"invalidation_flow,omitempty"`
	ExternalHost      string   `json:"external_host,omitempty"`
	Mode              string   `json:"mode,omitempty"`
	SkipPathRegex     string   `json:"skip_path_regex,omitempty"`
	PropertyMappings  []string `json:"property_mappings,omitempty"`
}

// RedirectURI is one allowed redirect entry on an OAuth2 provider.
type RedirectURI struct {
	MatchingMode string `json:"matching_mode"`
	URL          string `json:"url"`
}

// OAuth2Provider is an OAuth2/OIDC provider. pk is an integer. client_id and
// client_secret are writable on the request (verified against
// OAuth2ProviderRequest), so aboard SETS the secret inward rather than reading a
// generated one back; both appear here for completeness of the response decode.
type OAuth2Provider struct {
	PK                int           `json:"pk"`
	Name              string        `json:"name"`
	AuthorizationFlow string        `json:"authorization_flow"`
	InvalidationFlow  string        `json:"invalidation_flow"`
	RedirectURIs      []RedirectURI `json:"redirect_uris"`
	ClientType        string        `json:"client_type"`
	ClientID          string        `json:"client_id"`
	ClientSecret      string        `json:"client_secret"`
	SigningKey        *string       `json:"signing_key"`
	PropertyMappings  []string      `json:"property_mappings"`
}

// OAuth2ProviderRequest is the create/patch body for an OAuth2 provider. The
// schema requires name, authorization_flow, invalidation_flow, and redirect_uris
// on create. client_id and client_secret are settable (both plain writable
// strings on OAuth2ProviderRequest), which is what lets aboard push a named,
// operator-chosen client secret in rather than round-tripping a generated one.
type OAuth2ProviderRequest struct {
	Name              string        `json:"name,omitempty"`
	AuthorizationFlow string        `json:"authorization_flow,omitempty"`
	InvalidationFlow  string        `json:"invalidation_flow,omitempty"`
	RedirectURIs      []RedirectURI `json:"redirect_uris,omitempty"`
	ClientType        string        `json:"client_type,omitempty"`
	ClientID          string        `json:"client_id,omitempty"`
	ClientSecret      string        `json:"client_secret,omitempty"`
	SigningKey        string        `json:"signing_key,omitempty"`
	PropertyMappings  []string      `json:"property_mappings,omitempty"`
}

// SAMLProvider is a SAML provider. pk is an integer. It carries the writable
// shape aboard sets (acs_url, audience, issuer, sp_binding, signing_kp,
// property_mappings) plus the component discriminator and the read-only metadata
// download URL. Unlike ProxyProvider it is not an OAuth2Provider subclass, so it
// is a clean, separate type.
type SAMLProvider struct {
	PK                  int      `json:"pk"`
	Name                string   `json:"name"`
	AuthorizationFlow   string   `json:"authorization_flow"`
	InvalidationFlow    string   `json:"invalidation_flow"`
	ACSUrl              string   `json:"acs_url"`
	Audience            string   `json:"audience"`
	Issuer              string   `json:"issuer"`
	SpBinding           string   `json:"sp_binding"`
	SigningKp           *string  `json:"signing_kp"`
	PropertyMappings    []string `json:"property_mappings"`
	Component           string   `json:"component"`
	URLDownloadMetadata string   `json:"url_download_metadata"`
}

// SAMLProviderRequest is the create/patch body for a SAML provider. The schema
// requires name, authorization_flow, invalidation_flow, and acs_url on create.
// issuer carries omitempty because the request schema forbids an empty string
// (an unset issuer means Authentik's default), and signing_kp is a plain string
// (the keypair uuid) rather than a pointer because aboard always resolves and
// sends one. No field here is ever a secret: a SAML provider signs with a
// keypair Authentik holds, it shares no inward secret.
type SAMLProviderRequest struct {
	Name              string   `json:"name,omitempty"`
	AuthorizationFlow string   `json:"authorization_flow,omitempty"`
	InvalidationFlow  string   `json:"invalidation_flow,omitempty"`
	ACSUrl            string   `json:"acs_url,omitempty"`
	Audience          string   `json:"audience,omitempty"`
	Issuer            string   `json:"issuer,omitempty"`
	SpBinding         string   `json:"sp_binding,omitempty"`
	SigningKp         string   `json:"signing_kp,omitempty"`
	// SignAssertion and SignResponse are pointers so an explicit false is
	// sendable. Authentik requires that when a signing keypair is set at least one
	// of them is true (verified live: a POST with a signing_kp and both false is a
	// 400), so aboard, which always resolves a signing keypair, always sends
	// sign_assertion true. They are security-relevant fields aboard manages, never
	// left to a server default.
	SignAssertion    *bool    `json:"sign_assertion,omitempty"`
	SignResponse     *bool    `json:"sign_response,omitempty"`
	PropertyMappings []string `json:"property_mappings,omitempty"`
}

// SAMLMetadata is the response of the SAML provider metadata endpoint: the IdP
// metadata XML as a string plus a download URL. Both are read-only. This is the
// non-secret handoff an operator feeds to the SP, the SAML analog of an OIDC
// discovery document.
type SAMLMetadata struct {
	Metadata    string `json:"metadata"`
	DownloadURL string `json:"download_url"`
}

// SAMLPropertyMapping is a SAML attribute property mapping. managed is nullable;
// a mapping whose managed marker starts with ManagedSAMLPrefix is one of
// Authentik's own default attribute mappings.
type SAMLPropertyMapping struct {
	PK      string  `json:"pk"`
	Name    string  `json:"name"`
	Managed *string `json:"managed"`
}

// Outpost is an outpost instance. pk is a uuid string. managed is nullable and
// carries the marker aboard uses to find the embedded one. providers is the list
// of provider pks it serves; a proxy provider is inert until it appears here.
type Outpost struct {
	PK        string  `json:"pk"`
	Name      string  `json:"name"`
	Managed   *string `json:"managed"`
	Type      string  `json:"type"`
	Providers []int   `json:"providers"`
}

// OutpostProvidersRequest is the PATCH body that sets an outpost's providers
// list. The list is sent verbatim: the PATCH replaces rather than merges, so the
// reconciler (not this primitive) does the read-modify-write. providers has no
// omitempty because an explicit empty list is a valid, meaningful value.
type OutpostProvidersRequest struct {
	Providers []int `json:"providers"`
}

// Group is a directory group. pk is a uuid string.
type Group struct {
	PK   string `json:"pk"`
	Name string `json:"name"`
}

// GroupRequest is the create body for a group.
type GroupRequest struct {
	Name string `json:"name"`
}

// Flow is a flow instance, looked up by slug.
type Flow struct {
	PK   string `json:"pk"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// Policy is a policy from the polymorphic /policies/all/ list. aboard needs only
// its pk and name to bind an existing policy.
type Policy struct {
	PK   string `json:"pk"`
	Name string `json:"name"`
}

// ScopeMapping is an OAuth2 scope property mapping. managed is nullable; a lookup
// prefers a mapping whose managed marker starts with ManagedScopePrefix.
type ScopeMapping struct {
	PK        string  `json:"pk"`
	Name      string  `json:"name"`
	ScopeName string  `json:"scope_name"`
	Managed   *string `json:"managed"`
}

// CertificateKeyPair is a certificate keypair, used as an OIDC signing key.
type CertificateKeyPair struct {
	PK   string `json:"pk"`
	Name string `json:"name"`
}

// PolicyBinding binds a policy, group, or user to a target (an Application pk).
// aboard uses the group form. policy and group are nullable uuid strings.
type PolicyBinding struct {
	PK      string  `json:"pk"`
	Policy  *string `json:"policy"`
	Group   *string `json:"group"`
	Target  string  `json:"target"`
	Enabled bool    `json:"enabled"`
	Negate  bool    `json:"negate"`
	Order   int     `json:"order"`
}

// PolicyBindingRequest is the create body for a binding. The schema requires
// order and target. Enabled and Negate are pointers so an explicit false is
// sendable; order is always sent because the schema requires it.
type PolicyBindingRequest struct {
	Policy  *string `json:"policy,omitempty"`
	Group   *string `json:"group,omitempty"`
	Target  string  `json:"target"`
	Enabled *bool   `json:"enabled,omitempty"`
	Negate  *bool   `json:"negate,omitempty"`
	Order   int     `json:"order"`
}
