// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Package discovery turns a container's aboard.* labels into a validated
// desired-state spec.Spec plus a list of per-container Issues. It is the
// discovery / label-parsing layer of aboard, and it is deliberately PURE: it
// imports no Docker and no Authentik and touches no network, so it unit-tests
// against literal label maps without a socket.
//
// It recognizes two label prefixes, "aboard." (primary) and "tagwright.auth."
// (the org-namespaced alias), holding one internal grammar with two accepted
// spellings, and applies the ballast conflict rule verbatim. It validates only
// what is knowable from the labels and the loaded config alone (the namespace
// mechanics, the provider enum and its typed sub-namespaces, the host, the csv
// and indexed value shapes, the OIDC required-field rules). Everything that
// needs the live Authentik API (group, policy, flow, outpost, and certificate
// existence, the missing-group decision, adoption diffing, the actual secret
// resolution and its 32-character check, and the Traefik middleware-wiring
// audit) is left to the reconciler; discovery only records the parsed intent in
// the Spec. See the Aboard Label Grammar for the full contract.
package discovery

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/spec"
)

// composeServiceLabel is the Docker Compose service-name label, the middle rung
// of the service-identity ladder (aboard.name, then this, then the container
// name).
const composeServiceLabel = "com.docker.compose.service"

// Input is the minimal, Docker-free view of a container discovery needs. The
// daemon populates it from a core.Container later; keeping it a plain struct is
// what lets the whole package be tested with literals and no socket.
type Input struct {
	// ContainerName is the container name, the last-resort service identity when
	// no aboard.name and no compose service label is present.
	ContainerName string

	// Labels is the container's full label map, both the aboard.* labels and the
	// surrounding Traefik labels host inference reads.
	Labels map[string]string
}

// Discover reads in.Labels against cfg and returns the desired Spec plus every
// Issue found. The Spec always carries the resolved service identity in Name so
// a caller can name the container in an alert even on an error.
//
// A container that is not opted in (aboard.enable absent or "false") returns a
// Spec with Enable false. If other aboard.* labels are present without the gate,
// a single declared-but-unarmed warning is included. A caller reconciles a
// container only when Spec.Enable is true and HasError(issues) is false; any
// error means skip-and-alert.
func Discover(cfg *config.Config, in Input) (spec.Spec, []Issue) {
	norm, issues := mergeNamespaces(in.Labels)

	var sp spec.Spec
	sp.Name = serviceName(in, norm)

	enabled := norm["enable"] == "true"
	if !enabled {
		if declaredButUnarmed(norm) {
			issues = append(issues, Issue{
				Severity: SeverityWarning,
				Code:     CodeUnarmed,
				Message:  "aboard.* labels are present but aboard.enable is absent or false: this app is not protected while its labels suggest it is",
			})
		}
		return sp, issues
	}
	sp.Enable = true

	// Walk the suffixes once, in sorted order, so a container with two mistakes
	// fails on the same one every run. This pass classifies every suffix
	// (unknown and reserved suffixes become errors here), collects the typed
	// sub-namespace membership for the cross-field checks, and gathers the
	// indexed escape families.
	p := newParse()
	suffixes := sortedKeys(norm)
	for _, suffix := range suffixes {
		p.route(suffix, norm[suffix], &issues)
	}

	// Identity (Fork 2).
	sp.Title = firstNonEmpty(norm["title"], sp.Name)
	if slug, ok := norm["slug"]; ok {
		if !isValidSlug(slug) {
			issues = append(issues, Issue{SeverityError, CodeSlugInvalid,
				fmt.Sprintf("aboard.slug %q must be [a-z0-9-] only", slug)})
		}
		sp.Slug = slug
	} else {
		sp.Slug = sanitizeSlug(sp.Name)
	}

	// Provider (Fork 1).
	sp.Provider, _ = parseProvider(norm["provider"], &issues)

	// Flow override (empty means the fleet default flows.authorization).
	sp.Flow = norm["flow"]

	// Adopt (Fork 9).
	sp.Adopt = norm["adopt"] == "true"

	// Host (Fork 3): explicit wins, else infer from the Traefik router rules. A
	// SAML provider is server-served and has no Traefik half, so it needs no host
	// (there is no external_host and nothing to verify), and host inference is
	// skipped for it rather than failing a SAML container that carries no Traefik
	// router labels. An explicit aboard.host under saml is tolerated and ignored,
	// the same latitude OIDC has.
	if sp.Provider != spec.ProviderSAML {
		if host, ok := norm["host"]; ok {
			if iss := validateExplicitHost(host); iss != nil {
				issues = append(issues, *iss)
			} else {
				sp.Host = host
			}
		} else if host, iss := inferHost(in.Labels); iss != nil {
			issues = append(issues, *iss)
		} else {
			sp.Host = host
		}
	}

	// Access (Fork 5).
	parseAccess(norm, &sp, &issues)

	// Cosmetic library fields (declared means managed, absent means untouched).
	parseCosmetic(norm, &sp)

	// Typed sub-namespaces and their cross-field rules.
	parseForwardAuth(cfg, p, &sp, &issues)
	parseOIDC(p, &sp, &issues)
	parseSAML(p, &sp, &issues)

	return sp, issues
}

// serviceName applies the service-identity precedence (Fork 2): aboard.name,
// then the compose service label, then the container name with any leading "/"
// stripped. It keys off the service, not the container id, so the slug is stable
// across a force-recreate.
func serviceName(in Input, norm map[string]string) string {
	if v := norm["name"]; v != "" {
		return v
	}
	if v := in.Labels[composeServiceLabel]; v != "" {
		return v
	}
	return strings.TrimPrefix(in.ContainerName, "/")
}

// declaredButUnarmed reports whether the container carries any aboard.* label
// other than aboard.enable itself. A lone aboard.enable=false is a deliberate
// disable, not a copied block that forgot to arm, so it draws no warning.
func declaredButUnarmed(norm map[string]string) bool {
	for k := range norm {
		if k != "enable" {
			return true
		}
	}
	return false
}

// parseProvider resolves the aboard.provider enum (Fork 1). Any unrecognized
// value is a loud error, never a silent downgrade. The returned bool reports
// whether the value is a recognized reconcilable type, which gates the typed
// sub-namespace cross-checks.
func parseProvider(val string, issues *[]Issue) (spec.ProviderType, bool) {
	switch val {
	case "", string(spec.ProviderForwardAuth):
		return spec.ProviderForwardAuth, true
	case string(spec.ProviderOIDC):
		return spec.ProviderOIDC, true
	case string(spec.ProviderSAML):
		return spec.ProviderSAML, true
	default:
		*issues = append(*issues, Issue{SeverityError, CodeProviderInvalid,
			fmt.Sprintf("aboard.provider %q is not a valid provider (want forwardauth, oidc, or saml)", val)})
		return spec.ProviderForwardAuth, false
	}
}

// parseAccess fills the access fields (Fork 5): the three-state groups, the
// policies list, and the require mode.
func parseAccess(norm map[string]string, sp *spec.Spec, issues *[]Issue) {
	if g, ok := norm["groups"]; ok {
		sp.GroupsSet = true
		if g != "none" {
			sp.Groups = splitCSV(g)
		}
	}
	sp.Policies = splitCSV(norm["policies"])

	switch norm["require"] {
	case "", string(spec.RequireAny):
		sp.Require = spec.RequireAny
	case string(spec.RequireAll):
		sp.Require = spec.RequireAll
	default:
		*issues = append(*issues, Issue{SeverityError, CodeRequireInvalid,
			fmt.Sprintf("aboard.require %q must be any or all", norm["require"])})
		sp.Require = spec.RequireAny
	}
}

// parseCosmetic fills the library fields, which follow declared-means-managed,
// absent-means-untouched: the "set" flags carry that to the reconciler so a
// UI-set value survives when the label is absent.
func parseCosmetic(norm map[string]string, sp *spec.Spec) {
	if v, ok := norm["launch"]; ok {
		sp.LaunchSet = true
		if v == "none" {
			sp.LaunchNone = true
		} else {
			sp.Launch = v
		}
	}
	if v, ok := norm["icon"]; ok {
		sp.IconSet = true
		sp.Icon = v
	}
	if v, ok := norm["description"]; ok {
		sp.DescriptionSet = true
		sp.Description = v
	}
}

// parseForwardAuth fills the forward-auth sub-namespace and enforces its
// cross-field rules: every forward-auth key is an error under any other provider
// type, the whole aboard.traefik.* sub-namespace is an error under proxy: none,
// and forwardauth.public may not set both its csv and indexed forms.
func parseForwardAuth(cfg *config.Config, p *parse, sp *spec.Spec, issues *[]Issue) {
	if sp.Provider != spec.ProviderForwardAuth && len(p.forwardKeys) > 0 {
		*issues = append(*issues, Issue{SeverityError, CodeWrongProvider,
			fmt.Sprintf("forward-auth labels (%s) are set but aboard.provider is %q",
				strings.Join(p.forwardKeys, ", "), sp.Provider)})
	}
	if cfg.Proxy == config.ProxyNone && len(p.traefikKeys) > 0 {
		*issues = append(*issues, Issue{SeverityError, CodeProxyNoneTraefik,
			fmt.Sprintf("aboard.traefik.* labels (%s) are set but the fleet proxy is none",
				strings.Join(p.traefikKeys, ", "))})
	}

	public, iss := resolveList(p.publicCSV, p.hasPublicCSV, p.publicIdx, "aboard.forwardauth.public")
	if iss != nil {
		*issues = append(*issues, *iss)
	}
	sp.ForwardAuth.PublicPaths = public
	sp.ForwardAuth.TraefikRouters = splitCSV(p.traefikRouters)
	sp.Outpost = p.outpost
}

// parseOIDC fills the OIDC sub-namespace and enforces its cross-field rules:
// every OIDC key is an error under any other provider type, redirect is required
// and must be absolute URLs, and the client secret is required for a confidential
// client and forbidden for a public one. It records the secret NAME only and
// never resolves it (that, and the 32-character minimum, are reconcile-time).
func parseOIDC(p *parse, sp *spec.Spec, issues *[]Issue) {
	isOIDC := sp.Provider == spec.ProviderOIDC
	if !isOIDC && len(p.oidcKeys) > 0 {
		*issues = append(*issues, Issue{SeverityError, CodeWrongProvider,
			fmt.Sprintf("OIDC labels (%s) are set but aboard.provider is %q",
				strings.Join(p.oidcKeys, ", "), sp.Provider)})
	}

	// Client type (default confidential).
	kind := spec.ClientConfidential
	switch p.oidcClient {
	case "", string(spec.ClientConfidential):
		kind = spec.ClientConfidential
	case string(spec.ClientPublic):
		kind = spec.ClientPublic
	default:
		*issues = append(*issues, Issue{SeverityError, CodeClientInvalid,
			fmt.Sprintf("aboard.oidc.client %q must be confidential or public", p.oidcClient)})
	}
	sp.OIDC.ClientKind = kind
	sp.OIDC.SecretName = p.oidcSecret
	sp.OIDC.ClientID = firstNonEmpty(p.oidcID, sp.Slug)
	sp.OIDC.Scopes = splitCSV(p.oidcScopes)

	redirect, iss := resolveList(p.redirectCSV, p.hasRedirectCSV, p.redirectIdx, "aboard.oidc.redirect")
	if iss != nil {
		*issues = append(*issues, *iss)
	}
	sp.OIDC.Redirect = redirect

	// The remaining rules only make sense for an actual OIDC provider.
	if !isOIDC {
		return
	}
	for _, r := range redirect {
		if !isAbsoluteURL(r) {
			*issues = append(*issues, Issue{SeverityError, CodeOIDCRedirectInvalid,
				fmt.Sprintf("aboard.oidc.redirect %q is not an absolute URL", r)})
		}
	}
	if len(redirect) == 0 {
		*issues = append(*issues, Issue{SeverityError, CodeOIDCRedirectMissing,
			"aboard.oidc.redirect is required for an OIDC provider"})
	}
	switch kind {
	case spec.ClientConfidential:
		if p.oidcSecret == "" {
			*issues = append(*issues, Issue{SeverityError, CodeOIDCSecretMissing,
				"aboard.oidc.secret is required for a confidential OIDC client"})
		}
	case spec.ClientPublic:
		if p.oidcSecret != "" {
			*issues = append(*issues, Issue{SeverityError, CodeOIDCSecretForbidden,
				"aboard.oidc.secret is forbidden for a public OIDC client"})
		}
	}
}

// parseSAML fills the SAML sub-namespace and enforces its cross-field rules:
// every SAML key is an error under any other provider type, the ACS URL is
// required and must be an absolute URL, and the binding is a closed post/redirect
// enum. Audience and issuer are recorded verbatim, unvalidated: an SP entity ID
// is commonly a URI but may be a URN, so aboard does not force a URL shape on
// them. SAML carries no secret-shaped field.
func parseSAML(p *parse, sp *spec.Spec, issues *[]Issue) {
	isSAML := sp.Provider == spec.ProviderSAML
	if !isSAML && len(p.samlKeys) > 0 {
		*issues = append(*issues, Issue{SeverityError, CodeWrongProvider,
			fmt.Sprintf("SAML labels (%s) are set but aboard.provider is %q",
				strings.Join(p.samlKeys, ", "), sp.Provider)})
	}

	sp.SAML.ACSUrl = p.samlACS
	sp.SAML.Audience = p.samlAudience
	sp.SAML.Issuer = p.samlIssuer
	sp.SAML.Mappings = splitCSV(p.samlMappings)

	// Binding (default post).
	binding := spec.SAMLBindingPost
	switch p.samlBinding {
	case "", string(spec.SAMLBindingPost):
		binding = spec.SAMLBindingPost
	case string(spec.SAMLBindingRedirect):
		binding = spec.SAMLBindingRedirect
	default:
		*issues = append(*issues, Issue{SeverityError, CodeSAMLBindingInvalid,
			fmt.Sprintf("aboard.saml.binding %q must be post or redirect", p.samlBinding)})
	}
	sp.SAML.Binding = binding

	// The remaining rules only make sense for an actual SAML provider.
	if !isSAML {
		return
	}
	if p.samlACS == "" {
		*issues = append(*issues, Issue{SeverityError, CodeSAMLACSMissing,
			"aboard.saml.acs is required for a SAML provider"})
	} else if !isAbsoluteURL(p.samlACS) {
		*issues = append(*issues, Issue{SeverityError, CodeSAMLACSInvalid,
			fmt.Sprintf("aboard.saml.acs %q is not an absolute URL", p.samlACS)})
	}
}

// isAbsoluteURL reports whether s parses as an absolute URL with a scheme and a
// host, the shape a redirect URI must have.
func isAbsoluteURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.IsAbs() && u.Host != ""
}

// firstNonEmpty returns a if it is non-empty, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// sortedKeys returns the map keys sorted, for deterministic iteration.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
