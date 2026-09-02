// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package reconcile

import (
	"context"
	"errors"
	"strings"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/secret"
	"github.com/tagwright/aboard/internal/spec"
)

// Issue codes the reconciler raises. Like discovery's, they are stable tokens
// the daemon routes on and tests assert against, and none ever carries a secret
// value: an OIDC client secret is named only, never surfaced.
const (
	// CodeFlowMissing is a configured authorization or invalidation flow slug
	// that does not resolve to a flow. Sticky.
	CodeFlowMissing = "flow-missing"

	// CodeGroupMissing is an aboard.groups name that does not exist, without the
	// ABOARD_CREATE_GROUPS opt-in. Sticky.
	CodeGroupMissing = "group-missing"

	// CodeGroupCreated is the create-and-warn outcome under ABOARD_CREATE_GROUPS:
	// a missing group was created empty, which is fail-closed but a wider write
	// footprint, so it warns.
	CodeGroupCreated = "group-created"

	// CodePolicyMissing is an aboard.policies name that does not exist. Always an
	// error, never created. Sticky.
	CodePolicyMissing = "policy-missing"

	// CodeSigningKeyMissing is an OIDC reconcile that finds neither the named
	// signing certificate nor any fallback signing key. Sticky.
	CodeSigningKeyMissing = "signing-key-missing"

	// CodeScopeMissing is an OIDC scope-mapping name (an always-present one or an
	// extra) that does not resolve. Sticky.
	CodeScopeMissing = "scope-missing"

	// CodeSecretMissing is an OIDC client secret whose named reference does not
	// resolve. The error names the secret by NAME, never its value. Sticky.
	CodeSecretMissing = "oidc-secret-missing"

	// CodeSecretWeak is an OIDC client secret that resolves but is shorter than
	// the minimum. Named by NAME, never by value. Sticky.
	CodeSecretWeak = "oidc-secret-weak"

	// CodeOutpostMissing is a forward-auth attach whose target outpost (the
	// embedded one, or a named one) does not exist. Sticky.
	CodeOutpostMissing = "outpost-missing"

	// CodeAdopted is the informational, one-time notice that a pre-existing
	// object was adopted (Fork 9). Info severity, never an alert.
	CodeAdopted = "adopted"

	// CodeAdoptConflict is the sticky named-diff error: a pre-existing object
	// reconciling would change, without aboard.adopt=true. Sticky.
	CodeAdoptConflict = "adopt-conflict"

	// CodeAdoptTypeChange is a pre-existing object whose provider TYPE differs
	// from the label. Never adoptable, even with the affirmation. Sticky.
	CodeAdoptTypeChange = "adopt-type-change"

	// CodeBindingRemoved is the strict binding-ownership warning: a binding
	// present in Authentik and absent from the labels was removed on reconcile.
	CodeBindingRemoved = "binding-removed"

	// CodeSAMLMappingMissing is a SAML property-mapping name (an extra from
	// aboard.saml.mappings) that does not resolve. Sticky.
	CodeSAMLMappingMissing = "saml-mapping-missing"

	// CodeAPI is any other Authentik REST failure (a create, patch, delete, or
	// list that errored for a reason other than not-found). Sticky.
	CodeAPI = "api-error"
)

// hiddenLaunchURL is Authentik's value convention for hiding an application from
// the user library: an application whose launch URL is "blank://blank" does not
// appear in the library. It is not a schema field, so it is set here as the
// documented mechanism behind aboard.launch=none (Fork 5, "Library").
const hiddenLaunchURL = "blank://blank"

// alwaysScopes are the scope mappings every OIDC provider carries, so a provider
// can never be created that issues tokens with no scopes (Fork 7). Extras from
// aboard.oidc.scopes are added to these.
var alwaysScopes = []string{"openid", "email", "profile"}

// Error is the reconciler's typed failure. It carries the stable issue code and
// the human-readable message (the same pair recorded as a SeverityError Issue on
// the Result), so a caller can branch on the code and a test can assert it.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Result records what one Reconcile did: the converged identifiers, whether the
// object was adopted, whether the provider was attached to its outpost (the
// go-live moment), a human-readable action trail, and the Issues to route for
// alerting and status. Issues carry info, warnings, and, on failure, the
// terminal error too.
type Result struct {
	Slug       string
	Provider   spec.ProviderType
	ProviderPK int
	AppPK      string
	Adopted    bool
	Attached   bool
	Actions    []string
	Issues     []discovery.Issue
}

// Reconciler converges Authentik to match a Spec. It holds the API seam, the
// loaded config (flows, outpost, signing key, fleet default groups, and the
// create-groups global), and the secret resolver used to push an OIDC client
// secret inward. It carries no per-run state; each Reconcile is self-contained.
type Reconciler struct {
	api     API
	cfg     *config.Config
	resolve secret.Resolver
}

// New builds a Reconciler over api, cfg, and resolve.
func New(api API, cfg *config.Config, resolve secret.Resolver) *Reconciler {
	return &Reconciler{api: api, cfg: cfg, resolve: resolve}
}

// desiredBinding is one resolved access binding aboard means the Application to
// carry: a group or an existing policy, addressed by its resolved Authentik pk.
// name is kept only for messages.
type desiredBinding struct {
	isGroup bool
	pk      string
	name    string
}

// key is the identity of a binding for set comparison: the kind plus the pk. A
// desired binding and an existing PolicyBinding with the same key are the same
// binding.
func (d desiredBinding) key() string {
	if d.isGroup {
		return "g:" + d.pk
	}
	return "p:" + d.pk
}

// Reconcile converges Authentik to match s and returns what it did. The steps
// run in a fixed order that is a correctness requirement, not a style choice:
//
//	a. resolve inputs (flows, effective groups, effective outpost) and the
//	   desired access bindings.
//	b. converge the provider (create or PATCH the aboard-named provider).
//	c. converge the application (adopting a pre-existing object per Fork 9).
//	d. converge bindings STRICTLY (Fork 5): create the desired, remove the
//	   stray, before the attach.
//	e. attach the provider to the outpost, LAST, the moment the app goes live.
//
// Any failure in steps a-d returns before the attach, so a failed reconcile
// never attaches the provider and nothing goes live (Fork 4; architecture "Must
// verify empirically" item 2). The adoption GATE is evaluated read-only up
// front, before any write, so a refused adoption also leaves nothing behind.
func (r *Reconciler) Reconcile(ctx context.Context, s spec.Spec) (*Result, error) {
	res := &Result{Slug: s.Slug, Provider: s.Provider}

	slug := s.Slug
	markerName := providerMarkerName(slug)

	// adoptPK, when set, is the pk of a pre-existing provider an adopted
	// application points at, which the provider convergence PATCHes in place
	// (renaming it to the marker AND pushing the desired shape in one validated
	// call) rather than creating a fresh aboard-named provider and re-pointing.
	var adoptPK *int

	// Step a: resolve the effective flows, groups, outpost, and bindings.
	authzSlug := s.Flow
	if authzSlug == "" {
		authzSlug = r.cfg.Flows.Authorization
	}
	authz, err := r.api.GetFlowBySlug(ctx, authzSlug)
	if err != nil {
		if errors.Is(err, authentik.ErrNotFound) {
			return res, r.fail(res, CodeFlowMissing, "authorization flow "+authzSlug+" does not exist")
		}
		return res, r.fail(res, CodeAPI, "look up authorization flow "+authzSlug+": "+err.Error())
	}
	inval, err := r.api.GetFlowBySlug(ctx, r.cfg.Flows.Invalidation)
	if err != nil {
		if errors.Is(err, authentik.ErrNotFound) {
			return res, r.fail(res, CodeFlowMissing, "invalidation flow "+r.cfg.Flows.Invalidation+" does not exist")
		}
		return res, r.fail(res, CodeAPI, "look up invalidation flow "+r.cfg.Flows.Invalidation+": "+err.Error())
	}

	effOutpost := s.Outpost
	if effOutpost == "" {
		effOutpost = r.cfg.Outpost
	}

	desired, err := r.resolveBindings(ctx, res, effectiveGroups(s, r.cfg), s.Policies)
	if err != nil {
		return res, err
	}

	// Prelude: read the existing application and, if present and not already an
	// aboard-owned object of the desired type, run the adoption gate. This is
	// read-only and happens before any provider or application write.
	app, err := r.api.GetApplicationBySlug(ctx, slug)
	appExists := true
	if err != nil {
		if errors.Is(err, authentik.ErrNotFound) {
			appExists = false
			app = nil
		} else {
			return res, r.fail(res, CodeAPI, "look up application "+slug+": "+err.Error())
		}
	}
	if appExists {
		own, oerr := r.resolveOwnership(ctx, *app)
		if oerr != nil {
			return res, r.fail(res, CodeAPI, "resolve ownership of application "+slug+": "+oerr.Error())
		}
		ownedByDesired := own.owned && own.kind == s.Provider
		if !ownedByDesired {
			if aerr := r.adoptionGate(ctx, res, s, slug, app, own, desired); aerr != nil {
				return res, aerr
			}
			// Adoption was granted (the gate returned no error). Take over the
			// pre-existing provider the app points at by PATCHing it IN PLACE below,
			// rather than creating a fresh aboard-named provider and re-pointing the
			// app. Verified empirically against Authentik 2025.6.4: a
			// create-and-repoint leaves the old provider attached to the embedded
			// outpost with the SAME external_host, and aboard's app-based orphan scan
			// can never see it (it is not aboard-named and no application points at
			// it), so prune can never clean it and it lingers forever. Forward-auth
			// still RESOLVES with the duplicate (the outpost picks one deterministically
			// and returns a correct 302-to-login), so this is a cleanliness and
			// prunability fix, not a resolution fix. The single full-body PATCH the
			// converge step does both renames and reconfigures the provider, which
			// also sidesteps Authentik's proxy-provider validator rejecting a
			// name-only PATCH ("internal_host cannot be empty ...") on a partial
			// update that omits mode.
			if app != nil && app.Provider != nil {
				adoptPK = app.Provider
			}
		}
	}

	// Step b: provider convergence. The provider is always named "<slug>
	// (aboard)", the ownership marker (Fork 2).
	var providerPK int
	switch s.Provider {
	case spec.ProviderForwardAuth:
		providerPK, err = r.convergeProxyProvider(ctx, res, s, markerName, authz.PK, inval.PK, adoptPK)
	case spec.ProviderOIDC:
		providerPK, err = r.convergeOAuth2Provider(ctx, res, s, slug, markerName, authz.PK, inval.PK, adoptPK)
	case spec.ProviderSAML:
		providerPK, err = r.convergeSAMLProvider(ctx, res, s, markerName, authz.PK, inval.PK, adoptPK)
	default:
		return res, r.fail(res, CodeProviderUnknown, "unknown provider type "+string(s.Provider))
	}
	if err != nil {
		return res, err
	}
	res.ProviderPK = providerPK

	// Step c: application convergence.
	appPK, err := r.convergeApplication(ctx, res, s, slug, providerPK, appExists)
	if err != nil {
		return res, err
	}
	res.AppPK = appPK

	// Step d: bindings, STRICT, BEFORE the attach.
	if err := r.convergeBindings(ctx, res, appPK, desired); err != nil {
		return res, err
	}

	// Step e: outpost attach, LAST. This is the go-live moment for a forward-auth
	// provider, and it is reachable only when every step above succeeded: each
	// returns its error before this point, so a failed reconcile leaves the
	// provider unattached and nothing live (Fork 4; "Must verify empirically"
	// item 2). OIDC has no outpost step.
	if s.Provider == spec.ProviderForwardAuth {
		if err := r.attachOutpost(ctx, res, effOutpost, providerPK); err != nil {
			return res, err
		}
	}

	return res, nil
}

// CodeProviderUnknown is an unrecognized provider type reaching the reconciler.
// Defense in depth; discovery validates the enum first.
const CodeProviderUnknown = "provider-unknown"

// fail records a SeverityError Issue on res and returns the matching typed
// Error, so the terminal failure is both routable (in res.Issues) and returnable
// (for control flow). It never carries a secret value.
func (r *Reconciler) fail(res *Result, code, msg string) error {
	res.Issues = append(res.Issues, discovery.Issue{
		Severity: discovery.SeverityError,
		Code:     code,
		Message:  msg,
	})
	return &Error{Code: code, Message: msg}
}

// warn records a SeverityWarning Issue on res.
func (r *Reconciler) warn(res *Result, code, msg string) {
	res.Issues = append(res.Issues, discovery.Issue{
		Severity: discovery.SeverityWarning,
		Code:     code,
		Message:  msg,
	})
}

// info records a SeverityInfo Issue on res.
func (r *Reconciler) info(res *Result, code, msg string) {
	res.Issues = append(res.Issues, discovery.Issue{
		Severity: discovery.SeverityInfo,
		Code:     code,
		Message:  msg,
	})
}

// effectiveGroups applies the three-state Groups convention (Fork 5): unset uses
// the fleet default, the none sentinel is an empty gate (any authenticated
// user), and an explicit list replaces the fleet default wholesale.
func effectiveGroups(s spec.Spec, cfg *config.Config) []string {
	if !s.GroupsSet {
		return cfg.Defaults.Groups
	}
	if s.GroupsNone() {
		return nil
	}
	return s.Groups
}

// policyEngineMode maps the require mode to Authentik's policy-engine mode.
func policyEngineMode(req spec.Require) string {
	if req == spec.RequireAll {
		return authentik.PolicyEngineModeAll
	}
	return authentik.PolicyEngineModeAny
}

// containsInt reports whether xs contains x.
func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// dedupe returns xs with duplicates removed, preserving first-seen order. It
// keeps the always-present OIDC scopes from being requested twice if an operator
// also lists one in aboard.oidc.scopes.
func dedupe(xs []string) []string {
	seen := make(map[string]bool, len(xs))
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// resolveBindings turns the effective group and policy names into resolved
// desiredBindings. A missing group is a sticky error unless ABOARD_CREATE_GROUPS
// is set, in which case it is created empty and warned. A missing policy is
// always an error, never created (Fork 5).
func (r *Reconciler) resolveBindings(ctx context.Context, res *Result, groups, policies []string) ([]desiredBinding, error) {
	var out []desiredBinding

	for _, name := range groups {
		grp, err := r.api.GetGroupByName(ctx, name)
		if err == nil {
			out = append(out, desiredBinding{isGroup: true, pk: grp.PK, name: name})
			continue
		}
		if !errors.Is(err, authentik.ErrNotFound) {
			return nil, r.fail(res, CodeAPI, "look up group "+name+": "+err.Error())
		}
		if !r.cfg.Globals.CreateGroups {
			return nil, r.fail(res, CodeGroupMissing,
				"group "+name+" does not exist (set ABOARD_CREATE_GROUPS=true to create it empty)")
		}
		created, cerr := r.api.CreateGroup(ctx, name)
		if cerr != nil {
			return nil, r.fail(res, CodeAPI, "create group "+name+": "+cerr.Error())
		}
		r.warn(res, CodeGroupCreated, "created missing group "+name+" (empty) under ABOARD_CREATE_GROUPS")
		out = append(out, desiredBinding{isGroup: true, pk: created.PK, name: name})
	}

	for _, name := range policies {
		pol, err := r.api.GetPolicyByName(ctx, name)
		if err != nil {
			if errors.Is(err, authentik.ErrNotFound) {
				return nil, r.fail(res, CodePolicyMissing, "policy "+name+" does not exist (policies are bound, never created)")
			}
			return nil, r.fail(res, CodeAPI, "look up policy "+name+": "+err.Error())
		}
		out = append(out, desiredBinding{isGroup: false, pk: pol.PK, name: name})
	}

	return out, nil
}

// convergeProxyProvider creates or PATCHes the aboard-named proxy provider for a
// forward-auth spec and returns its pk.
func (r *Reconciler) convergeProxyProvider(ctx context.Context, res *Result, s spec.Spec, name, authzPK, invalPK string, adoptPK *int) (int, error) {
	body := authentik.ProxyProviderRequest{
		Name:              name,
		AuthorizationFlow: authzPK,
		InvalidationFlow:  invalPK,
		ExternalHost:      "https://" + s.Host,
		Mode:              authentik.ProxyModeForwardSingle,
		SkipPathRegex:     strings.Join(s.ForwardAuth.PublicPaths, "\n"),
	}

	// Adoption: PATCH the pre-existing provider the app points at, in place. This
	// single full-body PATCH both renames it to the marker and pushes the desired
	// shape, taking ownership without creating a duplicate.
	if adoptPK != nil {
		patched, perr := r.api.PatchProxyProvider(ctx, *adoptPK, body)
		if perr != nil {
			return 0, r.fail(res, CodeAPI, "adopt forward-auth provider as "+name+": "+perr.Error())
		}
		res.Actions = append(res.Actions, "adopted forward-auth provider as "+name)
		return patched.PK, nil
	}

	existing, err := r.api.GetProxyProviderByName(ctx, name)
	if err != nil {
		if errors.Is(err, authentik.ErrNotFound) {
			created, cerr := r.api.CreateProxyProvider(ctx, body)
			if cerr != nil {
				return 0, r.fail(res, CodeAPI, "create forward-auth provider "+name+": "+cerr.Error())
			}
			res.Actions = append(res.Actions, "created forward-auth provider "+name)
			return created.PK, nil
		}
		return 0, r.fail(res, CodeAPI, "look up forward-auth provider "+name+": "+err.Error())
	}
	patched, perr := r.api.PatchProxyProvider(ctx, existing.PK, body)
	if perr != nil {
		return 0, r.fail(res, CodeAPI, "patch forward-auth provider "+name+": "+perr.Error())
	}
	res.Actions = append(res.Actions, "patched forward-auth provider "+name)
	return patched.PK, nil
}

// convergeOAuth2Provider creates or PATCHes the aboard-named OAuth2 provider for
// an OIDC spec and returns its pk. It resolves the client secret inward (by
// NAME, length-checked, never logged), the signing key, and the always-present
// plus extra scope mappings.
func (r *Reconciler) convergeOAuth2Provider(ctx context.Context, res *Result, s spec.Spec, slug, name, authzPK, invalPK string, adoptPK *int) (int, error) {
	clientType := authentik.ClientTypeConfidential
	if s.OIDC.ClientKind == spec.ClientPublic {
		clientType = authentik.ClientTypePublic
	}

	var clientSecret string
	if clientType == authentik.ClientTypeConfidential {
		val, err := r.resolve(s.OIDC.SecretName)
		if err != nil {
			// The resolver names the secret by NAME, never its value.
			return 0, r.fail(res, CodeSecretMissing, "resolve OIDC client secret "+s.OIDC.SecretName+": "+err.Error())
		}
		if lerr := secret.CheckOIDCLength(s.OIDC.SecretName, val); lerr != nil {
			return 0, r.fail(res, CodeSecretWeak, lerr.Error())
		}
		clientSecret = val
	}

	signingKey, err := r.resolveSigningKey(ctx, res, r.cfg.OIDC.SigningKey)
	if err != nil {
		return 0, err
	}

	var mappingPKs []string
	for _, scopeName := range dedupe(append(append([]string{}, alwaysScopes...), s.OIDC.Scopes...)) {
		m, merr := r.api.GetScopeMappingByName(ctx, scopeName)
		if merr != nil {
			if errors.Is(merr, authentik.ErrNotFound) {
				return 0, r.fail(res, CodeScopeMissing, "scope mapping "+scopeName+" does not exist")
			}
			return 0, r.fail(res, CodeAPI, "look up scope mapping "+scopeName+": "+merr.Error())
		}
		mappingPKs = append(mappingPKs, m.PK)
	}

	clientID := s.OIDC.ClientID
	if clientID == "" {
		clientID = slug
	}

	redirects := make([]authentik.RedirectURI, 0, len(s.OIDC.Redirect))
	for _, u := range s.OIDC.Redirect {
		redirects = append(redirects, authentik.RedirectURI{MatchingMode: authentik.MatchingModeStrict, URL: u})
	}

	body := authentik.OAuth2ProviderRequest{
		Name:              name,
		AuthorizationFlow: authzPK,
		InvalidationFlow:  invalPK,
		RedirectURIs:      redirects,
		ClientType:        clientType,
		ClientID:          clientID,
		SigningKey:        signingKey,
		PropertyMappings:  mappingPKs,
	}
	if clientType == authentik.ClientTypeConfidential {
		body.ClientSecret = clientSecret
	}

	// Adoption: PATCH the pre-existing OIDC provider the app points at, in place,
	// renaming and reconfiguring it in one call rather than creating a duplicate.
	if adoptPK != nil {
		patched, perr := r.api.PatchOAuth2Provider(ctx, *adoptPK, body)
		if perr != nil {
			return 0, r.fail(res, CodeAPI, "adopt OIDC provider as "+name+": "+perr.Error())
		}
		res.Actions = append(res.Actions, "adopted OIDC provider as "+name)
		return patched.PK, nil
	}

	existing, err := r.api.GetOAuth2ProviderByName(ctx, name)
	if err != nil {
		if errors.Is(err, authentik.ErrNotFound) {
			created, cerr := r.api.CreateOAuth2Provider(ctx, body)
			if cerr != nil {
				return 0, r.fail(res, CodeAPI, "create OIDC provider "+name+": "+cerr.Error())
			}
			res.Actions = append(res.Actions, "created OIDC provider "+name)
			return created.PK, nil
		}
		return 0, r.fail(res, CodeAPI, "look up OIDC provider "+name+": "+err.Error())
	}
	patched, perr := r.api.PatchOAuth2Provider(ctx, existing.PK, body)
	if perr != nil {
		return 0, r.fail(res, CodeAPI, "patch OIDC provider "+name+": "+perr.Error())
	}
	res.Actions = append(res.Actions, "patched OIDC provider "+name)
	return patched.PK, nil
}

// resolveSigningKey resolves a provider signing key: the certificate named by
// keyName (the fleet oidc.signing_key or saml.signing_key), else the first
// available signing key. Neither present is a sticky error. It is shared by the
// OIDC and SAML convergence, which both sign with a keypair Authentik holds.
func (r *Reconciler) resolveSigningKey(ctx context.Context, res *Result, keyName string) (string, error) {
	cert, err := r.api.GetCertificateByName(ctx, keyName)
	if err == nil {
		return cert.PK, nil
	}
	if !errors.Is(err, authentik.ErrNotFound) {
		return "", r.fail(res, CodeAPI, "look up signing key "+keyName+": "+err.Error())
	}
	first, ferr := r.api.GetFirstSigningKey(ctx)
	if ferr != nil {
		if errors.Is(ferr, authentik.ErrNotFound) {
			return "", r.fail(res, CodeSigningKeyMissing,
				"no signing key: neither "+keyName+" nor any fallback certificate with a private key exists")
		}
		return "", r.fail(res, CodeAPI, "look up fallback signing key: "+ferr.Error())
	}
	return first.PK, nil
}

// convergeSAMLProvider creates or PATCHes the aboard-named SAML provider for a
// SAML spec and returns its pk. It resolves the signing keypair (the fleet
// saml.signing_key, else the first available), and the property mappings: the
// managed default attribute mappings ALWAYS, plus any extras named in
// aboard.saml.mappings, so the assertion always carries attributes. SAML has no
// outpost step and no client secret.
func (r *Reconciler) convergeSAMLProvider(ctx context.Context, res *Result, s spec.Spec, name, authzPK, invalPK string, adoptPK *int) (int, error) {
	signingKey, err := r.resolveSigningKey(ctx, res, r.cfg.SAML.SigningKey)
	if err != nil {
		return 0, err
	}

	// Managed default attribute mappings, always attached, plus the named extras.
	mappingPKs, err := r.api.GetSAMLPropertyMappings(ctx)
	if err != nil {
		return 0, r.fail(res, CodeAPI, "list managed SAML property mappings: "+err.Error())
	}
	for _, mName := range s.SAML.Mappings {
		m, merr := r.api.GetSAMLPropertyMappingByName(ctx, mName)
		if merr != nil {
			if errors.Is(merr, authentik.ErrNotFound) {
				return 0, r.fail(res, CodeSAMLMappingMissing, "SAML property mapping "+mName+" does not exist")
			}
			return 0, r.fail(res, CodeAPI, "look up SAML property mapping "+mName+": "+merr.Error())
		}
		mappingPKs = append(mappingPKs, m.PK)
	}
	mappingPKs = dedupe(mappingPKs)

	binding := authentik.SpBindingPost
	if s.SAML.Binding == spec.SAMLBindingRedirect {
		binding = authentik.SpBindingRedirect
	}

	body := authentik.SAMLProviderRequest{
		Name:              name,
		AuthorizationFlow: authzPK,
		InvalidationFlow:  invalPK,
		ACSUrl:            s.SAML.ACSUrl,
		Audience:          s.SAML.Audience,
		Issuer:            s.SAML.Issuer,
		SpBinding:         binding,
		SigningKp:         signingKey,
		// A signing keypair is always resolved, and Authentik requires at least one
		// sign flag when one is set. aboard signs the assertion (Authentik's own
		// model default), which is what SPs most commonly verify.
		SignAssertion:    boolPtr(true),
		SignResponse:     boolPtr(false),
		PropertyMappings: mappingPKs,
	}

	// Adoption: PATCH the pre-existing SAML provider the app points at, in place,
	// renaming and reconfiguring it in one call rather than creating a duplicate.
	if adoptPK != nil {
		patched, perr := r.api.PatchSAMLProvider(ctx, *adoptPK, body)
		if perr != nil {
			return 0, r.fail(res, CodeAPI, "adopt SAML provider as "+name+": "+perr.Error())
		}
		res.Actions = append(res.Actions, "adopted SAML provider as "+name)
		return patched.PK, nil
	}

	existing, err := r.api.GetSAMLProviderByName(ctx, name)
	if err != nil {
		if errors.Is(err, authentik.ErrNotFound) {
			created, cerr := r.api.CreateSAMLProvider(ctx, body)
			if cerr != nil {
				return 0, r.fail(res, CodeAPI, "create SAML provider "+name+": "+cerr.Error())
			}
			res.Actions = append(res.Actions, "created SAML provider "+name)
			return created.PK, nil
		}
		return 0, r.fail(res, CodeAPI, "look up SAML provider "+name+": "+err.Error())
	}
	patched, perr := r.api.PatchSAMLProvider(ctx, existing.PK, body)
	if perr != nil {
		return 0, r.fail(res, CodeAPI, "patch SAML provider "+name+": "+perr.Error())
	}
	res.Actions = append(res.Actions, "patched SAML provider "+name)
	return patched.PK, nil
}

// convergeApplication creates or PATCHes the Application by slug and returns its
// pk. Security-relevant fields (provider, policy engine mode) are always sent;
// cosmetic fields (launch, description, icon) are sent only when the label
// declared them, so a UI-set value survives (Fork 5, "Field ownership"). The
// icon rides its own set_icon_url action because meta_icon is read-only on the
// normal request body.
func (r *Reconciler) convergeApplication(ctx context.Context, res *Result, s spec.Spec, slug string, providerPK int, appExists bool) (string, error) {
	pk := providerPK
	body := authentik.ApplicationRequest{
		Name:             s.Title,
		Slug:             slug,
		Provider:         &pk,
		PolicyEngineMode: policyEngineMode(s.Require),
	}
	if s.LaunchSet {
		if s.LaunchNone {
			body.MetaLaunchURL = hiddenLaunchURL
		} else {
			body.MetaLaunchURL = s.Launch
		}
	}
	if s.DescriptionSet {
		body.MetaDescription = s.Description
	}

	var app *authentik.Application
	var err error
	if appExists {
		app, err = r.api.PatchApplication(ctx, slug, body)
		if err != nil {
			return "", r.fail(res, CodeAPI, "patch application "+slug+": "+err.Error())
		}
		res.Actions = append(res.Actions, "patched application "+slug)
	} else {
		app, err = r.api.CreateApplication(ctx, body)
		if err != nil {
			return "", r.fail(res, CodeAPI, "create application "+slug+": "+err.Error())
		}
		res.Actions = append(res.Actions, "created application "+slug)
	}

	if s.IconSet {
		if err := r.api.SetApplicationIconURL(ctx, slug, s.Icon); err != nil {
			return "", r.fail(res, CodeAPI, "set icon on application "+slug+": "+err.Error())
		}
		res.Actions = append(res.Actions, "set application icon "+slug)
	}

	return app.PK, nil
}

// convergeBindings enforces strict binding ownership on the aboard-owned
// Application (Fork 5): the desired set IS the binding set. It creates the
// desired bindings that are missing and DELETES every existing binding not in
// the desired set (group, policy, or any other kind), warning what it removed.
// An empty desired set (groups=none and no policies) means any authenticated
// user, and strict still removes any stray binding.
func (r *Reconciler) convergeBindings(ctx context.Context, res *Result, appPK string, desired []desiredBinding) error {
	existing, err := r.api.ListBindingsForTarget(ctx, appPK)
	if err != nil {
		return r.fail(res, CodeAPI, "list bindings for application "+appPK+": "+err.Error())
	}

	desiredByKey := make(map[string]desiredBinding, len(desired))
	for _, d := range desired {
		desiredByKey[d.key()] = d
	}

	// Remove stray bindings first so the app is never momentarily wider than the
	// labels declare, then add the desired ones that are missing.
	present := make(map[string]bool, len(existing))
	var removed []string
	for _, b := range existing {
		k := existingBindingKey(b)
		if k != "" {
			if _, want := desiredByKey[k]; want {
				present[k] = true
				continue
			}
		}
		if derr := r.api.DeleteBinding(ctx, b.PK); derr != nil {
			return r.fail(res, CodeAPI, "delete stray binding "+b.PK+": "+derr.Error())
		}
		removed = append(removed, describeExistingBinding(b))
	}

	for i, d := range desired {
		if present[d.key()] {
			continue
		}
		body := authentik.PolicyBindingRequest{
			Target:  appPK,
			Order:   i,
			Enabled: boolPtr(true),
			Negate:  boolPtr(false),
		}
		if d.isGroup {
			gpk := d.pk
			body.Group = &gpk
		} else {
			ppk := d.pk
			body.Policy = &ppk
		}
		if _, cerr := r.api.CreateBinding(ctx, body); cerr != nil {
			return r.fail(res, CodeAPI, "create binding for "+d.name+": "+cerr.Error())
		}
		res.Actions = append(res.Actions, "bound "+d.name)
	}

	if len(removed) > 0 {
		r.warn(res, CodeBindingRemoved,
			"strict binding ownership removed bindings absent from the labels: "+strings.Join(removed, ", "))
	}
	return nil
}

// attachOutpost is the go-live step (forward-auth only). It reads the target
// outpost, and if the provider is not already in its providers list, adds it and
// PATCHes the whole list back, read-modify-write, never dropping a provider it
// does not own (Fork 4). "embedded" resolves by the managed marker, any other
// name by exact name.
func (r *Reconciler) attachOutpost(ctx context.Context, res *Result, outpostName string, providerPK int) error {
	var outpost *authentik.Outpost
	var err error
	if outpostName == config.DefaultOutpost {
		outpost, err = r.api.GetEmbeddedOutpost(ctx)
	} else {
		outpost, err = r.api.GetOutpostByName(ctx, outpostName)
	}
	if err != nil {
		if errors.Is(err, authentik.ErrNotFound) {
			return r.fail(res, CodeOutpostMissing, "outpost "+outpostName+" does not exist (aboard never creates outposts)")
		}
		return r.fail(res, CodeAPI, "look up outpost "+outpostName+": "+err.Error())
	}

	if containsInt(outpost.Providers, providerPK) {
		res.Attached = true
		return nil
	}

	merged := append(append([]int{}, outpost.Providers...), providerPK)
	if _, perr := r.api.PatchOutpostProviders(ctx, outpost.PK, merged); perr != nil {
		return r.fail(res, CodeAPI, "attach provider to outpost "+outpostName+": "+perr.Error())
	}
	res.Attached = true
	res.Actions = append(res.Actions, "attached provider to outpost "+outpostName)
	return nil
}

// boolPtr returns a pointer to b, for the binding request's pointer bools where
// an explicit false is meaningful.
func boolPtr(b bool) *bool { return &b }

// existingBindingKey is the set-comparison identity of an existing PolicyBinding:
// its group or policy pk. A binding that is neither (a user binding, which
// aboard does not manage) has no key, so strict ownership treats it as stray.
func existingBindingKey(b authentik.PolicyBinding) string {
	if b.Group != nil && *b.Group != "" {
		return "g:" + *b.Group
	}
	if b.Policy != nil && *b.Policy != "" {
		return "p:" + *b.Policy
	}
	return ""
}

// describeExistingBinding names an existing binding for a removal warning, by pk
// (no name lookup, and never a secret).
func describeExistingBinding(b authentik.PolicyBinding) string {
	if b.Group != nil && *b.Group != "" {
		return "group " + *b.Group
	}
	if b.Policy != nil && *b.Policy != "" {
		return "policy " + *b.Policy
	}
	return "binding " + b.PK
}
