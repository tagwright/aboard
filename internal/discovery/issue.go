// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package discovery

import "fmt"

// Severity classifies a per-container discovery Issue. The two levels map to the
// grammar's two validation postures (see the "Grounding" section):
//
//   - SeverityError is skip-and-alert. A container with any error is not
//     reconciled: its Spec is incomplete or unsafe to act on, and the error is
//     surfaced through beacon. Because a skipped container may be an app that is
//     now open, or one whose access rule never landed, an error is sticky in the
//     digest until fixed.
//   - SeverityWarning does not skip. Today the only warning is declared-but-
//     unarmed (aboard.* labels present with aboard.enable absent or false), the
//     airlock rule: a copied compose block that names a group but never enables
//     is an app that is not protected while its labels suggest it is.
type Severity int

const (
	// SeverityError skips the container and alerts.
	SeverityError Severity = iota

	// SeverityWarning is a non-fatal notice that does not skip reconcile.
	SeverityWarning

	// SeverityInfo is a purely informational notice, below a warning. It never
	// skips or alerts on its own. The reconciler raises it, for the silent
	// adoption of a pre-existing object that reconciling would not change (Fork
	// 9), so the operator sees the one-time migration in the digest without it
	// being flagged as a problem. Appended after the two validation levels so
	// their numeric values, and HasError, are unchanged.
	SeverityInfo
)

// String is a stable machine-readable token for a severity, used in messages and
// test assertions.
func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// Issue codes. These are stable tokens the daemon routes on and tests assert
// against. None ever carries a secret value, only label names and non-secret
// values (a host candidate, a provider word, a suffix).
const (
	// CodeConflict is the ballast cross-prefix conflict rule: the same suffix
	// under aboard.* and tagwright.auth.* with different values.
	CodeConflict = "conflict"

	// CodeUnknownSuffix is an aboard.* / tagwright.auth.* suffix the grammar does
	// not recognize (a mistyped aboard.grops). Never ignored: a silently-absent
	// access rule is exactly the failure a security tool must not have.
	CodeUnknownSuffix = "unknown-suffix"

	// CodeReserved is a suffix the grammar reserves and rejects in v1
	// (aboard.users, aboard.caddy.*), held for additive arrival.
	CodeReserved = "reserved"

	// CodeUnarmed is the declared-but-unarmed warning: aboard.* labels present
	// with aboard.enable absent or false.
	CodeUnarmed = "unarmed"

	// CodeProviderInvalid is an aboard.provider value that is not one of the
	// recognized enum members.
	CodeProviderInvalid = "provider-invalid"

	// CodeWrongProvider is a typed sub-namespace key present under a provider type
	// that does not honor it (an aboard.oidc.* under forwardauth, an
	// aboard.outpost or aboard.traefik.* or aboard.forwardauth.* under oidc or
	// saml, an aboard.saml.* under forwardauth or oidc).
	CodeWrongProvider = "wrong-provider"

	// CodeProxyNoneTraefik is any aboard.traefik.* key under config proxy: none.
	CodeProxyNoneTraefik = "proxy-none-traefik"

	// CodeSlugInvalid is an aboard.slug override with a character outside
	// [a-z0-9-].
	CodeSlugInvalid = "slug-invalid"

	// CodeRequireInvalid is an aboard.require value that is not any or all.
	CodeRequireInvalid = "require-invalid"

	// CodeHostInvalid is an explicit aboard.host that is not a bare hostname (it
	// carries a scheme, a path, or a port).
	CodeHostInvalid = "host-invalid"

	// CodeHostMissing is host inference finding zero literal Host() matchers and
	// no explicit aboard.host.
	CodeHostMissing = "host-missing"

	// CodeHostAmbiguous is host inference finding more than one distinct literal
	// Host(), or any HostRegexp/HostSNI, with no explicit aboard.host.
	CodeHostAmbiguous = "host-ambiguous"

	// CodeIndexedConflict is a csv label and its indexed .<n> escape both present
	// for the same field. There is no silent precedence, so it is an error.
	CodeIndexedConflict = "indexed-conflict"

	// CodeIndexedInvalid is an indexed .<n> escape whose index is not an integer.
	CodeIndexedInvalid = "indexed-invalid"

	// CodeClientInvalid is an aboard.oidc.client value that is not confidential
	// or public.
	CodeClientInvalid = "client-invalid"

	// CodeOIDCRedirectMissing is an OIDC provider with no aboard.oidc.redirect.
	CodeOIDCRedirectMissing = "oidc-redirect-missing"

	// CodeOIDCRedirectInvalid is an aboard.oidc.redirect entry that is not an
	// absolute URL.
	CodeOIDCRedirectInvalid = "oidc-redirect-invalid"

	// CodeOIDCSecretMissing is a confidential OIDC client with no
	// aboard.oidc.secret. The secret is required for a confidential client.
	CodeOIDCSecretMissing = "oidc-secret-missing"

	// CodeOIDCSecretForbidden is a public OIDC client that names an
	// aboard.oidc.secret. A public client forbids the secret.
	CodeOIDCSecretForbidden = "oidc-secret-forbidden"

	// CodeSAMLACSMissing is a SAML provider with no aboard.saml.acs. The ACS URL
	// is required for a SAML provider, the analog of oidc.redirect.
	CodeSAMLACSMissing = "saml-acs-missing"

	// CodeSAMLACSInvalid is an aboard.saml.acs that is not an absolute URL.
	CodeSAMLACSInvalid = "saml-acs-invalid"

	// CodeSAMLBindingInvalid is an aboard.saml.binding value that is not post or
	// redirect.
	CodeSAMLBindingInvalid = "saml-binding-invalid"
)

// Issue is a classified discovery finding for one container. It carries a
// severity, a stable code, and a human-readable message. The message names
// labels, hosts, providers, and suffixes only, never a secret value.
type Issue struct {
	Severity Severity
	Code     string
	Message  string
}

// String renders an Issue for a log line or a test failure.
func (i Issue) String() string {
	return fmt.Sprintf("%s: %s: %s", i.Severity, i.Code, i.Message)
}

// HasError reports whether any Issue in the slice is a SeverityError, the
// signal the daemon uses to skip-and-alert a container rather than reconcile it.
func HasError(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == SeverityError {
			return true
		}
	}
	return false
}
