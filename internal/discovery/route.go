// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package discovery

import (
	"fmt"
	"strings"
)

// parse accumulates the per-suffix classification of one container's labels: the
// raw values of the typed sub-namespace fields, the indexed escape families, and
// the membership lists the cross-field checks in discovery.go consult. It exists
// so the single classification pass over the suffixes both rejects unknown and
// reserved keys AND records which sub-namespaces were touched, without reading
// the label map twice.
type parse struct {
	// Forward-auth sub-namespace.
	outpost        string
	traefikRouters string
	publicCSV      string
	hasPublicCSV   bool
	publicIdx      map[int]string

	// OIDC sub-namespace.
	oidcSecret    string
	oidcID        string
	oidcClient    string
	oidcScopes    string
	redirectCSV   string
	hasRedirectCSV bool
	redirectIdx   map[int]string

	// Membership lists for the wrong-provider and proxy:none checks. Each holds
	// the full aboard.* label spelling so an error names what the operator wrote.
	forwardKeys []string // outpost + forwardauth.* + traefik.*, forward-auth only
	traefikKeys []string // aboard.traefik.*, the proxy:none sub-namespace
	oidcKeys    []string // aboard.oidc.*
}

func newParse() *parse {
	return &parse{
		publicIdx:   map[int]string{},
		redirectIdx: map[int]string{},
	}
}

// exactKeys are the suffixes with no sub-structure that discovery reads straight
// from the norm map. route only needs to recognize them so they are not flagged
// as unknown; their values are pulled in discovery.go.
var exactKeys = map[string]bool{
	"enable": true, "name": true, "slug": true, "title": true,
	"provider": true, "host": true, "flow": true, "adopt": true,
	"groups": true, "policies": true, "require": true,
	"launch": true, "icon": true, "description": true,
}

// route classifies one suffix, appending an Issue for an unknown or reserved
// key and otherwise recording the value into the right accumulator. It is called
// once per suffix, in sorted order.
func (p *parse) route(suffix, val string, issues *[]Issue) {
	switch {
	case exactKeys[suffix]:
		// Recognized simple key, read later from norm.

	case suffix == "outpost":
		p.outpost = val
		p.forwardKeys = append(p.forwardKeys, "aboard.outpost")

	case suffix == "forwardauth.public":
		p.publicCSV, p.hasPublicCSV = val, true
		p.forwardKeys = append(p.forwardKeys, "aboard.forwardauth.public")

	case strings.HasPrefix(suffix, "forwardauth.public."):
		p.forwardKeys = append(p.forwardKeys, "aboard."+suffix)
		p.collectIndexed(p.publicIdx, suffix, "forwardauth.public.", val, issues)

	case strings.HasPrefix(suffix, "forwardauth."):
		unknown(suffix, issues)

	case suffix == "traefik.routers":
		p.traefikRouters = val
		p.forwardKeys = append(p.forwardKeys, "aboard.traefik.routers")
		p.traefikKeys = append(p.traefikKeys, "aboard.traefik.routers")

	case strings.HasPrefix(suffix, "traefik."):
		// An unrecognized aboard.traefik.* key is both a proxy:none-scoped
		// sub-namespace member and an unknown suffix. Record membership so the
		// proxy:none check still names it, then flag it unknown.
		p.traefikKeys = append(p.traefikKeys, "aboard."+suffix)
		unknown(suffix, issues)

	case suffix == "oidc.redirect":
		p.redirectCSV, p.hasRedirectCSV = val, true
		p.oidcKeys = append(p.oidcKeys, "aboard.oidc.redirect")

	case strings.HasPrefix(suffix, "oidc.redirect."):
		p.oidcKeys = append(p.oidcKeys, "aboard."+suffix)
		p.collectIndexed(p.redirectIdx, suffix, "oidc.redirect.", val, issues)

	case suffix == "oidc.secret":
		p.oidcSecret = val
		p.oidcKeys = append(p.oidcKeys, "aboard.oidc.secret")

	case suffix == "oidc.id":
		p.oidcID = val
		p.oidcKeys = append(p.oidcKeys, "aboard.oidc.id")

	case suffix == "oidc.client":
		p.oidcClient = val
		p.oidcKeys = append(p.oidcKeys, "aboard.oidc.client")

	case suffix == "oidc.scopes":
		p.oidcScopes = val
		p.oidcKeys = append(p.oidcKeys, "aboard.oidc.scopes")

	case strings.HasPrefix(suffix, "oidc."):
		p.oidcKeys = append(p.oidcKeys, "aboard."+suffix)
		unknown(suffix, issues)

	case suffix == "users" || strings.HasPrefix(suffix, "users."):
		reserved(suffix, "aboard.users is reserved and rejected in v1", issues)

	case suffix == "saml" || strings.HasPrefix(suffix, "saml."):
		reserved(suffix, "aboard.saml.* is reserved and rejected in v1", issues)

	case suffix == "caddy" || strings.HasPrefix(suffix, "caddy."):
		reserved(suffix, "aboard.caddy.* is reserved for a future proxy integration", issues)

	default:
		unknown(suffix, issues)
	}
}

// collectIndexed records one indexed escape value (aboard.<base><n>) into dst,
// or flags a non-integer index as an error.
func (p *parse) collectIndexed(dst map[int]string, suffix, base, val string, issues *[]Issue) {
	rest := strings.TrimPrefix(suffix, base)
	n, ok := parseIndex(rest)
	if !ok {
		*issues = append(*issues, Issue{SeverityError, CodeIndexedInvalid,
			fmt.Sprintf("aboard.%s has a non-integer index %q", suffix, rest)})
		return
	}
	dst[n] = val
}

// unknown appends an unknown-suffix error, never ignoring a mistyped key, since
// a silently-absent access rule is exactly the failure a security tool must not
// have.
func unknown(suffix string, issues *[]Issue) {
	*issues = append(*issues, Issue{SeverityError, CodeUnknownSuffix,
		fmt.Sprintf("unknown aboard label suffix %q", suffix)})
}

// reserved appends a reserved-suffix error with the grammar's held-for-additive
// message.
func reserved(suffix, msg string, issues *[]Issue) {
	*issues = append(*issues, Issue{SeverityError, CodeReserved, msg})
}
