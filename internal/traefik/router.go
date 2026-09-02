// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Package traefik is aboard's Traefik verifier and renderer (Fork 6, the "audit
// the proxy" half). aboard NEVER writes Traefik config: it READS a container's
// traefik.http.routers.* labels, applies the mixed-host callback rule, raises a
// sticky alert when declared protection is not wired, and RENDERS the exact
// labels an operator should paste. The package is deliberately PURE: it imports
// only config, spec, and discovery (for the shared rule matchers and the Issue
// type), no Docker, no Authentik, no network, so it unit-tests against literal
// label maps without a socket.
//
// The load-bearing rule (grammar Fork 6, "The Traefik side"): a host where
// EVERY router carries the forward-auth middleware needs nothing else, because
// the outpost callback paths travel through the middleware and complete. A host
// where ANY router lacks the middleware (a public router beside a protected one)
// needs a callback router, Host(h) && PathPrefix(/outpost.goauthentik.io/),
// carrying the middleware, at a priority above every unprotected router on that
// host, pointed at authentik-server. This whole-host mechanism is a documented
// MUST-VERIFY assumption (Aboard Architecture, "Must verify empirically" item 1):
// it is implemented here exactly as specified and is pending empirical
// confirmation against real Authentik plus Traefik in Phase 5.
package traefik

import (
	"strconv"
	"strings"

	"github.com/tagwright/aboard/internal/discovery"
)

// routerPrefix is the label prefix every router field shares:
// traefik.http.routers.<name>.<field>.
const routerPrefix = "traefik.http.routers."

// callbackPathPrefix is the outpost callback path. A router whose rule carries a
// PathPrefix on this path is the Authentik outpost callback router, the route
// the login redirect lands on after Authentik authenticates a request. It is
// recognized structurally rather than by name, so travels-outpost, cum-outpost,
// or any operator naming is caught.
const callbackPathPrefix = "/outpost.goauthentik.io/"

// Router is the parsed model of one Traefik router on a container: its name, the
// raw rule, the literal Host() values in the rule, whether the rule carries a
// path matcher, the router's middlewares, its priority, and its service. It is a
// pure value built from labels, with no knowledge of Docker or Authentik.
type Router struct {
	// Name is the <name> segment of traefik.http.routers.<name>.*.
	Name string

	// Rule is the raw rule string (traefik.http.routers.<name>.rule).
	Rule string

	// Hosts is the set of literal Host() values in the rule, parsed with the
	// same matcher discovery infers the external host with.
	Hosts []string

	// HasPath reports whether the rule carries a path matcher (PathPrefix, Path,
	// or PathRegexp), the shape that distinguishes a subpath router from a
	// whole-host one.
	HasPath bool

	// Middlewares are the router's middlewares, csv-split
	// (traefik.http.routers.<name>.middlewares).
	Middlewares []string

	// Priority is the router's explicit priority, or -1 when none was set. Use
	// EffectivePriority for the value Traefik actually routes on.
	Priority int

	// Service is the router's service (traefik.http.routers.<name>.service).
	Service string
}

// priorityUnset is the sentinel for a router with no explicit priority label.
const priorityUnset = -1

// pathMatcherPrefixes are the rule tokens that make a router a subpath router
// rather than a whole-host one.
var pathMatcherPrefixes = []string{"PathPrefix(", "PathRegexp(", "Path("}

// ParseRouters parses every traefik.http.routers.<name>.* label in labels into a
// map of Router by name. It reads the four fields the verifier needs (rule,
// middlewares, priority, service) and derives the rule-level facts (Hosts,
// HasPath) once. Unrecognized router fields (tls, entrypoints) are ignored, and
// a malformed priority leaves the router at priorityUnset.
func ParseRouters(labels map[string]string) map[string]*Router {
	routers := map[string]*Router{}
	for k, v := range labels {
		if !strings.HasPrefix(k, routerPrefix) {
			continue
		}
		rest := strings.TrimPrefix(k, routerPrefix)
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			continue
		}
		name, field := rest[:dot], rest[dot+1:]
		r := routers[name]
		if r == nil {
			r = &Router{Name: name, Priority: priorityUnset}
			routers[name] = r
		}
		switch field {
		case "rule":
			r.Rule = v
			r.Hosts = discovery.HostLiterals(v)
			r.HasPath = hasPathMatcher(v)
		case "middlewares":
			r.Middlewares = splitCSV(v)
		case "priority":
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				r.Priority = n
			}
		case "service":
			r.Service = v
		}
	}
	return routers
}

// EffectivePriority is the priority Traefik routes on: the explicit priority
// when set, else the length of the rule. Traefik's documented default router
// priority is the length of the rule expression, so a more specific (longer)
// rule wins by default. The verifier and renderer need a concrete number to
// place a callback router above the unprotected routers on a host.
func (r *Router) EffectivePriority() int {
	if r.Priority != priorityUnset {
		return r.Priority
	}
	return len(r.Rule)
}

// MatchesHost reports whether the router's rule contains a literal Host() for
// host. A router with no literal Host() (a HostRegexp catch-all, say) does not
// match a specific host here.
func (r *Router) MatchesHost(host string) bool {
	for _, h := range r.Hosts {
		if h == host {
			return true
		}
	}
	return false
}

// HasMiddleware reports whether the router carries the named middleware.
func (r *Router) HasMiddleware(mw string) bool {
	for _, m := range r.Middlewares {
		if m == mw {
			return true
		}
	}
	return false
}

// IsCallback reports whether the router is an Authentik outpost callback router:
// its rule carries a PathPrefix on the outpost callback path. Recognized
// structurally, so any router name is caught.
func (r *Router) IsCallback() bool {
	return isCallbackRule(r.Rule)
}

// isCallbackRule reports whether a rule contains a PathPrefix matcher on the
// outpost callback path. It looks for PathPrefix(`/outpost.goauthentik.io/`),
// the exact shape travels and cum use, tolerant of surrounding whitespace.
func isCallbackRule(rule string) bool {
	if !strings.Contains(rule, "PathPrefix(") {
		return false
	}
	return strings.Contains(rule, "`"+callbackPathPrefix+"`") ||
		strings.Contains(rule, callbackPathPrefix)
}

// hasPathMatcher reports whether a rule carries any path matcher.
func hasPathMatcher(rule string) bool {
	for _, p := range pathMatcherPrefixes {
		if strings.Contains(rule, p) {
			return true
		}
	}
	return false
}

// splitCSV splits a comma-separated label value, trimming whitespace and
// dropping empty fields. It mirrors discovery's csv handling for the labels the
// verifier reads (middlewares).
func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
