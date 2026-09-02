// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Shared Traefik router-rule primitives. These are the low-level matchers that
// both host inference (Fork 3, host.go) and the Traefik verifier (Fork 6,
// package traefik) read a rule with. They live in discovery, the lower package,
// so the verifier reuses the EXACT same Host()/HostRegexp parsing rather than
// duplicating the regexes, and so the dependency runs one way (traefik imports
// discovery, never the reverse) with no import cycle.

package discovery

import "regexp"

// hostLiteralRe matches a Traefik literal Host() matcher and captures the
// backtick-quoted hostname. A rule may combine Host(`h`) with && PathPrefix(...)
// and other matchers, so this pulls only the Host() literal and ignores the
// rest. Traefik quotes matcher arguments in backticks.
var hostLiteralRe = regexp.MustCompile("Host\\(`([^`]*)`\\)")

// hostRegexpRe detects a HostRegexp() or HostSNI() matcher, whose argument is
// not a single literal host and so makes inference impossible.
var hostRegexpRe = regexp.MustCompile(`Host(Regexp|SNI)\(`)

// traefikRuleRe matches the router-rule label keys whose values inference
// scans: traefik.http.routers.<name>.rule.
var traefikRuleRe = regexp.MustCompile(`^traefik\.http\.routers\.[^.]+\.rule$`)

// HostLiterals returns every literal Host() value in a single Traefik router
// rule, in order, skipping empty captures. It is exported so the Traefik
// verifier matches host-membership with the exact matcher host inference uses.
func HostLiterals(rule string) []string {
	var out []string
	for _, m := range hostLiteralRe.FindAllStringSubmatch(rule, -1) {
		if m[1] != "" {
			out = append(out, m[1])
		}
	}
	return out
}

// RuleHasHostRegexp reports whether a rule uses a HostRegexp or HostSNI matcher,
// which is not a single literal host.
func RuleHasHostRegexp(rule string) bool {
	return hostRegexpRe.MatchString(rule)
}

// IsRouterRuleKey reports whether a label key is a
// traefik.http.routers.<name>.rule key.
func IsRouterRuleKey(key string) bool {
	return traefikRuleRe.MatchString(key)
}
