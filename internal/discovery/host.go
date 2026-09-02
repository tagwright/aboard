// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Host inference (Fork 3). aboard needs the external host twice: as the proxy
// provider's external_host on the Authentik side, and as the Host() to verify
// the Traefik router against on the proxy side. Explicit aboard.host wins; else
// it is inferred from exactly one distinct literal Host() across the container's
// Traefik router rules. Zero, several, or any HostRegexp/HostSNI is an error.

package discovery

import (
	"fmt"
	"sort"
	"strings"
)

// The Traefik router-rule matchers this file reads (hostLiteralRe,
// hostRegexpRe, traefikRuleRe) live in rule.go, exported as HostLiterals,
// RuleHasHostRegexp, and IsRouterRuleKey, so the Traefik verifier reuses them.

// validateExplicitHost checks an explicit aboard.host is a BARE hostname: no
// scheme, no path, no port, no whitespace. aboard composes https:// in front, so
// a value that already carries one of those is a misconfiguration, not a host.
func validateExplicitHost(host string) *Issue {
	if host == "" || strings.ContainsAny(host, "/: \t") || strings.Contains(host, "://") {
		return &Issue{
			Severity: SeverityError,
			Code:     CodeHostInvalid,
			Message: fmt.Sprintf("aboard.host %q must be a bare hostname: no scheme, path, or port (aboard composes https://)",
				host),
		}
	}
	return nil
}

// inferHost scans every traefik.http.routers.*.rule label on the container and
// returns the single distinct literal Host() found. Exactly one distinct host is
// inference. Zero, more than one, or any HostRegexp/HostSNI returns a nil host
// and an Issue naming the candidates and telling the operator to set
// aboard.host. labels is the container's RAW label map, since the Traefik keys
// live outside the aboard namespace.
func inferHost(labels map[string]string) (string, *Issue) {
	var (
		distinct   []string
		seen       = map[string]bool{}
		regexpSeen bool
	)

	// Walk rule keys in sorted order so the candidate list in an error is
	// deterministic.
	keys := make([]string, 0, len(labels))
	for k := range labels {
		if IsRouterRuleKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	for _, k := range keys {
		rule := labels[k]
		if RuleHasHostRegexp(rule) {
			regexpSeen = true
		}
		for _, h := range HostLiterals(rule) {
			if !seen[h] {
				seen[h] = true
				distinct = append(distinct, h)
			}
		}
	}

	if regexpSeen {
		return "", &Issue{
			Severity: SeverityError,
			Code:     CodeHostAmbiguous,
			Message:  "host cannot be inferred: a HostRegexp or HostSNI matcher is not a single literal host, set aboard.host",
		}
	}
	switch len(distinct) {
	case 1:
		return distinct[0], nil
	case 0:
		return "", &Issue{
			Severity: SeverityError,
			Code:     CodeHostMissing,
			Message:  "host cannot be inferred: no literal Host() matcher on any Traefik router, set aboard.host",
		}
	default:
		return "", &Issue{
			Severity: SeverityError,
			Code:     CodeHostAmbiguous,
			Message: fmt.Sprintf("host cannot be inferred: %d distinct Host() matchers (%s), set aboard.host",
				len(distinct), strings.Join(distinct, ", ")),
		}
	}
}
