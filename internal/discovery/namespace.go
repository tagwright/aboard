// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package discovery

import (
	"fmt"
	"sort"
	"strings"
)

// Recognized label prefixes. primaryPrefix is primary and leads all
// documentation and examples; aliasPrefix is the org-namespaced alias. Both
// carry the identical suffix grammar (the Namespace section of the grammar):
// aboard.enable and tagwright.auth.enable mean the same thing. Two doorways, one
// grammar.
const (
	primaryPrefix = "aboard."
	aliasPrefix   = "tagwright.auth."
)

// stripPrefix removes whichever recognized prefix key carries, returning the
// canonical suffix (e.g. "enable", "oidc.redirect", "traefik.routers") and
// whether key was recognized as an aboard label at all.
func stripPrefix(key string) (string, bool) {
	if suffix, ok := strings.CutPrefix(key, primaryPrefix); ok && suffix != "" {
		return suffix, true
	}
	if suffix, ok := strings.CutPrefix(key, aliasPrefix); ok && suffix != "" {
		return suffix, true
	}
	return "", false
}

// mergeNamespaces strips the two recognized prefixes off a container's labels
// and folds them into a single suffix -> value map, applying the ballast
// conflict rule verbatim: the same suffix under both prefixes with DIFFERENT
// values is a validation error (skip and alert), the same value under both is
// harmless, and there is no silent precedence. Labels under neither prefix are
// ignored.
//
// Keys are walked in sorted order so the first value kept on a conflict, and the
// error message naming the two conflicting keys, are deterministic regardless of
// Go's randomized map iteration. On a conflict the first-seen value is kept in
// the map so the rest of discovery can still run (the container is skipped for
// the error regardless), rather than dropping the whole label set.
func mergeNamespaces(labels map[string]string) (map[string]string, []Issue) {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		if _, ok := stripPrefix(k); ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	norm := make(map[string]string, len(keys))
	firstKey := make(map[string]string, len(keys))
	var issues []Issue

	for _, k := range keys {
		suffix, _ := stripPrefix(k)
		v := labels[k]

		if existingKey, seen := firstKey[suffix]; seen {
			if norm[suffix] != v {
				issues = append(issues, Issue{
					Severity: SeverityError,
					Code:     CodeConflict,
					Message: fmt.Sprintf("label %q conflicts with %q: %q != %q",
						existingKey, k, norm[suffix], v),
				})
			}
			continue
		}

		norm[suffix] = v
		firstKey[suffix] = k
	}

	return norm, issues
}
