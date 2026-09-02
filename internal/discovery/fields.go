// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package discovery

import (
	"sort"
	"strconv"
	"strings"
)

// splitCSV splits a comma-separated label value, trimming whitespace and
// dropping empty elements. An absent or empty value yields nil. It is the plain
// csv form; a value that itself contains commas uses the indexed .<n> escape
// instead (see indexedList).
func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sanitizeSlug lowercases s and maps every rune outside [a-z0-9-] to a single
// hyphen, collapsing runs and trimming leading and trailing hyphens. It is the
// default-slug derivation from the service name (Fork 2), never applied to an
// explicit aboard.slug (an explicit bad slug is a validation error, not a
// silent rewrite).
func sanitizeSlug(s string) string {
	var b strings.Builder
	lastHyphen := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastHyphen = false
		default:
			if !lastHyphen && b.Len() > 0 {
				b.WriteByte('-')
				lastHyphen = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// isValidSlug reports whether s is a nonempty string of [a-z0-9-] only, the
// constraint an explicit aboard.slug must satisfy.
func isValidSlug(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}

// indexedList assembles the values of an indexed escape family collected in idx
// (a map of integer index to value) into a slice in ascending index order. It is
// the comma-escape form: each aboard.<base>.<n> label carries one literal value
// that may itself contain commas.
func indexedList(idx map[int]string) []string {
	if len(idx) == 0 {
		return nil
	}
	keys := make([]int, 0, len(idx))
	for n := range idx {
		keys = append(keys, n)
	}
	sort.Ints(keys)
	out := make([]string, 0, len(keys))
	for _, n := range keys {
		out = append(out, idx[n])
	}
	return out
}

// resolveList picks the csv form or the indexed escape for one field, enforcing
// that they are not both present (there is no silent precedence). It returns the
// resolved values and an optional issue when both forms appear. The label name
// is used only for the error message.
func resolveList(csv string, hasCSV bool, idx map[int]string, label string) ([]string, *Issue) {
	if hasCSV && csv != "" && len(idx) > 0 {
		return nil, &Issue{
			Severity: SeverityError,
			Code:     CodeIndexedConflict,
			Message:  label + " and its indexed ." + "<n> escape are both set: choose one",
		}
	}
	if len(idx) > 0 {
		return indexedList(idx), nil
	}
	return splitCSV(csv), nil
}

// parseIndex parses the integer index of an indexed escape suffix (the "<n>" in
// aboard.oidc.redirect.<n>). A non-integer is not a valid index.
func parseIndex(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
