// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Package blueprint emits the Authentik BLUEPRINT that defines the identity-layer
// objects aboard references by NAME but deliberately never creates: the groups a
// fleet's labels bind, and the OIDC groups scope mapping that delivers group
// membership in tokens when group-claim is on.
//
// It is the identity-layer analog of package traefik's render: pure string
// output, no Docker and no Authentik, so aboard NEVER writes a file. The operator
// drops the emitted blueprint into the directory their Authentik worker already
// reconciles, the same IaC path the fleet's other blueprints travel. This keeps
// aboard in its lane: groups and scope mappings are fleet-level identity objects,
// so aboard proposes the IaC and the worker applies it, rather than aboard
// imperatively minting identity objects over the REST API.
package blueprint

import (
	"sort"
	"strconv"
	"strings"
)

// GroupsExpression is the canonical Authentik expression a groups scope mapping
// carries: it returns the names of every group the authenticating user belongs
// to, which is what a downstream app maps to its own roles. It is Authentik's own
// standard groups expression (authentik/providers/oauth2 docs), reproduced here
// so the emitted mapping behaves identically to a hand-written one.
const GroupsExpression = "return [group.name for group in request.user.ak_groups.all()]"

// Model names, verified against the live Authentik 2025.6.4 schema (a scope
// mapping's own meta_model_name is authentik_providers_oauth2.scopemapping, and a
// directory group is authentik_core.group). Hardcoding a wrong model name would
// make the whole blueprint fail to reconcile, so these are checked, not guessed.
const (
	modelGroup        = "authentik_core.group"
	modelScopeMapping = "authentik_providers_oauth2.scopemapping"
)

// Render returns a ready-to-drop Authentik blueprint (version 1, auto-
// instantiate) containing an authentik_core.group entry for every distinct name
// in groups, plus the OIDC groups scope mapping named groupsScope carrying the
// standard membership expression. groups is de-duplicated and sorted for a stable
// output. It is pure output: aboard writes nothing.
func Render(groups []string, groupsScope string) string {
	var b strings.Builder

	b.WriteString("# aboard render --blueprint: Authentik IaC for group-claim.\n")
	b.WriteString("#\n")
	b.WriteString("# Drop this into the blueprints directory your Authentik worker reconciles.\n")
	b.WriteString("# It defines the identity-layer objects aboard references BY NAME but never\n")
	b.WriteString("# creates: the groups your labels bind, and the OIDC groups scope mapping that\n")
	b.WriteString("# delivers group membership in tokens (oidc.groups_scope). aboard never writes\n")
	b.WriteString("# files, this is for you to save.\n")
	b.WriteString("version: 1\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: aboard group-claim\n")
	b.WriteString("  labels:\n")
	b.WriteString("    blueprints.goauthentik.io/instantiate: \"true\"\n")
	b.WriteString("entries:\n")

	for _, g := range dedupeSorted(groups) {
		b.WriteString("  # Group referenced by an aboard.groups label (bound, not gated here).\n")
		b.WriteString("  - model: " + modelGroup + "\n")
		b.WriteString("    identifiers:\n")
		b.WriteString("      name: " + quote(g) + "\n")
		b.WriteString("    attrs:\n")
		b.WriteString("      name: " + quote(g) + "\n")
	}

	scopeDisplay := "aboard groups scope (" + groupsScope + ")"
	b.WriteString("  # The OIDC groups scope mapping: delivers group membership in tokens.\n")
	b.WriteString("  - model: " + modelScopeMapping + "\n")
	b.WriteString("    identifiers:\n")
	b.WriteString("      name: " + quote(scopeDisplay) + "\n")
	b.WriteString("    attrs:\n")
	b.WriteString("      name: " + quote(scopeDisplay) + "\n")
	b.WriteString("      scope_name: " + quote(groupsScope) + "\n")
	b.WriteString("      expression: |-\n")
	b.WriteString("        " + GroupsExpression + "\n")

	return b.String()
}

// dedupeSorted returns the distinct, non-empty, whitespace-trimmed names in
// groups, sorted, so a re-render of the same fleet emits byte-identical output.
func dedupeSorted(groups []string) []string {
	seen := make(map[string]bool, len(groups))
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// quote renders s as a YAML double-quoted scalar. strconv.Quote's Go escaping is
// a subset of YAML's double-quoted escaping (\" \\ \n and the like), so it is
// safe for the freeform group and scope names an operator may have chosen,
// including one that would otherwise need quoting.
func quote(s string) string {
	return strconv.Quote(s)
}
