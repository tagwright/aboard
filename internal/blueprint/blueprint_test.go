// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package blueprint

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// blueprintDoc is the subset of the emitted blueprint the tests assert against,
// decoded from the output to prove it is well-formed YAML with the right shape.
type blueprintDoc struct {
	Version  int `yaml:"version"`
	Metadata struct {
		Name   string            `yaml:"name"`
		Labels map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Entries []struct {
		Model       string            `yaml:"model"`
		Identifiers map[string]string `yaml:"identifiers"`
		Attrs       map[string]string `yaml:"attrs"`
	} `yaml:"entries"`
}

func parse(t *testing.T, out string) blueprintDoc {
	t.Helper()
	var doc blueprintDoc
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("emitted blueprint is not well-formed YAML: %v\n---\n%s", err, out)
	}
	return doc
}

func TestRenderWellFormedAndComplete(t *testing.T) {
	// Duplicates and an empty entry must fold away; order must not matter.
	out := Render([]string{"staff", "admins", "staff", "  ", "admins"}, "groups")
	doc := parse(t, out)

	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if doc.Metadata.Labels["blueprints.goauthentik.io/instantiate"] != "true" {
		t.Errorf("missing the auto-instantiate label: %v", doc.Metadata.Labels)
	}

	var groupNames []string
	var scopeEntries int
	for _, e := range doc.Entries {
		switch e.Model {
		case modelGroup:
			groupNames = append(groupNames, e.Identifiers["name"])
			if e.Attrs["name"] != e.Identifiers["name"] {
				t.Errorf("group attrs.name %q != identifiers.name %q", e.Attrs["name"], e.Identifiers["name"])
			}
		case modelScopeMapping:
			scopeEntries++
			if e.Attrs["scope_name"] != "groups" {
				t.Errorf("scope_name = %q, want groups", e.Attrs["scope_name"])
			}
			if strings.TrimSpace(e.Attrs["expression"]) != GroupsExpression {
				t.Errorf("expression = %q, want %q", e.Attrs["expression"], GroupsExpression)
			}
		default:
			t.Errorf("unexpected model %q", e.Model)
		}
	}

	// One entry per DISTINCT non-empty group, sorted.
	if len(groupNames) != 2 || groupNames[0] != "admins" || groupNames[1] != "staff" {
		t.Errorf("group entries = %v, want [admins staff] deduped and sorted", groupNames)
	}
	if scopeEntries != 1 {
		t.Errorf("scope mapping entries = %d, want exactly 1", scopeEntries)
	}
}

func TestRenderCustomScopeName(t *testing.T) {
	out := Render(nil, "roles")
	doc := parse(t, out)

	// No groups: just the one scope mapping, carrying the custom scope name.
	if len(doc.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (the scope mapping only)", len(doc.Entries))
	}
	e := doc.Entries[0]
	if e.Model != modelScopeMapping || e.Attrs["scope_name"] != "roles" {
		t.Errorf("entry = %s scope_name=%q, want the scope mapping with scope_name roles", e.Model, e.Attrs["scope_name"])
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a := Render([]string{"b", "a"}, "groups")
	b := Render([]string{"a", "b"}, "groups")
	if a != b {
		t.Error("render must be byte-identical regardless of input order")
	}
}
