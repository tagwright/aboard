// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package blueprint

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// saDoc decodes only the parts of the service-account blueprint that carry no
// custom YAML tags: version, metadata, and each entry's model. The attrs bodies
// hold !KeyOf tags, so they are deliberately NOT decoded into Go values (the
// struct omits an attrs field, so yaml.v3 skips those nodes). Structural
// well-formedness is proven separately by decoding into a yaml.Node.
type saDoc struct {
	Version  int `yaml:"version"`
	Metadata struct {
		Name   string            `yaml:"name"`
		Labels map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Entries []struct {
		ID    string `yaml:"id"`
		Model string `yaml:"model"`
		State string `yaml:"state"`
	} `yaml:"entries"`
}

func TestRenderServiceAccount_WellFormedAndComplete(t *testing.T) {
	out := RenderServiceAccount("aboard-api-token")

	// Structural: the whole document (including the !KeyOf-tagged nodes) parses.
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(out), &node); err != nil {
		t.Fatalf("emitted blueprint is not well-formed YAML: %v\n---\n%s", err, out)
	}

	var doc saDoc
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("could not decode version/metadata/models: %v\n---\n%s", err, out)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	if doc.Metadata.Labels["blueprints.goauthentik.io/instantiate"] != "true" {
		t.Errorf("missing the auto-instantiate label: %v", doc.Metadata.Labels)
	}

	// Exactly the four expected entries, in the model shape aboard needs.
	byID := map[string]string{}
	for _, e := range doc.Entries {
		byID[e.ID] = e.Model
	}
	for id, wantModel := range map[string]string{
		"aboard-user":    modelUser,
		"aboard-role":    modelRole,
		"aboard-binding": modelGroup,
		"aboard-token":   modelToken,
	} {
		if byID[id] != wantModel {
			t.Errorf("entry %q model = %q, want %q", id, byID[id], wantModel)
		}
	}
	if len(doc.Entries) != 4 {
		t.Errorf("entries = %d, want exactly 4 (user, role, binding, token)", len(doc.Entries))
	}
}

func TestRenderServiceAccount_NonSuperuserServiceAccount(t *testing.T) {
	out := RenderServiceAccount("aboard-api-token")

	// The user is a passwordless service account, and is never marked superuser
	// (superuser would come only from a superuser group, which this is
	// deliberately not). type internal_service_account is serializer-blocked in
	// blueprints, so service_account is the type that reconciles.
	if !strings.Contains(out, "type: service_account") {
		t.Errorf("service-account user must be type service_account, got:\n%s", out)
	}
	if strings.Contains(out, "type: internal_service_account") {
		t.Errorf("internal_service_account is serializer-blocked; must use service_account, got:\n%s", out)
	}
	if strings.Contains(out, "is_superuser: true") {
		t.Errorf("nothing in the blueprint may be superuser, got:\n%s", out)
	}
	// The binding group is explicitly not a superuser group.
	if !strings.Contains(out, "is_superuser: false") {
		t.Errorf("the binding group should be explicitly non-superuser, got:\n%s", out)
	}
}

func TestRenderServiceAccount_RoleCarriesExactlyRequiredPerms(t *testing.T) {
	out := RenderServiceAccount("aboard-api-token")

	// Every required permission is present...
	for _, p := range RequiredPermissions {
		if !strings.Contains(out, "        - "+p+"\n") {
			t.Errorf("role is missing required permission %q, got:\n%s", p, out)
		}
	}
	// ...including the base-model provider perm that /providers/all/ needs and
	// the typed view_*provider perms do NOT cover.
	if !strings.Contains(out, "        - authentik_core.view_provider\n") {
		t.Errorf("role must carry authentik_core.view_provider, got:\n%s", out)
	}
	// ...and the OIDC scope-mapping subclass perm, which the base
	// view_propertymapping does NOT cover and the OIDC scope-mapping lookup
	// (GET /propertymappings/provider/scope/) needs. Same base-vs-subclass
	// gotcha as view_provider.
	if !strings.Contains(out, "        - authentik_providers_oauth2.view_scopemapping\n") {
		t.Errorf("role must carry authentik_providers_oauth2.view_scopemapping, got:\n%s", out)
	}

	// ...and EXACTLY that set: count the permission list lines (six-space indent,
	// "- " prefix) and compare to the required count. Comment lines start with
	// "# ", not "- ", so they are not counted.
	var got int
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "        - authentik_") {
			got++
		}
	}
	if got != len(RequiredPermissions) {
		t.Errorf("role carries %d permissions, want exactly %d (the minimal set)", got, len(RequiredPermissions))
	}
}

func TestRenderServiceAccount_TokenIsIntentAPIWithNoKey(t *testing.T) {
	out := RenderServiceAccount("my-token-name")

	if !strings.Contains(out, "intent: api") {
		t.Errorf("token must be intent: api, got:\n%s", out)
	}
	if !strings.Contains(out, "identifier: \"my-token-name\"") {
		t.Errorf("token identifier should honour the argument, got:\n%s", out)
	}
	// The blueprint must NEVER carry a key value: Authentik generates it at
	// reconcile. Assert there is no key: field at the attrs indentation.
	if strings.Contains(out, "\n      key:") {
		t.Errorf("blueprint must contain NO token key value, got:\n%s", out)
	}
	// The token binds to the service-account user by reference.
	if !strings.Contains(out, "user: !KeyOf aboard-user") {
		t.Errorf("token must bind to the service account, got:\n%s", out)
	}
}

func TestRenderServiceAccount_DefaultsAndDeterministic(t *testing.T) {
	// Empty identifier falls back to the default.
	if !strings.Contains(RenderServiceAccount("  "), "identifier: \""+DefaultTokenIdentifier+"\"") {
		t.Errorf("empty token identifier must fall back to %q", DefaultTokenIdentifier)
	}
	// Byte-identical for the same input.
	if RenderServiceAccount("aboard-api-token") != RenderServiceAccount("aboard-api-token") {
		t.Error("render must be deterministic for a given token identifier")
	}
}
