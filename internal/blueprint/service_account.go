// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package blueprint

import "strings"

// The RBAC model names, verified against the live Authentik 2025.6.4 schema:
// authentik_core.user (a user, type internal_service_account for a passwordless
// API-only account), authentik_rbac.role (a role carrying global permissions in
// blueprint context via the attrs.permissions list), authentik_core.group (the
// Group is how Authentik binds a Role to a user, via Group.roles + Group.users),
// and authentik_core.token (an intent=api token whose key Authentik GENERATES at
// reconcile when no key value is supplied). A wrong model name would fail the
// whole reconcile, so these are checked against schema.yml, not guessed.
const (
	modelUser  = "authentik_core.user"
	modelRole  = "authentik_rbac.role"
	modelToken = "authentik_core.token"
)

// Fixed identity names for the aboard service account. The username and role are
// stable so a re-apply adopts the same objects; the token identifier defaults to
// the same name but is overridable so it can match the aboard.yml token: NAME.
const (
	ServiceAccountUsername = "aboard"
	ServiceAccountName     = "aboard service account"
	RoleName               = "aboard"
	BindingGroupName       = "aboard-service"
	DefaultTokenIdentifier = "aboard-api-token"
)

// readPermissions is aboard's minimal READ permission set, derived from the
// tool's real API calls (see docs/DEPLOY.md and the least-privilege
// investigation). Every one is a GLOBAL Django model permission codename in
// app_label.codename form, exactly as Authentik's blueprint role permissions
// list expects.
var readPermissions = []string{
	"authentik_core.view_application",
	// The base-model perm, REQUIRED for GET /providers/all/ (the polymorphic
	// provider viewset). The typed view_*provider perms below do NOT cover it.
	"authentik_core.view_provider",
	"authentik_providers_proxy.view_proxyprovider",
	"authentik_providers_oauth2.view_oauth2provider",
	"authentik_providers_saml.view_samlprovider",
	"authentik_outposts.view_outpost",
	"authentik_policies.view_policybinding",
	"authentik_flows.view_flow",
	"authentik_crypto.view_certificatekeypair",
	"authentik_core.view_group",
	"authentik_core.view_propertymapping",
	"authentik_providers_saml.view_samlpropertymapping",
}

// writePermissions is aboard's minimal WRITE permission set: create/change/delete
// the aboard-shaped SSO objects (applications and the three provider kinds),
// attach/detach on the embedded outpost, add/remove policy bindings, and add a
// group (only exercised when ABOARD_CREATE_GROUPS is set). A leaked token with
// exactly these perms can manage aboard-shaped objects but cannot mint arbitrary
// tokens, edit flows or stages, or grant superuser: it is not full-IdP
// compromise.
var writePermissions = []string{
	"authentik_core.add_application",
	"authentik_core.change_application",
	"authentik_core.delete_application",
	"authentik_providers_proxy.add_proxyprovider",
	"authentik_providers_proxy.change_proxyprovider",
	"authentik_providers_proxy.delete_proxyprovider",
	"authentik_providers_oauth2.add_oauth2provider",
	"authentik_providers_oauth2.change_oauth2provider",
	"authentik_providers_oauth2.delete_oauth2provider",
	"authentik_providers_saml.add_samlprovider",
	"authentik_providers_saml.change_samlprovider",
	"authentik_providers_saml.delete_samlprovider",
	"authentik_outposts.change_outpost",
	"authentik_policies.add_policybinding",
	"authentik_policies.delete_policybinding",
	"authentik_core.add_group",
}

// RequiredPermissions is the full flat set (reads then writes) the emitted role
// carries. Exposed so tests and callers can assert on the exact minimal set.
var RequiredPermissions = append(append([]string{}, readPermissions...), writePermissions...)

// RenderServiceAccount returns a ready-to-apply Authentik blueprint declaring
// aboard's least-privilege identity: the service-account user, the RBAC role
// carrying EXACTLY RequiredPermissions, a group binding the role to the user, and
// an intent=api token for the user. The token entry carries NO key value, so
// Authentik generates the key at reconcile: this output is pure string, contains
// no secret, and is byte-identical for a given tokenIdentifier. An empty
// tokenIdentifier falls back to DefaultTokenIdentifier.
func RenderServiceAccount(tokenIdentifier string) string {
	tokenIdentifier = strings.TrimSpace(tokenIdentifier)
	if tokenIdentifier == "" {
		tokenIdentifier = DefaultTokenIdentifier
	}

	var b strings.Builder

	b.WriteString("# aboard render --service-account: least-privilege Authentik identity for aboard.\n")
	b.WriteString("#\n")
	b.WriteString("# Drop this into the blueprints directory your Authentik worker reconciles. It\n")
	b.WriteString("# declares the identity aboard authenticates AS: a non-superuser service-account\n")
	b.WriteString("# user, an RBAC role carrying exactly aboard's minimal global permissions, the\n")
	b.WriteString("# group that binds the role to the user, and an intent=api token. aboard never\n")
	b.WriteString("# writes files: this is for you to save.\n")
	b.WriteString("#\n")
	b.WriteString("# Onboarding, in order:\n")
	b.WriteString("#   1. Apply this blueprint (recreate authentik-server + authentik-worker, or\n")
	b.WriteString("#      let the worker reconcile it). It creates the account, role, and token.\n")
	b.WriteString("#   2. In the Authentik UI, open the token \"" + tokenIdentifier + "\" and copy its key\n")
	b.WriteString("#      (Directory -> Tokens, or the service account's token). The KEY IS NOT IN\n")
	b.WriteString("#      THIS FILE: Authentik generates it at reconcile.\n")
	b.WriteString("#   3. Run your token-provisioning script to encrypt that key into aboard's\n")
	b.WriteString("#      secrets file. No agent sees the key: only you, at that step.\n")
	b.WriteString("#\n")
	b.WriteString("# NOTE: is_superuser is not set on the user. In Authentik superuser status comes\n")
	b.WriteString("# only from membership in a superuser group, so this account is non-superuser by\n")
	b.WriteString("# construction. Verify against your Authentik version if you have customized RBAC.\n")
	b.WriteString("version: 1\n")
	b.WriteString("metadata:\n")
	b.WriteString("  name: aboard service account\n")
	b.WriteString("  labels:\n")
	b.WriteString("    blueprints.goauthentik.io/instantiate: \"true\"\n")
	b.WriteString("entries:\n")

	// 1. The service-account user. Non-superuser, type service_account (a
	//    passwordless account whose only credential is the API token below).
	//    NOTE: type internal_service_account is deliberately NOT used: Authentik's
	//    user serializer refuses to create/modify that reserved type via a
	//    blueprint ("Can't modify internal service account users"), so
	//    service_account is the correct type for an operator-provisioned account.
	b.WriteString("  # 1. The service-account user aboard authenticates as. Non-superuser, type\n")
	b.WriteString("  #    service_account (passwordless: only the API token below logs in).\n")
	b.WriteString("  #    NOTE: type internal_service_account is reserved and serializer-blocked in\n")
	b.WriteString("  #    blueprints, so service_account is the correct operator-provisioned type.\n")
	b.WriteString("  - id: aboard-user\n")
	b.WriteString("    model: " + modelUser + "\n")
	b.WriteString("    state: present\n")
	b.WriteString("    identifiers:\n")
	b.WriteString("      username: " + quote(ServiceAccountUsername) + "\n")
	b.WriteString("    attrs:\n")
	b.WriteString("      name: " + quote(ServiceAccountName) + "\n")
	b.WriteString("      type: service_account\n")
	b.WriteString("      path: goauthentik.io/user/service-account\n")
	b.WriteString("      is_active: true\n")

	// 2. The RBAC role. attrs.permissions is Authentik's blueprint-context way of
	//    granting GLOBAL model permissions to a role.
	b.WriteString("  # 2. The RBAC role carrying EXACTLY aboard's minimal global permissions.\n")
	b.WriteString("  #    attrs.permissions grants global (model-level) permissions to the role.\n")
	b.WriteString("  - id: aboard-role\n")
	b.WriteString("    model: " + modelRole + "\n")
	b.WriteString("    state: present\n")
	b.WriteString("    identifiers:\n")
	b.WriteString("      name: " + quote(RoleName) + "\n")
	b.WriteString("    attrs:\n")
	b.WriteString("      name: " + quote(RoleName) + "\n")
	b.WriteString("      permissions:\n")
	b.WriteString("        # Reads.\n")
	for _, p := range readPermissions {
		b.WriteString("        - " + p + "\n")
	}
	b.WriteString("        # Writes.\n")
	for _, p := range writePermissions {
		b.WriteString("        - " + p + "\n")
	}

	// 3. The group binding the role to the user. Authentik grants a Role to a
	//    user through a Group (Group.roles), so this group carries the role and
	//    has the service account as its only member. NOT a superuser group.
	b.WriteString("  # 3. Bind the role to the account. Authentik grants a role to a user through a\n")
	b.WriteString("  #    group (Group.roles), so this group carries the role and has the service\n")
	b.WriteString("  #    account as its only member. is_superuser is false: not a superuser group.\n")
	b.WriteString("  - id: aboard-binding\n")
	b.WriteString("    model: " + modelGroup + "\n")
	b.WriteString("    state: present\n")
	b.WriteString("    identifiers:\n")
	b.WriteString("      name: " + quote(BindingGroupName) + "\n")
	b.WriteString("    attrs:\n")
	b.WriteString("      name: " + quote(BindingGroupName) + "\n")
	b.WriteString("      is_superuser: false\n")
	b.WriteString("      users:\n")
	b.WriteString("        - !KeyOf aboard-user\n")
	b.WriteString("      roles:\n")
	b.WriteString("        - !KeyOf aboard-role\n")

	// 4. The API token. intent: api (an app_password token is rejected for API
	//    calls). NO key value: Authentik GENERATES it at reconcile. Non-expiring.
	b.WriteString("  # 4. The API token for the service account. intent: api (an app_password token\n")
	b.WriteString("  #    is rejected for programmatic API calls). NO key value is set here, so\n")
	b.WriteString("  #    Authentik GENERATES the key at reconcile. Retrieve it from the UI (step 2\n")
	b.WriteString("  #    above). expiring: false keeps it long-lived for the daemon.\n")
	b.WriteString("  - id: aboard-token\n")
	b.WriteString("    model: " + modelToken + "\n")
	b.WriteString("    state: present\n")
	b.WriteString("    identifiers:\n")
	b.WriteString("      identifier: " + quote(tokenIdentifier) + "\n")
	b.WriteString("    attrs:\n")
	b.WriteString("      intent: api\n")
	b.WriteString("      user: !KeyOf aboard-user\n")
	b.WriteString("      description: aboard API token (key generated by Authentik at reconcile)\n")
	b.WriteString("      expiring: false\n")

	return b.String()
}
