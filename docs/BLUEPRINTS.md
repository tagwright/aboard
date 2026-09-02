# Group-claim IaC: the Authentik blueprint

aboard delivers a user's Authentik **group membership** to a protected app so the
app can do its own role and permission mapping. This is on by default, opted out
per container with `aboard.groups.claim=false`.

Group-claim leans on two identity-layer objects that aboard references **by name**
but never creates, because groups and scope mappings are fleet-level identity
(IaC) objects, not per-app config:

- the **groups** your `aboard.groups` labels bind, and
- the **OIDC groups scope mapping** that puts group membership into tokens.

Define them as IaC in an Authentik **blueprint** the worker reconciles, the same
path the fleet's other blueprints travel. aboard then attaches the scope mapping
to each OIDC provider and binds the groups, never minting either itself. If the
groups scope mapping is missing when an OIDC app wants the claim, aboard raises a
loud `groups-scope-missing` error pointing back here, rather than silently
issuing tokens with no groups.

## Generate it

```
aboard render --blueprint
```

emits a ready-to-drop blueprint containing one `authentik_core.group` entry per
distinct group across the enabled fleet (the explicit labels plus the fleet
default `defaults.groups`), and the groups scope mapping. aboard writes nothing:
save the output into the directory your Authentik worker reconciles.

## Static snippet (copy-paste)

If you do not run `render`, this is the same IaC by hand. Replace the group
entries with your own, and keep `scope_name` matching `oidc.groups_scope` in
aboard.yml (default `groups`).

```yaml
version: 1
metadata:
  name: aboard group-claim
  labels:
    blueprints.goauthentik.io/instantiate: "true"
entries:
  # One entry per group your aboard.groups labels bind.
  - model: authentik_core.group
    identifiers:
      name: "public-users"
    attrs:
      name: "public-users"
  - model: authentik_core.group
    identifiers:
      name: "nutrition-users"
    attrs:
      name: "nutrition-users"

  # The OIDC groups scope mapping: delivers group membership in tokens.
  - model: authentik_providers_oauth2.scopemapping
    identifiers:
      name: "aboard groups scope (groups)"
    attrs:
      name: "aboard groups scope (groups)"
      scope_name: "groups"
      expression: |-
        return [group.name for group in request.user.ak_groups.all()]
```

The model names are exact for Authentik 2025.6.4: a directory group is
`authentik_core.group`, and an OIDC scope mapping is
`authentik_providers_oauth2.scopemapping`. The expression is Authentik's own
standard groups expression, so the mapping behaves identically to a
hand-written one.

## Per-provider behaviour

- **OIDC** is the real work: Authentik ships **no** groups scope mapping by
  default, so aboard attaches the one named above to every OIDC provider whose
  container wants the claim, alongside the always-present `openid`, `email`,
  `profile`.
- **SAML** needs nothing extra: aboard already attaches the managed default
  "authentik default SAML Mapping: Groups" to every SAML provider, so assertions
  carry groups out of the box.
- **forward-auth** delivers groups through the shared Traefik middleware's
  `X-authentik-groups` response header, not through anything on aboard's side.
  aboard **verifies and surfaces** this: if the middleware definition it can see
  drops that header, `aboard status` and the digest raise a `groups-header-missing`
  warning. aboard never edits Traefik. `aboard render --setup` shows the full
  `authResponseHeaders` set, including `X-authentik-groups`.
