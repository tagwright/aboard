# Deploy

Aboard runs as one container alongside the services it enrolls. This guide
covers the compose deploy, the `aboard.yml` config, the secrets model, and the
dedicated Authentik service account the API token belongs to.

## The container

Aboard needs three mounts: the Docker socket (read-only) to discover and inspect
containers, the `aboard.yml` config, and the secrets directory its API token
resolves from. Aboard reads the socket, it never writes it.

```yaml
services:
  aboard:
    image: ghcr.io/tagwright/aboard:latest
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./aboard.yml:/etc/aboard/aboard.yml:ro
      - /run/aboard/secrets:/run/aboard/secrets:ro
    # aboard's image runs as a distroless NONROOT uid (65532), which is not in
    # the host docker group, so it cannot read /var/run/docker.sock (root:docker,
    # mode 660) on its own. Add the HOST docker group by gid so it can. The gid
    # is host-specific: find yours with `stat -c %g /var/run/docker.sock` and
    # replace the value below.
    group_add:
      - "139"
    command: ["daemon", "--config", "/etc/aboard/aboard.yml"]
```

The `group_add` line is not optional on a nonroot deploy. aboard runs as uid
65532 with no host group membership, and the Docker socket is owned
`root:docker` mode 660, so without the host docker gid added the daemon cannot
open the socket and exits. The gid is host-specific: read it with
`stat -c %g /var/run/docker.sock` and use that number. Root deployments do not
need it, but the shipped image is nonroot by design, so keep this line.

The image's entrypoint is `aboard` and its default command is `daemon`, so the
explicit `command` above is only spelling out the config path. Aboard must be
able to reach the Authentik server over the container network, so run it on the
same Docker network as authentik-server (or one that routes to it).

The socket path is `/var/run/docker.sock`, fixed. The shipped binary wires the
Docker runtime only. The daemon's runtime seam is the shared suite one, which
has a Podman implementation too, but the current CLI does not select it.

Aboard never enrolls the Authentik containers or its own container, so it is
safe to run in the same compose project as authentik.

## aboard.yml

`aboard.yml` holds structure, not secrets, so it is safe to commit. Every
credential in it is a NAME, resolved at runtime from a file, never a value. A
minimal file is the Authentik endpoint and the token name. Everything else has a
fleet default. The annotated full file is [aboard.example.yml](../aboard.example.yml).

```yaml
authentik:
  # The INTERNAL Authentik endpoint. See "Why the internal endpoint" below.
  url: http://authentik-server:9000
  # Used ONLY to compose discovery and metadata URLs in `aboard render` output.
  public_url: https://auth.example.org
  # Secret NAME of aboard's Authentik API token, resolved from a file at runtime.
  # This is a name, never the token value.
  token: aboard-api-token

# Fleet default flows every reconcile starts from. A per-container aboard.flow
# overrides the authorization flow. These are Authentik's built-in defaults.
flows:
  authorization: default-provider-authorization-implicit-consent
  invalidation: default-provider-invalidation-flow

# Fleet default outpost a forward-auth provider attaches to. `embedded` is
# Authentik's built-in embedded outpost. Aboard NEVER creates outposts.
outpost: embedded

oidc:
  # Certificate NAME of the OIDC signing key, not a secret. Defaults to
  # Authentik's own self-signed pair.
  signing_key: authentik Self-signed Certificate
  # NAME of the OAuth2 groups scope mapping aboard attaches for group-claim.
  # Referenced by name, never created. Define it with `aboard render --blueprint`.
  groups_scope: groups

saml:
  # Certificate NAME of the SAML signing key, not a secret. Same default as OIDC.
  signing_key: authentik Self-signed Certificate

# Proxy integration switch, mirrors ABOARD_PROXY. `traefik` runs the verify-and-
# render audit, `none` turns it off for a Caddy or nginx fleet (which then writes
# aboard.host explicitly on each container).
proxy: traefik

traefik:
  # The one shared forward-auth middleware name, defined once for the whole
  # fleet. There is deliberately no per-container override.
  middleware: authentik@docker
  # The fleet's Traefik major version. v2 and v3 spell HostRegexp differently,
  # so `aboard render` targets this major.
  version: 3

defaults:
  # Fleet default group list bound to every enrolled Application. Any
  # aboard.groups label REPLACES this wholesale. The listed groups must exist.
  groups: [public-users]
```

Only `authentik.url` and `authentik.token` are truly required, plus a valid
`proxy` (`traefik` or `none`) and, under `traefik`, a `version` of `2` or `3`.
Everything else falls back to the defaults shown.

### Globals

A small set of `ABOARD_*` environment variables on the aboard container tune
behavior. They are env, not `aboard.yml` fields:

- `ABOARD_SECRETS_DIR`: root under which named secret refs resolve file-first.
  Default `/run/aboard/secrets`.
- `ABOARD_CREATE_GROUPS`: set to `true` to opt into creating a missing group
  (empty) and alerting. Default off, so a missing group is a validation error.
- `ABOARD_PROXY`: mirrors `proxy:` in `aboard.yml`. When set it overlays the
  file value.
- `ABOARD_DIGEST_SCHEDULE`: the daily beacon digest cadence. Default `daily`.

Only the literal string `true` opts a boolean global in. Anything else,
including a typo, is `false`, because a security tool must not widen its write
footprint on a malformed value.

### Why the internal endpoint

`authentik.url` must be the internal endpoint (for example
`http://authentik-server:9000`), not the Cloudflare-fronted public URL. The
public URL is blocked for programmatic calls, so aboard would never reach the
API through it. `authentik.public_url` is used ONLY to compose the discovery and
SAML metadata URLs that `aboard render` prints for you, never for an API call.

## Secrets

Aboard holds two secret-shaped things and neither ever appears in a label or in
`aboard.yml`:

- the Authentik API token (the crown jewel), named by `authentik.token`, and
- for a confidential OIDC app, the client secret, named by `aboard.oidc.secret`.

Both are NAMES. A name resolves file-first from `$ABOARD_SECRETS_DIR/<name>`
(default `/run/aboard/secrets/<name>`), then falls back to the environment
variable `ABOARD_SECRET_<NAME>` (the name uppercased, `-` to `_`). Whichever
source supplies it, the value is trimmed the same way, so a file with a trailing
newline and an env var without one resolve identically. The resolved OIDC secret
is pushed INTO Authentik on every reconcile and never read back, logged, or
written to a file aboard controls. Aboard validates a resolved OIDC secret is at
least 32 characters before pushing it.

### berm (recommended)

berm is the recommended deliverer. It holds the age key, decrypts your
SOPS/age-encrypted sources, and lands aboard's API token and any OIDC client
secret as files in aboard's container, one file per secret name. Aboard then
consumes them from the path like the rest of the fleet, holding no key of its
own. This is the composition the suite is built for: berm owns the crypto and
delivery, aboard owns the reconcile, and no secret value ever crosses a log or a
terminal. See the berm docs for its labels.

### SOPS (manual path)

Without berm, decrypt secrets into the mounted directory at deploy time. A small
init step run before `aboard daemon` writes one file per secret name:

```sh
#!/bin/sh
set -eu
mkdir -p /run/aboard/secrets
sops -d aboard-secrets.sops.env | while IFS='=' read -r name value; do
  [ -n "$name" ] || continue
  printf '%s' "$value" > "/run/aboard/secrets/$name"
  chmod 600 "/run/aboard/secrets/$name"
done
```

Each key on the left is a secret NAME, the same name `authentik.token` or an
`aboard.oidc.secret` label references, never the value itself. The age private
key needs to be available only where this decrypt step runs, never inside
aboard's own container. Aboard never reads a `.sops` file and never runs `sops`
itself: by the time it starts, the directory holds plaintext files named after
each secret.

A secret value NEVER goes in a label or in `aboard.yml`, where `docker inspect`
or a committed file would expose it.

## The Authentik service account

Aboard authenticates to the Authentik API with a bearer token. Give it a
DEDICATED service account, not `akadmin` and not a person's admin login. A
dedicated account keeps aboard's writes attributable in the Authentik audit log
and lets you rotate or revoke aboard's access without touching anyone else.

1. In Authentik, create a Service Account (Directory then Users, create with
   type "Service account"), for example named `aboard`.
2. Create an app token for it (the account's Tokens, an "API Token"), and store
   the token value in your secret store under the name `aboard.token` references
   (for example `aboard-api-token`). It reaches aboard's container as a file,
   through berm or the SOPS init step above. The token value never goes in
   `aboard.yml`.
3. Create an RBAC role (for example `aboard`) carrying the permissions in the
   tables below, assign those permissions to the role globally, and bind the role
   to the service account through a group. Do NOT enable "Is superuser" on the
   account or its group.

### Generate it as a blueprint (recommended)

Rather than click all of that in by hand, let aboard emit the whole least-
privilege identity as an Authentik blueprint:

```
aboard render --service-account
```

It prints a ready-to-apply blueprint declaring the service-account user (a
non-superuser `service_account`), an RBAC role carrying EXACTLY the permission
set in the tables below (including the easily-missed base `view_provider`), the
group that binds the role to the user, and an intent=api token for the account.
The blueprint carries NO token key: Authentik generates the key at reconcile, and
you retrieve it from the UI afterward. The token's Authentik identifier defaults
to your `aboard.yml` `authentik.token` NAME so the emitted object and the secret
aboard reads line up. As with every `render` subcommand aboard writes nothing:
save the output where your Authentik worker reconciles blueprints (the same IaC
path as `render --blueprint`, see [BLUEPRINTS.md](BLUEPRINTS.md)).

Four-step onboarding, in order:

1. **Apply the service-account blueprint.** Save `aboard render --service-account`
   output into your Authentik blueprints directory and recreate
   authentik-server + authentik-worker (or let the worker reconcile it). This
   creates the account, role, group binding, and the token OBJECT.
2. **Provision the token.** In the Authentik UI open the token (Directory then
   Tokens, or the service account's Tokens tab), copy its key, and store it in
   your secret store under the name `authentik.token` references (for example
   `aboard-api-token`), via berm or the SOPS init step above. The key never goes
   in `aboard.yml` or the blueprint.
3. **Run the compose.** Bring up aboard's container (see [The container](#the-container)),
   with the secret mounted so the token resolves by NAME at runtime.
4. **Add a label.** Put `aboard.enable=true` (and `aboard.host=...` for a proxy
   app) on a container and let the daemon reconcile it. `aboard validate` and
   `aboard status` confirm the fleet.

### What the token must be allowed to do

The aboard service account is a DEDICATED non-superuser service account. It does
NOT need superuser, and you should not grant it superuser. Assign it the
fine-grained RBAC role below (globally, through a group, which is how Authentik
binds a role to a service account), and nothing more. The whole role is proven
end to end against a live Authentik on a scoped token: aboard enumerates every
application it owns, including ones whose access policy the service account's own
user cannot pass, and reconciles, detects orphans, and prunes without a superuser
flag.

How this works without superuser, and the one gotcha to know:

- Aboard reads a single application by its slug through the DETAIL route
  `GET /core/applications/{slug}/`, which gates on the global `view_application`
  permission and is NOT access-filtered. The application LIST endpoint, by
  contrast, runs the access policy for the token's own user and silently drops
  applications it may not launch (only a superuser's `superuser_full_list=true`
  overrides that), so aboard does not use it for existence checks. A non-superuser
  token therefore still sees an application it manages but is not itself a member
  of, which is what stops reconcile from creating a duplicate.

- Aboard enumerates its owned providers (for the orphan scan and `prune`) through
  the polymorphic `GET /providers/all/` list, which is not access-filtered
  either. GOTCHA: that viewset checks the BASE model permission
  `authentik_core.view_provider`, which the typed `view_proxyprovider` /
  `view_oauth2provider` / `view_samlprovider` permissions do NOT cover. Without
  the base `view_provider` the route returns 403 even with every typed provider
  read granted. The base `view_provider` is REQUIRED and is easy to miss, so
  grant it explicitly.

Read permissions (all global):

| Authentik permission | Why |
|---|---|
| `authentik_core.view_application` | Read an application by its slug detail route (existence and adoption). |
| `authentik_core.view_provider` | REQUIRED for `GET /providers/all/` (base model perm, which the typed `view_*provider` perms do not cover). The orphan scan and prune depend on it. |
| `authentik_providers_proxy.view_proxyprovider` | Look up the forward-auth provider by name. |
| `authentik_providers_oauth2.view_oauth2provider` | Look up the OIDC provider by name. |
| `authentik_providers_saml.view_samlprovider` | Look up the SAML provider by name and read its metadata. |
| `authentik_outposts.view_outpost` | Read the embedded outpost's providers list before the read-modify-write. |
| `authentik_policies.view_policybinding` | Read the existing bindings on an application for the strict binding pass. |
| `authentik_flows.view_flow` | Look up the authorization and invalidation flows by slug. |
| `authentik_crypto.view_certificatekeypair` | Look up the OIDC and SAML signing keys by name. |
| `authentik_core.view_group` | Read the groups your labels bind. |
| `authentik_core.view_propertymapping` | Look up the OIDC groups scope mapping by name. |
| `authentik_providers_oauth2.view_scopemapping` | REQUIRED for the OIDC scope-mapping lookup `GET /propertymappings/provider/scope/` (subclass model perm, which the base `view_propertymapping` does not cover). Without it OIDC enrollment's scope-mapping lookup returns 403. |
| `authentik_providers_saml.view_samlpropertymapping` | Look up the SAML attribute mappings by name. |

Write permissions (all global):

| Authentik permission | Why |
|---|---|
| `authentik_core.add_application`, `change_application` | Create and reconcile the Application. |
| `authentik_providers_proxy.add_proxyprovider`, `change_proxyprovider` | Create and reconcile the forward-auth provider. |
| `authentik_providers_oauth2.add_oauth2provider`, `change_oauth2provider` | Create and reconcile the OIDC provider. |
| `authentik_providers_saml.add_samlprovider`, `change_samlprovider` | Create and reconcile the SAML provider. |
| `authentik_outposts.change_outpost` | Attach and detach providers on the embedded outpost (PATCH). Aboard never creates or deletes an outpost. |
| `authentik_policies.add_policybinding`, `delete_policybinding` | Bind and unbind groups and policies on the Application. A binding is added or removed, never edited, so no `change`. |
| `authentik_core.add_group` | ONLY when `ABOARD_CREATE_GROUPS=true`. Create an empty group aboard is told to own. Never needed otherwise, and aboard never changes or deletes a group. |

Prune-only permissions (all global), needed ONLY if you run `aboard prune`:

| Authentik permission | Why |
|---|---|
| `authentik_core.delete_application` | Delete an orphaned Application. |
| `authentik_providers_proxy.delete_proxyprovider` | Delete an orphaned forward-auth provider. |
| `authentik_providers_oauth2.delete_oauth2provider` | Delete an orphaned OIDC provider. |
| `authentik_providers_saml.delete_samlprovider` | Delete an orphaned SAML provider. |

The daemon never deletes (the `keep`-on-removal default), so a reconcile-only
deployment can leave every `delete_*` permission off. If you run `prune` from a
separate operator context, grant the delete permissions to that context and keep
them off the daemon's own role.

A leaked scoped token can manage aboard-shaped SSO objects but is not a full-IdP
compromise: it cannot read or mint arbitrary tokens, edit flows or stages, or
grant superuser. That is the point of scoping it.

The identity-layer objects aboard references but never creates (the groups your
labels bind, and the OIDC groups scope mapping) are defined as IaC in an
Authentik blueprint, generated by `aboard render --blueprint`. See
[BLUEPRINTS.md](BLUEPRINTS.md).

## The Traefik fleet pieces

Under `proxy: traefik`, the fleet needs the shared forward-auth middleware
defined once, and (recommended) one catch-all callback router. Aboard writes
neither, it prints them:

```
aboard render --setup
```

Paste its output as labels on the traefik and authentik-server containers. With
the catch-all callback router present, no per-app callback router is needed for
any host under the fleet domain. Per-service pieces come from
`aboard render <service>`.

## Verify it worked

```
aboard validate
```

reads every container's `aboard.*` labels and validates them exactly as the
daemon's discovery pass does, printing errors and warnings grouped by container.
It makes no Authentik call and writes nothing, so it doubles as a pre-deploy CI
gate. Exit status is nonzero if any container has an error.

```
aboard status
```

reports the enabled containers and the Authentik applications they map to, the
sticky findings from a fresh label and Traefik audit, and the orphan set. It
reads Authentik but never writes. Orphaned OIDC providers (live credentials) are
listed first.

Then confirm in Authentik directly:

- the Application appears, with a provider named `<slug> (aboard)` (the
  ` (aboard)` suffix is the ownership marker),
- for a forward-auth app, that provider is attached to the embedded outpost,
- for an OIDC app, the discovery URL that `aboard render <service>` prints
  resolves,
- for a SAML app, the metadata URL `aboard render <service>` prints resolves,
  and you have handed it (and set the ACS URL and entity ID) on the SP.

## Teardown

Removing a container or its labels never deletes anything: the objects become
orphans, surfaced in `status` and the digest. `aboard prune` is the only delete
path. It prints what it would delete (orphaned OIDC providers first), asks for
confirmation, and only ever touches objects carrying the aboard ownership
marker. Use `--dry-run` to print the plan and stop, or `--yes` to skip the
prompt for automation.
</content>
