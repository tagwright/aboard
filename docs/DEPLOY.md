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
    command: ["daemon", "--config", "/etc/aboard/aboard.yml"]
```

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

### What the token must be allowed to do

Aboard lists applications with `superuser_full_list=true`. On the live API that
flag is honored only for a superuser: without it the applications LIST endpoint
access-filters the result set for the token's own user, so a non-superuser token
cannot reliably see an application it manages but whose access policy its own
account does not pass. Aboard depends on seeing every application
deterministically, both to avoid creating a duplicate on reconcile and to detect
orphans for `prune`. So the aboard service account must currently be a
SUPERUSER: put it in a group with "Is superuser" enabled (a dedicated `aboard`
group is cleanest, so the grant is visible and revocable), and keep it a service
account with a single API token, nothing more.

That is the honest state of the tool today. The fine-grained permission set
below documents exactly which Authentik objects aboard actually touches, so you
know the real surface and can scope a role toward least privilege as the flag
requirement is lifted. It is the intended target, not yet a sufficient
standalone grant given the `superuser_full_list` behavior above.

| Authentik object | Permissions aboard uses | Notes |
|---|---|---|
| Application | view, add, change, delete | Create and reconcile the Application. Delete only via `aboard prune`. |
| Proxy provider | view, add, change, delete | The forward-auth provider. |
| OAuth2 provider | view, add, change, delete | The OIDC provider. |
| SAML provider | view, add, change, delete | The SAML provider, plus reading its metadata. |
| Outpost | view, change | Read-modify-write the outpost's providers list (PATCH). Aboard never creates or deletes an outpost. |
| Policy binding | view, add, delete | Bind and unbind groups and policies on the Application. No change (a binding is added or removed, never edited). |
| Group | view (add) | Read groups to bind. `add` only if `ABOARD_CREATE_GROUPS=true`. Never changed or deleted. |
| Flow | view | Look up the authorization and invalidation flows by slug. Read-only. |
| Certificate keypair | view | Look up the OIDC and SAML signing keys by name. Read-only. |
| Property mapping | view | Look up the OIDC groups scope and SAML attribute mappings by name. Read-only. Aboard never creates a mapping. |
| Policy | view | Look up a policy by name before binding it. Read-only. |

Delete on Application and the three provider types is exercised only by
`aboard prune`. The daemon never deletes (the `keep`-on-removal default), so if
you run `prune` from a separate operator context you can leave delete off the
daemon's own grant.

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
