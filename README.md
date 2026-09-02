# Aboard

Label-driven single sign-on for Authentik. Aboard watches the Docker socket,
reads `aboard.*` labels off a container, and reconciles the matching state
inside Authentik over Authentik's REST API: the Application, the Provider, the
group and policy bindings, and, for forward-auth, the embedded-outpost
attachment. Protecting a service becomes adding a couple of labels next to the
service in its compose file, instead of clicking through the Authentik UI per
app.

Aboard drives Authentik. It never rebuilds the IdP, and it never writes Traefik
config. Its stance is "reconcile the IdP, audit the proxy": it configures
Authentik, then reads the container's own Traefik forward-auth labels to confirm
the proxy half is wired, and raises a sticky alert on a gap rather than papering
over one. A label names a secret, it never carries one.

Status: beta (`v00.01.00b1`). The label grammar, the three provider types, the
CLI, group-claim delivery, and the Traefik audit are built and proven end to end
against a live Authentik. See [Status](#status).

## The idea

Add one label to a service and it joins the fleet's login:

```yaml
services:
  whoami:
    image: traefik/whoami
    labels:
      traefik.enable: "true"
      traefik.http.routers.whoami.rule: "Host(`whoami.example.com`)"
      traefik.http.routers.whoami.entrypoints: "websecure"
      traefik.http.routers.whoami.tls.certresolver: "cloudflare"
      traefik.http.routers.whoami.middlewares: "authentik@docker"
      aboard.enable: "true"
```

That is the whole minimum for the common case. The host is inferred from the
single Traefik router (`whoami.example.com`), the slug and title are `whoami`,
aboard creates an Application named `whoami` and a proxy provider named
`whoami (aboard)` in `forward_single` mode, binds the fleet default groups from
`aboard.yml`, and attaches the provider to the embedded outpost last, after the
bindings, so the app never goes live open. The verifier confirms the router
carries the forward-auth middleware. Delete that middleware line and the next
reconcile raises a sticky alert naming the unprotected router.

Everything past the single label (a title, a group gate, a different provider
type, unauthenticated paths) is optional and set through more `aboard.*` labels.
The full label reference is in [docs/LABELS.md](docs/LABELS.md).

## Provider types

One label, `aboard.provider`, selects the Authentik provider. All three are
built and proven:

- `forwardauth` (the default): an Authentik proxy provider in `forward_single`
  mode, attached to an outpost, for the per-app forward-auth pattern behind
  Traefik. This is the case the hero example above covers.
- `oidc`: an Authentik OAuth2 and OpenID provider, for apps that speak OIDC
  themselves (Gitea, Vikunja, Headscale). Confidential by default, its client
  secret named by label and pushed inward, never read back. Public clients are
  supported and forbid a secret.
- `saml`: an Authentik SAML provider, for apps that speak SAML themselves. Like
  OIDC it is server-served, so there is no outpost attach, no Traefik
  middleware, and no client secret. Aboard drives the Authentik side and
  surfaces the IdP metadata URL for you to hand to the SP.

## Group delivery

Aboard delivers a user's Authentik group membership to the protected app so the
app can do its own role mapping. This is on by default, opted out per container
with `aboard.groups.claim=false`. The mechanism differs by provider type: for
OIDC aboard attaches a groups scope mapping by name, for SAML the managed Groups
mapping already ships, and for forward-auth groups ride the shared middleware's
`X-authentik-groups` header, which aboard verifies rather than mutates. The
groups and the OIDC scope mapping are fleet-level identity objects aboard
references by name but never creates. Define them as IaC with
`aboard render --blueprint`. See [docs/BLUEPRINTS.md](docs/BLUEPRINTS.md).

## Quickstart

Aboard runs as one container, alongside the services it enrolls. It needs the
Docker socket (read-only) to discover and inspect them, the `aboard.yml` that
holds the fleet config, and a secrets directory that its API token resolves
from:

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

`aboard.yml` holds structure, not secrets, so it is safe to commit. The minimum
is the internal Authentik endpoint and the NAME of the API token:

```yaml
authentik:
  url: http://authentik-server:9000        # the INTERNAL endpoint, never the public URL
  public_url: https://auth.example.org     # for discovery URLs in render output only
  token: aboard-api-token                  # a secret NAME, resolved from a file, never a value
```

`authentik.url` is the internal endpoint because the public URL is
Cloudflare-blocked for programmatic calls. The token is a secret name that
resolves from a file under `/run/aboard/secrets` at runtime, delivered by berm.

The service account the token belongs to, and the full config, are in
[docs/DEPLOY.md](docs/DEPLOY.md). A ready-to-edit `aboard.yml` is
[aboard.example.yml](aboard.example.yml).

## Verify it worked

Two commands confirm the fleet's labels are sound and Authentik reflects them,
without waiting for a reconcile pass:

```
aboard validate
```

reads every container's `aboard.*` labels, validates them exactly as the
daemon's discovery pass does, and prints every error and warning grouped by
container. It makes no call to Authentik and writes nothing, so it works as a
pre-deploy CI gate. Exit status is nonzero if any container has an error.

```
aboard status
```

reports what aboard sees right now: the enabled containers and the Authentik
applications they map to, the sticky findings from a fresh label and Traefik
audit, and the orphan set (owned objects with no enabled container). It reads
Authentik but never writes. Orphaned OIDC providers, which are live
credentials, are listed first.

Beyond the two commands, confirm in Authentik that the Application appears with
a provider named `<slug> (aboard)`, that a forward-auth provider is attached to
the embedded outpost, and that an OIDC app's discovery URL (printed by
`aboard render <service>`) resolves.

## Secrets

Aboard holds two secret-shaped things and neither ever appears in a label or in
`aboard.yml`: the Authentik API token (the crown jewel) and, for a confidential
OIDC app, the client secret. Both are named, not carried. A name resolves
file-first from `$ABOARD_SECRETS_DIR/<name>` (default `/run/aboard/secrets`),
then from `ABOARD_SECRET_<NAME>`. The resolved OIDC secret is pushed INTO
Authentik on every reconcile and never read back, logged, or written to a file
aboard controls.

berm is the recommended deliverer: it holds the age key, decrypts the sources,
and lands aboard's API token and any OIDC client secret as files in aboard's
container. Aboard consumes them from a path and holds no key of its own. SOPS
straight into the secrets directory at deploy time is the manual path. Both are
walked through in [docs/DEPLOY.md](docs/DEPLOY.md).

## Documentation

- [docs/LABELS.md](docs/LABELS.md): every `aboard.*` label, the `tagwright.auth.*`
  alias, the conflict and unknown-suffix rules, and worked compose examples per
  provider type.
- [docs/DEPLOY.md](docs/DEPLOY.md): the compose deploy, the annotated
  `aboard.yml`, the secrets model, and the dedicated Authentik service account
  with its minimal role.
- [docs/BLUEPRINTS.md](docs/BLUEPRINTS.md): the group-claim IaC, the groups and
  the OIDC groups scope mapping aboard references but never creates.
- [docs/TESTING.md](docs/TESTING.md): what is proven live, what is unit-only,
  and the honest coverage matrix.

## Build and run

Aboard builds in a `golang:1.25` container. The suite dependencies
(`github.com/tagwright/core`, `github.com/tagwright/beacon`) are fetched over
HTTPS, so set `GOPRIVATE` for the org:

```sh
docker run --rm -v "$PWD":/work -w /work \
  -e GOPRIVATE='github.com/tagwright/*' \
  golang:1.25 sh -c 'go build -buildvcs=false -o aboard ./cmd/aboard && ./aboard version'
```

That prints the current version:

```
aboard 00.01.00b1
```

The version string lives in the `VERSION` file and in `internal/version`, and
follows the suite's beta scheme, `v00.01.00bN`. Released images are published to
`ghcr.io/tagwright/aboard` when a `v*` tag is pushed.

## Suite

Aboard is a tagwright tool. It shares the runtime abstraction in
`github.com/tagwright/core` and the notifier in `github.com/tagwright/beacon`
with the rest of the suite, and it is designed to pair with berm, the secrets
tool: berm delivers aboard's Authentik API token and any OIDC client secret into
the container as files, and aboard consumes them from a path, holding no key of
its own.

The shipped binary wires the Docker runtime, at `/var/run/docker.sock`. The
daemon's runtime seam is the shared suite one, which also has a Podman
implementation, but the current CLI constructs the Docker runtime only.

## Status

Aboard is built and running. Discovery, the Authentik REST reconcile
(Application, all three provider types, group and policy bindings, the outpost
attach), the Traefik forward-auth audit, group-claim delivery, adoption of
pre-existing objects, the orphan and prune model, and the CLI (`daemon`,
`validate`, `status`, `prune`, `render`, `version`) all work end to end, proven
against a live Authentik. What to keep in mind:

- The shipped CLI wires the Docker runtime only. The runtime seam is
  Podman-capable in `core`, but nothing in aboard selects it yet.
- Removal keeps objects as orphans (the `keep` behavior). `detach` and `delete`
  on removal are reserved, not built.

Pin a version if you build on it. The label grammar can still change before a
1.0.

## License

GPL-3.0-or-later. You can run it, charge for it, and modify it. If you
distribute a modified version, it stays open under the same license. Each source
file carries an `SPDX-License-Identifier: GPL-3.0-or-later` header. See
[LICENSE](LICENSE).
</content>
</invoke>
