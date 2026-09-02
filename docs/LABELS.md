# Labels

This is the authoritative `aboard.*` label reference, derived from the discovery
code. Every label is listed with its type, default, whether it is required, and
what it does. The frozen grammar behind it is the wiki page **Aboard Label
Grammar (Draft)**. Where this file and the grammar ever disagree, the code (and
so this file) wins.

All values are strings. Booleans are the literal strings `"true"` and `"false"`.
`none` and `all` are sentinels, used only where a table says so.

## Two prefixes, one grammar

Aboard reads two label prefixes:

- `aboard.*`, the primary, tool-branded form. All examples lead with it.
- `tagwright.auth.*`, the org-namespaced alias. Every suffix below exists
  identically under it, so `aboard.enable` and `tagwright.auth.enable` mean the
  same thing.

The reader strips whichever prefix matches and parses one canonical suffix
grammar. Labels under neither prefix are ignored.

The conflict rule (inherited from ballast, verbatim): the same suffix under both
prefixes with DIFFERENT values is a validation error, and the container is
skipped and alerted. The same value under both is harmless. There is no silent
precedence.

## Unknown suffixes are errors

A `aboard.*` suffix the grammar does not recognize is a validation error, not a
silently-ignored label. A mistyped `aboard.grops` fails loudly rather than
leaving an app open while its labels suggest a gate. Reserved suffixes
(`aboard.users`, `aboard.caddy.*`) are likewise errors in v1. This is the
security posture: a silently-absent access rule is exactly the failure this tool
must not have.

A validation error skips that one container and alerts through beacon. It never
breaks reconcile for the rest of the fleet. Declared-but-unarmed (any `aboard.*`
label present while `aboard.enable` is absent or `false`) draws a sticky warning
rather than an error, because a copied compose block that names a group but
never enables is an app that is not protected while its labels suggest it is.

## Core

| Label | Type | Default | Required | Description |
|---|---|---|---|---|
| `aboard.enable` | bool | absent | required | Opt the container in. Absent or `false` means inert. Other `aboard.*` labels without it draw a sticky warning. |
| `aboard.name` | string | compose service name, else container name | optional | Stable service identity. Keys the default slug and the alert identity, and is stable across a force-recreate. |
| `aboard.slug` | slug | sanitized `aboard.name` | optional | Authentik Application slug, the reconcile key. Must be `[a-z0-9-]` only, or it is a validation error. |
| `aboard.title` | string | service name verbatim | optional | Authentik Application display name, what users see in the library. No case-mangling. |
| `aboard.provider` | enum | `forwardauth` | optional | `forwardauth`, `oidc`, or `saml`. Any other value is a validation error. |
| `aboard.host` | hostname | inferred from Traefik router labels | required when uninferable | Bare public hostname, no scheme, path, or port. Aboard composes `https://`. Inferred only when exactly one distinct literal `Host()` exists across the container's Traefik routers. Not needed for `saml`. |
| `aboard.flow` | flow slug | `aboard.yml` `flows.authorization` | optional | Authorization flow override for this app. A nonexistent flow is a reconcile-time validation error. |
| `aboard.adopt` | bool | `false` | optional | Affirms taking ownership of a pre-existing Authentik object whose state differs from these labels. Inert once adopted. See [Adoption](#adoption). |

Service identity precedence for `aboard.name` when it is absent: the
`com.docker.compose.service` label, then the container name with any leading `/`
stripped.

Host must be a BARE hostname. A value with a scheme, a path, a port, or
whitespace is a validation error, because aboard composes `https://` in front of
it. Host inference reads the container's own `traefik.http.routers.*.rule`
labels: exactly one distinct literal `Host()` is used, and zero, more than one,
or any `HostRegexp`/`HostSNI` is an error telling you to set `aboard.host`.

## Access

| Label | Type | Default | Required | Description |
|---|---|---|---|---|
| `aboard.groups` | csv of group names, or `none` | `aboard.yml` `defaults.groups` | optional | Groups bound to the Application. Any label REPLACES the fleet default wholesale, it never merges. `none` declares no group gate (any authenticated user). A nonexistent group is a validation error unless `ABOARD_CREATE_GROUPS=true`. |
| `aboard.groups.claim` | bool | `true` | optional | Deliver the user's group membership to the app for its own role mapping. Default ON. `false` opts out. Any non-bool value is a validation error. |
| `aboard.policies` | csv of policy names | none | optional | Existing Authentik policies bound to the Application, by name. Never created. |
| `aboard.require` | enum | `any` | optional | `any` or `all`, the policy-engine bind mode across every binding. Any other value is a validation error. |

`aboard.groups` is three-state: absent means "use the fleet default", `none`
means "no group gate", and an explicit list replaces the fleet default. Bindings
on an aboard-owned Application are strictly owned: a group or policy binding
present in Authentik and absent from the labels is REMOVED on the next reconcile
and alerted, naming what was removed. That is what keeps the labels the truth
about who can enter.

Group GATING (who may enter) is distinct from group CLAIM (whether the app is
told which groups the entrant is in). `aboard.groups.claim` controls the latter,
and it is independent of the gate: an app open to any authenticated user can
still want the claim. Its mechanism differs by provider type, see
[docs/BLUEPRINTS.md](BLUEPRINTS.md):

- OIDC: aboard attaches the groups scope mapping named by `aboard.yml`
  `oidc.groups_scope` (default `groups`) alongside the always-present `openid`,
  `email`, `profile`. Aboard references it by name and never creates it. A
  missing one is a loud reconcile-time error.
- SAML: the managed default Groups mapping already ships, so nothing extra is
  attached.
- forward-auth: groups ride the shared middleware's `X-authentik-groups`
  response header. Aboard verifies the middleware carries it and warns if not,
  and never edits Traefik.

## Forward-auth (`aboard.provider=forwardauth`)

Every label in this section is a validation error under any other provider type.

| Label | Type | Default | Required | Description |
|---|---|---|---|---|
| `aboard.outpost` | outpost name | `aboard.yml` `outpost` (`embedded`) | optional | Existing outpost to attach the provider to. Aboard never creates outposts. A nonexistent outpost is a validation error. |
| `aboard.forwardauth.public` | csv of path regexes | none | optional | Unauthenticated paths on the provider (health checks, webhooks). Authentik's `skip_path_regex`. Use the indexed `.<n>` escape below for a value that itself contains commas. |
| `aboard.traefik.routers` | csv of router names | every host-matching router except a callback router | optional | Which of this container's Traefik routers must carry the forward-auth middleware. Names a deliberate public router by omission. An unknown router name is a validation error. Only under `proxy: traefik`. |

The whole `aboard.traefik.*` sub-namespace is a validation error under
`proxy: none` (a Caddy or nginx fleet), because there is no Traefik audit to
honor those labels.

## OIDC (`aboard.provider=oidc`)

Every label in this section is a validation error under any other provider type.

| Label | Type | Default | Required | Description |
|---|---|---|---|---|
| `aboard.oidc.redirect` | csv of absolute URLs | none | required | Redirect URIs, strict matching. Each must be an absolute URL. Use the indexed `.<n>` escape for a value with commas. |
| `aboard.oidc.secret` | secret ref | none | required when `client=confidential` | NAME of the client secret, resolved from `$ABOARD_SECRETS_DIR/<name>` then `ABOARD_SECRET_<NAME>`, and pushed INTO Authentik on every reconcile. Never read back, never logged. Minimum 32 characters, checked at reconcile time. |
| `aboard.oidc.id` | string | the slug | optional | Client id. Not a secret. |
| `aboard.oidc.client` | enum | `confidential` | optional | `confidential` or `public`. `public` FORBIDS `aboard.oidc.secret` (setting both is an error), and `confidential` REQUIRES it. Any other value is a validation error. |
| `aboard.oidc.scopes` | csv of scope names | none | optional | Extra scope mappings ADDED to the always-present `openid`, `email`, `profile`. |

The client secret is a NAME, never a value. Aboard resolves it, validates it is
at least 32 characters, and sets it on the provider on create and on every
reconcile, one direction only. Rotation is editing the secret in your own store
and recreating the container.

The redirect-URI gotcha, verbatim from the knowledge base: apps build their
callback URL from a provider name or an index, not from what you configured in
the IdP. Read the app's expected callback out of the app, and set
`aboard.oidc.redirect` to match it exactly.

## SAML (`aboard.provider=saml`)

Every label in this section is a validation error under any other provider type.
SAML is server-served: there is no outpost attach, no Traefik middleware, and no
client secret, so `aboard.host`, `aboard.outpost`, `aboard.traefik.*`, and
`aboard.oidc.*` are all skipped or rejected for a SAML container.

| Label | Type | Default | Required | Description |
|---|---|---|---|---|
| `aboard.saml.acs` | absolute URL | none | required | SP Assertion Consumer Service URL, the SAML analog of `aboard.oidc.redirect`. Must be absolute. |
| `aboard.saml.audience` | string | none | optional | SP audience restriction, commonly the SP entity ID. Optional at the API, but most SPs reject an assertion whose audience does not match, so set it. |
| `aboard.saml.issuer` | string | Authentik's default | optional | IdP issuer (EntityID) override. Empty means Authentik's own default. |
| `aboard.saml.binding` | enum | `post` | optional | `post` or `redirect`, the SP binding the provider responds with. Any other value is a validation error. |
| `aboard.saml.mappings` | csv of mapping names | none | optional | Extra SAML property mappings ADDED to the always-present managed default attribute mappings. |

Aboard surfaces the IdP metadata URL,
`<public_url>/application/saml/<slug>/metadata/`, in `aboard render <service>`
and `aboard status`. The ACS URL and entity ID still get configured on the SP by
hand. Audience and issuer are recorded verbatim and not URL-validated, since an
SP entity ID may be a URN rather than a URL.

## Library (cosmetic)

These follow declared-means-managed, absent-means-untouched, so a value you set
in the Authentik UI survives when the label is absent.

| Label | Type | Default | Required | Description |
|---|---|---|---|---|
| `aboard.launch` | URL, or `none` | untouched (Authentik derives it from the provider) | optional | Launch URL in the user library. `none` hides the app from the library. |
| `aboard.icon` | URL | untouched | optional | Library icon URL. |
| `aboard.description` | string | untouched | optional | Library description. |

## Reserved (validation errors in v1)

| Surface | Status |
|---|---|
| `aboard.users` (and `aboard.users.*`) | Reserved, per-user bindings. Rejected in v1. |
| `aboard.caddy.*` | Reserved for a future second proxy integration. Rejected in v1. |
| `ABOARD_ON_REMOVE=detach\|delete` | Reserved. `keep` is the only v1 behavior. |

## CSV and the indexed escape

A list label (`aboard.groups`, `aboard.policies`, `aboard.forwardauth.public`,
`aboard.oidc.redirect`, `aboard.oidc.scopes`, `aboard.saml.mappings`,
`aboard.traefik.routers`) is comma-separated, with surrounding whitespace
trimmed and empty elements dropped.

When a single value itself contains a comma, use the indexed escape instead of
the plain csv, available on the two fields whose values can legitimately carry a
comma:

```yaml
# Plain csv:
aboard.oidc.redirect: "https://a.example.com/cb,https://b.example.com/cb"

# Indexed escape, one literal value per key (each may contain commas):
aboard.oidc.redirect.0: "https://a.example.com/cb"
aboard.oidc.redirect.1: "https://b.example.com/cb"
```

The same applies to `aboard.forwardauth.public.<n>`. Setting BOTH the plain csv
form and the indexed form on the same field is a validation error, there is no
silent precedence. A non-integer index (`aboard.oidc.redirect.x`) is an error.

## Adoption

`aboard.enable=true` on a container whose slug already exists in Authentik (made
by hand or by an older script) triggers adoption:

- If reconciling the existing objects to these labels would change nothing
  except renaming the provider to carry the ` (aboard)` ownership marker, aboard
  adopts silently and alerts once, informationally.
- If reconciling would CHANGE anything material (title, engine mode, bindings),
  it is a sticky validation error naming the diff, and nothing is written until
  you add `aboard.adopt=true` to affirm the takeover.
- An existing object whose provider TYPE differs from the label (a hand-made
  OIDC provider where the label says `forwardauth`) is never adoptable, even
  with the affirmation. That is a replace, done deliberately in two steps.

## Removal

Removing a container, or removing its labels, never deletes or detaches anything
in Authentik. Aboard-owned objects with no matching enabled container become
ORPHANS, surfaced in `aboard status` and the daily digest, with orphaned OIDC
providers (live credentials) called out first. `aboard prune` is the only delete
path, a human act guarded by confirmation, and it only ever touches objects
carrying the aboard ownership marker.

## Worked examples

### Whole-host forward-auth (the minimum)

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

One aboard label. Host inferred, slug and title `whoami`, provider
`whoami (aboard)` in `forward_single`, bound to the fleet default groups,
attached to the embedded outpost last.

### Group-gated, explicit title

```yaml
services:
  nutrition:
    image: example/nutrition
    labels:
      traefik.enable: "true"
      traefik.http.routers.nutrition.rule: "Host(`nutrition.example.org`)"
      traefik.http.routers.nutrition.entrypoints: "websecure"
      traefik.http.routers.nutrition.tls.certresolver: "cloudflare"
      traefik.http.routers.nutrition.middlewares: "authentik@docker"
      aboard.enable: "true"
      aboard.title: "Nutrition"
      aboard.groups: "nutrition-users"
```

`nutrition-users` replaces the fleet default wholesale and must already exist. If
someone later binds another group in the UI, the next reconcile removes it and
alerts.

### Mixed host: public site, protected admin subpath

```yaml
services:
  travels:
    build: .
    labels:
      traefik.enable: "true"
      traefik.http.routers.travels.rule: "Host(`travels.example.org`)"
      traefik.http.routers.travels.entrypoints: "websecure"
      traefik.http.routers.travels.tls.certresolver: "cloudflare"
      traefik.http.routers.travels.service: "travels-svc"
      traefik.http.routers.travels.priority: "1"
      traefik.http.routers.travels-admin.rule: "Host(`travels.example.org`) && PathPrefix(`/admin`)"
      traefik.http.routers.travels-admin.entrypoints: "websecure"
      traefik.http.routers.travels-admin.tls.certresolver: "cloudflare"
      traefik.http.routers.travels-admin.middlewares: "authentik@docker"
      traefik.http.routers.travels-admin.service: "travels-svc"
      traefik.http.routers.travels-admin.priority: "10"
      traefik.http.services.travels-svc.loadbalancer.server.port: "5000"
      aboard.enable: "true"
      aboard.title: "Travels"
      aboard.traefik.routers: "travels-admin"
```

Two routers, one distinct host, so inference works. `aboard.traefik.routers`
names `travels-admin` as the protected router, marking the bare `travels` router
deliberate. The mixed-host rule then wants a callback router. If the fleet
catch-all from `aboard render --setup` is present on authentik-server it is
satisfied, otherwise `aboard render travels` prints the per-app callback block.

### OIDC, secret flows inward

```yaml
services:
  gitea:
    image: gitea/gitea
    labels:
      traefik.enable: "true"
      traefik.http.routers.gitea.rule: "Host(`git.example.org`)"
      traefik.http.routers.gitea.entrypoints: "websecure"
      traefik.http.routers.gitea.tls.certresolver: "cloudflare"
      aboard.enable: "true"
      aboard.provider: "oidc"
      aboard.title: "Gitea"
      aboard.oidc.redirect: "https://git.example.org/user/oauth2/authentik/callback"
      aboard.oidc.secret: "gitea-oidc-client-secret"
      aboard.groups: "public-users"
```

No middleware line, because OIDC has no proxy half. Provider `gitea (aboard)`,
client id `gitea`, confidential, with `openid`, `email`, `profile` and the
`groups` scope attached. The client secret named `gitea-oidc-client-secret` is
resolved from aboard's secret store (delivered by berm), pushed into Authentik,
and never read back. Setting `aboard.outpost` or `aboard.traefik.routers` here
would be a validation error.

### SAML, metadata flows outward

```yaml
services:
  kimai:
    image: kimai/kimai2
    labels:
      aboard.enable: "true"
      aboard.provider: "saml"
      aboard.title: "Kimai"
      aboard.saml.acs: "https://kimai.example.org/auth/saml/acs"
      aboard.saml.audience: "https://kimai.example.org"
      aboard.groups: "public-users"
```

No middleware line and no `aboard.host`, because SAML is server-served. Provider
`kimai (aboard)`, signed with the fleet SAML signing key, `post` binding, with
the managed default attribute mappings attached. `aboard render kimai` prints
the IdP metadata URL for you to feed to Kimai, plus the reminder that the ACS URL
and entity ID still get set on Kimai by hand.
</content>
