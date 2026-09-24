<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Security

Aboard configures an identity provider, so the two things worth being careful
about are the credential it authenticates with and the reach of what that
credential can change. This document states what aboard holds, what it does with
it, and where the boundary actually sits. Every claim here is checkable against
the code and the coverage matrix in [TESTING.md](TESTING.md).

## What aboard holds

Aboard drives Authentik over its REST API. To do that it resolves two
secret-shaped values, and neither ever appears in a label or in `aboard.yml`:

- the Authentik API token, which is the credential the daemon authenticates with
- for a confidential OIDC app, that app's client secret

Both are referenced by name. The value is resolved at runtime, file-first from
`$ABOARD_SECRETS_DIR/<name>` (default `/run/aboard/secrets`) and then from
`ABOARD_SECRET_<NAME>`. Aboard holds no key of its own and no datastore. There
is nothing on disk that aboard writes a secret into.

Secrets move one way. The API token is read to make API calls. A resolved OIDC
client secret is pushed into Authentik on every reconcile and never read back,
never logged, and never written to a file aboard controls. The resolver and the
error taxonomy around it name secrets by their name, never by their value, so a
missing or too-short secret surfaces as an alert on the owning container without
the value reaching a log line. The one length check aboard does run on an OIDC
secret (a 32-character floor before it is pushed into the IdP) reports the name
and the count, not the secret.

berm is the recommended deliverer: it holds the age key, decrypts the source,
and lands the token as a file in aboard's container. The manual path is SOPS
decrypting straight into the secrets directory at deploy time. Either way the
age key that opens the encrypted source lives with the deliverer, never inside
aboard.

## The token's blast radius

The API token is the crown jewel, so the honest question is what a leaked one
can do. That depends entirely on the role behind the token, and aboard ships the
role it actually needs rather than leaving you to grant more.

`aboard render --service-account` emits an Authentik blueprint that declares a
non-superuser service account, an RBAC role carrying exactly aboard's minimal
permission set, the group that binds the role to the account, and an `intent=api`
token whose key Authentik generates at reconcile. The permission set is derived
from the tool's real API calls: read on the application, provider, outpost,
policy-binding, flow, certificate, group, and property-mapping views it reads,
and write only on the aboard-shaped objects it manages (applications, the three
provider kinds, the outpost attach, policy bindings, and group creation when
`ABOARD_CREATE_GROUPS` is set).

A token scoped to exactly that role can manage aboard-shaped SSO objects. It
cannot mint arbitrary tokens, edit flows or stages, or grant superuser. The
account is non-superuser by construction, because in Authentik superuser status
comes only from membership in a superuser group and this one is not that. That is
the bound worth deploying against. It is a real reduction from full-IdP
compromise, not full-IdP compromise.

The rendered blueprint is pure string and contains no secret. Authentik
generates the token key at reconcile, and you retrieve it once from the UI to
provision it. No agent that renders the blueprint ever sees the key.

## The Docker socket

Aboard needs the container socket to discover and inspect the services it
enrolls. It reads and it inspects. It never creates, stops, signals, or execs a
container. There is no code path in aboard that mutates a container through the
socket, which is why the compose example mounts the socket read-only.

Read-only intent is not the same as harmless. Socket access lets aboard read
every container's full configuration, and the image runs with the host docker
group added so it can reach a `root:docker` socket at all. Treat access to that
socket as sensitive on its own terms. What aboard reads off a container is
structure and labels, which by design never carry a secret value, but the socket
still exposes the whole fleet's configuration to whatever holds it.

## What aboard does not defend against

**It configures one half of the login and audits the other.** Aboard reconciles
the Authentik side: the application, the provider, the bindings, and the outpost
attach, in that order, so a forward-auth app is bound before it is attached and
never goes live open. It does not write Traefik config. For a forward-auth app it
reads the container's own Traefik labels to confirm the middleware is wired, and
raises a sticky alert on a gap. That alert is a report, not a barrier. If the
forward-auth middleware is missing, the app is unprotected until an operator
fixes it. Aboard cannot itself keep a request out, because the enforcement lives
in Traefik and Authentik, not in aboard.

**It does not defend against the operator.** Whoever writes the compose files and
labels is the operator, and the operator can point aboard at any token and grant
that token any role. The least-privilege blueprint is a default that catches a
mistake, not a boundary against the person who controls the deployment. If you
hand aboard a superuser token, aboard will use a superuser token.

**It trusts the internal endpoint.** `authentik.url` is the internal Authentik
address because the public URL is Cloudflare-blocked for programmatic calls.
Aboard trusts that endpoint and the network path to it. It does no certificate
pinning of its own beyond what the Go HTTP client does.

## Rotation and recovery

- **Rotate the token by minting a new one.** Regenerate the service account's
  token in Authentik, re-provision the secret file (through berm or SOPS), and
  recreate the aboard container so it resolves the new value at start. The old
  token is revoked in Authentik, not in aboard.
- **The identity is reproducible.** The service account, its role, and its token
  are declared by the rendered blueprint, so a lost or rebuilt Authentik can
  re-create aboard's identity from that blueprint and a fresh token retrieval.
- **Orphans surface, they do not vanish.** `aboard status` lists owned objects
  that no longer have an enabled container, with orphaned OIDC providers (which
  are live credentials) listed first, so a removed service does not silently
  leave a working login behind.

## Reporting a vulnerability

Report a suspected vulnerability through GitHub's private vulnerability reporting
on this repository: open the Security tab and choose "Report a vulnerability".
That opens a private advisory visible only to the maintainers, which keeps the
report out of public issues while it is being worked. Fixes are coordinated
there, and public disclosure follows a fix rather than preceding it. The Security
tab is the channel for this.
