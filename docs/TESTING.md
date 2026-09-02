# Testing

aboard's test methodology and an honest accounting of what has actually been
proven against a real Authentik, as opposed to what merely compiles.

## How we test

Two layers, in increasing order of how much they prove:

1. **Unit tests, in-tree** (`go test ./...`, run in CI, `-buildvcs=false`,
   `GOPRIVATE=github.com/tagwright/*`). Pure-function and seam coverage: label
   discovery and the grammar's validation rules, the Traefik verifier's
   mixed-host callback logic, the config loader, the secret resolver, and the
   reconciler driven over an in-memory `fakeAPI` that records the exact ordered
   call sequence. The fake is what lets the ordering contract (bindings before
   the outpost attach) and every adoption branch be proven without a live
   Authentik. It is narrow by design: a fake can prove the reconcile *decisions*
   but not that aboard's REST calls match a real Authentik's actual behavior,
   which is exactly where every bug below hid.

2. **`test/integration/` harness, against a real Authentik.** This is where
   aboard is proven end to end: a DISPOSABLE Authentik (its own postgres, redis,
   server, worker, and bridge network, image `ghcr.io/goauthentik/server:2025.6.4`,
   the version this tool pins to) is brought up with a bootstrap token, the REAL
   `aboard` binary is driven against it over real REST, and every assertion is a
   query back to the disposable Authentik's REST API. Every object is prefixed
   `aboard-itest-*` and lives on its own compose project and network; it never
   touches the production Authentik, its postgres, or the shared proxy networks.

   The harness is a set of shell scripts, not Go, because the thing under test is
   the interaction between aboard and a real IdP, and the cheapest honest way to
   drive that is: create real labeled containers, run the real daemon boot pass,
   and `curl` the real REST API for the result.

   - `docker-compose.yml` — the disposable Authentik stack (self-contained, no
     host bind mounts of any production file).
   - `aboard.yml` — points at `http://aboard-itest-server:9000`, token by NAME.
   - `secrets/` — the throwaway API token and OIDC client-secret files
     (git-ignored; the token is a bootstrap throwaway for the ephemeral instance
     only).
   - `pass.sh` — runs ONE real `aboard daemon` boot reconcile pass against the
     disposable Authentik and dumps its log. `CREATE_GROUPS=true` sets
     `ABOARD_CREATE_GROUPS`.
   - `api.sh METHOD PATH [BODYFILE]` — a curl helper that runs inside
     `aboard-itest-net` (this host cannot route to the bridge IP directly, so
     both aboard and the assertions reach the server by its network name, exactly
     as a real deployment does).

### A network note

On this host the Docker bridge IP is not routable from the host namespace, so
the harness reaches the disposable Authentik by its container network name from
inside `aboard-itest-net` (aboard's container, and the curl assertion
containers, all join that network). This matches how aboard runs in production:
it calls the INTERNAL endpoint `http://authentik-server:9000` over the shared
network, never a routable host address and never the Cloudflare-fronted public
URL.

## What is PROVEN end-to-end

Each of these was driven with the real `aboard` binary against the real
2025.6.4 API and asserted by querying that API back.

1. **Forward-auth create.** A labeled `traefik/whoami` reconciles to an
   Application + a `<slug> (aboard)` ProxyProvider in `forward_single` mode with
   `external_host https://<host>`, ATTACHED to the embedded outpost's providers
   list. App, provider, mode, host, and outpost membership all confirmed. Re-run
   is idempotent (no duplicate, no spurious adopt).

2. **Attach-last, nothing live on a pre-attach failure** (must-verify item 2).
   Two independent proofs:
   - A forward-auth container naming a MISSING group with `ABOARD_CREATE_GROUPS`
     off errors at binding resolution (step a); NO provider and NO application
     are created and the outpost is untouched.
   - A forward-auth container naming a MISSING outpost succeeds through provider
     create, application create, and bindings, then FAILS at the attach: the
     provider and application exist but the provider is NOT in any outpost's
     providers list. This is the direct proof that the attach is last and that a
     failure before it leaves nothing live.

3. **OIDC.** A labeled `provider=oidc` container with a client-secret file
   reconciles to an OAuth2Provider with `client_id = slug`, `client_type
   confidential`, the client secret SET inward (length-validated, never logged),
   a signing key set, and the `openid`/`email`/`profile` managed scope mappings
   attached. The app's `.well-known/openid-configuration` is reachable on the
   disposable server and lists those three scopes.

4. **Group gating + STRICT binding ownership** (Fork 5). `aboard.groups` binds
   the named group to the Application (one binding, confirmed). A stray extra
   binding added directly via the API (simulating a UI edit) is REMOVED on the
   next reconcile, with the `binding-removed` warning naming what was removed;
   only the labeled binding remains.

5. **Missing group, both postures.** Errors `group-missing` by default;
   with `ABOARD_CREATE_GROUPS=true` creates the group empty, warns
   `group-created`, binds it (fail-closed), and attaches.

6. **Adoption** (Fork 9). A hand-made Application whose provider is named the
   production-script way (`<name> Provider`, not aboard-named) for a matching
   host is adopted: reconcile is a no-op beyond taking ownership, and it emits
   the informational `adopted` issue. See the empirical result below for how
   adoption takes ownership.

7. **launch=none.** `aboard.launch=none` sets `meta_launch_url = blank://blank`,
   which round-trips and is stored verbatim. Verified against the Authentik
   2025.6.4 docs shipped INSIDE the server image: `blank://blank` is the
   documented sentinel that hides an application from a user's *My applications*
   library page. The constant is correct for this version; no change needed.
   (The REST list still returns the app under `superuser_full_list`; hiding is a
   library-frontend behavior keyed on the `blank://blank` launch URL, not a REST
   filter.)

8. **Prune** (Fork 8 KEEP). Removing a labeled container leaves its aboard-owned
   objects as ORPHANS (the daemon deletes nothing on a die/destroy event);
   `aboard status` lists them with the OIDC orphan (live credentials) first.
   `aboard prune --yes` then deletes each orphan's Application + Provider,
   detaching a forward-auth provider from the outpost FIRST (confirmed: the
   provider's pk leaves the outpost's providers list). A hand-made, non-aboard
   object is NEVER touched by prune (confirmed: a hand-made app + provider with
   no ownership marker survives a prune untouched, because the app-based orphan
   scan never sees it).

9. **Whole-host callback mechanism** (must-verify item 1, lightweight form). The
   embedded outpost serves `/outpost.goauthentik.io/auth/traefik` for a live,
   attached, protected host, returning a correct 302-to-login for an
   unauthenticated request; `/outpost.goauthentik.io/ping` returns 204; an
   UNCONFIGURED host returns 404. This confirms the outpost serves the callback
   auth path for a protected host, which is what the verifier's mixed-host rule
   depends on.

10. **SAML.** A labeled `provider=saml` container (`aboard.saml.acs`,
   `aboard.saml.audience`, `aboard.groups`) reconciles to a `<slug> (aboard)`
   SAMLProvider with the ACS URL, `sp_binding post`, the resolved signing keypair,
   `sign_assertion true`, and the seven managed default attribute mappings
   attached, linked to an Application group-bound to the labeled group. The
   provider is NOT added to the embedded outpost's providers list (SAML is
   server-served, it has no outpost half), confirmed by reading the list back.
   `GET /api/v3/providers/saml/{pk}/metadata/` returns HTTP 200 and a valid
   `EntityDescriptor` IdP metadata document. A second reconcile is a clean no-op:
   the provider pk is stable, still one provider, one binding, `sticky=0`.

## The adoption empirical result (must-verify)

The architecture flagged that adoption's create-a-marked-provider-and-repoint
path briefly leaves TWO proxy providers with the SAME `external_host` attached to
the embedded outpost, and asked whether forward-auth still resolves.

**Measured result: it still resolves.** With two providers sharing
`external_host https://adopt1.itest.local` both attached to the embedded outpost,
`/outpost.goauthentik.io/auth/traefik` with that Host returns a correct
302-to-login (the outpost picks one provider deterministically); no error, no
ambiguity, no 500. So the duplicate does not BREAK resolution.

**But** the create-and-repoint approach was still changed, because it fails the
other half of the "leave it" condition: the old provider is not aboard-named and
no application points at it once the app is re-pointed, so aboard's app-based
orphan scan can never see it and `aboard prune` can never clean it. It lingers
attached to the outpost forever. Create-and-repoint also had a latent
type-change gap: it never inspected the hand-made provider's type, so a hand-made
OIDC provider under a `forwardauth` label would be silently type-changed.

Adoption now takes ownership by **renaming the existing provider in place**: a
single full-body PATCH on the provider the app already points at, which renames
it to `<slug> (aboard)` and pushes the desired shape in one call. This leaves
exactly one provider, no dangling orphan, and it is prunable and idempotent.
It also adds a by-pk provider-type lookup (`GET /api/v3/providers/all/{pk}/`,
which returns the `component` discriminator) so a hand-made provider of the wrong
type is refused as a type-change, closing the gap. Proven end-to-end: after
adoption there is ONE provider `adopt1 (aboard)`, the app points at it, the
outpost lists it once, forward-auth resolves, and a re-run is a clean no-op.

## Bugs found and fixed by this harness

Every one of these passed the unit suite and only surfaced against a real
Authentik.

- **List pagination never terminated.** Authentik 2025.6.4 returns
  `"next": 0` (not `null`) on the last page. `ListApplications` treated the
  non-nil `0` as "there is a page 0", requested it, and got `404 Invalid page.`
  This broke the orphan scan and `aboard prune` entirely. Fixed to stop when
  `next` is nil or does not name a page beyond the current one.

- **Ownership misread every proxy provider as OIDC.** In Authentik a
  ProxyProvider is a subclass of OAuth2Provider, so `/providers/oauth2/?search=`
  returns proxy providers too. `resolveOwnership` checked the oauth2 endpoint
  first and so classified every aboard forward-auth provider as OIDC, spuriously
  flagging a provider-type change on the second reconcile of any forward-auth
  app. Fixed to consult the type-accurate proxy endpoint first.

- **Applications were access-filtered out of the reconciler's view.** The
  applications LIST endpoint applies per-app policy filtering to the result set
  unless `superuser_full_list=true` is passed (the pagination count is computed
  before the filter, so count can exceed results). Without the flag,
  `GetApplicationBySlug` returned not-found for an application that exists but
  whose access policy the token's user does not pass, so aboard tried to CREATE a
  duplicate and got a 400 slug-conflict; the orphan scan silently missed filtered
  apps. This bites hardest under the architecture's intended minimal-role service
  account. Fixed by passing `superuser_full_list=true` on both application reads.

- **Adoption left an uncleanable duplicate provider** (and a name-only PATCH was
  rejected by Authentik's proxy validator). Reworked to the in-place rename
  described above.

- **SAML create was rejected for an unsigned response.** aboard always resolves a
  signing keypair for a SAML provider, and Authentik enforces that when a signing
  keypair is set at least one of `sign_assertion` / `sign_response` must be true.
  The first POST set `signing_kp` but neither flag (the request omitted them and
  the model default did not apply through the serializer), so Authentik returned a
  400 "With a signing keypair selected, at least one of 'Sign assertion' and
  'Sign Response' must be selected." Fixed by having the reconciler always send
  `sign_assertion true` (Authentik's own model default, and what SPs most commonly
  verify), a security-relevant field aboard now manages explicitly rather than
  leaving to a server default.

## What is PARTIAL

- **OIDC adoption in place** is covered by the reconciler's code path (symmetric
  with the proven forward-auth adoption) and unit tests, but the live end-to-end
  adoption proof above was run against a forward-auth provider, not an OIDC one.

- **Fleet catch-all callback detection** is unit-tested from labels; the live
  harness did not stand up a Traefik with a fleet catch-all router.

## RESIDUALS (need a real deployment to prove)

- **The live Traefik-in-the-loop forward-auth flow.** This harness proves aboard
  configures Authentik correctly and that the embedded outpost serves the
  callback auth path for a protected host (step 9). It does NOT stand up a real
  Traefik with the `authentik@docker` middleware in front of a real app and walk
  a browser through the redirect-login-callback loop. That end-to-end proof
  belongs to a real deployment; the Traefik verifier's correctness against a
  live fleet is the remaining unproven link.

- **Multi-page listings at fleet scale, and Podman** were not exercised here.
  SAML is now proven end-to-end (step 10); the one SAML-side residual is the same
  as OIDC's, that finishing the integration still needs the ACS URL and entity ID
  configured on the SP by hand, which lives outside Authentik and outside aboard.

## Running the harness

From `test/integration/`:

```
docker compose -p aboard-itest up -d          # bring up the disposable Authentik
# poll http://<server>:9000/api/v3/root/config/ with the bootstrap token until 200
# (from inside aboard-itest-net; boot takes 2-4 minutes)
CGO_ENABLED=0 go build -o aboard-bin ../../cmd/aboard   # build the binary (in a golang:1.25 container)
./pass.sh                                     # one real boot reconcile pass
./api.sh GET /api/v3/core/applications/?superuser_full_list=true   # assert against the API
docker compose -p aboard-itest down -v        # tear down everything
```

The unit suite is the fast gate; the integration harness is the honest one.
