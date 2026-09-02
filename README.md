# Aboard

Label-driven single sign-on for Authentik. Aboard watches the Docker or Podman
socket, reads `aboard.*` labels on a container, and reconciles the matching
state inside Authentik over Authentik's REST API: the Application, the Provider,
the group and policy bindings, and the embedded-outpost attachment. Protecting a
service with SSO becomes adding a couple of labels next to the service, instead
of clicking through the Authentik UI per app.

Aboard drives Authentik. It never rebuilds the IdP, and it never writes Traefik
config. Its stance is "reconcile the IdP, audit the proxy": it configures
Authentik, then reads the container's own Traefik forward-auth labels to confirm
the proxy half is wired, and it alerts on a gap rather than papering over one.
A label names a secret, it never carries one.

v1 targets two provider types, selected with `aboard.provider`: `forwardauth`
(a Traefik forward-auth proxy provider, the default) and `oidc` (for apps that
speak OIDC themselves). The primary label namespace is `aboard.*`, with the
org-namespaced alias `tagwright.auth.*`.

## Status

Early development. This repository is the scaffold: a compiling CLI with a
`version` subcommand and nothing else. None of the reconcile, Authentik REST,
Traefik audit, or discovery logic is implemented yet.

The public label grammar is frozen, and the design is written down before the
code:

- Label grammar: the wiki page **Aboard Label Grammar (Draft)**.
- Architecture: the wiki page **Aboard Architecture**.

Those pages are the source of truth for the planned behavior. This README stays
deliberately narrow and describes only what the skeleton actually does, so
nothing here promises a flag or a label that does not exist yet.

## Build and run

There is no host Go toolchain here; aboard builds in a `golang:1.25` container.
The module's suite dependencies (`github.com/tagwright/core`,
`github.com/tagwright/beacon`) are fetched over HTTPS, so set `GOPRIVATE` for the
org:

```sh
docker run --rm -v "$PWD":/work -w /work \
  -e GOPRIVATE='github.com/tagwright/*' \
  golang:1.25 sh -c 'go build -o aboard ./cmd/aboard && ./aboard version'
```

That prints the current version:

```
aboard 00.01.00b1
```

The version string lives in the `VERSION` file and in
`internal/version`, and follows the suite's beta scheme, `v00.01.00bN`.

## Suite

Aboard is a tagwright tool. It shares the runtime abstraction in
`github.com/tagwright/core` and the notifier in `github.com/tagwright/beacon`
with the rest of the suite, and it is designed to pair with berm, the secrets
tool: berm delivers aboard's Authentik API token and any OIDC client secret into
the container as files, and aboard consumes them from a path, holding no key of
its own.

## License

GPL-3.0-or-later. You can run it, charge for it, and modify it. If you
distribute a modified version, it stays open under the same license. Each source
file carries an `SPDX-License-Identifier: GPL-3.0-or-later` header. See
[LICENSE](LICENSE).
