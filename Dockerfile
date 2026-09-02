# SPDX-License-Identifier: GPL-3.0-or-later
#
# aboard daemon image. Multi-stage: a golang build stage compiles the single
# aboard binary CGO-free, a distroless static stage carries only that binary. The
# final image has no shell, no package manager, and no network tooling of its
# own.
#
# Build from the aboard repository root:
#
#   docker build -t ghcr.io/tagwright/aboard:dev .
#
# core and beacon are consumed as published modules (github.com/tagwright/core,
# github.com/tagwright/beacon). GOPRIVATE makes the build fetch tagwright's own
# modules directly from their source rather than through the public module proxy.
# go.sum still verifies their integrity. The build context is this one repo with
# no sibling module directories, the clean-room a committed local replace would
# fail: a stale replace pointing at ../core or ../beacon breaks the build here.
#
# aboard drives Authentik over its REST API and reads the container socket to
# watch and inspect the fleet. It is an ordinary API-driven daemon: it needs the
# container socket mounted read-only, but NOT --privileged and NOT host pid
# (unlike airlock, bathyscaphe, or berm). Runtime mounts the operator provides:
#
#   - the container socket, read-only, e.g. /var/run/docker.sock:/var/run/docker.sock:ro
#   - aboard.yml, e.g. ./aboard.yml:/etc/aboard/aboard.yml:ro
#   - the secrets dir (ABOARD_SECRETS_DIR, default /run/aboard/secrets), where
#     berm delivers the Authentik API token and any named OIDC client secrets

FROM golang:1.25 AS build

ENV GOPRIVATE=github.com/tagwright/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build CGO-free so the binary runs on distroless static, and stamp the version
# from the VERSION file into the shared version package so the binary's version
# output matches the release tag.
RUN VERSION="$(cat VERSION)" \
    && LDFLAGS="-s -w -X github.com/tagwright/aboard/internal/version.Version=${VERSION}" \
    && CGO_ENABLED=0 go build -buildvcs=false -ldflags "${LDFLAGS}" -o /out/aboard ./cmd/aboard

# Distroless static, the NONROOT variant (uid 65532): aboard talks to Authentik
# and reads the container socket over the Docker Engine API, neither of which
# needs uid 0 in the host pid namespace, so it runs unprivileged. ca-certificates
# ships in this base, which aboard needs for the deployments that reach Authentik
# over HTTPS (the default is the internal http endpoint). The image ships no
# shell, no package manager, and nothing that can open a network connection on
# its own beyond the API calls aboard makes.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/aboard /usr/local/bin/aboard

ENTRYPOINT ["aboard"]
CMD ["daemon"]
