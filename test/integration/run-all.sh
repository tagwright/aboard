#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 techgaud
#
# The live integration harness aggregator (tagwright Testing Standard, task
# #548). It is the single entry point the self-hosted CI leg (ci-selfhosted.yml)
# and the release gate (release.yml) both call, so "the harness" means one thing
# in one place rather than a drifting list per caller.
#
# What it does, in order (cheapest scenario first, fail on first break):
#   1. stand up the DISPOSABLE Authentik stack (docker-compose.yml) on its own
#      compose project + network (aboard-itest-net), wait for it healthy,
#   2. build the real aboard binary CGO-free in a golang:1.25 container,
#   3. api    - assert the disposable Authentik REST API is reachable and the
#               bootstrap token is valid,
#   4. pass   - run one real `aboard daemon` boot reconcile pass and assert it
#               completes,
#   5. golive - the full provision -> attach -> go-live-poll -> prune e2e leg,
#      then tear the disposable stack down (always, via the trap).
#
# EVERYTHING here runs against the DISPOSABLE Authentik only: its objects are all
# prefixed aboard-itest-* and live on the aboard-itest-net network and the
# aboard-itest compose project. It NEVER touches the production Authentik, its
# postgres, or the shared proxy networks. On the self-hosted runner this whole
# sequence runs inside the ISOLATED privileged dind (never the production
# socket); locally it runs against whatever Docker socket is in the environment.
#
# Usage: test/integration/run-all.sh [--keep]
#   --keep  leave the disposable stack, the built binary, and the secrets up
#           after the run (for debugging); default tears everything down.
set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HARNESS_DIR/../.." && pwd)"

KEEP=0
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

PROJECT=aboard-itest
NET=aboard-itest-net
SERVER=aboard-itest-server
BOOTSTRAP_TOKEN=aboard-itest-bootstrap-token-throwaway
BIN="$HARNESS_DIR/aboard-bin"
SECRETS="$HARNESS_DIR/secrets"

log() { printf '\n########## harness: %s ##########\n' "$1"; }

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    log "skipping teardown (--keep); 'docker compose -p $PROJECT down -v' when done"
    return
  fi
  log "teardown: docker compose -p $PROJECT down -v"
  docker compose -p "$PROJECT" -f "$HARNESS_DIR/docker-compose.yml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- secrets ----------------------------------------------------------------
# secrets/ is git-ignored (throwaway values for the ephemeral instance only), so
# a fresh CI checkout has none. The disposable Authentik is bootstrapped with
# BOOTSTRAP_TOKEN, and aboard.yml resolves its token by the NAME aboard-api-token
# from ABOARD_SECRETS_DIR, so that file must hold the bootstrap token. pass.sh,
# api.sh, and golive.sh with the default aboard.yml need only this one secret (no
# OIDC client secrets, because none of these three scenarios labels an OIDC app).
mkdir -p "$SECRETS"
if [ ! -s "$SECRETS/aboard-api-token" ]; then
  log "writing throwaway secrets/aboard-api-token (the bootstrap token)"
  printf '%s' "$BOOTSTRAP_TOKEN" > "$SECRETS/aboard-api-token"
fi

# --- disposable Authentik ---------------------------------------------------
log "bring up the disposable Authentik (docker compose -p $PROJECT up -d)"
docker compose -p "$PROJECT" -f "$HARNESS_DIR/docker-compose.yml" up -d

# Wait for the server's REST API to answer 200 with the bootstrap token. The
# probe runs INSIDE aboard-itest-net because this host cannot route the bridge IP
# (see docs/TESTING.md). Authentik boot is 2-4 minutes cold, so poll generously.
log "wait for the disposable Authentik REST API (up to ~6 min)"
ready=0
for i in $(seq 1 120); do
  code="$(docker run --rm --network "$NET" curlimages/curl:latest \
    -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $BOOTSTRAP_TOKEN" \
    "http://$SERVER:9000/api/v3/root/config/" 2>/dev/null || true)"
  if [ "$code" = "200" ]; then ready=1; echo "authentik ready (HTTP 200) after $((i*3))s"; break; fi
  sleep 3
done
if [ "$ready" -ne 1 ]; then
  echo "harness: FAIL: disposable Authentik never became ready" >&2
  docker compose -p "$PROJECT" -f "$HARNESS_DIR/docker-compose.yml" logs --tail 40 >&2 || true
  exit 1
fi

# --- build the real binary --------------------------------------------------
# CGO-free, matching the Dockerfile build stage, into the harness dir where
# pass.sh and golive.sh mount it. Built in golang:1.25 so there is no host Go
# dependency; the source is the repo root (a workspace path the runner shares
# into the dind at the same path, exactly as ballast's harness relies on).
log "build the real aboard binary (golang:1.25, CGO-free)"
docker run --rm -v "$REPO_ROOT":/src -w /src \
  -e GOPRIVATE=github.com/tagwright/* -e GOFLAGS=-buildvcs=false \
  golang:1.25 sh -c 'CGO_ENABLED=0 go build -o test/integration/aboard-bin ./cmd/aboard'
if [ ! -x "$BIN" ]; then
  echo "harness: FAIL: aboard-bin was not built at $BIN" >&2
  exit 1
fi

# --- scenarios, cheapest first, fail on first break -------------------------

# api: the disposable Authentik REST API is reachable and the bootstrap token is
# valid. A well-formed response carries the "pagination" envelope; an auth or
# routing failure would not.
log "api: assert the disposable Authentik REST API answers with a valid token"
API_OUT="$("$HARNESS_DIR/api.sh" GET '/api/v3/core/applications/?superuser_full_list=true')" || {
  echo "harness: FAIL: api.sh returned non-zero" >&2; exit 1; }
if ! printf '%s' "$API_OUT" | grep -q '"pagination"'; then
  echo "harness: FAIL: api.sh response is not a well-formed Authentik list:" >&2
  printf '%s\n' "$API_OUT" | head -5 >&2
  exit 1
fi
echo "api: OK (REST reachable, token valid)"

# pass: one real aboard daemon boot reconcile pass completes against the live
# disposable Authentik. With no labeled containers this is a clean no-op
# reconcile, so it gates the boot + config load + token resolve + API-connect
# path end to end.
log "pass: run one real aboard daemon boot reconcile pass"
PASS_OUT="$("$HARNESS_DIR/pass.sh")" || {
  echo "harness: FAIL: pass.sh returned non-zero" >&2; exit 1; }
if ! printf '%s' "$PASS_OUT" | grep -q "full reconcile pass complete"; then
  echo "harness: FAIL: the boot reconcile pass did not complete:" >&2
  printf '%s\n' "$PASS_OUT" | tail -20 >&2
  exit 1
fi
echo "pass: OK (boot reconcile pass complete)"

# golive: the full provision -> attach -> go-live-poll -> prune e2e leg. It
# self-asserts (no go-live-stale, the live outpost serves a 302 with no server
# restart) and exits non-zero on any failure, cleaning up its own objects.
log "golive: full go-live poll e2e leg"
if ! "$HARNESS_DIR/golive.sh"; then
  echo "harness: FAIL: golive.sh failed" >&2
  exit 1
fi
echo "golive: OK"

echo
echo "harness: all 3 scenarios passed (api, pass, golive)"
