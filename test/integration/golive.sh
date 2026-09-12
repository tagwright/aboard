#!/bin/bash
# golive.sh - the go-live poll e2e leg (b3), against the disposable Authentik.
#
# This closes the live-only residual for OutpostServesHost and the go-live poll.
# It proves the exact behavior the b2 e2e test caught as a bug: the embedded
# outpost reloads SLOWLY (~80s measured, no server restart), and aboard must POLL
# until the host serves rather than give up on one re-probe. It:
#
#   1. creates a real labeled forward-auth container on aboard-itest-net,
#   2. runs one real aboard daemon boot pass (which provisions the app, attaches
#      the provider, forces the outpost reload, and POLLS for go-live),
#   3. asserts the daemon reported go-live WITHOUT reporting go-live-stale, and
#      that the live embedded outpost actually serves the host (a 302, not a 404),
#      WITHOUT any authentik-server restart,
#   4. cleans up: removes the test container and prunes the orphaned objects.
#
# Prereqs (operator-run, NOT CI here): the disposable Authentik stack is up
# (docker compose -p aboard-itest up -d) and healthy, and aboard-bin is built.
# See docs/TESTING.md "Running the harness". It NEVER touches the production
# Authentik: everything is aboard-itest-* on aboard-itest-net.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOSTNAME_UNDER_TEST="golive.itest.local"
TESTC=aboard-itest-golive
# A window comfortably past the observed ~80s reload lag, so a healthy slow reload
# reads as live and only a genuinely broken one reports stale.
GOLIVE_TIMEOUT=150s

cleanup() {
  docker rm -f "$TESTC" >/dev/null 2>&1 || true
  docker rm -f aboard-itest-daemon >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== go-live e2e: create a labeled forward-auth container =="
docker rm -f "$TESTC" >/dev/null 2>&1 || true
docker run -d --name "$TESTC" --network aboard-itest-net \
  --label aboard.enable=true \
  --label aboard.host="$HOSTNAME_UNDER_TEST" \
  --label aboard.groups=none \
  --label "traefik.http.routers.golive.rule=Host(\`$HOSTNAME_UNDER_TEST\`)" \
  --label traefik.http.routers.golive.middlewares=authentik@docker \
  traefik/whoami:latest >/dev/null
echo "created $TESTC for $HOSTNAME_UNDER_TEST"

echo "== run one aboard daemon boot pass (provisions, attaches, polls go-live) =="
docker rm -f aboard-itest-daemon >/dev/null 2>&1 || true
docker run -d --name aboard-itest-daemon --network aboard-itest-net \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$DIR/aboard.yml":/etc/aboard/aboard.yml:ro \
  -v "$DIR/secrets":/run/aboard/secrets:ro \
  -v "$DIR/aboard-bin":/usr/local/bin/aboard:ro \
  -e ABOARD_CONFIG=/etc/aboard/aboard.yml \
  -e ABOARD_SECRETS_DIR=/run/aboard/secrets \
  -e ABOARD_CREATE_GROUPS=true \
  -e ABOARD_GOLIVE_TIMEOUT="$GOLIVE_TIMEOUT" \
  alpine:latest /usr/local/bin/aboard daemon >/dev/null

# The boot pass now BLOCKS inside the go-live poll until the outpost serves the
# host (or the timeout), so "full reconcile pass complete" only prints after the
# poll resolves. Wait past the poll window with margin.
echo "waiting for the boot pass to complete (it polls go-live, up to $GOLIVE_TIMEOUT)..."
for _ in $(seq 1 200); do
  if docker logs aboard-itest-daemon 2>&1 | grep -q "full reconcile pass complete"; then break; fi
  sleep 1
done
LOG="$(docker logs aboard-itest-daemon 2>&1)"

echo "== assert: no go-live-stale, go-live confirmed =="
if grep -q "go-live-stale" <<<"$LOG"; then
  echo "FAIL: aboard reported go-live-stale for $HOSTNAME_UNDER_TEST (the poll gave up too early or the reload is broken)"
  echo "$LOG" | tail -30
  exit 1
fi

echo "== assert: the LIVE outpost serves the host (302, not 404), no server restart =="
served=0
for _ in $(seq 1 30); do
  CODE="$(docker run --rm --network aboard-itest-net curlimages/curl:latest \
    -s -o /dev/null -w '%{http_code}' \
    -H "X-Forwarded-Host: $HOSTNAME_UNDER_TEST" -H "X-Forwarded-Proto: https" \
    "http://aboard-itest-server:9000/outpost.goauthentik.io/auth/traefik" || true)"
  if [ "$CODE" != "404" ] && [ -n "$CODE" ]; then served=1; echo "outpost serves $HOSTNAME_UNDER_TEST (HTTP $CODE)"; break; fi
  sleep 3
done
if [ "$served" != "1" ]; then
  echo "FAIL: the embedded outpost never served $HOSTNAME_UNDER_TEST (still 404)"
  exit 1
fi

echo "== cleanup: remove the container and prune the orphan =="
docker rm -f "$TESTC" >/dev/null 2>&1 || true
docker run --rm --network aboard-itest-net \
  -v "$DIR/aboard.yml":/etc/aboard/aboard.yml:ro \
  -v "$DIR/secrets":/run/aboard/secrets:ro \
  -v "$DIR/aboard-bin":/usr/local/bin/aboard:ro \
  -e ABOARD_CONFIG=/etc/aboard/aboard.yml \
  -e ABOARD_SECRETS_DIR=/run/aboard/secrets \
  alpine:latest /usr/local/bin/aboard prune --yes 2>&1 | sed 's/^/prune: /' || true

echo "PASS: go-live poll confirmed $HOSTNAME_UNDER_TEST live within the window, no server restart"
