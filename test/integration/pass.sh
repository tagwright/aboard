#!/bin/bash
# pass.sh — run ONE aboard daemon boot reconcile pass and dump its log.
# Starts the real aboard daemon against the disposable Authentik, waits for the
# boot "full reconcile pass complete" line, prints the daemon log, then removes
# the daemon container. Set CREATE_GROUPS=true to pass ABOARD_CREATE_GROUPS=true.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker rm -f aboard-itest-daemon >/dev/null 2>&1 || true

ENVARGS=(-e ABOARD_CONFIG=/etc/aboard/aboard.yml -e ABOARD_SECRETS_DIR=/run/aboard/secrets)
if [ "${CREATE_GROUPS:-}" = "true" ]; then
  ENVARGS+=(-e ABOARD_CREATE_GROUPS=true)
fi

docker run -d --name aboard-itest-daemon --network aboard-itest-net \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$DIR/aboard.yml":/etc/aboard/aboard.yml:ro \
  -v "$DIR/secrets":/run/aboard/secrets:ro \
  -v "$DIR/aboard-bin":/usr/local/bin/aboard:ro \
  "${ENVARGS[@]}" \
  alpine:latest /usr/local/bin/aboard daemon >/dev/null

for i in $(seq 1 40); do
  if docker logs aboard-itest-daemon 2>&1 | grep -q "full reconcile pass complete"; then break; fi
  sleep 1
done
sleep 1
docker logs aboard-itest-daemon 2>&1
docker rm -f aboard-itest-daemon >/dev/null 2>&1 || true
