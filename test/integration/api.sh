#!/bin/bash
# api.sh METHOD PATH [BODYFILE]
# Runs curl inside a container on aboard-itest-net (the host cannot route to the
# bridge IP) and prints the raw response body to stdout. BODYFILE, when given, is
# a path relative to this integration dir, sent as the JSON request body.
set -euo pipefail
METHOD="$1"; APIPATH="$2"; BODYFILE="${3:-}"
TOKEN=aboard-itest-bootstrap-token-throwaway
BASE=http://aboard-itest-server:9000
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -n "$BODYFILE" ]; then
  docker run --rm --network aboard-itest-net -v "$DIR":/work:ro curlimages/curl:latest \
    -s -X "$METHOD" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    --data "@/work/$BODYFILE" "$BASE$APIPATH"
else
  docker run --rm --network aboard-itest-net curlimages/curl:latest \
    -s -X "$METHOD" -H "Authorization: Bearer $TOKEN" "$BASE$APIPATH"
fi
