#!/usr/bin/env bash
# matrix-bridge-e2e.sh - end-to-end test of the Matrix bridge (#50) against a
# THROWAWAY continuwuity homeserver on 127.0.0.1:18448, removed on exit.
# Never point it at a real homeserver: it registers users and creates rooms.
#
# Covers: setup (login, cross-signing, SAS emoji verification with a fake
# Sean, pin), an encrypted round trip through the bridge and the real Python
# worker to a stub opencode, `show draft` / `approve draft` on a fixture
# snapshot, resume with confirm, a replayed event ignored, a message from
# Sean's second, unverified device dropped, and the red-team round 6
# regressions (redteam_test.go: RT1-RT4).
#
# Needs: docker, go (matrix-bridge/go.mod), python3 with aiohttp.
#   bash selftest/matrix-bridge-e2e.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${CONTINUWUITY_IMAGE:-forgejo.ellis.link/continuwuation/continuwuity:v26.9.4@sha256:5f21a556290df5b6eda30c7d695288f5c4b06f9529a64e2cae040297287496c3}"
NAME="jill-bridge-e2e-$$"
REG_TOKEN="e2e-throwaway-token"

docker run -d --rm --name "$NAME" -p 127.0.0.1:18448:8008 --tmpfs /data "$IMAGE" /sbin/conduwuit \
  -O 'server_name="test.local"' -O 'database_path="/data/db"' -O 'address=["0.0.0.0"]' -O 'port=8008' \
  -O 'allow_registration=true' -O "registration_token=\"$REG_TOKEN\"" -O 'allow_federation=false' \
  -O 'log="warn"' >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

# The first account needs the one-time token the server prints at boot.
first=""
for _ in $(seq 1 60); do
  first="$(docker logs "$NAME" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' \
    | sed -n 's/.*using the registration token \([A-Za-z0-9]*\).*/\1/p' | head -1)"
  [ -n "$first" ] && break
  sleep 1
done
[ -n "$first" ] || { echo "no first-user token in the homeserver log" >&2; docker logs "$NAME" | tail -20; exit 1; }

cd "$REPO_ROOT/matrix-bridge"
IT_HS_URL="http://127.0.0.1:18448" IT_FIRST_TOKEN="$first" IT_TOKEN="$REG_TOKEN" CGO_ENABLED=0 \
  go test -tags 'goolm integration' -run 'TestE2E|TestRT' -count=1 -v -timeout 30m ./...
