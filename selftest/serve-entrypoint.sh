#!/usr/bin/env bash
# Entry point for the opencode-serve container (runs as root, cap-dropped).
#
#   1. guard + containment self-test (selftest/run.sh)
#   2. start opencode serve
#   3. prove the API refuses callers without the password, including the
#      session shell route, before declaring the container up
#
# Any failure exits instead of serving; the healthcheck never passes and the
# bridge (which depends on a healthy serve) never starts.
set -euo pipefail
umask 002

# Server state lives in root-only dirs the node user (tool shells) cannot
# reach; global config is a nobody-owned, read-only dir.
export XDG_DATA_HOME=/var/lib/opencode/data
export XDG_STATE_HOME=/var/lib/opencode/state
export XDG_CACHE_HOME=/var/cache/opencode
export XDG_CONFIG_HOME=/etc/opencode-xdg

refuse() { echo "[serve] $* - refusing to start opencode serve" >&2; exit 1; }

[[ -n "${OPENCODE_SERVER_PASSWORD:-}" ]] || refuse "OPENCODE_SERVER_PASSWORD is not set"
bash /app/selftest/run.sh || refuse "guard self-test failed"

opencode serve --port 4747 --hostname 0.0.0.0 &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null' TERM INT

auth=(-u "opencode:${OPENCODE_SERVER_PASSWORD}")
for _ in $(seq 1 60); do
  curl -fsS "${auth[@]}" -o /dev/null http://127.0.0.1:4747/global/health 2>/dev/null && break
  sleep 1
done
curl -fsS "${auth[@]}" -o /dev/null http://127.0.0.1:4747/global/health || { kill "$pid"; refuse "serve never became healthy"; }
for route in /global/health /config /config/providers /session; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:4747$route")
  [[ "$code" == 401 ]] || { kill "$pid"; refuse "unauthenticated GET $route returned $code, expected 401"; }
done
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
  -d '{"agent":"build","command":"true"}' http://127.0.0.1:4747/session/ses_selftest/shell)
[[ "$code" == 401 ]] || { kill "$pid"; refuse "unauthenticated session shell returned $code, expected 401"; }
echo "[serve] self-test passed; API requires the password"
wait "$pid"
