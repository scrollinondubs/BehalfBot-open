#!/usr/bin/env bash
# Entry point for the opencode-serve container: node, no capabilities, no
# secrets, in the network namespace jill-netns owns and firewalls.
#
#   1. guard + containment self-test (selftest/run.sh)
#   2. start opencode serve
#   3. in the compose stack (JILL_EXPECT_FIREWALL=1), prove nothing in this
#      namespace can reach the API it just started, then mark ready
#
# Any failure exits instead of serving; api-proxy waits on this container's
# health, and the bridge waits on api-proxy, so nothing talks to a server
# that failed its self-test.
set -euo pipefail

export XDG_DATA_HOME=/var/lib/opencode/data
export XDG_STATE_HOME=/var/lib/opencode/state
export XDG_CACHE_HOME=/var/cache/opencode
export XDG_CONFIG_HOME=/etc/opencode-xdg

refuse() { echo "[serve] $* - refusing to start opencode serve" >&2; exit 1; }

rm -f /tmp/serve-ready
if [[ "${JILL_EXPECT_FIREWALL:-}" == 1 ]]; then
  touch /tmp/jill-expect-firewall
fi
bash /app/selftest/run.sh || refuse "guard self-test failed"

opencode serve --port 4747 --hostname 0.0.0.0 &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null' TERM INT

listening() { awk 'NR>1 && $2 ~ /:128B$/ && $4 == "0A" {f=1} END {exit !f}' /proc/net/tcp /proc/net/tcp6 2>/dev/null; }
for _ in $(seq 1 60); do listening && break; sleep 1; done
listening || { kill "$pid"; refuse "serve never started listening on 4747"; }

if [[ -f /tmp/jill-expect-firewall ]]; then
  for host in 127.0.0.1 "$(hostname -I | awk '{print $1}')"; do
    if curl -s -m 3 -o /dev/null "http://$host:4747/global/health"; then
      kill "$pid"; refuse "the API is reachable from inside this namespace via $host; the jill-netns firewall is not in place"
    fi
  done
fi
touch /tmp/serve-ready
echo "[serve] self-test passed; serving (API reachable only through api-proxy)"
wait "$pid"
