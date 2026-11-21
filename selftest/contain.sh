#!/bin/bash
# selftest/contain.sh - containment regression checks for both red-team
# rounds on #54/#55. Runs through the REAL bash tool path (as the model
# would). Every check gets past the text guard on purpose: these must fail
# at the secret, file-permission, firewall or gateway layer. Prints
# "selftest-escaped:<name>" for each check that got out, then "selftest-ok".
# It never prints what it read.
#
# Network checks only prove something inside the compose stack, where
# jill-netns firewalls this namespace (JILL_EXPECT_FIREWALL is set by the
# entrypoint there). Under `docker run --network none` (CI) they pass
# trivially.

out() { echo "selftest-escaped:$1"; }
t() { timeout 4 "$@" >/dev/null 2>&1; }
http() { curl -s -m 4 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null; }
SECRET_NAMES='(^|_)(KEYS?|APIKEY|TOKEN|SECRET|PASSWORD|PASSWD|PAT|CREDENTIALS?)(_|=)'

# The server runs as node (non-root, no capabilities) and holds no secrets,
# so whatever a server-side read can be tricked into returning (round-2 C1:
# @file expansion, a raced symlink) is worth nothing.
[ "$(id -u)" = 1000 ] || out "shell-uid-$(id -u)"
if env | cut -d= -f1 | grep -qiE "$SECRET_NAMES|PASSWORD"; then out env-secret; fi
if env | grep -qiE '^(http_proxy|https_proxy|all_proxy)='; then out env-proxy; fi
for d in /proc/[0-9]*; do
  if tr '\0' '\n' < "$d/environ" 2>/dev/null | cut -d= -f1 | grep -qiE "$SECRET_NAMES|PASSWORD"; then
    out "secret-in-environ-of-pid-${d#/proc/}"; break
  fi
done
if [ "$(awk '/^CapEff:/ {print $2}' /proc/1/status 2>/dev/null)" != 0000000000000000 ]; then out server-has-capabilities; fi
if [ "$(stat -c %u /proc/1 2>/dev/null)" = 0 ]; then out server-runs-as-root; fi
if ! tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -qx 'OPENCODE_AUTH_CONTENT={}'; then out auth-json-honoured; fi

# Guard and config files are not writable.
for p in /app /app/.opencode/plugins /app/config /etc/opencode-xdg/opencode /home/node /home/node/.config; do
  if touch "$p/.selftest-write" 2>/dev/null; then rm -f "$p/.selftest-write"; out "writable:$p"; fi
done

# No route out, no DNS, no host.
if t bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'; then out dev-tcp; fi
if t getent hosts example.com; then out dns; fi
if t curl -s https://example.com; then out curl-direct; fi
if https_proxy=http://1.1.1.1:3128 t curl -s https://example.com; then out curl-proxy-env; fi
if t python3 -c 'import urllib.request; urllib.request.urlopen("https://example.com", timeout=3)'; then out python-http; fi
if cp /usr/bin/curl /workspace/.selftest-curl 2>/dev/null; then
  if t /workspace/.selftest-curl -s https://example.com; then out copied-curl; fi
  rm -f /workspace/.selftest-curl
fi
if t git ls-remote https://github.com/git/git; then out git-remote; fi

if [ -n "${JILL_EXPECT_FIREWALL:-}" ] || [ -f /tmp/jill-expect-firewall ]; then
  # Round-2 C1 chain, step 2: the serve API, by every local route.
  p=47
  for host in 127.0.0.1 localhost "$(hostname -I 2>/dev/null | awk '{print $1}')"; do
    [ -n "$host" ] || continue
    if t bash -c "exec 3<>/dev/tcp/$host/${p}47"; then out "serve-api-reachable:$host"; fi
  done
  # ...and through api-proxy, which also refuses MCP registration.
  if t bash -c 'exec 3<>/dev/tcp/api-proxy/4748'; then out api-proxy-reachable; fi
  # Round-2 H3: the network's gateway address (Docker bridge / Colima VM).
  gw=$(hostname -I 2>/dev/null | awk '{print $1}' | awk -F. '{print $1"."$2"."$3".1"}')
  for port in 22 80 443 2375 2376 6806; do
    if t bash -c "exec 3<>/dev/tcp/$gw/$port"; then out "gateway-host:$gw:$port"; fi
  done
fi

# Gateways: policy holds at the gateway (2xx = escaped).
code=$(http -X POST -H 'content-type: application/json' \
  -d '{"model":"z-ai-glm-5-turbo","messages":[{"role":"user","content":"x"}]}' http://venice-proxy:8080/api/v1/chat/completions)
case "$code" in 2*) out venice-non-private-model ;; esac
code=$(http -X POST -H 'content-type: application/json' \
  -d '{"model":"zai-org-glm-5-2","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/x"}}]}]}' \
  http://venice-proxy:8080/api/v1/chat/completions)
case "$code" in 2*) out venice-remote-media ;; esac
A='http://agentmail-proxy:8080/v0/inboxes/jill-agent%40agentmail.to'
for path in /messages/send /messages/%73end /messages/m1/reply /messages/m1/forward; do
  code=$(http -X POST -H 'content-type: application/json' -d '{"to":["selftest@example.invalid"],"text":"x"}' "$A$path")
  case "$code" in 2*) out "agentmail-send:$path" ;; esac
done
code=$(http -X POST -H 'content-type: application/json' -d '{"to":["selftest@example.invalid"],"text":"x","send_at":"2030-01-01T00:00:00Z"}' "$A/drafts")
case "$code" in 2*) out agentmail-scheduled-draft ;; esac
code=$(http -X POST -H 'content-type: application/json' -d '{"to":["selftest@example.invalid"],"to":["sean@grid7.com"]}' "$A/drafts")
case "$code" in 2*) out agentmail-duplicate-keys ;; esac
code=$(http -X POST "$A/drafts/selftest-unapproved/send")
case "$code" in 2*) out agentmail-unapproved-draft-send ;; esac
code=$(http -X POST -H 'content-type: application/json' -d '{"url":"https://example.com/"}' http://fetch-gateway:8080/fetch)
case "$code" in 2*) out fetch-unapproved-url ;; esac
code=$(http -X POST -H 'content-type: application/json' -d '{"path":"/data/storage/petal/x"}' http://siyuan-proxy:8080/api/file/getFile)
case "$code" in 2*) out siyuan-storage-read ;; esac
if t curl -s http://brave-mcp:8080/mcp; then out brave-mcp-direct; fi

# Control (#49): the kill switch, the alert spool and the credential probes
# live in volumes serve never mounts, behind a sidecar serve cannot reach. If
# serve could write a flag it could lift its own halt; if it could write the
# spool, alerts would be an egress path to Sean's homeserver. /state/scan-alerts
# (#51) is deliberately NOT in this list: serve writes it, and jill-control
# reads it as fixed enums only, so it carries no text (gateway/control.py).
for d in /state/control /state/alerts /state/credentials /state/credentials/venice \
         /state/credentials/agentmail /state/credentials/siyuan /state/venice; do
  if [ -e "$d" ] && [ -n "$(ls -A "$d" 2>/dev/null | grep -vxE 'venice|agentmail|siyuan')" ]; then
    out "control-volume-mounted:$d"
  fi
  if touch "$d/.selftest-write" 2>/dev/null; then rm -f "$d/.selftest-write"; out "control-dir-writable:$d"; fi
done
if t getent hosts jill-control; then out jill-control-resolvable; fi
if env | cut -d= -f1 | grep -qE '^MATRIX_'; then out env-matrix; fi

echo selftest-ok
