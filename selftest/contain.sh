#!/bin/bash
# selftest/contain.sh - containment regression checks for the #54 red-team
# findings. Runs through the REAL bash tool path (as the model would), so it
# runs as whatever user a tool shell gets. Every check here gets past the
# text guard on purpose: these must fail at the uid, file-permission or
# network layer. Prints "selftest-escaped:<name>" for each check that got
# out, then "selftest-ok". It never prints what it read.
#
# Network checks only prove something where opencode-serve is on its
# internal compose network (the boot self-test under compose). Under
# `docker run --network none` (CI) they pass trivially.

out() { echo "selftest-escaped:$1"; }
t() { timeout 4 "$@" >/dev/null 2>&1; }

# Tool shells run as node, with nothing secret in their environment.
[ "$(id -u)" = 1000 ] || out "shell-not-node-uid-$(id -u)"
if env | grep -qiE '^[^=]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|_PAT)[^=]*=.'; then out env-secret; fi
if env | grep -qiE '^(http_proxy|https_proxy|all_proxy)='; then out env-proxy; fi

# C1/H2: no other user's process environment is readable (glob form too).
for d in /proc/[0-9]*; do
  [ "$(stat -c %u "$d" 2>/dev/null)" = 1000 ] && continue
  if cat "$d"/envi* 2>/dev/null | tr '\0' '\n' | grep -q '='; then out "proc-environ-${d#/proc/}"; break; fi
done

# C2: OpenCode cannot be launched (or read) by a tool shell.
for b in opencode /usr/local/bin/opencode /usr/local/lib/node_modules/opencode-ai/bin/opencode; do
  if OPENCODE_CONFIG_CONTENT='{}' t "$b" --version; then out "nested-opencode:$b"; fi
done
if [ -r /usr/local/lib/node_modules/opencode-ai ]; then out opencode-package-readable; fi
for f in $(find / -xdev -name opencode -type f 2>/dev/null); do
  if t "$f" --version; then out "nested-opencode:$f"; fi
done

# H1 and guard files: config-affecting paths are not writable.
for p in /app /app/.opencode/plugins /app/config /etc/opencode-xdg/opencode /var/lib/opencode \
         /var/lib/opencode/data /data /home/node /home/node/.config; do
  if touch "$p/.selftest-write" 2>/dev/null; then rm -f "$p/.selftest-write"; out "writable:$p"; fi
done
if touch /var/lib/opencode/data/auth.json 2>/dev/null; then out auth-json-writable; fi

# C1/H3/H4/M2/M3: no route out except the gateways.
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

# H6: the serve API needs a password tool shells do not have.
p=47
code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${p}47/config" 2>/dev/null)
[ "$code" = 200 ] && out serve-api-unauthenticated

# Gateways: no caller token means no service; AgentMail policy is on the
# decoded path (H5). Only meaningful when the gateways are up.
code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
  -d '{"model":"zai-org-glm-5-2","messages":[]}' http://venice-proxy:8080/api/v1/chat/completions 2>/dev/null)
case "$code" in 2*) out venice-proxy-no-token ;; esac
code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
  -d '{"to":["selftest@example.invalid"],"subject":"x","text":"x"}' \
  'http://agentmail-proxy:8080/v0/inboxes/jill-agent%40agentmail.to/messages/%73end' 2>/dev/null)
case "$code" in 2*) out agentmail-encoded-send ;; esac
code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' -X POST -d '{"stmt":"select 1"}' http://siyuan-proxy:8080/api/query/sql 2>/dev/null)
case "$code" in 2*) out siyuan-proxy-no-token ;; esac
code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' -X POST -d '{}' http://brave-proxy:8080/mcp 2>/dev/null)
case "$code" in 2*) out brave-proxy-no-token ;; esac
if t curl -s http://brave-mcp:8080/mcp; then out brave-mcp-direct; fi

echo selftest-ok
