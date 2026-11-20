#!/usr/bin/env bash
# selftest/run.sh - prove the guards deny, inside the image, before serving.
#
# Two parts, proving different things:
#
#   1. Filesystem and env checks (static). The guard files, the app tree and
#      OpenCode's global config dir must not be writable by this user, and the
#      real Venice key must not be in this container's environment (the
#      venice-proxy sidecar holds it). Checked with test -w, which asks the
#      kernel, so a read-only mount and root ownership both count.
#
#   2. A real `opencode run` against a scripted local model (mock_llm.py). The
#      mock makes the parent session call tools the guards must deny, then
#      launches a subagent through `task` whose child session does the same.
#      OpenCode runs every call through its real tool path with the real
#      plugin loaded from /app/.opencode. The mock records, per case, only
#      whether the result carried "[guardrails]" or the positive-control
#      marker. A missing case, a missing denial or a missing control is a
#      failure. This is what proves the plugin LOADED and fires in subagents:
#      OpenCode skips a plugin that fails to load without stopping.
#
# Exit 0 only if everything passes. The serve entrypoint refuses to start
# otherwise. Every case is harmless if its guard fails (see cases.json).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$(cd "$HERE/.." && pwd)"
OPENCODE_BIN="${OPENCODE_BIN:-opencode}"
PORT="${SELFTEST_PORT:-39181}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/guard-selftest.XXXXXX")"
RESULTS="$WORK/results.json"
fail=0

say() { printf '[selftest] %s\n' "$*"; }
bad() { say "FAIL: $*"; fail=1; }

cleanup() {
  [[ -n "${MOCK_PID:-}" ]] && kill "$MOCK_PID" 2>/dev/null
  rm -rf "$WORK" /tmp/selftest-canary
}
trap cleanup EXIT

# --- 1. static checks ------------------------------------------------------
if [[ "$(id -u)" == 0 ]]; then
  bad "running as root; the guards assume the unprivileged node user"
fi
for p in "$APP" "$APP/AGENTS.md" "$APP/opencode.json" "$APP/.opencode" "$APP/.opencode/plugins" \
         "$APP/.opencode/plugins/guardrails.ts" "$APP/.opencode/guards" "$APP/.opencode/guards/policy.ts" \
         "$APP/config" "$APP/config/guards.json" "$APP/selftest" "$HOME/.config/opencode" \
         "$HOME/.config"; do
  if [[ -e "$p" && -w "$p" ]]; then
    bad "$p is writable by $(id -un)"
  fi
done
[[ -r "$APP/config/guards.json" ]] || bad "config/guards.json is not readable"
if [[ -n "${VENICE_API_KEY:-}" && "${VENICE_API_KEY}" != "${VENICE_KEY_PLACEHOLDER:-held-by-venice-proxy}" ]]; then
  bad "VENICE_API_KEY in this container is not the proxy placeholder; the real key belongs only in venice-proxy"
fi
say "static checks done"

# --- 2. live run through OpenCode -------------------------------------------
python3 "$HERE/mock_llm.py" "$PORT" "$RESULTS" &
MOCK_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$PORT/v1/models" >/dev/null 2>&1 && break
  sleep 0.1
done

mcp_off='{"type":"local","command":["true"],"enabled":false}'
CONFIG=$(cat <<EOF
{
  "enabled_providers": ["selftest"],
  "model": "selftest/mock",
  "small_model": "selftest/mock",
  "provider": {
    "selftest": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "selftest",
      "options": {"baseURL": "http://127.0.0.1:$PORT/v1", "apiKey": "selftest"},
      "models": {"mock": {"name": "mock", "tool_call": true}}
    }
  },
  "mcp": {"memory": $mcp_off, "brave-search": $mcp_off, "siyuan": $mcp_off, "tavily": $mcp_off, "context7": $mcp_off}
}
EOF
)

mkdir -p "$WORK/data" "$WORK/state" "$WORK/cache"
(
  cd "$APP" || exit 1
  OPENCODE_CONFIG_CONTENT="$CONFIG" \
  OPENCODE_DISABLE_MODELS_FETCH=1 \
  XDG_DATA_HOME="$WORK/data" XDG_STATE_HOME="$WORK/state" XDG_CACHE_HOME="$WORK/cache" \
  SELFTEST_CANARY_TOKEN=present \
  timeout 180 "$OPENCODE_BIN" run --auto --format json --model selftest/mock "SELFTEST-PARENT" \
    > "$WORK/events.jsonl" 2> "$WORK/stderr.log"
) || say "opencode run exited non-zero (judged on the recorded results below)"

python3 - "$HERE/cases.json" "$RESULTS" <<'PY' || fail=1
import json, sys
cases = json.load(open(sys.argv[1]))
res = json.load(open(sys.argv[2]))
bad = 0
for scope in ("parent", "child"):
    for c in cases[scope]:
        r = res.get(c["id"])
        want = c["expect"]
        if r is None:
            verdict, ok = "MISSING (tool result never came back)", False
        elif want == "deny":
            ok = r["denied"]
            verdict = "denied" if ok else "NOT DENIED"
        elif want == "ok":
            ok = r["ok"] and not r["denied"]
            verdict = "ran" if ok else "DID NOT RUN AS EXPECTED"
        else:
            ok, verdict = True, "returned"
        print(f"[selftest] {'ok  ' if ok else 'FAIL'} {scope:6} {c['id']:22} {verdict}")
        bad += 0 if ok else 1
sys.exit(1 if bad else 0)
PY

if [[ "$fail" != 0 ]]; then
  say "GUARD SELF-TEST FAILED"
  tail -n 20 "$WORK/stderr.log" 2>/dev/null | sed 's/^/[selftest] opencode: /' | cut -c1-300
  exit 1
fi
say "all guards denied, in the parent session and in a subagent"
