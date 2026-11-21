#!/usr/bin/env bash
# Venice-only model resolution in the heartbeat dispatcher (BehalfBot-open#46).
# Extracts resolve_model from the dispatcher and proves every path either
# yields venice/<model> or refuses.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DISPATCHER="$ROOT/scheduled-tasks/heartbeat-dispatcher.sh"
LOG_FILE="$(mktemp)"
trap 'rm -f "$LOG_FILE"' EXIT
log() { echo "$1" >> "$LOG_FILE"; }

eval "$(sed -n '/^DEFAULT_HEARTBEAT_MODEL=/,/^DEFAULT_SMALL_MODEL=/p' "$DISPATCHER")"
eval "$(sed -n '/^resolve_model() {/,/^}/p' "$DISPATCHER")"

fail=0
expect() {  # expect <want|REFUSE> <alias> [ENV=val ...]
  local want="$1" alias="$2"; shift 2
  local got rc
  got=$(env -u HEARTBEAT_MODEL_OPUS -u HEARTBEAT_MODEL_SONNET -u HEARTBEAT_MODEL_HAIKU "$@" \
    bash -c "$(declare -f log resolve_model); LOG_FILE='$LOG_FILE'; DEFAULT_HEARTBEAT_MODEL='$DEFAULT_HEARTBEAT_MODEL'; DEFAULT_SMALL_MODEL='$DEFAULT_SMALL_MODEL'; resolve_model '$alias'")
  rc=$?
  if [[ "$want" == REFUSE ]]; then
    if [[ $rc -eq 0 ]]; then echo "FAIL: '$alias' $* -> '$got' (want refusal)"; fail=1; else echo "ok: '$alias' $* refused"; fi
  else
    if [[ $rc -ne 0 || "$got" != "$want" ]]; then echo "FAIL: '$alias' $* -> '$got' rc=$rc (want $want)"; fail=1; else echo "ok: '$alias' $* -> $got"; fi
  fi
}

expect venice/zai-org-glm-5-2 opus
expect venice/zai-org-glm-5-2 sonnet
expect venice/zai-org-glm-5-2 ""
expect venice/z-ai-glm-5-3-flash haiku
expect venice/z-ai-glm-5-3-flash venice/z-ai-glm-5-3-flash
expect venice/z-ai-glm-5-3-flash sonnet HEARTBEAT_MODEL_SONNET=venice/z-ai-glm-5-3-flash
expect REFUSE anthropic/claude-sonnet-4-5
expect REFUSE openrouter/z-ai/glm-5.2
expect REFUSE gpt-5
expect REFUSE venice/
expect REFUSE sonnet HEARTBEAT_MODEL_SONNET=anthropic/claude-sonnet-4-5
expect REFUSE haiku HEARTBEAT_MODEL_HAIKU=anthropic/claude-haiku-4-5
expect REFUSE opus HEARTBEAT_MODEL_OPUS=openrouter/anthropic/claude-opus

exit $fail
