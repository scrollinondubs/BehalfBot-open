#!/usr/bin/env bash
# opencode-serve.sh - start a headless opencode server for the Discord bridge.
#
# Binds to localhost only. Reads secrets (VENICE_API_KEY etc.) from the repo
# root .env. Intended to be run by launchd (see com.jax.opencode-serve.plist)
# but works fine by hand:
#
#   bash bridge/opencode-serve.sh
#
# Env overrides:
#   OPENCODE_PORT      port to listen on          (default 4747)
#   OPENCODE_BIN       path to the opencode binary (default ~/.opencode/bin/opencode)
#   OPENCODE_LOG_FILE  log destination             (default <repo>/logs/opencode-serve.log)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Load secrets without echoing them anywhere.
if [ -f "$REPO_ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$REPO_ROOT/.env"
  set +a
fi

OPENCODE_BIN="${OPENCODE_BIN:-$HOME/.opencode/bin/opencode}"
OPENCODE_PORT="${OPENCODE_PORT:-4747}"
OPENCODE_LOG_FILE="${OPENCODE_LOG_FILE:-$REPO_ROOT/logs/opencode-serve.log}"

mkdir -p "$(dirname "$OPENCODE_LOG_FILE")"

if [ ! -x "$OPENCODE_BIN" ]; then
  echo "opencode binary not found at $OPENCODE_BIN" >&2
  exit 1
fi

echo "[opencode-serve] starting on 127.0.0.1:$OPENCODE_PORT (log: $OPENCODE_LOG_FILE)" >> "$OPENCODE_LOG_FILE"

# exec so launchd supervises the real process, not a wrapper shell.
exec "$OPENCODE_BIN" serve \
  --port "$OPENCODE_PORT" \
  --hostname 127.0.0.1 \
  >> "$OPENCODE_LOG_FILE" 2>&1
