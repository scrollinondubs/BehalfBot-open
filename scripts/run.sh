#!/usr/bin/env bash
# scripts/run.sh - headless wrapper mirroring the chassis `claude -p` pattern.
#
# Usage:
#   bash scripts/run.sh "prompt text"
#   bash scripts/run.sh --model venice/kimi-k2-7-code "prompt text"
#   bash scripts/run.sh --agent software-engineering "prompt text"
#
# Emits raw JSON events (one per line) to stdout, same role as
# `claude -p --output-format json` in the dispatcher.
#
# Key: VENICE_API_KEY from the environment or a repo-local .env (gitignored).
# Venice is the only enabled provider (opencode.json enabled_providers).

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load repo-local .env if present (key NAMES documented in .env.example).
if [[ -f "$REPO_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$REPO_DIR/.env"
  set +a
fi

if [[ -z "${VENICE_API_KEY:-}" ]]; then
  echo "error: VENICE_API_KEY is not set (environment or $REPO_DIR/.env)" >&2
  exit 1
fi

# Bare-host runs talk to Venice directly; the Docker stack points this at the
# venice-proxy sidecar instead, which holds the key.
export VENICE_BASE_URL="${VENICE_BASE_URL:-https://api.venice.ai/api/v1}"
# opencode.json carries no key (the Docker stack's venice-proxy holds it);
# bare-host runs supply the key from the environment instead.
if [[ -z "${OPENCODE_CONFIG_CONTENT:-}" ]]; then
  OPENCODE_CONFIG_CONTENT='{"provider":{"venice":{"options":{"apiKey":"{env:VENICE_API_KEY}"}}}}'
  export OPENCODE_CONFIG_CONTENT
fi

# Default memory MCP store to a repo-local gitignored path.
export BEHALFBOT_MEMORY_FILE="${BEHALFBOT_MEMORY_FILE:-$REPO_DIR/memory/memory.jsonl}"
mkdir -p "$(dirname "$BEHALFBOT_MEMORY_FILE")"

OPENCODE_BIN="${OPENCODE_BIN:-opencode}"
if ! command -v "$OPENCODE_BIN" >/dev/null 2>&1; then
  if [[ -x "$HOME/.opencode/bin/opencode" ]]; then
    OPENCODE_BIN="$HOME/.opencode/bin/opencode"
  else
    echo "error: opencode not found. Install: curl -fsSL https://opencode.ai/install | bash" >&2
    exit 1
  fi
fi

cd "$REPO_DIR"
exec "$OPENCODE_BIN" run --format json "$@"
