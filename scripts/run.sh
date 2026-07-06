#!/usr/bin/env bash
# scripts/run.sh - headless wrapper mirroring the chassis `claude -p` pattern.
#
# Usage:
#   bash scripts/run.sh "prompt text"
#   bash scripts/run.sh --model openrouter/z-ai/glm-5.2 "prompt text"
#   bash scripts/run.sh --agent software-engineering "prompt text"
#
# Emits raw JSON events (one per line) to stdout, same role as
# `claude -p --output-format json` in the dispatcher.
#
# Keys: opencode picks up ANTHROPIC_API_KEY / VENICE_API_KEY /
# OPENROUTER_API_KEY from the environment or a repo-local .env (gitignored).

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load repo-local .env if present (key NAMES documented in .env.example).
if [[ -f "$REPO_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$REPO_DIR/.env"
  set +a
fi

if [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${VENICE_API_KEY:-}" && -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "error: no provider key found. Set ANTHROPIC_API_KEY (or VENICE_API_KEY / OPENROUTER_API_KEY) in the environment or $REPO_DIR/.env" >&2
  exit 1
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
