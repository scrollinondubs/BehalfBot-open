#!/usr/bin/env bash
# Entry point for the opencode-serve container: run the guard self-test,
# then serve. A failing self-test means the container exits instead of
# serving, the healthcheck never passes, and the bridge (which depends on a
# healthy serve) never starts.
set -euo pipefail

if ! bash /app/selftest/run.sh; then
  echo "[serve] guard self-test failed - refusing to start opencode serve" >&2
  exit 1
fi
exec opencode serve --port 4747 --hostname 0.0.0.0
