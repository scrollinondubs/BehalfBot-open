#!/usr/bin/env bash
# boot.sh - single boot entrypoint for the BehalfBot-open Docker stack.
#
# Ensures Colima (the Docker runtime on this Mac) is up, then starts the
# compose stack. Idempotent - safe to run any time:
#
#   bash docker/boot.sh
#
# For boot persistence, either rely on `colima start` at login plus
# `restart: unless-stopped` (compose brings containers back when the daemon
# returns), or install the single launchd agent:
#
#   sed "s|__REPO_ROOT__|$(pwd)|g" docker/com.jax.behalfbot-docker.plist \
#     > ~/Library/LaunchAgents/com.jax.behalfbot-docker.plist
#   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.jax.behalfbot-docker.plist

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

if ! colima status >/dev/null 2>&1; then
  echo "[boot] colima not running - starting it"
  colima start
fi

# Wait for the docker socket to answer (colima start returns before the
# daemon is always ready).
for _ in $(seq 1 30); do
  docker info >/dev/null 2>&1 && break
  sleep 2
done
docker info >/dev/null 2>&1 || { echo "[boot] docker daemon never came up" >&2; exit 1; }

docker compose up -d
echo "[boot] behalfbot-open stack is up:"
docker compose ps
