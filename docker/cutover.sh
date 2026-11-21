#!/usr/bin/env bash
# cutover.sh - bring Jill's chat up on the Matrix bridge, safely.
#
# The Discord bridge is gone (#50). This script:
#
#   1. boots out and parks any legacy host launchd agents left from the
#      pre-Docker install (com.jax.discord-bridge, com.jax.opencode-serve),
#      so a reboot cannot resurrect them
#   2. refuses to go on until `matrix-bridge setup` has run (the state
#      volume holds Jill's login and the pin of Sean's master key)
#   3. docker compose up -d
#   4. verifies opencode-serve and matrix-bridge report healthy (the bridge
#      is healthy only after its first sync with the crypto store loaded)
#   5. on failure: stops matrix-bridge, so nothing half-configured listens
#
# Run it:          bash docker/cutover.sh
# Stop chat only:  bash docker/cutover.sh --rollback

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LEGACY_AGENTS=(com.jax.discord-bridge com.jax.opencode-serve)
LA_DIR="$HOME/Library/LaunchAgents"
PARKED_DIR="$LA_DIR/behalfbot-parked"
UID_N="$(id -u)"
VERIFY_TIMEOUT=120

log() { printf '[cutover] %s\n' "$*"; }

rollback() {
  log "ROLLBACK: stopping matrix-bridge; nothing reaches Jill by chat until it is started again"
  docker compose stop matrix-bridge || true
}

if [ "${1:-}" = "--rollback" ]; then
  rollback
  exit 0
fi

# --- preflight --------------------------------------------------------------
command -v docker >/dev/null || { log "docker not found"; exit 1; }
docker info >/dev/null 2>&1 || { log "docker daemon down - run: colima start"; exit 1; }
[ -f .env ] || { log ".env missing - see .env.example"; exit 1; }
for v in MATRIX_PRINCIPAL MATRIX_JILL_ROOM; do
  grep -q "^$v=..*" .env || { log "$v missing from .env (bridge/WIRING.md)"; exit 1; }
done

log "building image (no-op if current)"
docker compose build --quiet

if ! docker compose run --rm --no-deps matrix-bridge test -s /state/matrix-bridge/pin.json; then
  log "matrix-bridge setup has not completed (no pin in the state volume)."
  log "Run it first, interactively: docker compose run --rm matrix-bridge-setup"
  exit 1
fi

# --- 1: retire legacy host agents ---------------------------------------------
mkdir -p "$PARKED_DIR"
for a in "${LEGACY_AGENTS[@]}"; do
  launchctl bootout "gui/$UID_N/$a" 2>/dev/null && log "booted out $a" || true
  if [ -f "$LA_DIR/$a.plist" ]; then
    mv "$LA_DIR/$a.plist" "$PARKED_DIR/$a.plist"
    log "parked $LA_DIR/$a.plist -> $PARKED_DIR/ (delete it; the Discord bridge no longer exists)"
  fi
done

# --- 3: up ----------------------------------------------------------------------
if ! docker compose up -d; then
  log "FAIL: docker compose up did not complete"
  rollback
  exit 1
fi

# --- 4: verify ------------------------------------------------------------------
wait_healthy() {  # wait_healthy <container> <seconds>
  local c="$1" n=$(( $2 / 3 )) health
  for _ in $(seq 1 "$n"); do
    health="$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null || echo missing)"
    [ "$health" = healthy ] && return 0
    sleep 3
  done
  return 1
}

if ! wait_healthy behalfbot-opencode-serve 240; then
  log "FAIL: opencode-serve never went healthy"
  rollback
  exit 1
fi
log "serve healthy"

if ! wait_healthy behalfbot-matrix-bridge "$VERIFY_TIMEOUT"; then
  log "FAIL: matrix-bridge did not complete its first sync"
  docker compose logs --tail 30 matrix-bridge || true
  rollback
  exit 1
fi

if docker compose logs --since 10m matrix-bridge 2>/dev/null | grep -q "IDENTITY LOCK"; then
  log "WARNING: matrix-bridge is up but IDENTITY-LOCKED: it refuses all chat. Re-run setup to re-pin."
  exit 1
fi

log "SUCCESS: matrix-bridge synced and listening."
log "Now run the step-F checks in docs/control.md (fingerprint, Element X shield, round trip, replay, second device)."
