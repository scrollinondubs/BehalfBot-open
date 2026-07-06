#!/usr/bin/env bash
# cutover.sh - move the Jill stack from host launchd to Docker, safely.
#
# The Discord bot token allows ONE gateway session. The host launchd bridge
# holds it today, so ordering matters:
#
#   1. bootout the host launchd agents (releases the Jill token + port 4747)
#   2. park their plists so a reboot cannot resurrect them
#   3. flip BRIDGE_DRY_RUN=0 in .env
#   4. docker compose up -d
#   5. verify serve health on 127.0.0.1:4848 and "gateway connected as" in
#      the bridge logs
#   6. on any failure: automatic rollback (stop containers, restore plists,
#      reload launchd agents, restore BRIDGE_DRY_RUN=1)
#
# Run it:        bash docker/cutover.sh
# Rollback only: bash docker/cutover.sh --rollback

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

AGENTS=(com.jax.discord-bridge com.jax.opencode-serve)
LA_DIR="$HOME/Library/LaunchAgents"
PARKED_DIR="$LA_DIR/behalfbot-parked"
UID_N="$(id -u)"
VERIFY_TIMEOUT=90

log() { printf '[cutover] %s\n' "$*"; }

set_dry_run() {  # set_dry_run 0|1
  local val="$1"
  if grep -q '^BRIDGE_DRY_RUN=' .env 2>/dev/null; then
    sed -i '' "s/^BRIDGE_DRY_RUN=.*/BRIDGE_DRY_RUN=$val/" .env
  else
    printf '\nBRIDGE_DRY_RUN=%s\n' "$val" >> .env
  fi
}

rollback() {
  log "ROLLBACK: stopping container bridge (frees the Jill token)"
  docker compose stop discord-bridge || true
  set_dry_run 1
  for a in "${AGENTS[@]}"; do
    if [ -f "$PARKED_DIR/$a.plist" ]; then
      mv "$PARKED_DIR/$a.plist" "$LA_DIR/$a.plist"
    fi
    if [ -f "$LA_DIR/$a.plist" ]; then
      launchctl bootstrap "gui/$UID_N" "$LA_DIR/$a.plist" 2>/dev/null || \
        launchctl kickstart -k "gui/$UID_N/$a" 2>/dev/null || true
      log "restored host agent $a"
    else
      log "WARNING: no plist found for $a - restore it by hand (bridge/WIRING.md section 5)"
    fi
  done
  log "ROLLBACK complete: host launchd stack is authoritative again."
}

if [ "${1:-}" = "--rollback" ]; then
  rollback
  exit 0
fi

# --- preflight --------------------------------------------------------------
command -v docker >/dev/null || { log "docker not found"; exit 1; }
docker info >/dev/null 2>&1 || { log "docker daemon down - run: colima start"; exit 1; }
[ -f .env ] || { log ".env missing - see .env.example"; exit 1; }
grep -q '^DISCORD_BOT_TOKEN=..*' .env || { log "DISCORD_BOT_TOKEN missing from .env"; exit 1; }

log "building image (no-op if current)"
docker compose build --quiet

# --- 1+2: retire the host launchd agents ------------------------------------
mkdir -p "$PARKED_DIR"
for a in "${AGENTS[@]}"; do
  launchctl bootout "gui/$UID_N/$a" 2>/dev/null && log "booted out $a" \
    || log "$a was not loaded"
  if [ -f "$LA_DIR/$a.plist" ]; then
    mv "$LA_DIR/$a.plist" "$PARKED_DIR/$a.plist"
    log "parked $LA_DIR/$a.plist -> $PARKED_DIR/"
  fi
done

log "waiting 10s for Discord to release the old gateway session"
sleep 10

# --- 3+4: go live in Docker ---------------------------------------------------
set_dry_run 0
log "BRIDGE_DRY_RUN=0 set in .env; starting compose stack"
docker compose up -d

# --- 5: verify ----------------------------------------------------------------
log "verifying opencode serve on 127.0.0.1:4848"
ok_serve=0
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:4848/global/health >/dev/null 2>&1; then
    ok_serve=1; break
  fi
  sleep 2
done
if [ "$ok_serve" != 1 ]; then
  log "FAIL: containerized opencode serve never went healthy"
  rollback
  exit 1
fi
log "serve healthy"

log "verifying bridge gateway connection (up to ${VERIFY_TIMEOUT}s)"
ok_bridge=0
for _ in $(seq 1 $((VERIFY_TIMEOUT / 3))); do
  if docker compose logs --since 5m discord-bridge 2>/dev/null | grep -q "gateway connected as"; then
    ok_bridge=1; break
  fi
  # a crash-looping bridge shows up as restarts; bail early if it is dying
  state="$(docker inspect -f '{{.State.Restarting}} {{.RestartCount}}' behalfbot-discord-bridge 2>/dev/null || echo '')"
  case "$state" in *" 3"*|*" 4"*|*" 5"*) log "bridge crash-looping ($state)"; break ;; esac
  sleep 3
done
if [ "$ok_bridge" != 1 ]; then
  log "FAIL: container bridge did not connect to Discord"
  docker compose logs --tail 30 discord-bridge || true
  rollback
  exit 1
fi

log "SUCCESS: container bridge connected as Jill. Host launchd agents retired"
log "(plists parked in $PARKED_DIR - delete once the container stack has run clean for a day)."
log "Smoke test: as the principal, send a message in the allowlisted channel."
