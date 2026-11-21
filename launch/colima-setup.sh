#!/usr/bin/env bash
# colima-setup.sh - Jill's own Docker: a Colima VM owned by her macOS user
# (BehalfBot-open#52). Sean runs this signed in as that user (jillvibe by
# default). Jax has no access to the account and never runs it.
#
#   bash launch/colima-setup.sh                 # create or start the VM
#   bash launch/colima-setup.sh --install-agent # also install the boot agent
#
# Idempotent: a VM that exists is started with its saved settings (to resize
# one, `colima stop` and run `colima start --cpu N --memory N` by hand); a
# running VM is left alone. Each macOS user has their own ~/.colima, so this
# VM, its Docker socket and its volumes are separate from any other user's.
#
# Sizing (first run only), overridable from the environment:
#   JILL_COLIMA_CPU=2 JILL_COLIMA_MEMORY=6 JILL_COLIMA_DISK=40
# The stack is opencode serve plus gateways, each gateway capped at 512 MB.
#
# Plain bash 3.2 (stock macOS); no secrets are read or printed.

set -euo pipefail

JILL_USER="${JILL_USER:-jillvibe}"
CPU="${JILL_COLIMA_CPU:-2}"
MEMORY="${JILL_COLIMA_MEMORY:-6}"
DISK="${JILL_COLIMA_DISK:-40}"
INSTALL_AGENT=0

for arg in "$@"; do
  case "$arg" in
    --install-agent) INSTALL_AGENT=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
export PATH

say() { printf '[colima-setup] %s\n' "$*"; }
die() { printf '[colima-setup] FAIL: %s\n' "$*" >&2; exit 1; }

me="$(id -un)"
[ "$(id -u)" -ne 0 ] || die "do not run this as root; sign in as $JILL_USER"
[ "$me" = "$JILL_USER" ] || die "running as '$me', expected '$JILL_USER' (set JILL_USER if her account has another name)"

for tool in colima limactl docker git; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH; an admin installs it with: brew install colima docker docker-compose git"
done

# docker compose: Homebrew's plugin lives outside the default search path.
# A per-user symlink is the least invasive way to make `docker compose` work
# (it leaves ~/.docker/config.json to Colima).
if ! docker compose version >/dev/null 2>&1; then
  plugin=""
  for p in /opt/homebrew/lib/docker/cli-plugins/docker-compose /usr/local/lib/docker/cli-plugins/docker-compose; do
    if [ -x "$p" ]; then plugin="$p"; break; fi
  done
  [ -n "$plugin" ] || die "docker compose plugin not found; an admin installs it with: brew install docker-compose"
  mkdir -p "$HOME/.docker/cli-plugins"
  ln -sf "$plugin" "$HOME/.docker/cli-plugins/docker-compose"
  docker compose version >/dev/null 2>&1 || die "docker compose still not found after linking $plugin"
  say "linked the docker compose plugin into ~/.docker/cli-plugins"
fi

if colima status >/dev/null 2>&1; then
  say "Colima is already running for $me"
elif [ -d "$HOME/.colima/default" ]; then
  say "starting the existing Colima VM (saved settings)"
  colima start
else
  say "creating Colima VM: ${CPU} CPU, ${MEMORY} GiB memory, ${DISK} GiB disk (vz, virtiofs)"
  colima start --cpu "$CPU" --memory "$MEMORY" --disk "$DISK" --vm-type vz --mount-type virtiofs
fi

for _ in $(seq 1 30); do
  docker info >/dev/null 2>&1 && break
  sleep 2
done
docker info >/dev/null 2>&1 || die "the Docker daemon in Colima never answered"

# The socket in use must be this user's own, never another user's VM.
host="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
if [ -n "${DOCKER_HOST:-}" ]; then
  die "DOCKER_HOST is set ($DOCKER_HOST); unset it so the colima context is used"
fi
case "$host" in
  "unix://$HOME/.colima/"*) say "docker uses this user's socket: $host" ;;
  *) die "docker context points at '$host', not $HOME/.colima; run: docker context use colima" ;;
esac

if [ "$INSTALL_AGENT" -eq 1 ]; then
  label="com.${JILL_USER}.behalfbot-docker"
  agents="$HOME/Library/LaunchAgents"
  plist="$agents/$label.plist"
  mkdir -p "$agents" "$REPO_ROOT/logs"
  sed -e "s|__REPO_ROOT__|$REPO_ROOT|g" -e "s|com.jax.behalfbot-docker|$label|g" \
    "$REPO_ROOT/docker/com.jax.behalfbot-docker.plist" > "$plist.tmp"
  mv "$plist.tmp" "$plist"
  uid="$(id -u)"
  launchctl bootout "gui/$uid/$label" >/dev/null 2>&1 || true
  if launchctl bootstrap "gui/$uid" "$plist" 2>/dev/null; then
    say "boot agent installed: gui/$uid/$label (runs docker/boot.sh at login)"
  else
    say "could not load into gui/$uid (no GUI session for $me?); the plist is at $plist"
    say "load it from a login session of $me: launchctl bootstrap gui/$uid $plist"
  fi
fi

say "done. Colima:"
colima list
