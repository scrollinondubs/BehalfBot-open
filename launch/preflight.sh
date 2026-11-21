#!/usr/bin/env bash
# preflight.sh - check every prerequisite for Jill's launch (BehalfBot-open#52)
# and print PASS / FAIL / WARN per item. Sean runs it signed in as her macOS
# user (jillvibe by default) from the repo checkout:
#
#   bash launch/preflight.sh
#
# Prints key NAMES and non-secret ids only, never a secret value. Matrix
# tokens reach curl on stdin inside a throwaway container, never on a
# command line. It changes nothing (no build, no start, no write) and makes
# no paid call: the Matrix checks are a version query and two whoami calls.
# Exit 0 when nothing FAILed. Plain bash 3.2. ENV_FILE and JILL_USER
# override the defaults.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/.env}"
JILL_USER="${JILL_USER:-jillvibe}"
IMAGE="${JILL_IMAGE:-behalfbot-open:latest}"
PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
export PATH
cd "$REPO_ROOT" || exit 2

fails=0
warns=0
pass() { printf 'PASS  %-28s %s\n' "$1" "${2:-}"; }
fail() { printf 'FAIL  %-28s %s\n' "$1" "${2:-}"; fails=$((fails + 1)); }
warn() { printf 'WARN  %-28s %s\n' "$1" "${2:-}"; warns=$((warns + 1)); }
info() { printf 'INFO  %-28s %s\n' "$1" "${2:-}"; }

# .env value, unquoted; never printed by this script except for the ids
# listed as non-secret below.
envval() {
  local key="$1" line v=""
  [ -r "$ENV_FILE" ] || { printf ''; return 0; }
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in "$key="*) v="${line#*=}" ;; esac
  done < "$ENV_FILE"
  case "$v" in
    \'*\') v="${v#\'}"; v="${v%\'}" ;;
    \"*\") v="${v#\"}"; v="${v%\"}" ;;
  esac
  printf '%s' "$v"
}

# --- the account --------------------------------------------------------
me="$(id -un)"
if [ "$(id -u)" -eq 0 ]; then fail "user" "running as root"
elif [ "$me" = "$JILL_USER" ]; then pass "user" "$me"
else fail "user" "running as '$me', expected '$JILL_USER'"
fi

# --- tools ----------------------------------------------------------------
for tool in colima limactl docker git curl openssl; do
  if command -v "$tool" >/dev/null 2>&1; then pass "tool $tool" "$(command -v "$tool")"; else fail "tool $tool" "not on PATH (brew install $tool)"; fi
done
if docker compose version >/dev/null 2>&1; then pass "tool docker compose" "$(docker compose version --short 2>/dev/null)"
else fail "tool docker compose" "missing; run launch/colima-setup.sh"; fi

# --- this user's own Docker -----------------------------------------------
docker_ok=0
if colima status >/dev/null 2>&1; then pass "colima running" "profile default, owner $me"
else fail "colima running" "not running for $me; run launch/colima-setup.sh"; fi
if [ -n "${DOCKER_HOST:-}" ]; then fail "docker socket" "DOCKER_HOST is set; unset it"
else
  host="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
  case "$host" in
    "unix://$HOME/.colima/"*)
      if docker info >/dev/null 2>&1; then pass "docker socket" "$host"; docker_ok=1
      else fail "docker socket" "$host does not answer"; fi ;;
    *) fail "docker socket" "context points at '${host:-none}', not this user's ~/.colima (docker context use colima)" ;;
  esac
fi

# --- the checkout ---------------------------------------------------------
if git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  pass "repo" "$(git -C "$REPO_ROOT" rev-parse --short HEAD) on $(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"
  if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no 2>/dev/null)" ]; then
    warn "repo clean" "tracked files are modified; the eval records the commit, so run it from a clean tree"
  else pass "repo clean" ""; fi
else fail "repo" "$REPO_ROOT is not a git checkout"; fi

# --- .env -----------------------------------------------------------------
if [ ! -f "$ENV_FILE" ]; then
  fail ".env" "missing; run launch/setup-secrets.sh"
else
  owner="$(stat -f '%Su' "$ENV_FILE" 2>/dev/null || stat -c '%U' "$ENV_FILE")"
  mode="$(stat -f '%Lp' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE")"
  if [ "$mode" = 600 ] && [ "$owner" = "$me" ]; then pass ".env mode" "600, owner $owner"
  else fail ".env mode" "mode $mode owner $owner; want 600 owned by $me (chmod 600 .env)"; fi
  for key in VENICE_API_KEY OPENCODE_SERVER_PASSWORD MATRIX_CONTROL_TOKEN MATRIX_PRINCIPAL MATRIX_CONTROL_ROOM MATRIX_JILL_USER MATRIX_JILL_ROOM; do
    if [ -n "$(envval "$key")" ]; then pass "env $key" "set"; else fail "env $key" "missing (launch/setup-secrets.sh)"; fi
  done
  for key in AGENTMAIL_API_KEY BRAVE_API_KEY SIYUAN_TOKEN; do
    if [ -n "$(envval "$key")" ]; then pass "env $key" "set"; else info "env $key" "not set; that tool stays off"; fi
  done
  for key in ANTHROPIC_API_KEY OPENROUTER_API_KEY OPENAI_API_KEY; do
    if [ -n "$(envval "$key")" ]; then warn "env $key" "set; Jill runs on Venice only, remove it"; fi
  done
  # Non-secret ids, checked for shape.
  for key in MATRIX_PRINCIPAL MATRIX_JILL_USER; do
    v="$(envval "$key")"
    case "$v" in @?*:?*) pass "id $key" "$v" ;; "") ;; *) fail "id $key" "'$v' is not @name:server" ;; esac
  done
  for key in MATRIX_JILL_ROOM MATRIX_CONTROL_ROOM; do
    v="$(envval "$key")"
    case "$v" in !?*:?*) pass "id $key" "$v" ;; "") ;; *) fail "id $key" "'$v' is not a room id (!abc:server)" ;; esac
  done
  if [ -n "$(envval MATRIX_PRINCIPAL)" ] && [ "$(envval MATRIX_PRINCIPAL)" = "$(envval MATRIX_JILL_USER)" ]; then
    fail "id MATRIX_JILL_USER" "is Sean's own id"
  fi
  if [ -n "$(envval MATRIX_JILL_ROOM)" ] && [ "$(envval MATRIX_JILL_ROOM)" = "$(envval MATRIX_CONTROL_ROOM)" ]; then
    fail "id MATRIX_CONTROL_ROOM" "same room as the encrypted chat room; they must differ"
  fi
  # docker compose takes a variable from the shell before .env.
  for key in VENICE_API_KEY OPENCODE_SERVER_PASSWORD MATRIX_CONTROL_TOKEN MATRIX_PRINCIPAL MATRIX_CONTROL_ROOM \
             MATRIX_JILL_USER MATRIX_JILL_ROOM MATRIX_HOMESERVER AGENTMAIL_API_KEY BRAVE_API_KEY SIYUAN_TOKEN VENICE_MAX_USD_PER_DAY; do
    if [ -n "${!key+x}" ]; then fail "shell $key" "exported in this shell; it overrides .env for docker compose (unset it)"; fi
  done
  ceiling="$(envval VENICE_MAX_USD_PER_DAY)"
  info "Venice ceiling" "VENICE_MAX_USD_PER_DAY=${ceiling:-5 (default)}; 50 only for the eval run, then back to 5"
fi

# --- images ---------------------------------------------------------------
if [ "$docker_ok" -eq 1 ]; then
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    pass "image $IMAGE" "$(docker image inspect "$IMAGE" --format '{{.Id}}' | cut -c1-19)"
  else
    fail "image $IMAGE" "not built; docker compose build"
  fi
  if grep -q '^  opencode-eval:' docker-compose.yml 2>/dev/null; then
    if docker image inspect behalfbot-open:eval >/dev/null 2>&1; then pass "image behalfbot-open:eval" "built"
    else warn "image behalfbot-open:eval" "not built yet; docs/control.md step F builds it"; fi
  fi
  if docker volume ls --format '{{.Name}}' 2>/dev/null | grep -q '_matrix-bridge-state$'; then
    info "matrix-bridge setup" "state volume exists (setup has run at least once)"
  else
    info "matrix-bridge setup" "not run yet (docker compose run --rm matrix-bridge-setup)"
  fi
fi

# --- Matrix, from a container (as the stack sees it) -----------------------
hs="$(envval MATRIX_HOMESERVER)"
hs="${hs:-http://host.docker.internal:8008}"
if [ "$docker_ok" -eq 1 ] && docker image inspect "$IMAGE" >/dev/null 2>&1; then
  incurl() { docker run --rm -i --network bridge --entrypoint curl "$IMAGE" "$@"; }
  code="$(incurl -sS -m 10 -o /dev/null -w '%{http_code}' "$hs/_matrix/client/versions" </dev/null 2>/dev/null || true)"
  if [ "$code" = 200 ]; then pass "homeserver reachable" "$hs from a container"
  else fail "homeserver reachable" "$hs answered '${code:-nothing}' from a container"; fi

  whoami() {  # whoami KEY: the user id the token belongs to, or ''
    local tok
    tok="$(envval "$1")"
    [ -n "$tok" ] || return 0
    printf 'Authorization: Bearer %s\n' "$tok" | incurl -sS -m 10 -H @- "$hs/_matrix/client/v3/account/whoami" 2>/dev/null \
      | sed -n 's/.*"user_id" *: *"\([^"]*\)".*/\1/p'
    tok=""
  }
  if [ "$code" = 200 ]; then
    who="$(whoami MATRIX_CONTROL_TOKEN)"
    if [ -z "$who" ]; then fail "control token" "rejected by the homeserver (or not set)"
    elif [ "$who" = "$(envval MATRIX_PRINCIPAL)" ] || [ "$who" = "$(envval MATRIX_JILL_USER)" ]; then
      fail "control token" "belongs to $who; the kill switch needs its own account"
    else pass "control token" "valid, $who"; fi
  fi
else
  warn "homeserver reachable" "skipped (needs Docker and $IMAGE)"
fi

# --- boot agent -----------------------------------------------------------
label="com.${JILL_USER}.behalfbot-docker"
if launchctl print "gui/$(id -u)/$label" >/dev/null 2>&1; then pass "boot agent" "$label loaded"
else info "boot agent" "not loaded (launch/colima-setup.sh --install-agent, after the eval passes)"; fi

echo
if [ "$fails" -eq 0 ]; then
  printf 'PREFLIGHT PASS (%d warning(s))\n' "$warns"
  exit 0
fi
printf 'PREFLIGHT FAIL: %d item(s) failed, %d warning(s)\n' "$fails" "$warns"
exit 1
