#!/usr/bin/env bash
# setup-secrets.sh - write Jill's .env (BehalfBot-open#52). Sean runs this
# signed in as her macOS user (jillvibe by default), pasting keys from
# 1Password. Jax never holds these values and never runs it.
#
#   bash launch/setup-secrets.sh           # prompt for anything missing
#   bash launch/setup-secrets.sh --check   # only report which keys are set
#
# - Secrets are read with no echo and never printed, logged or put on a
#   command line (curl gets them on stdin). Output names keys, never values.
# - .env is written mode 600 through a temp file in the same directory, then
#   renamed. A missing .env starts from .env.example (comments kept).
# - A key that is already set is kept unless you answer y to replacing it.
# - OPENCODE_SERVER_PASSWORD is generated (openssl rand -hex 32) if empty.
# - MATRIX_CONTROL_TOKEN can be pasted, or obtained by logging in to the
#   control account here (its password is typed hidden and not stored); the
#   control account can then join the control and alerts rooms.
#
# Plain bash 3.2 (stock macOS). ENV_FILE and JILL_USER override the defaults.

set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/.env}"
EXAMPLE="$REPO_ROOT/.env.example"
JILL_USER="${JILL_USER:-jillvibe}"
PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
export PATH
CHECK_ONLY=0

for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '[setup-secrets] %s\n' "$*"; }
die() { printf '[setup-secrets] FAIL: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "do not run this as root; sign in as $JILL_USER"
[ "$(id -un)" = "$JILL_USER" ] || die "running as '$(id -un)', expected '$JILL_USER' (set JILL_USER if her account has another name)"

REQUIRED="VENICE_API_KEY OPENCODE_SERVER_PASSWORD MATRIX_HOMESERVER MATRIX_PRINCIPAL MATRIX_CONTROL_TOKEN MATRIX_CONTROL_ROOM MATRIX_JILL_USER MATRIX_JILL_ROOM"
OPTIONAL="AGENTMAIL_API_KEY AGENTMAIL_INBOX BRAVE_API_KEY SIYUAN_URL SIYUAN_TOKEN TAVILY_API_KEY MATRIX_ALERTS_ROOM"
MANAGED="$REQUIRED $OPTIONAL"
FORBIDDEN="ANTHROPIC_API_KEY OPENROUTER_API_KEY OPENAI_API_KEY"

# The value of KEY in .env, unquoted ('' if absent). Never printed.
current() {
  local key="$1" line v=""
  [ -f "$ENV_FILE" ] || { printf ''; return 0; }
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$key="*) v="${line#*=}" ;;
    esac
  done < "$ENV_FILE"
  case "$v" in
    \'*\') v="${v#\'}"; v="${v%\'}" ;;
    \"*\") v="${v#\"}"; v="${v%\"}" ;;
  esac
  printf '%s' "$v"
}

# What KEY will be after this run: a new value if one was entered.
effective() {
  local name="NEW_$1"
  if [ -n "${!name+x}" ]; then printf '%s' "${!name}"; else current "$1"; fi
}

is_set() { [ -n "$(effective "$1")" ]; }

report() {
  local key bad=0
  for key in $REQUIRED; do
    if is_set "$key"; then say "PASS  $key set"; else say "FAIL  $key missing"; bad=1; fi
  done
  for key in $OPTIONAL; do
    if is_set "$key"; then say "ok    $key set"; else say "--    $key not set (optional)"; fi
  done
  for key in $FORBIDDEN; do
    if is_set "$key"; then say "WARN  $key is set; Jill runs on Venice only, remove it"; fi
  done
  return "$bad"
}

if [ "$CHECK_ONLY" -eq 1 ]; then
  [ -f "$ENV_FILE" ] || die "$ENV_FILE does not exist"
  report
  exit $?
fi

[ -t 0 ] || say "stdin is not a terminal; reading answers from it"

yesno() {  # yesno "question" default(y|n)
  local ans
  printf '%s [%s] ' "$1" "$([ "$2" = y ] && echo Y/n || echo y/N)"
  IFS= read -r ans || ans=""
  [ -n "$ans" ] || ans="$2"
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

valid_value() {  # no newline or single quote: .env values are single-quoted
  case "$1" in
    *"'"*) say "that value contains a single quote, which .env cannot hold here; not saved"; return 1 ;;
  esac
  case "$1" in
    *$'\n'*|*$'\r'*) say "that value contains a line break; not saved"; return 1 ;;
  esac
  return 0
}

check_format() {  # check_format KEY VALUE
  case "$1" in
    MATRIX_PRINCIPAL|MATRIX_JILL_USER)
      case "$2" in @?*:?*) return 0 ;; *) say "$1 must be a full user id like @name:server"; return 1 ;; esac ;;
    MATRIX_CONTROL_ROOM|MATRIX_JILL_ROOM|MATRIX_ALERTS_ROOM)
      case "$2" in !?*:?*) return 0 ;; *) say "$1 must be a room id like !abc:server (Room settings > Advanced), not an alias"; return 1 ;; esac ;;
    MATRIX_HOMESERVER|SIYUAN_URL)
      case "$2" in http://?*|https://?*) return 0 ;; *) say "$1 must start with http:// or https://"; return 1 ;; esac ;;
  esac
  return 0
}

# ask KEY secret|plain required|optional "what it is" [default]
ask() {
  local key="$1" kind="$2" need="$3" what="$4" def="${5:-}" val tries=0
  if is_set "$key"; then
    yesno "$key is already set. Replace it?" n || return 0
  fi
  while :; do
    tries=$((tries + 1))
    if [ "$kind" = secret ]; then
      printf '%s - %s (hidden; Enter to skip): ' "$key" "$what"
      IFS= read -rs val || val=""
      printf '\n'
    else
      if [ -n "$def" ]; then printf '%s - %s [%s]: ' "$key" "$what" "$def"; else printf '%s - %s: ' "$key" "$what"; fi
      IFS= read -r val || val=""
      [ -n "$val" ] || val="$def"
    fi
    if [ -z "$val" ]; then
      if [ "$need" = required ] && ! is_set "$key"; then
        [ "$tries" -lt 3 ] || { say "$key left empty"; return 0; }
        say "$key is required"
        continue
      fi
      return 0
    fi
    if valid_value "$val" && check_format "$key" "$val"; then
      printf -v "NEW_$key" '%s' "$val"
      if [ "$kind" = secret ]; then say "$key saved (${#val} characters)"; else say "$key saved"; fi
      val=""
      return 0
    fi
    val=""
    [ "$tries" -lt 3 ] || return 0
  done
}

# The homeserver as this Mac sees it (containers use host.docker.internal).
host_view() { local u="$1"; printf '%s' "${u/host.docker.internal/127.0.0.1}"; }

url_room() { local r="$1"; r="${r//!/%21}"; r="${r//:/%3A}"; printf '%s' "$r"; }

matrix_login() {
  local hs cuser pw esc body resp tok code
  hs="$(host_view "$(effective MATRIX_HOMESERVER)")"
  printf 'Control account full user id (for example @jill-control:<server>): '
  IFS= read -r cuser || cuser=""
  case "$cuser" in @?*:?*) ;; *) say "not a full user id; skipped"; return 0 ;; esac
  printf 'Password for %s (hidden): ' "$cuser"
  IFS= read -rs pw || pw=""
  printf '\n'
  [ -n "$pw" ] || { say "no password; skipped"; return 0; }
  esc="${pw//\\/\\\\}"; esc="${esc//\"/\\\"}"
  body="$(printf '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"%s"},"password":"%s","initial_device_display_name":"jill-control"}' "$cuser" "$esc")"
  pw=""; esc=""
  resp="$(printf '%s' "$body" | curl -sS -m 20 -X POST -H 'Content-Type: application/json' --data-binary @- "$hs/_matrix/client/v3/login" 2>/dev/null || true)"
  body=""
  tok="$(printf '%s' "$resp" | sed -n 's/.*"access_token" *: *"\([^"]*\)".*/\1/p')"
  if [ -z "$tok" ]; then
    code="$(printf '%s' "$resp" | sed -n 's/.*"errcode" *: *"\([^"]*\)".*/\1/p')"
    resp=""
    say "login failed (${code:-no answer from $hs}); paste a token instead or retry"
    return 0
  fi
  resp=""
  # shellcheck disable=SC2034  # read through effective()'s indirection
  printf -v NEW_MATRIX_CONTROL_TOKEN '%s' "$tok"
  say "MATRIX_CONTROL_TOKEN saved from a new login (device jill-control)"
  local room key status
  for key in MATRIX_CONTROL_ROOM MATRIX_ALERTS_ROOM; do
    room="$(effective "$key")"
    [ -n "$room" ] || continue
    if yesno "Have the control account join $key now (invite it first in Element)?" y; then
      status="$(printf 'Authorization: Bearer %s\n' "$tok" | curl -sS -m 20 -o /dev/null -w '%{http_code}' -X POST \
        -H @- -H 'Content-Type: application/json' --data '{}' "$hs/_matrix/client/v3/join/$(url_room "$room")" 2>/dev/null || true)"
      if [ "$status" = 200 ]; then say "joined $key"; else say "join $key: HTTP ${status:-none} (invite the control account, then rerun or join from Element)"; fi
    fi
  done
  tok=""
}

if [ ! -f "$ENV_FILE" ]; then
  [ -f "$EXAMPLE" ] || die "neither $ENV_FILE nor $EXAMPLE exists"
  say "no .env yet; starting from .env.example"
fi

say "Matrix (ids are not secret; see docs/LAUNCH.md for creating the accounts and rooms)"
ask MATRIX_HOMESERVER plain required "homeserver URL as the containers see it" "http://host.docker.internal:8008"
ask MATRIX_PRINCIPAL plain required "Sean's full Matrix user id"
ask MATRIX_JILL_USER plain required "Jill's full Matrix user id"
ask MATRIX_JILL_ROOM plain required "the ENCRYPTED room Sean shares with Jill (room id)"
ask MATRIX_CONTROL_ROOM plain required "the UNENCRYPTED control room (room id)"
ask MATRIX_ALERTS_ROOM plain optional "separate alerts room (room id; empty = control room)"

say "Control account token (the kill switch's bot, not Jill and not Sean)"
if is_set MATRIX_CONTROL_TOKEN && ! yesno "MATRIX_CONTROL_TOKEN is already set. Replace it?" n; then
  :
elif yesno "Log in to the control account here to get its token?" y; then
  matrix_login
  is_set MATRIX_CONTROL_TOKEN || ask MATRIX_CONTROL_TOKEN secret required "the control account's access token"
else
  ask MATRIX_CONTROL_TOKEN secret required "the control account's access token"
fi

say "Keys from 1Password"
ask VENICE_API_KEY secret required "Venice API key (Jill's own)"
ask AGENTMAIL_API_KEY secret optional "AgentMail API key (Jill's inbox)"
ask AGENTMAIL_INBOX plain optional "AgentMail inbox address" "jill-agent@agentmail.to"
ask BRAVE_API_KEY secret optional "Brave Search API key"
ask SIYUAN_URL plain optional "SiYuan API URL as the containers see it"
ask SIYUAN_TOKEN secret optional "SiYuan API token"
ask TAVILY_API_KEY secret optional "Tavily API key"

if ! is_set OPENCODE_SERVER_PASSWORD; then
  gen="$(openssl rand -hex 32)" || die "openssl rand failed"
  # shellcheck disable=SC2034  # read through effective()'s indirection
  printf -v NEW_OPENCODE_SERVER_PASSWORD '%s' "$gen"
  gen=""
  say "OPENCODE_SERVER_PASSWORD generated"
fi

# Write: keep every line we do not manage, replace the managed ones.
src="$ENV_FILE"
[ -f "$src" ] || src="$EXAMPLE"
dir="$(dirname "$ENV_FILE")"
tmp="$(mktemp "$dir/.env.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
written=" "
emit() {  # emit KEY: the managed line, from the new or current value
  local v
  v="$(effective "$1")"
  printf "%s='%s'\n" "$1" "$v"
  written="$written$1 "
}
managed() { case " $MANAGED " in *" $1 "*) return 0 ;; esac; return 1; }

# shellcheck disable=SC2094  # reads $src, writes $tmp
{
  while IFS= read -r line || [ -n "$line" ]; do
    key="${line%%=*}"
    if [ "$key" != "$line" ] && managed "$key"; then
      case "$written" in *" $key "*) continue ;; esac
      if ! is_set "$key"; then printf '%s\n' "$line"; written="$written$key "; continue; fi
      emit "$key"
    else
      printf '%s\n' "$line"
    fi
  done < "$src"
  for key in $MANAGED; do
    case "$written" in *" $key "*) continue ;; esac
    is_set "$key" && emit "$key"
  done
} > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$ENV_FILE"
trap - EXIT
chmod 600 "$ENV_FILE"
say "wrote $ENV_FILE (mode $(stat -f '%Lp' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE"))"

report
