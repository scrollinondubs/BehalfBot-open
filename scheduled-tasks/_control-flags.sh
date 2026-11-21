#!/usr/bin/env bash
# _control-flags.sh - the dispatcher's reader for the halt and conservation
# flags. Sourced, not executed. Ported from the chassis
# (chassis/scripts/_control-flags.sh, behalfbot 47a13d6) with one change:
# it NEVER writes.
#
# Both flags share one five-key schema (gateway/control_flags.py has the
# Python twin, used by jill-control, the only writer):
#
#   {"enabled": bool, "enabled_at": ts, "enabled_by": str,
#    "auto_lift_after": ts, "reason": str}
#
# In the compose stack the dispatcher mounts the control-state volume
# read-only, so the chassis behaviour of rewriting an expired flag to "off"
# is not available and not wanted: an expired auto-lift reads as off here,
# and jill-control clears the file on its own loop.
#
# Failure direction: a flag file that exists but cannot be parsed, or whose
# auto_lift_after cannot be parsed, reads as ON. The chassis paid for the
# opposite once: a BSD-only `date -j` made every auto-lift parse as epoch 0,
# so a throttle with an expiry lifted itself on the next tick while logging
# the same line a working auto-lift logs.
#
# Locals are _cf_-prefixed and every substitution is guarded, because the
# caller runs under `set -euo pipefail`.

# control_parse_iso8601 <timestamp> - epoch seconds, or return 1.
control_parse_iso8601() {
    local _cf_ts="$1" _cf_out=""
    [[ -n "$_cf_ts" ]] || return 1
    _cf_out=$(date -u -d "$_cf_ts" +%s 2>/dev/null) || _cf_out=""
    if [[ -z "$_cf_out" ]]; then
        _cf_out=$(date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$_cf_ts" +%s 2>/dev/null) || _cf_out=""
    fi
    [[ "$_cf_out" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$_cf_out"
}

# control_flag_state <file> - prints on | off | expired. Never writes.
control_flag_state() {
    local _cf_flag="$1" _cf_enabled="" _cf_lift="" _cf_lift_epoch=""
    if [[ ! -e "$_cf_flag" ]]; then
        printf 'off\n'
        return 0
    fi
    if ! jq -e 'type == "object"' "$_cf_flag" >/dev/null 2>&1; then
        printf 'on\n'
        return 0
    fi
    # `enabled` must be the boolean true, and auto_lift_after null or exactly
    # YYYY-MM-DDTHH:MM:SSZ. Anything else is invalid, so on (red-team F6).
    _cf_enabled=$(jq -r 'if has("enabled") | not then "false"
                         elif (.enabled | type) == "boolean" then (.enabled | tostring)
                         else "invalid" end' "$_cf_flag" 2>/dev/null) || _cf_enabled="invalid"
    case "$_cf_enabled" in
        true) ;;
        false) printf 'off\n'; return 0 ;;
        *) printf 'on\n'; return 0 ;;
    esac
    _cf_lift=$(jq -r '.auto_lift_after | if . == null then "__none__" elif type == "string" then . else "invalid" end' \
        "$_cf_flag" 2>/dev/null) || _cf_lift="invalid"
    if [[ "$_cf_lift" == "__none__" ]]; then
        printf 'on\n'
        return 0
    fi
    if [[ ! "$_cf_lift" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
        printf 'on\n'
        return 0
    fi
    _cf_lift_epoch=$(control_parse_iso8601 "$_cf_lift") || {
        printf 'on\n'
        return 0
    }
    if [[ "$(date +%s)" -ge "$_cf_lift_epoch" ]]; then
        printf 'expired\n'
    else
        printf 'on\n'
    fi
}
