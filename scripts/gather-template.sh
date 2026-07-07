#!/usr/bin/env bash
# gather-template.sh - template for a heartbeat gather script.
#
# The dispatcher fires every 15 min on a fixed cadence. Gather scripts decide
# whether the model gets to run. Most of them MUST short-circuit cheaply (no
# paid API calls, no slow I/O) when there is no work - that's how 96
# dispatcher runs/day translate to ~4 model invocations.
#
# Contract:
#   - Invoked by the dispatcher with its working directory set to
#     $BEHALFBOT_HOME (the repo root). Don't assume any other CWD.
#   - The dispatcher parses stdout as JSON.
#     - For `condition: threshold count > 0`: emit `{"count": N}` (and any
#       additional structured fields the prompt may need).
#     - For `condition: ask_model`: emit any JSON; the model decides.
#     - For `condition: always`: emit `{}` or any context the prompt needs.
#   - Bare `count=N` text is rejected by the dispatcher and treated as
#     count=0. Always emit JSON.
#   - Exit 0 on success, even when there's no work. Exit non-zero only on
#     genuine failures (bad credentials, network unreachable). Non-zero exit
#     gets logged and the heartbeat skips this tick.
#
# Lessons carried over from the chassis:
#   - gather-first dispatcher: this script gates every paid invocation
#   - register every heartbeat in HEARTBEATS.md (this script is dead until
#     its heartbeat block is registered)
#   - if multiple heartbeats need the same destructive-read source, write a
#     cached digest file once and have downstream gathers read the cache,
#     not the source. Otherwise the second heartbeat sees zero state.
#   - cheap no-op gates short-circuit before any expensive I/O

set -euo pipefail

BEHALFBOT_HOME="${BEHALFBOT_HOME:-$(pwd)}"
BEHALFBOT_STATE_HOME="${BEHALFBOT_STATE_HOME:-$BEHALFBOT_HOME}"
STATE_FILE="${BEHALFBOT_STATE_HOME}/scheduled-tasks/example-state.json"

# --- Cheap no-op gates ---
#
# Add ALL trivial short-circuit conditions here BEFORE any expensive I/O.
# Examples:
#   - feature flag disabled
#   - out-of-window (e.g. only run during business hours)
#   - last-fired-too-recently
#   - dependency unavailable

# Example: only run between 06:00 and 23:00 local
HOUR=$(date +%H | sed 's/^0//')
if [[ $HOUR -lt 6 || $HOUR -ge 23 ]]; then
    echo '{"count": 0, "reason": "out_of_window"}'
    exit 0
fi

# --- Real work ---
#
# Whatever signal source this gather is supposed to check goes here. Keep it
# cheap: jq over a local file, a sqlite3 SELECT, an HTTP HEAD against your
# own infrastructure. Avoid third-party API calls except where the specific
# feature requires them.
#
# Pattern: read a state file or query a local DB -> count items needing work
# -> emit count.

count=0  # replace with actual logic - e.g. unread inbox count, queue depth

# Persist any state the gather should remember across runs (last-seen IDs,
# watermarks). The dispatcher does NOT persist gather state - each gather
# script owns its own state file.
if [[ ! -f "$STATE_FILE" ]]; then
    mkdir -p "$(dirname "$STATE_FILE")"
    echo '{}' > "$STATE_FILE"
fi

# --- Emit JSON ---

jq -n --argjson count "$count" '{"count": $count}'
