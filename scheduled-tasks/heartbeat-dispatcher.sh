#!/usr/bin/env bash
# BehalfBot-open Heartbeat Dispatcher (OpenCode port of the chassis dispatcher)
#
# Parses HEARTBEATS.md, checks schedules, evaluates conditions, invokes the
# model via `opencode run` when work exists. Run it on a fixed tick (default
# every 15 minutes) from cron, launchd, systemd, or the compose
# `heartbeat-dispatcher` service (`docker compose --profile heartbeats up -d`).
#
# Architecture (gather-first dispatcher, ported from scrollinondubs/behalfbot
# chassis/scheduled-tasks/heartbeat-dispatcher.sh):
#   - Dispatcher fires on a fixed cadence regardless of whether there is work.
#   - For each registered heartbeat: check schedule -> run cheap gather script
#     -> evaluate condition -> only invoke the model when the condition is true.
#   - 96 dispatcher runs/day -> ~4 actual model invocations. Pay-to-play only
#     on real work.
#
# Differences from the chassis original (Phase 3, issue #4):
#   - `claude -p` is replaced by `opencode run --format json`. When
#     OPENCODE_ATTACH_URL is set the run attaches to a long-lived
#     `opencode serve` (kills MCP cold-boot per tick).
#   - The HEARTBEATS.md `model:` field accepts either a full OpenCode
#     `provider/model` string (e.g. `venice/zai-org-glm-5-2`) or one of the
#     chassis aliases `opus` / `sonnet` / `haiku`, mapped via
#     HEARTBEAT_MODEL_OPUS / HEARTBEAT_MODEL_SONNET / HEARTBEAT_MODEL_HAIKU
#     (defaults: venice/zai-org-glm-5-2, and venice/z-ai-glm-5-3-flash for
#     haiku). Non-venice results are refused.
#   - Telemetry is parsed from OpenCode's JSON event stream (`step_finish`
#     events carry per-step token counts and cost).
#   - `budget` is ADVISORY: OpenCode has no --max-budget-usd equivalent, so
#     the dispatcher logs a WARN when a run's summed cost exceeds the budget
#     instead of hard-capping it mid-run.
#   - Venice only: resolve_model refuses any model that is not venice/<id>,
#     and opencode.json sets enabled_providers to ["venice"].
#
# Required environment (graceful defaults when unset):
#   BEHALFBOT_HOME        - repo root holding HEARTBEATS.md, scripts/, prompts.
#                           Defaults to the parent of this script's directory.
#   BEHALFBOT_STATE_HOME  - where state/logs/briefings/telemetry are written.
#                           Defaults to BEHALFBOT_HOME. Point it at a volume
#                           (e.g. /data) in the Docker stack.
#
# Optional environment:
#   OPENCODE_BIN            - opencode binary (default: `opencode` on PATH,
#                             falling back to ~/.opencode/bin/opencode)
#   OPENCODE_ATTACH_URL     - attach runs to a live `opencode serve`
#                             (e.g. http://opencode-serve:4747)
#   HEARTBEAT_OPENCODE_AUTO - "1" (default) passes --auto so unattended runs
#                             never hang on a permission prompt. Safety comes
#                             from opencode.json permission denies plus the
#                             guardrails plugin, which auto-loads. Set "0" to
#                             drop the flag.
#   OLLAMA_URL              - local Ollama for ask_model conditions. If
#                             unreachable the dispatcher fails open (fires the
#                             model on ask_model conditions).
#   OLLAMA_MODEL            - Ollama model for ask_model (default gemma2)
#   DRY_RUN                 - "true" logs the FIRE and skips the invocation
#
# Control (Jill v2 C, BehalfBot-open#49; see docs/control.md):
#   CONTROL_DIR             - where halt.json and conservation-mode.json live.
#                             Compose mounts jill-control's volume here
#                             READ-ONLY. Default: $BEHALFBOT_STATE_HOME/scheduled-tasks
#   CONTROL_REQUIRE_ARMED   - "1": refuse to fire unless jill-control has
#                             refreshed armed.json in the last
#                             CONTROL_ARMED_MAX_AGE_SECONDS (default 900).
#                             A kill switch that is not listening is treated
#                             as a halt. Compose sets 1; default 0.
#   ALERT_SPOOL_DIR         - alerts are dropped here as JSON for jill-control
#                             to post to Matrix. Content-free by contract.
#   DISPATCHER_MAX_USD_PER_DAY - daily spend ceiling across ALL heartbeats
#                             (default 1, one alert at 50%). Critical
#                             heartbeats included.
#   DISPATCHER_DEFAULT_MAX_FIRES_PER_DAY - per-heartbeat fire cap used when a
#                             heartbeat sets no max_fires_per_day (default 24;
#                             0 disables the default).
#   VENICE_PRICES           - "model=in:out:cache_read,..." USD per million
#                             tokens, used when OpenCode reports no cost.
#                             An unlisted model is priced at the highest rate.
#   OPENCODE_GLOBAL_FAIL_THRESHOLD / OPENCODE_GLOBAL_DISTINCT_THRESHOLD /
#   OPENCODE_GLOBAL_ALERT_COOLDOWN_SECONDS - the all-runs-failed alarm
#                             (defaults 3, 2, 14400)
#   DISPATCHER_RETRY_BASE_SECONDS - first retry wait (default 20; tests use 0)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${BEHALFBOT_HOME:=$(dirname "$SCRIPT_DIR")}"
: "${BEHALFBOT_STATE_HOME:=$BEHALFBOT_HOME}"
export BEHALFBOT_HOME BEHALFBOT_STATE_HOME

# Cross-platform timeout binary (gtimeout on macOS Homebrew, timeout on Linux).
TIMEOUT_CMD="$(command -v gtimeout 2>/dev/null || command -v timeout 2>/dev/null || echo timeout)"

HEARTBEATS_FILE="$BEHALFBOT_HOME/HEARTBEATS.md"
STATE_DIR="$BEHALFBOT_STATE_HOME/scheduled-tasks"
STATE_FILE="$STATE_DIR/heartbeat-state.json"
CONTROL_DIR="${CONTROL_DIR:-$STATE_DIR}"
CONSERVATION_FILE="$CONTROL_DIR/conservation-mode.json"
# Remote kill switch. Written only by jill-control (gateway/control.py) from
# the principal's Matrix control room, with no model and no shell in the
# path. Same five-key schema as conservation-mode.json.
HALT_FILE="$CONTROL_DIR/halt.json"
ARMED_FILE="$CONTROL_DIR/armed.json"
ALERT_SPOOL_DIR="${ALERT_SPOOL_DIR:-}"
LOG_DIR="$BEHALFBOT_STATE_HOME/logs/scheduled"
LOCK_FILE="$LOG_DIR/dispatcher.lock"
TELEMETRY_DIR="$BEHALFBOT_STATE_HOME/logs/telemetry"
OUTPUT_DIR="$BEHALFBOT_STATE_HOME/briefings"
DATE=$(date +%Y-%m-%d)
LOG_FILE="$LOG_DIR/${DATE}-dispatcher.log"
OLLAMA_MODEL="${OLLAMA_MODEL:-gemma2}"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
DRY_RUN="${DRY_RUN:-false}"

mkdir -p "$LOG_DIR" "$STATE_DIR" "$TELEMETRY_DIR" "$OUTPUT_DIR"

# Source .env for tokens needed by gather scripts and opencode providers.
if [[ -f "$BEHALFBOT_HOME/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$BEHALFBOT_HOME/.env"
    set +a
fi

# Resolve the opencode binary once.
OPENCODE_BIN="${OPENCODE_BIN:-opencode}"
if ! command -v "$OPENCODE_BIN" >/dev/null 2>&1; then
    if [[ -x "$HOME/.opencode/bin/opencode" ]]; then
        OPENCODE_BIN="$HOME/.opencode/bin/opencode"
    fi
fi

# --- Operator hooks (optional) ---
#
# Sourced AFTER .env, BEFORE the dispatch loop. Lets an install layer
# extensions (recovery logic, notification overrides, instrumentation) on top
# of the canonical dispatcher without forking it.
HOOKS_FILE="$BEHALFBOT_STATE_HOME/scheduled-tasks/dispatcher-hooks.sh"
if [[ -f "$HOOKS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$HOOKS_FILE"
fi

# --- Logging ---

log() {
    echo "[$(date +%H:%M:%S)] $1" >> "$LOG_FILE"
}

# --- Cross-platform date parsing ---

# epoch_from_iso "<YYYY-MM-DDTHH:MM:SS>" -> epoch seconds (0 on parse failure)
epoch_from_iso() {
    local iso="$1"
    date -d "$iso" +%s 2>/dev/null \
        || date -j -f "%Y-%m-%dT%H:%M:%S" "$iso" +%s 2>/dev/null \
        || echo 0
}

# --- Control flags: halt + conservation ---
#
# The flag arithmetic lives in _control-flags.sh, shared by both flags so
# they never disagree about what "expired" means, and it never writes: the
# control volume is read-only here and jill-control owns it. If the library
# is missing (a partial update), keep reading `.enabled` so the kill switch
# survives; only the auto-lift arithmetic is lost.
if [[ -f "$SCRIPT_DIR/_control-flags.sh" ]]; then
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/_control-flags.sh"
else
    control_flag_state() {
        [[ -e "$1" ]] || { echo off; return 0; }
        local enabled
        enabled=$(jq -r '.enabled // false' "$1" 2>/dev/null) || { echo on; return 0; }
        [[ "$enabled" == "true" ]] && echo on || echo off
    }
fi

flag_on() {
    local file="$1" label="$2" st
    st=$(control_flag_state "$file")
    if [[ "$st" == "expired" ]]; then
        log "$label - auto-lift time has passed; treated as off (jill-control clears the file)"
    fi
    [[ "$st" == "on" ]]
}

is_halted() { flag_on "$HALT_FILE" "HALT"; }

is_conservation_mode() { flag_on "$CONSERVATION_FILE" "CONSERVATION"; }

# A kill switch that is not listening cannot stop anything, so with
# CONTROL_REQUIRE_ARMED=1 an unarmed switch is a halt. jill-control
# refreshes armed.json after every successful read of the control room.
kill_switch_unarmed() {
    [[ "${CONTROL_REQUIRE_ARMED:-0}" == "1" ]] || return 1
    local armed_at max_age now
    # A number only: a string armed_at is rejected (red-team N6).
    armed_at=$(jq -r 'if (.armed_at | type) == "number" then (.armed_at | floor) else 0 end' "$ARMED_FILE" 2>/dev/null) \
        || armed_at=0
    [[ "$armed_at" =~ ^[0-9]+$ ]] || armed_at=0
    max_age="${CONTROL_ARMED_MAX_AGE_SECONDS:-90}"
    now=$(date +%s)
    (( now - armed_at > max_age ))
}

# --- Locking ---

acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "LOCKED - dispatcher already running (pid $pid), exiting"
            exit 0
        fi
        log "STALE LOCK - removing (pid $pid no longer running)"
        rm -f "$LOCK_FILE"
    fi
    echo $$ > "$LOCK_FILE"
}

release_lock() {
    rm -f "$LOCK_FILE"
}
trap release_lock EXIT

# --- State Management ---

init_state() {
    if [[ ! -f "$STATE_FILE" ]]; then
        echo '{}' > "$STATE_FILE"
    fi
}

get_state() {
    local name="$1" field="$2"
    jq -r --arg n "$name" --arg f "$field" '.[$n][$f] // ""' "$STATE_FILE"
}

# Mutex around the whole read-modify-write cycle (ported from chassis
# a22251c). A unique temp path alone only stops two writers' staging files
# colliding; it does nothing about two writers both reading the state file,
# computing from the same stale snapshot, and the second mv discarding the
# first writer's change.
#
# flock(1) is REQUIRED (main refuses to start without it). It is
# kernel-enforced and released when its holder dies, so there are no
# orphaned locks. The chassis's mkdir lock is not used: on a GitHub-hosted
# runner it lost 2 of 40 concurrent updates with no recovery path taken.
# A lock held for DISPATCHER_STATE_LOCK_WAIT_SECONDS (default 10) makes the
# write REFUSED, never done unlocked: STATE_LOCK_FAILED stops the tick
# firing anything more (red team F6), because a lost fire count is a cap
# bypass. fd 9 keeps this runnable by older bash.
FLOCK_BIN="${DISPATCHER_FLOCK_BIN:-$(command -v flock 2>/dev/null || true)}"
STATE_LOCK_FAILED=0
STATE_LOCK_ALERTED=0

_state_lock_alert() {
    log "$1"
    if [[ $STATE_LOCK_ALERTED -eq 0 ]]; then
        STATE_LOCK_ALERTED=1
        alert_ops state-lock "$2"
    fi
}

_state_lock_acquire() {
    exec 9>>"${STATE_FILE}.flock"
    if "$FLOCK_BIN" -w "${DISPATCHER_STATE_LOCK_WAIT_SECONDS:-10}" 9; then
        return 0
    fi
    exec 9>&-
    STATE_LOCK_FAILED=1
    _state_lock_alert "ERROR state lock held >${DISPATCHER_STATE_LOCK_WAIT_SECONDS:-10}s - write refused; this tick fires nothing more" \
        "The dispatcher could not take its state lock in time, so it refused the write and stopped firing for this tick. Another dispatcher may be running."
    return 1
}

_state_lock_release() {
    exec 9>&-
}

# _state_update <jq filter> [jq args...] - one locked read-modify-write.
# Released only when THIS call holds the lock: releasing on the timeout path
# would delete a lock another writer still owns.
# The result replaces the state file only if it is a non-empty JSON object
# (red-team F2): an empty or invalid temp file is discarded, never renamed
# over the state.
_state_update() {
    local filter="$1"; shift
    local tmp="${STATE_FILE}.$$.${RANDOM}.tmp"
    _state_lock_acquire || return 0
    if jq "$@" "$filter" "$STATE_FILE" > "$tmp" 2>/dev/null && [[ -s "$tmp" ]] \
        && jq -e 'type == "object"' "$tmp" >/dev/null 2>&1; then
        mv "$tmp" "$STATE_FILE"
    else
        rm -f "$tmp"
        log "WARNING a state update produced no valid JSON object - discarded (jq exit or empty output)"
    fi
    _state_lock_release
}

# Non-empty AND a JSON object: jq 1.6 accepts a zero-byte file (red-team N4).
state_valid() {
    [[ -s "$STATE_FILE" ]] && jq -e 'type == "object"' "$STATE_FILE" >/dev/null 2>&1
}

set_state() {
    local name="$1" field="$2" value="$3"
    _state_update '.[$n] = (.[$n] // {}) | .[$n][$f] = $v' --arg n "$name" --arg f "$field" --arg v "$value"
}

increment_fire_count() {
    local name="$1"
    _state_update '.[$n] = (.[$n] // {}) | .[$n].fire_count = ((.[$n].fire_count // "0") | tonumber + 1 | tostring)' \
        --arg n "$name"
}

# --- Model alias resolution ---

# HEARTBEATS.md model: field -> OpenCode provider/model string.
#
# Venice only (BehalfBot-open#46). Every alias, every override and every
# fallback must resolve to venice/<model>; anything else is refused rather
# than passed through, so a typo or a stale HEARTBEATS.md can never route
# private material to another provider. opencode.json enforces the same rule
# with enabled_providers; this is the dispatcher's half of it.
DEFAULT_HEARTBEAT_MODEL="venice/zai-org-glm-5-2"
DEFAULT_SMALL_MODEL="venice/z-ai-glm-5-3-flash"

resolve_model() {
    local m="$1" resolved
    case "$m" in
        */*)    resolved="$m" ;;
        opus)   resolved="${HEARTBEAT_MODEL_OPUS:-$DEFAULT_HEARTBEAT_MODEL}" ;;
        sonnet) resolved="${HEARTBEAT_MODEL_SONNET:-$DEFAULT_HEARTBEAT_MODEL}" ;;
        haiku)  resolved="${HEARTBEAT_MODEL_HAIKU:-$DEFAULT_SMALL_MODEL}" ;;
        "")     resolved="${HEARTBEAT_MODEL_SONNET:-$DEFAULT_HEARTBEAT_MODEL}" ;;
        *)
            log "ERROR: unknown model alias '$m' - refusing (use venice/<model>)"
            return 1
            ;;
    esac
    case "$resolved" in
        venice/?*) echo "$resolved" ;;
        *)
            log "ERROR: model '$m' resolves to '$resolved', which is not a venice/ model - refusing"
            return 1
            ;;
    esac
}

# --- Ollama ---

ensure_ollama() {
    if curl -sf "$OLLAMA_URL/api/tags" > /dev/null 2>&1; then
        return 0
    fi
    log "Ollama not responding at $OLLAMA_URL"
    return 1
}

ask_model() {
    local prompt="$1"
    local result
    result=$("$TIMEOUT_CMD" 60 curl -sf "$OLLAMA_URL/api/generate" \
        -d "$(jq -n --arg model "$OLLAMA_MODEL" --arg prompt "$prompt" \
            '{model: $model, prompt: $prompt, stream: false}')" \
        2>/dev/null | jq -r '.response // empty') || {
        log "ERROR: Ollama timed out or failed"
        echo "YES"  # fail-open
        return
    }
    if [[ -z "$result" ]]; then
        log "ERROR: Ollama returned empty response"
        echo "YES"  # fail-open
        return
    fi
    echo "$result"
}

# --- Schedule Matching ---

schedule_matches() {
    local schedule="$1" name="$2"
    local now_epoch now_hour now_min now_dow
    now_epoch=$(date +%s)
    now_hour=$(date +%H | sed 's/^0//')
    now_min=$(date +%M | sed 's/^0//')
    now_dow=$(date +%A | tr '[:upper:]' '[:lower:]')

    if [[ "$schedule" == every\ * ]]; then
        local interval_str="${schedule#every }"
        local interval_seconds=0
        if [[ "$interval_str" == *m ]]; then
            interval_seconds=$(( ${interval_str%m} * 60 ))
        elif [[ "$interval_str" == *h ]]; then
            interval_seconds=$(( ${interval_str%h} * 3600 ))
        fi

        local last_checked
        last_checked=$(get_state "$name" "last_checked")
        if [[ -z "$last_checked" ]]; then
            return 0  # never checked, run now
        fi

        local last_epoch delta
        last_epoch=$(epoch_from_iso "$last_checked")
        delta=$(( now_epoch - last_epoch ))
        [[ $delta -ge $interval_seconds ]]
        return $?

    elif [[ "$schedule" == daily\ * ]]; then
        # "daily 08:03" (a trailing timezone token is tolerated and ignored;
        # the dispatcher uses the local system clock)
        local time_str sched_hour sched_min
        time_str=$(echo "${schedule#daily }" | awk '{print $1}')
        sched_hour=$(echo "$time_str" | cut -d: -f1 | sed 's/^0//')
        sched_min=$(echo "$time_str" | cut -d: -f2 | sed 's/^0//')

        local last_fired
        last_fired=$(get_state "$name" "last_fired")
        if [[ -n "$last_fired" && "$last_fired" == "$DATE"* ]]; then
            return 1  # already ran today
        fi

        # Deterministic jitter per day+name
        local jitter_str
        jitter_str=$(get_config_field "$name" "jitter")
        if [[ -n "$jitter_str" ]]; then
            local jitter_minutes=0
            if [[ "$jitter_str" == *m ]]; then
                jitter_minutes=${jitter_str%m}
            elif [[ "$jitter_str" == *h ]]; then
                jitter_minutes=$(( ${jitter_str%h} * 60 ))
            fi
            if [[ $jitter_minutes -gt 0 ]]; then
                local seed_hash md5_bin offset_min total_min
                md5_bin=$(command -v md5sum 2>/dev/null || command -v md5 2>/dev/null || echo md5)
                seed_hash=$(echo -n "${DATE}${name}" | "$md5_bin" | awk '{print $1}')
                offset_min=$(( 16#${seed_hash:0:8} % jitter_minutes ))
                total_min=$(( sched_hour * 60 + sched_min + offset_min ))
                sched_hour=$(( total_min / 60 ))
                sched_min=$(( total_min % 60 ))
            fi
        fi

        if [[ $now_hour -gt $sched_hour ]] || \
           [[ $now_hour -eq $sched_hour && $now_min -ge $sched_min ]]; then
            return 0
        fi
        return 1

    elif [[ "$schedule" == weekly\ * ]]; then
        # "weekly sunday 18:00"
        local rest sched_dow time_str sched_hour sched_min
        rest="${schedule#weekly }"
        sched_dow=$(echo "$rest" | awk '{print $1}')
        time_str=$(echo "$rest" | awk '{print $2}')
        sched_hour=$(echo "$time_str" | cut -d: -f1 | sed 's/^0//')
        sched_min=$(echo "$time_str" | cut -d: -f2 | sed 's/^0//')

        if [[ "$now_dow" != "$sched_dow" ]]; then
            return 1
        fi

        local last_fired
        last_fired=$(get_state "$name" "last_fired")
        if [[ -n "$last_fired" && "$last_fired" == "$DATE"* ]]; then
            return 1
        fi

        if [[ $now_hour -gt $sched_hour ]] || \
           [[ $now_hour -eq $sched_hour && $now_min -ge $sched_min ]]; then
            return 0
        fi
        return 1
    fi

    log "WARN: unknown schedule format: $schedule"
    return 1
}

# --- Condition Evaluation ---

evaluate_condition() {
    local condition="$1" gathered_data="$2" name="$3"

    if [[ "$condition" == "always" ]]; then
        echo "YES - scheduled"
        return 0
    fi

    if [[ "$condition" == threshold\ * ]]; then
        # "threshold count > 0"
        local rest field op target
        rest="${condition#threshold }"
        field=$(echo "$rest" | awk '{print $1}')
        op=$(echo "$rest" | awk '{print $2}')
        target=$(echo "$rest" | awk '{print $3}')

        local actual=0
        # JSON array length, then JSON object field. Reject non-JSON: a bare
        # key=value line must be treated as count=0, never as work.
        if echo "$gathered_data" | jq -e 'type == "array"' &>/dev/null; then
            actual=$(echo "$gathered_data" | jq 'length')
        elif echo "$gathered_data" | jq -e 'type == "object"' &>/dev/null; then
            actual=$(echo "$gathered_data" | jq --arg f "$field" '.[$f] // 0')
        else
            log "WARN $name - gather output is not JSON, treating as count=0 (first line: $(echo "$gathered_data" | head -1))"
            actual=0
        fi

        local result=false
        case "$op" in
            ">")  [[ $actual -gt $target ]] && result=true ;;
            ">=") [[ $actual -ge $target ]] && result=true ;;
            "<")  [[ $actual -lt $target ]] && result=true ;;
            "=")  [[ $actual -eq $target ]] && result=true ;;
        esac

        if [[ "$result" == "true" ]]; then
            echo "YES - $field=$actual (${op} ${target})"
            return 0
        else
            echo "NO - $field=$actual (not ${op} ${target})"
            return 1
        fi
    fi

    if [[ "$condition" == "ask_model" ]]; then
        if ! ensure_ollama; then
            log "FAIL-OPEN: Ollama down, firing for $name"
            echo "YES - fail-open (Ollama unavailable)"
            return 0
        fi

        local condition_prompt
        condition_prompt=$(get_config_field "$name" "condition_prompt")

        local model_prompt="You are a task dispatcher. Given the data below, answer the question.
Reply with exactly YES or NO on the first line, followed by a one-sentence reason.

QUESTION: ${condition_prompt}

DATA:
${gathered_data}"

        local response first_line
        response=$(ask_model "$model_prompt")
        first_line=$(echo "$response" | head -1 | tr '[:lower:]' '[:upper:]')

        if [[ "$first_line" == YES* ]]; then
            echo "YES - model: $(echo "$response" | head -1)"
            return 0
        else
            echo "NO - model: $(echo "$response" | head -1)"
            return 1
        fi
    fi

    log "WARN: unknown condition type: $condition"
    return 1
}

# --- HEARTBEATS.md Parser ---

# Extract a field value from a heartbeat's YAML block (skips HTML-commented sections)
get_config_field() {
    local name="$1" field="$2"
    awk -v name="$name" -v field="$field" '
        /^<!--/ { commenting = 1 }
        /-->/ { commenting = 0; next }
        commenting { next }
        /^## / { current = $2 }
        current == name && /^```yaml/ { in_block = 1; next }
        current == name && /^```/ && in_block { in_block = 0 }
        in_block && $0 ~ "^" field ":" {
            sub("^" field ": *", ""); print; exit
        }
    ' "$HEARTBEATS_FILE"
}

# List all heartbeat names (skips HTML-commented sections)
list_heartbeats() {
    awk '
        /^<!--/ { commenting = 1 }
        /-->/ { commenting = 0; next }
        !commenting && /^## / { sub(/^## /, ""); print }
    ' "$HEARTBEATS_FILE"
}

# --- OpenCode Invocation ---

# Build the shared argv prefix for `opencode run`.
opencode_args() {
    local model="$1" cwd="$2"
    local args=(run --format json -m "$model")
    if [[ -n "${OPENCODE_ATTACH_URL:-}" ]]; then
        args+=(--attach "$OPENCODE_ATTACH_URL")
    fi
    if [[ -n "$cwd" && "$cwd" != "$BEHALFBOT_HOME" ]]; then
        args+=(--dir "$cwd")
    fi
    if [[ "${HEARTBEAT_OPENCODE_AUTO:-1}" == "1" ]]; then
        args+=(--auto)
    fi
    printf '%s\n' "${args[@]}"
}

invoke_opencode() {
    local prompt_input="$1" output_file="$2" model="$3" budget="$4" heartbeat_name="${5:-unknown}" cwd="${6:-$BEHALFBOT_HOME}"
    local telemetry_file="$TELEMETRY_DIR/$DATE-usage.jsonl"
    local tmp_events="$LOG_DIR/.opencode-events-$$.jsonl"
    local start_ts exit_code=0 end_ts wall_secs ts_iso rows_before rows_after

    rows_before=$(wc -l < "$telemetry_file" 2>/dev/null | tr -d ' ') || rows_before=0
    [[ "$rows_before" =~ ^[0-9]+$ ]] || rows_before=0
    start_ts=$(date +%s)

    local args=()
    while IFS= read -r line; do args+=("$line"); done < <(opencode_args "$model" "$cwd")

    # 20-minute cap per invocation, same as the chassis.
    "$TIMEOUT_CMD" 1200 "$OPENCODE_BIN" "${args[@]}" "$prompt_input" \
        > "$tmp_events" 2>> "$LOG_FILE" || exit_code=$?

    end_ts=$(date +%s)
    wall_secs=$((end_ts - start_ts))
    ts_iso=$(date +%Y-%m-%dT%H:%M:%S)

    if [[ -s "$tmp_events" ]]; then
        # Result text = concatenated `text` events from the JSON event stream.
        jq -rs '[.[] | select(.type == "text") | .part.text] | join("\n")' \
            "$tmp_events" > "$output_file" 2>> "$LOG_FILE" \
            || cp "$tmp_events" "$output_file"

        # Telemetry: sum cost/tokens over step_finish events. cost_usd is the
        # larger of OpenCode's figure and our own token-based estimate:
        # opencode.json carries no prices, so OpenCode reports 0, and a spend
        # cap summing zeros never trips.
        #
        # Every cost and token value is clamped to a non-negative number. A
        # value that is not one marks the row `invalid`, and an invalid row
        # makes the spend caps read "cap reached" (red-team F1): a negative
        # or string cost must never make spend look smaller.
        local price
        price=$(model_price "$model")
        jq -cs \
            --arg name "$heartbeat_name" \
            --arg model "$model" \
            --arg ts "$ts_iso" \
            --argjson wall "$wall_secs" \
            --argjson exit_code "$exit_code" \
            --argjson price "$price" \
            'def ok: type == "number" and . >= 0 and . < 1e12;
            def s(f): [.[] | (f // 0) | if ok then . else 0 end] | add // 0;
            [.[] | select(.type == "step_finish") | .part] as $steps |
            ([$steps[] | (.cost // 0), (.tokens.input // 0), (.tokens.output // 0), (.tokens.reasoning // 0),
              (.tokens.cache.write // 0), (.tokens.cache.read // 0)] | all(ok)) as $valid |
            ($steps | s(.cost)) as $reported |
            ((($steps | s(.tokens.input)) * $price[0]
              + ($steps | s(.tokens.output)) * $price[1]
              + ($steps | s(.tokens.reasoning)) * $price[1]
              + ($steps | s(.tokens.cache.write)) * $price[0]
              + ($steps | s(.tokens.cache.read)) * $price[2]) / 1000000) as $estimated |
            {
                ts: $ts,
                heartbeat: $name,
                model: $model,
                cost_usd: ([$reported, $estimated] | max),
                reported_cost_usd: $reported,
                input_tokens: ($steps | s(.tokens.input)),
                output_tokens: ($steps | s(.tokens.output)),
                cache_read_tokens: ($steps | s(.tokens.cache.read)),
                cache_create_tokens: ($steps | s(.tokens.cache.write)),
                wall_seconds: $wall,
                exit_code: $exit_code
            } + (if $valid then {} else {invalid: true} end)' "$tmp_events" >> "$telemetry_file" 2>> "$LOG_FILE" \
            && log "TELEMETRY $heartbeat_name - cost logged" \
            || log "WARN: telemetry parse failed for $heartbeat_name"

        # Advisory budget check (no hard cap in OpenCode).
        local run_cost over_budget
        run_cost=$(tail -n 1 "$telemetry_file" 2>/dev/null | jq -r '.cost_usd // 0' 2>/dev/null || echo 0)
        over_budget=$(jq -n --argjson c "${run_cost:-0}" --argjson b "${budget:-0}" '$c > $b' 2>/dev/null || echo false)
        if [[ "$over_budget" == "true" ]]; then
            log "WARN $heartbeat_name - run cost \$$run_cost exceeded advisory budget \$$budget"
        fi

        # A successful run that reports neither tokens nor cost means spend is
        # not being measured (the provider returned no usage). It is charged
        # a pessimistic amount, DISPATCHER_UNMEASURED_RUN_USD (default 0.25),
        # as its own telemetry row so the caps count it (red-team N6), and
        # alerted once a day.
        if [[ $exit_code -eq 0 ]] && tail -n 1 "$telemetry_file" 2>/dev/null \
            | jq -e '.cost_usd == 0 and .input_tokens == 0 and .output_tokens == 0 and .cache_read_tokens == 0 and .cache_create_tokens == 0' >/dev/null 2>&1; then
            local charge="${DISPATCHER_UNMEASURED_RUN_USD:-0.25}"
            [[ "$charge" =~ ^[0-9]+([.][0-9]+)?$ ]] || charge=0.25
            jq -cn --arg ts "$ts_iso" --arg name "$heartbeat_name" --arg model "$model" --argjson c "$charge" \
                '{ts: $ts, heartbeat: $name, model: $model, cost_usd: $c, unmeasured_charge: true}' >> "$telemetry_file" \
                || set_state "_dispatcher" "telemetry_fault_date" "$DATE"
            rows_before=$((rows_before + 1))
            log "WARN $heartbeat_name - the run reported no token usage and no cost; charged \$$charge against the caps"
            if [[ "$(get_state "_dispatcher" "unmeasured_alert_date")" != "$DATE" ]]; then
                set_state "_dispatcher" "unmeasured_alert_date" "$DATE"
                alert_ops spend-unmeasured "A run of ${heartbeat_name} reported no token usage and no cost, so the daily spend caps cannot see Jill's spend. Check that Venice returns usage on streamed responses."
            fi
        fi

        rm -f "$tmp_events"
    else
        printf '%s\n' "{\"ts\":\"$ts_iso\",\"heartbeat\":\"$heartbeat_name\",\"model\":\"$model\",\"cost_usd\":0,\"input_tokens\":0,\"output_tokens\":0,\"cache_read_tokens\":0,\"cache_create_tokens\":0,\"wall_seconds\":$wall_secs,\"exit_code\":$exit_code,\"error\":\"no_json_output\"}" >> "$telemetry_file"
        rm -f "$tmp_events"
    fi

    # Every run must leave exactly one more telemetry row. If it did not, the
    # spend of that run is invisible, so the day's cap reads as reached.
    rows_after=$(wc -l < "$telemetry_file" 2>/dev/null | tr -d ' ') || rows_after=0
    [[ "$rows_after" =~ ^[0-9]+$ ]] || rows_after=0
    if [[ $rows_after -le $rows_before ]]; then
        log "ERROR $heartbeat_name - no telemetry row was recorded; treating today's spend cap as reached"
        set_state "_dispatcher" "telemetry_fault_date" "$DATE"
    fi

    # A run that produced an empty result file is a failure even on exit 0.
    if [[ $exit_code -eq 0 && ! -s "$output_file" ]]; then
        log "WARN $heartbeat_name - opencode exited 0 but produced no text output"
        exit_code=1
    fi

    return $exit_code
}

# --- Notifications ---
#
# A heartbeat whose output starts with `notify: true` raises an alert
# through the Matrix alerts path (alert_ops). That room is not end-to-end
# encrypted, so the alert carries the heartbeat and output file names only,
# never the model-written summary: read the output on Jill's side. The bit
# itself is model-controlled, so it is rate-limited per heartbeat
# (NOTIFY_MIN_INTERVAL_SECONDS, default 6h): Jill cannot signal through the
# timing of alerts more often than that (red-team round 6 L2).

check_and_notify() {
    local name="$1" output_file="$2"

    if ! head -20 "$output_file" | grep -q '^notify: *true'; then
        return
    fi

    local now last
    now=$(date +%s)
    last=$(get_state "$name" "last_notify_at")
    if [[ "$last" =~ ^[0-9]+$ ]] && (( now - last < ${NOTIFY_MIN_INTERVAL_SECONDS:-21600} )); then
        log "NOTIFY $name suppressed (rate limit)"
        return
    fi
    set_state "$name" "last_notify_at" "$now"
    log "NOTIFY $name"
    alert_ops "notify" "Heartbeat $name finished and asked for your attention (output $(basename "$output_file"))."
}

# --- Post-Output Validator (Five Failure Modes check) ---
#
# For heartbeats with `output_validator: true`, run a small-model Five Failure
# Modes check against the output before it is "published". On pass: artifact
# stays. On fail: artifact quarantined (.quarantined suffix) and a Matrix
# alert raised. If the validator itself fails, fail-open.

VALIDATOR_PROMPT='You are a code and content quality gate. Given the artifact text below, run the Five Failure Modes check and emit a single JSON object on stdout (no other text):

{"pass": true, "mode": null, "reason": null}
or
{"pass": false, "mode": "<one of: hallucinated_actions|scope_creep|cascading_errors|context_loss|tool_misuse>", "reason": "<one sentence>"}

Five Failure Modes to check:
1. Hallucinated actions - tool calls or writes referencing values that were not verified against reality (invented file paths, env vars, IDs)
2. Scope creep - artifact modifies things outside the stated change boundary
3. Cascading errors - a workaround that papers over a root error and creates a deeper one
4. Context loss - re-asking established questions, contradicting earlier decisions, forgetting completed steps
5. Tool misuse - wrong tool, wrong parameters, or ignoring tool output

If the artifact is a briefing or summary, also check: does it contain placeholder text, truncation markers ("..."), or summary-of-a-summary patterns that suggest the agent summarised its own prior output rather than producing the original artifact?

Fail on the most severe mode if multiple fire. Pass only if none fire.

---
ARTIFACT:
'

run_output_validator() {
    local name="$1" output_file="$2"

    local validate_flag
    validate_flag=$(get_config_field "$name" "output_validator")
    if [[ "$validate_flag" != "true" ]]; then
        return 0
    fi

    log "VALIDATOR $name - running Five Failure Modes check on output"

    local artifact_content
    artifact_content=$(cat "$output_file" 2>/dev/null || echo "")
    if [[ -z "$artifact_content" ]]; then
        log "VALIDATOR $name - output file empty, skipping"
        return 0
    fi

    local truncated_content validator_input
    truncated_content=$(echo "$artifact_content" | head -c 4000)
    validator_input="${VALIDATOR_PROMPT}${truncated_content}"

    local validator_events="$LOG_DIR/.validator-events-$$.jsonl"
    local validator_model
    if ! validator_model=$(resolve_model haiku); then
        log "VALIDATOR $name - no venice model for the validator, fail-open"
        return 0
    fi

    local args=()
    while IFS= read -r line; do args+=("$line"); done < <(opencode_args "$validator_model" "$BEHALFBOT_HOME")

    "$TIMEOUT_CMD" 120 "$OPENCODE_BIN" "${args[@]}" "$validator_input" \
        > "$validator_events" 2>> "$LOG_FILE" || {
        log "VALIDATOR $name - validator call failed or timed out, fail-open"
        rm -f "$validator_events"
        return 0
    }

    local validator_result=""
    if [[ -s "$validator_events" ]]; then
        local ts_iso cost_usd
        ts_iso=$(date +%Y-%m-%dT%H:%M:%S)
        cost_usd=$(jq -rs --argjson price "$(model_price "$validator_model")" '
            [.[] | select(.type == "step_finish") | .part] as $s |
            [([$s[].cost // 0] | add // 0),
             ((([$s[].tokens.input // 0] | add // 0) * $price[0] + ([$s[].tokens.output // 0] | add // 0) * $price[1]
               + ([$s[].tokens.reasoning // 0] | add // 0) * $price[1]
               + ([$s[].tokens.cache.write // 0] | add // 0) * $price[0]
               + ([$s[].tokens.cache.read // 0] | add // 0) * $price[2]) / 1000000)] | max' \
            "$validator_events" 2>/dev/null || echo 0)
        printf '%s\n' "{\"ts\":\"$ts_iso\",\"heartbeat\":\"${name}-validator\",\"model\":\"$validator_model\",\"cost_usd\":${cost_usd:-0},\"input_tokens\":0,\"output_tokens\":0,\"cache_read_tokens\":0,\"cache_create_tokens\":0,\"wall_seconds\":0,\"exit_code\":0}" \
            >> "$TELEMETRY_DIR/$DATE-usage.jsonl" 2>> "$LOG_FILE" || true

        validator_result=$(jq -rs '[.[] | select(.type == "text") | .part.text] | join("\n")' "$validator_events" 2>/dev/null || echo "")
    fi
    rm -f "$validator_events"

    if [[ -z "$validator_result" ]]; then
        log "VALIDATOR $name - could not parse result, fail-open"
        return 0
    fi

    # Strip an optional markdown fence around the JSON verdict.
    validator_result=$(echo "$validator_result" | sed -e 's/^```json//' -e 's/^```//' -e 's/```$//')

    local pass_val mode_val reason_val
    pass_val=$(echo "$validator_result" | jq -r '.pass // true' 2>/dev/null || echo "true")
    mode_val=$(echo "$validator_result" | jq -r '.mode // "unknown"' 2>/dev/null || echo "unknown")
    reason_val=$(echo "$validator_result" | jq -r '.reason // ""' 2>/dev/null || echo "")

    if [[ "$pass_val" == "true" ]]; then
        log "VALIDATOR $name - PASS"
        return 0
    fi

    local quarantine_file="${output_file}.quarantined"
    mv "$output_file" "$quarantine_file" 2>> "$LOG_FILE" || {
        log "VALIDATOR $name - FAIL but could not quarantine artifact (mv failed)"
        return 1
    }

    log "VALIDATOR $name - FAIL mode=$mode_val reason=$reason_val - artifact quarantined at $quarantine_file"

    # The reason is model-written prose about private material, so it stays
    # in the log; the alert carries only the heartbeat name and the mode,
    # which is one of five fixed words.
    case "$mode_val" in
        hallucinated_actions|scope_creep|cascading_errors|context_loss|tool_misuse) ;;
        *) mode_val="other" ;;
    esac
    alert_ops validator "Five Failure Modes validator blocked ${name} (mode: ${mode_val}). The artifact is quarantined; the reason is in the dispatcher log."

    return 1
}

# --- Alerts ---
#
# alert_ops <kind> <text>. The text goes to the principal's Matrix alerts
# room through jill-control, which is NOT end-to-end encrypted and runs on a
# homeserver Jill does not own. So every caller passes a fixed template with
# heartbeat names, counts and dollar figures only: never model output,
# gather data, prompt text or log lines. Delivery: a JSON file in
# ALERT_SPOOL_DIR (jill-control drains it). Without a spool the alert is
# logged and dropped, loudly.
alert_ops() {
    local kind="$1" msg="$2" delivered=0
    if [[ -n "$ALERT_SPOOL_DIR" ]]; then
        local f
        f="$ALERT_SPOOL_DIR/$(date +%s)-$$-${RANDOM}-${kind}"
        if jq -n --arg kind "$kind" --arg text "$msg" --argjson ts "$(date +%s)" \
                '{kind: $kind, text: $text, ts: $ts}' > "$f.tmp" 2>/dev/null \
            && mv "$f.tmp" "$f.json"; then
            delivered=1
        else
            rm -f "$f.tmp"
            log "WARN: could not write alert to spool $ALERT_SPOOL_DIR"
        fi
    fi
    if [[ $delivered -eq 0 ]]; then
        log "WARN: no alert path (ALERT_SPOOL_DIR unset or unwritable), dropped: $kind"
    fi
    return 0
}

# --- Spend accounting ---
#
# model_price <provider/model> -> JSON [in, out, cache_read], USD per million
# tokens. From VENICE_PRICES; an unlisted model gets the highest listed rate
# in each column, so a model missing from the table is over-counted, never
# free. The defaults are Venice list prices for GLM 5.2 and GLM 5.3 Flash
# as seen 2026-11-21; confirm them against venice.ai/pricing.
DEFAULT_VENICE_PRICES="zai-org-glm-5-2=1.40:4.40:0.26,z-ai-glm-5-3-flash=0.17:0.55:0.03"

model_price() {
    local id="${1#venice/}"
    printf '%s' "${VENICE_PRICES:-$DEFAULT_VENICE_PRICES}" | awk -v id="$id" -v RS=',' '
        {
            gsub(/[[:space:]]/, "")
            split($0, kv, "="); n = split(kv[2], p, ":")
            if (n < 2 || p[1] == "" || p[2] == "") next
            if (n < 3 || p[3] == "") p[3] = p[1]
            for (i = 1; i <= 3; i++) if (p[i] + 0 > max[i]) max[i] = p[i] + 0
            if (kv[1] == id) { hit = 1; for (i = 1; i <= 3; i++) got[i] = p[i] + 0 }
        }
        END {
            if (!hit) for (i = 1; i <= 3; i++) got[i] = max[i] + 0
            if (got[1] == 0 && got[2] == 0) { got[1] = 5; got[2] = 15; got[3] = 5 }
            printf "[%s,%s,%s]\n", got[1], got[2], got[3]
        }'
}

_num_ge() {
    awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 >= b + 0) }'
}

_state_int() {
    local v
    v=$(get_state "$1" "$2")
    [[ "$v" =~ ^[0-9]+$ ]] || v=0
    echo "$v"
}

# Dollars spent today from the dispatcher's own telemetry: the surface an
# operator audits afterwards, so the cap cannot disagree with it. With a
# name, that heartbeat plus its validator rows; without, everything.
#
# Prints a number, or "invalid" (red-team F1) when the file cannot be read,
# or any row is not JSON, is marked invalid, or carries a cost that is not a
# non-negative number. Callers treat "invalid" as cap reached.
usd_today() {
    local name="${1:-}"
    local tfile="$TELEMETRY_DIR/$DATE-usage.jsonl"
    [[ -e "$tfile" ]] || { echo 0; return 0; }
    jq -r -R -s --arg n "$name" '
        [ split("\n")[] | select(length > 0) | (try fromjson catch "BAD") ] as $rows
        | if any($rows[]; type != "object" or .invalid == true
                 or (.cost_usd | type) != "number" or .cost_usd < 0)
          then "invalid"
          else [ $rows[] | select($n == "" or .heartbeat == $n or .heartbeat == ($n + "-validator"))
                 | .cost_usd ] | add // 0
          end
    ' "$tfile" 2>/dev/null || echo invalid
}

# cents <n>: a dollar figure for an alert, rounded and clamped to [0, 1e6].
cents() {
    awk -v v="$1" 'BEGIN { v += 0; if (v < 0) v = 0; if (v > 1000000) v = 1000000; printf "%.2f", v }'
}

# --- Daily fire caps (ported from chassis 3205a7f) ---
#
# `budget:` is per invocation and does not bound a loop: the chassis's
# repo-drift heartbeat fired 514 times in five days at ~$0.09 each, never
# once over its budget, because its condition could only be cleared by a
# human who was off-grid. Caps are absolute: once hit, no more model runs
# for that heartbeat until the date rolls. A changed condition does not
# lift one. The chassis's alert dedup (realert_after, dedupe_key) and its
# suppression ledger are not ported.

fires_today() {
    local name="$1"
    if [[ "$(get_state "$name" "fires_date")" != "$DATE" ]]; then
        echo 0
        return 0
    fi
    _state_int "$name" "fires_today"
}

# One count per fire decision, not per retry attempt; a failed fire still
# spent tokens, so it counts.
note_fire() {
    local name="$1" n=1
    if [[ "$(get_state "$name" "fires_date")" == "$DATE" ]]; then
        n=$(( $(_state_int "$name" "fires_today") + 1 ))
    else
        set_state "$name" "fires_date" "$DATE"
    fi
    set_state "$name" "fires_today" "$n"
}

CAP_REASON=""

# 0 = capped (do not fire), 1 = may fire. Sets CAP_REASON.
fire_cap_check() {
    local name="$1" max_fires max_usd fired spent
    CAP_REASON=""
    max_fires=$(get_config_field "$name" "max_fires_per_day")
    max_usd=$(get_config_field "$name" "max_usd_per_day")
    if [[ -z "$max_fires" ]]; then
        max_fires="${DISPATCHER_DEFAULT_MAX_FIRES_PER_DAY:-24}"
        [[ "$max_fires" == "0" ]] && max_fires=""
    fi
    if [[ -n "$max_fires" ]]; then
        if [[ ! "$max_fires" =~ ^[0-9]+$ ]]; then
            log "WARN $name - max_fires_per_day '$max_fires' is not a whole number. Ignoring."
        else
            fired=$(fires_today "$name")
            if [[ $fired -ge $max_fires ]]; then
                CAP_REASON="max_fires_per_day reached: $fired of $max_fires model runs already spent today"
                return 0
            fi
        fi
    fi
    if [[ -n "$max_usd" ]]; then
        if [[ ! "$max_usd" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            log "WARN $name - max_usd_per_day '$max_usd' is not a number. Ignoring."
        else
            spent=$(usd_today "$name")
            if [[ "$spent" == "invalid" ]]; then
                CAP_REASON="max_usd_per_day treated as reached: today's telemetry cannot be read reliably"
                return 0
            fi
            if _num_ge "$spent" "$max_usd"; then
                CAP_REASON="max_usd_per_day reached: \$$(cents "$spent") of \$$(cents "$max_usd") already spent today"
                return 0
            fi
        fi
    fi
    return 1
}

# One notice per heartbeat per day; the notice itself is capped or it
# recreates the 50-alert problem in miniature.
cap_alert_once() {
    local name="$1" reason="$2"
    [[ "$(get_state "$name" "cap_alert_date")" == "$DATE" ]] && return 0
    set_state "$name" "cap_alert_date" "$DATE"
    alert_ops fire-cap "${name} hit its daily cap and will not run the model again today. ${reason}. Its gather still runs every tick; only the date rolling lifts a cap."
}

# --- Daily Venice spend cap (all heartbeats) ---
#
# The per-heartbeat caps bound one loop. This bounds the dispatcher: once
# today's summed telemetry reaches DISPATCHER_MAX_USD_PER_DAY, nothing fires
# until the date rolls, `critical` included. It does NOT bound chat through
# the bridge, which does not go through the dispatcher.
SPEND_REASON=""

# 0 = over the cap (do not fire), 1 = may fire.
#
# Default $1/day (Sean, 2026-11-21), with one alert at 50%. Fail-closed: an
# unreadable telemetry file, an invalid row, or a run that left no row
# today all read as "cap reached" (red-team F1).
global_spend_capped() {
    local cap="${DISPATCHER_MAX_USD_PER_DAY:-1}" spent
    SPEND_REASON=""
    if [[ ! "$cap" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        log "WARN: DISPATCHER_MAX_USD_PER_DAY '$cap' is not a number - using 1"
        cap=1
    fi
    if [[ "$(get_state "_dispatcher" "telemetry_fault_date")" == "$DATE" ]]; then
        SPEND_REASON="a run today left no telemetry row, so today's spend is unknown"
        return 0
    fi
    spent=$(usd_today)
    if [[ "$spent" == "invalid" ]]; then
        SPEND_REASON="today's telemetry cannot be read reliably, so today's spend is unknown"
        return 0
    fi
    if _num_ge "$spent" "$cap"; then
        SPEND_REASON="\$$(cents "$spent") of the \$$(cents "$cap") daily budget is spent"
        return 0
    fi
    if _num_ge "$spent" "$(awk -v c="$cap" 'BEGIN { print c / 2 }')" \
        && [[ "$(get_state "_dispatcher" "spend_half_alert_date")" != "$DATE" ]]; then
        set_state "_dispatcher" "spend_half_alert_date" "$DATE"
        alert_ops spend-half "Heartbeat spend today is \$$(cents "$spent"), half of the \$$(cents "$cap") daily cap."
    fi
    return 1
}

spend_alert_once() {
    [[ "$(get_state "_dispatcher" "spend_alert_date")" == "$DATE" ]] && return 0
    set_state "_dispatcher" "spend_alert_date" "$DATE"
    alert_ops spend-cap "Daily spend cap reached: ${SPEND_REASON}. No heartbeat will run the model again today, critical ones included. Raise DISPATCHER_MAX_USD_PER_DAY and restart the dispatcher to lift it."
}

# --- Recovery Hooks ---
#
# Installs can drop *.sh files into scheduled-tasks/recovery-hooks.d/ that
# define functions prefixed `behalfbot_recovery_`. Each is invoked once per
# dispatcher tick, before the dispatch loop, to detect external-state
# transitions and rewind heartbeat schedules accordingly.
if [[ -d "$BEHALFBOT_STATE_HOME/scheduled-tasks/recovery-hooks.d" ]]; then
    for _hook in "$BEHALFBOT_STATE_HOME/scheduled-tasks/recovery-hooks.d/"*.sh; do
        [[ -f "$_hook" ]] || continue
        # shellcheck disable=SC1090
        source "$_hook"
    done
    unset _hook
fi

# --- Main Dispatch Loop ---

main() {
    # flock is required for the state lock. Without it: refuse to start,
    # alert once (until flock is back), exit non-zero.
    local no_flock_marker="$STATE_DIR/.no-flock-alerted"
    if [[ -z "$FLOCK_BIN" || ! -x "$FLOCK_BIN" ]]; then
        log "FATAL flock(1) not found - the dispatcher will not run without its state lock"
        if [[ ! -e "$no_flock_marker" ]]; then
            : > "$no_flock_marker"
            alert_ops no-flock "The heartbeat dispatcher refused to start: flock is not installed where it runs, and it will not run without its state lock."
        fi
        exit 78
    fi
    rm -f "$no_flock_marker"

    acquire_lock
    init_state
    log "=== Dispatcher run started ==="

    # Red-team F2: a state file that is not a JSON object loses every fire
    # count and cap date, so nothing fires until a human looks.
    if ! state_valid; then
        log "ERROR $STATE_FILE is not a JSON object - nothing fires until it is repaired"
        local marker="$STATE_DIR/.state-invalid-alerted-$DATE"
        if [[ ! -e "$marker" ]]; then
            : > "$marker"
            alert_ops state-invalid "The dispatcher's state file is corrupt, so no heartbeat runs until it is repaired. Check scheduled-tasks/heartbeat-state.json in the dispatcher volume."
        fi
        return
    fi

    if [[ ! -f "$HEARTBEATS_FILE" ]]; then
        log "No HEARTBEATS.md at $HEARTBEATS_FILE (copy HEARTBEATS.md.template to get started)"
        return
    fi

    # Remote kill switch, before anything else in the tick: ahead of the
    # recovery hooks, conservation mode and every gather. Unlike conservation
    # this ignores `criticality`: the principal asking for silence outranks a
    # heartbeat's own opinion of how important it is.
    if is_halted; then
        local halt_reason halt_lift
        halt_reason=$(jq -r '.reason // "no reason given"' "$HALT_FILE" 2>/dev/null || echo "unreadable flag file")
        halt_lift=$(jq -r '.auto_lift_after // "none"' "$HALT_FILE" 2>/dev/null || echo "unknown")
        log "HALTED - every heartbeat skipped (reason: $halt_reason, auto-lift: $halt_lift)"
        log "HALTED - say 'resume' in the Matrix control room to lift"
        return
    fi
    if kill_switch_unarmed; then
        log "HALTED - the kill switch is not armed (no fresh $ARMED_FILE); nothing fires until jill-control is listening"
        if [[ "$(get_state "_dispatcher" "unarmed_alert_date")" != "$DATE" ]]; then
            set_state "_dispatcher" "unarmed_alert_date" "$DATE"
            alert_ops unarmed "The Matrix kill switch is not listening, so Jill's heartbeats are paused until it is. Check the jill-control container."
        fi
        return
    fi

    while IFS= read -r _hook_fn; do
        [[ -n "$_hook_fn" ]] || continue
        "$_hook_fn" || log "WARN: recovery hook $_hook_fn returned non-zero"
    done < <(compgen -A function | grep '^behalfbot_recovery_' || true)

    local conservation_active=false
    if is_conservation_mode; then
        conservation_active=true
        local cons_reason
        cons_reason=$(jq -r '.reason // "unspecified"' "$CONSERVATION_FILE")
        log "CONSERVATION MODE ACTIVE - reason: $cons_reason - skipping normal/background heartbeats"
    fi

    local heartbeats=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && heartbeats+=("$line")
    done < <(list_heartbeats)

    if [[ ${#heartbeats[@]} -eq 0 ]]; then
        log "No heartbeats found in $HEARTBEATS_FILE"
        return
    fi

    local name
    for name in "${heartbeats[@]}"; do
        local schedule="" condition="" prompt_file="" model="" budget="" cwd="" criticality=""

        schedule=$(get_config_field "$name" "schedule")
        condition=$(get_config_field "$name" "condition")
        prompt_file=$(get_config_field "$name" "prompt")
        model=$(get_config_field "$name" "model")
        budget=$(get_config_field "$name" "budget")
        cwd=$(get_config_field "$name" "cwd")
        criticality=$(get_config_field "$name" "criticality")

        # `schedule: disabled` parks a heartbeat intentionally (kept catalogued
        # in HEARTBEATS.md without dispatching).
        if [[ "$schedule" == "disabled" ]]; then
            log "DISABLED $name - schedule:disabled (intentional)"
            continue
        fi

        if [[ -z "$schedule" || -z "$condition" || -z "$prompt_file" ]]; then
            log "SKIP $name - missing required fields (schedule/condition/prompt)"
            continue
        fi

        if ! model=$(resolve_model "$model"); then
            log "SKIP $name - model is not a venice/ model"
            continue
        fi
        budget=${budget:-5}
        cwd=${cwd:-$BEHALFBOT_HOME}
        criticality=${criticality:-normal}

        if [[ "$conservation_active" == "true" && "$criticality" != "critical" ]]; then
            log "SKIP $name - conservation mode (criticality=$criticality)"
            continue
        fi

        if ! schedule_matches "$schedule" "$name"; then
            log "SKIP $name - not scheduled"
            continue
        fi

        log "CHECK $name - schedule matched"

        # Gather data
        local gather_cmd="" gathered_data=""
        gather_cmd=$(get_config_field "$name" "gather")
        if [[ -n "$gather_cmd" ]]; then
            log "GATHER $name - running: $gather_cmd"
            gathered_data=$(cd "$BEHALFBOT_HOME" && eval "$gather_cmd" 2>> "$LOG_FILE") || {
                log "ERROR $name - gather script failed"
                set_state "$name" "last_checked" "$(date +%Y-%m-%dT%H:%M:%S)"
                set_state "$name" "last_result" "gather_failed"
                continue
            }
        fi

        set_state "$name" "last_checked" "$(date +%Y-%m-%dT%H:%M:%S)"

        # Evaluate condition
        local decision should_fire
        decision=$(evaluate_condition "$condition" "$gathered_data" "$name") && should_fire=true || should_fire=false

        set_state "$name" "last_decision" "$decision"
        log "DECISION $name - $decision"

        if [[ "$should_fire" != "true" ]]; then
            log "PASS $name - no work"
            # Clear any stale failure label from a prior run so operators
            # reading heartbeat-state.json see the recovery.
            set_state "$name" "last_result" "success"
            continue
        fi

        # Daily caps, before the DRY_RUN branch so a dry run reports exactly
        # what a live run would suppress. Both suppress the FIRE, not just a
        # notification: the model run is the expensive half.
        if global_spend_capped; then
            log "SPEND-CAPPED $name - $SPEND_REASON"
            set_state "$name" "last_result" "spend_capped"
            spend_alert_once
            continue
        fi
        if fire_cap_check "$name"; then
            log "CAPPED $name - $CAP_REASON"
            set_state "$name" "last_result" "fire_capped"
            cap_alert_once "$name" "$CAP_REASON"
            continue
        fi

        # Resolve prompt path (relative to BEHALFBOT_HOME, absolute allowed)
        local full_prompt_path
        if [[ "$prompt_file" == /* ]]; then
            full_prompt_path="$prompt_file"
        else
            full_prompt_path="$BEHALFBOT_HOME/$prompt_file"
        fi
        if [[ ! -f "$full_prompt_path" ]]; then
            log "ERROR $name - prompt file not found: $full_prompt_path"
            set_state "$name" "last_result" "prompt_missing"
            continue
        fi

        # Circuit-breaker: skip the FIRE while a failing heartbeat's cooldown
        # window is open. One broken auth state must not serialize the whole
        # dispatcher for hours (each failing FIRE eats up to 20min + retries).
        local circuit_open_until
        circuit_open_until=$(get_state "$name" "circuit_open_until")
        if [[ -n "$circuit_open_until" ]]; then
            local now_epoch_for_circuit
            now_epoch_for_circuit=$(date +%s)
            if [[ $now_epoch_for_circuit -lt $circuit_open_until ]]; then
                local remaining_min=$(( (circuit_open_until - now_epoch_for_circuit) / 60 ))
                log "CIRCUIT-OPEN $name - opencode has been failing; skipping FIRE for ${remaining_min}min more"
                set_state "$name" "last_result" "circuit_open"
                continue
            fi
            set_state "$name" "circuit_open_until" ""
        fi

        # The halt gate is checked again here, not only at tick start: a tick
        # walks every heartbeat, and each run can take 20 minutes, so a halt
        # sent mid-tick must stop the heartbeats that have not fired yet.
        if is_halted || kill_switch_unarmed; then
            log "HALTED mid-tick - $name and every later heartbeat skipped (halt flag or unarmed switch)"
            break
        fi
        if [[ $STATE_LOCK_FAILED -eq 1 ]]; then
            log "STOPPED - the state lock could not be taken; $name and every later heartbeat skipped"
            break
        fi

        log "FIRE $name - invoking opencode run (model=$model, budget=\$$budget advisory)"

        if [[ "$DRY_RUN" == "true" ]]; then
            log "DRY-RUN $name - would invoke opencode run (skipping)"
            set_state "$name" "last_result" "dry_run"
            continue
        fi

        note_fire "$name"

        local output_file="$OUTPUT_DIR/${DATE}-${name}.md"

        # Build the prompt input. Explicit ="" initializer prevents a prior
        # loop iteration's prompt bleeding into this heartbeat's invocation.
        local prompt_input=""
        if [[ -n "$gathered_data" ]]; then
            prompt_input="$(cat "$full_prompt_path")

---
## Gathered Data (from dispatcher)
\`\`\`json
${gathered_data}
\`\`\`"
        else
            prompt_input=$(cat "$full_prompt_path")
        fi

        # Retry policy: 3 attempts total with backoff (20s, 60s).
        local invoke_success=false
        local attempt
        for attempt in 1 2 3; do
            if [[ $attempt -gt 1 ]] && { is_halted || kill_switch_unarmed || [[ $STATE_LOCK_FAILED -eq 1 ]]; }; then
                log "HALTED - retry $attempt of $name skipped"
                break
            fi
            if invoke_opencode "$prompt_input" "$output_file" "$model" "$budget" "$name" "$cwd"; then
                invoke_success=true
                break
            fi
            if [[ $attempt -lt 3 ]]; then
                local wait_s=$(( ${DISPATCHER_RETRY_BASE_SECONDS:-20} * (3 ** (attempt - 1)) ))
                log "RETRY $name - opencode failed (attempt $attempt/3), waiting ${wait_s}s..."
                sleep "$wait_s"
            fi
        done

        if [[ "$invoke_success" != "true" ]]; then
            log "FAILED $name - opencode failed after 3 attempts"
            set_state "$name" "last_result" "opencode_failed_after_3_attempts"

            # Circuit-breaker bookkeeping: exponential-backoff cooldown,
            # capped at 32 ticks (~8h on the default 15-min tick).
            local fail_streak
            fail_streak=$(get_state "$name" "opencode_fail_streak")
            fail_streak=$(( ${fail_streak:-0} + 1 ))
            set_state "$name" "opencode_fail_streak" "$fail_streak"

            local circuit_threshold="${OPENCODE_FAIL_CIRCUIT_THRESHOLD:-2}"
            if [[ $fail_streak -ge $circuit_threshold ]]; then
                local backoff_factor=$(( fail_streak - circuit_threshold + 1 ))
                if [[ $backoff_factor -gt 5 ]]; then backoff_factor=5; fi
                local backoff_ticks=$(( 1 << (backoff_factor - 1) ))
                if [[ $backoff_ticks -gt 32 ]]; then backoff_ticks=32; fi
                local tick_sec="${DISPATCHER_INTERVAL_SECONDS:-900}"
                local backoff_sec=$(( backoff_ticks * tick_sec ))
                local open_until=$(( $(date +%s) + backoff_sec ))
                set_state "$name" "circuit_open_until" "$open_until"
                log "CIRCUIT-OPENED $name - streak=$fail_streak, skipping FIRE for $backoff_ticks ticks (~$((backoff_sec/60))min)"
            fi

            # Cross-heartbeat failure alarm (ported from chassis 22fdfd4).
            # The per-heartbeat breaker is right for ONE flaky heartbeat and
            # wrong when opencode cannot run at all: each failing heartbeat
            # opens its own breaker and goes quiet, gathers keep reporting
            # "no work", and the install looks healthy from outside. So count
            # failures across DIFFERENT heartbeats and alert once (with a
            # cooldown) when both thresholds are crossed. Unlike the chassis
            # this alert does not quote the last error line: it goes to an
            # unencrypted room, and opencode's stderr can carry prompt text.
            local global_streak failed_names distinct_count
            global_streak=$(_state_int "_dispatcher" "opencode_global_fail_streak")
            global_streak=$(( global_streak + 1 ))
            set_state "_dispatcher" "opencode_global_fail_streak" "$global_streak"
            failed_names=$(get_state "_dispatcher" "opencode_global_failed_names")
            case " $failed_names " in
                *" $name "*) : ;;
                *) failed_names="${failed_names:+$failed_names }$name" ;;
            esac
            set_state "_dispatcher" "opencode_global_failed_names" "$failed_names"
            distinct_count=$(wc -w <<<"$failed_names" | tr -d ' ')

            if [[ $global_streak -ge ${OPENCODE_GLOBAL_FAIL_THRESHOLD:-3} \
                  && $distinct_count -ge ${OPENCODE_GLOBAL_DISTINCT_THRESHOLD:-2} ]]; then
                local now_epoch last_alert cooldown
                now_epoch=$(date +%s)
                last_alert=$(get_state "_dispatcher" "opencode_global_alerted_at")
                cooldown="${OPENCODE_GLOBAL_ALERT_COOLDOWN_SECONDS:-14400}"
                if [[ -z "$last_alert" ]] || (( now_epoch - last_alert >= cooldown )); then
                    alert_ops all-failed "Every heartbeat run is failing: ${global_streak} consecutive failed runs across ${distinct_count} heartbeats, most recently ${name}. Each one is opening its own circuit breaker, so Jill will look quiet rather than broken. The cause is in the dispatcher log (logs/scheduled/${DATE}-dispatcher.log). Re-alerts at most every $(( cooldown / 3600 ))h."
                    set_state "_dispatcher" "opencode_global_alerted_at" "$now_epoch"
                fi
            fi

            continue
        fi

        log "SUCCESS $name - output at $output_file"
        set_state "$name" "last_fired" "$(date +%Y-%m-%dT%H:%M:%S)"
        set_state "$name" "last_result" "success"
        increment_fire_count "$name"
        set_state "$name" "opencode_fail_streak" "0"
        set_state "$name" "circuit_open_until" ""

        # One success proves opencode can run, so the cross-heartbeat counter
        # resets too. If we had alerted, say so: an alarm that never clears
        # trains you to ignore it.
        if [[ -n "$(get_state "_dispatcher" "opencode_global_alerted_at")" ]]; then
            alert_ops recovered "Heartbeat runs are working again (first success: ${name}). Breakers opened during the outage stay open until their cooldown ends."
            set_state "_dispatcher" "opencode_global_alerted_at" ""
        fi
        set_state "_dispatcher" "opencode_global_fail_streak" "0"
        set_state "_dispatcher" "opencode_global_failed_names" ""

        # Red-team F6: a halt that arrived during the run also stops the
        # validator (another model call) and the notification.
        if is_halted || kill_switch_unarmed; then
            log "HALTED - validator and notify for $name skipped"
            set_state "$name" "last_result" "halted_after_run"
            break
        fi

        # Five Failure Modes post-output validator (opt-in per heartbeat)
        if ! run_output_validator "$name" "$output_file"; then
            set_state "$name" "last_result" "validator_blocked"
            continue
        fi

        # `notify: true` in the output raises a content-free Matrix alert
        check_and_notify "$name" "$output_file"
    done

    log "=== Dispatcher run complete ==="
}

# Guarded so tests can source this file for its functions without a tick.
if [[ "${DISPATCHER_TEST_SOURCE:-0}" != "1" ]]; then
    main "$@" >> "$LOG_FILE" 2>&1
fi
