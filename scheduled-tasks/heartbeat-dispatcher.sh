#!/usr/bin/env bash
# BehalfBot-open Heartbeat Dispatcher (OpenCode port of the chassis dispatcher)
#
# Parses HEARTBEATS.md, checks schedules, evaluates conditions, invokes the
# model via `opencode run` when work exists. Run it on a fixed tick (default
# every 15 minutes) from cron, launchd, systemd, or the compose
# `heartbeat-dispatcher` service (`docker compose --profile dispatcher up -d`).
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
#   DISCORD_WEBHOOK_URL     - notifications for heartbeats that emit
#                             `notify: true` in their output
#   DISCORD_OPS_WEBHOOK_URL - output-validator quarantine alerts
#   DRY_RUN                 - "true" logs the FIRE and skips the invocation

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
CONSERVATION_FILE="$STATE_DIR/conservation-mode.json"
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

# --- Conservation Mode ---

is_conservation_mode() {
    if [[ ! -f "$CONSERVATION_FILE" ]]; then
        return 1
    fi
    local enabled
    enabled=$(jq -r '.enabled // false' "$CONSERVATION_FILE")
    if [[ "$enabled" != "true" ]]; then
        return 1
    fi

    local auto_lift
    auto_lift=$(jq -r '.auto_lift_after // ""' "$CONSERVATION_FILE")
    if [[ -n "$auto_lift" && "$auto_lift" != "null" ]]; then
        local lift_epoch now_epoch
        lift_epoch=$(epoch_from_iso "${auto_lift%Z}")
        now_epoch=$(date +%s)
        if [[ $lift_epoch -gt 0 && $now_epoch -ge $lift_epoch ]]; then
            log "CONSERVATION - auto-lift triggered (past $auto_lift), disabling"
            printf '{"enabled": false, "enabled_at": null, "enabled_by": null, "auto_lift_after": null, "reason": null}\n' > "$CONSERVATION_FILE"
            return 1
        fi
    fi
    return 0
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

set_state() {
    local name="$1" field="$2" value="$3"
    local tmp="${STATE_FILE}.tmp"
    jq --arg n "$name" --arg f "$field" --arg v "$value" \
        '.[$n] = (.[$n] // {}) | .[$n][$f] = $v' "$STATE_FILE" > "$tmp" \
        && mv "$tmp" "$STATE_FILE"
}

increment_fire_count() {
    local name="$1"
    local tmp="${STATE_FILE}.tmp"
    jq --arg n "$name" \
        '.[$n] = (.[$n] // {}) | .[$n].fire_count = ((.[$n].fire_count // "0") | tonumber + 1 | tostring)' \
        "$STATE_FILE" > "$tmp" \
        && mv "$tmp" "$STATE_FILE"
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
    local start_ts exit_code=0 end_ts wall_secs ts_iso

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

        # Telemetry: sum cost/tokens over step_finish events.
        jq -cs \
            --arg name "$heartbeat_name" \
            --arg model "$model" \
            --arg ts "$ts_iso" \
            --argjson wall "$wall_secs" \
            --argjson exit_code "$exit_code" \
            '[.[] | select(.type == "step_finish") | .part] as $steps |
            {
                ts: $ts,
                heartbeat: $name,
                model: $model,
                cost_usd: ([$steps[].cost // 0] | add // 0),
                input_tokens: ([$steps[].tokens.input // 0] | add // 0),
                output_tokens: ([$steps[].tokens.output // 0] | add // 0),
                cache_read_tokens: ([$steps[].tokens.cache.read // 0] | add // 0),
                cache_create_tokens: ([$steps[].tokens.cache.write // 0] | add // 0),
                wall_seconds: $wall,
                exit_code: $exit_code
            }' "$tmp_events" >> "$telemetry_file" 2>> "$LOG_FILE" \
            && log "TELEMETRY $heartbeat_name - cost logged" \
            || log "WARN: telemetry parse failed for $heartbeat_name"

        # Advisory budget check (no hard cap in OpenCode).
        local run_cost over_budget
        run_cost=$(jq -rs '[.[] | select(.type == "step_finish") | .part.cost // 0] | add // 0' "$tmp_events" 2>/dev/null || echo 0)
        over_budget=$(jq -n --argjson c "${run_cost:-0}" --argjson b "${budget:-0}" '$c > $b' 2>/dev/null || echo false)
        if [[ "$over_budget" == "true" ]]; then
            log "WARN $heartbeat_name - run cost \$$run_cost exceeded advisory budget \$$budget"
        fi

        rm -f "$tmp_events"
    else
        printf '%s\n' "{\"ts\":\"$ts_iso\",\"heartbeat\":\"$heartbeat_name\",\"model\":\"$model\",\"cost_usd\":0,\"input_tokens\":0,\"output_tokens\":0,\"cache_read_tokens\":0,\"cache_create_tokens\":0,\"wall_seconds\":$wall_secs,\"exit_code\":$exit_code,\"error\":\"no_json_output\"}" >> "$telemetry_file"
        rm -f "$tmp_events"
    fi

    # A run that produced an empty result file is a failure even on exit 0.
    if [[ $exit_code -eq 0 && ! -s "$output_file" ]]; then
        log "WARN $heartbeat_name - opencode exited 0 but produced no text output"
        exit_code=1
    fi

    return $exit_code
}

# --- Discord Notifications ---

send_discord_notification() {
    local heartbeat_name="$1" summary="$2" output_file="$3"

    if [[ -z "${DISCORD_WEBHOOK_URL:-}" ]]; then
        log "WARN: DISCORD_WEBHOOK_URL not set, skipping notification"
        return
    fi

    local payload
    payload=$(jq -n \
        --arg name "$heartbeat_name" \
        --arg summary "$summary" \
        --arg file "$(basename "$output_file")" \
        --arg instance "${INSTANCE_NAME:-BehalfBot-open}" \
        '{
            content: ("🤖 **" + $instance + " | " + $name + "**\n" + $summary + "\n> " + $file)
        }')

    curl -sf -X POST "$DISCORD_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$payload" >> "$LOG_FILE" 2>&1 \
        || log "WARN: Discord notification failed for $heartbeat_name"
}

check_and_notify() {
    local name="$1" output_file="$2"

    if ! head -20 "$output_file" | grep -q '^notify: *true'; then
        return
    fi

    local summary
    summary=$(head -20 "$output_file" | grep '^summary: *' | sed 's/^summary: *//' | head -1)
    if [[ -z "$summary" ]]; then
        summary="Heartbeat completed with actions taken."
    fi

    log "NOTIFY $name - $summary"
    send_discord_notification "$name" "$summary" "$output_file"
}

# --- Post-Output Validator (Five Failure Modes check) ---
#
# For heartbeats with `output_validator: true`, run a small-model Five Failure
# Modes check against the output before it is "published". On pass: artifact
# stays. On fail: artifact quarantined (.quarantined suffix), ops webhook
# alerted. If the validator itself fails, fail-open.

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
        cost_usd=$(jq -rs '[.[] | select(.type == "step_finish") | .part.cost // 0] | add // 0' "$validator_events" 2>/dev/null || echo 0)
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

    local ops_webhook="${DISCORD_OPS_WEBHOOK_URL:-${DISCORD_WEBHOOK_URL:-}}"
    if [[ -n "$ops_webhook" ]]; then
        local alert_msg="**Five Failure Modes validator blocked ${name}** - mode: \`${mode_val}\`\n${reason_val}\nArtifact at: \`${quarantine_file}\`"
        curl -sf -X POST "$ops_webhook" \
            -H "Content-Type: application/json" \
            -d "$(jq -n --arg content "$alert_msg" '{content: $content}')" \
            >> "$LOG_FILE" 2>&1 || true
    fi

    return 1
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
    acquire_lock
    init_state
    log "=== Dispatcher run started ==="

    if [[ ! -f "$HEARTBEATS_FILE" ]]; then
        log "No HEARTBEATS.md at $HEARTBEATS_FILE (copy HEARTBEATS.md.template to get started)"
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

        log "FIRE $name - invoking opencode run (model=$model, budget=\$$budget advisory)"

        if [[ "$DRY_RUN" == "true" ]]; then
            log "DRY-RUN $name - would invoke opencode run (skipping)"
            set_state "$name" "last_result" "dry_run"
            continue
        fi

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
            if invoke_opencode "$prompt_input" "$output_file" "$model" "$budget" "$name" "$cwd"; then
                invoke_success=true
                break
            fi
            if [[ $attempt -lt 3 ]]; then
                local wait_s=$(( 20 * (3 ** (attempt - 1)) ))
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

            continue
        fi

        log "SUCCESS $name - output at $output_file"
        set_state "$name" "last_fired" "$(date +%Y-%m-%dT%H:%M:%S)"
        set_state "$name" "last_result" "success"
        increment_fire_count "$name"
        set_state "$name" "opencode_fail_streak" "0"
        set_state "$name" "circuit_open_until" ""

        # Five Failure Modes post-output validator (opt-in per heartbeat)
        if ! run_output_validator "$name" "$output_file"; then
            set_state "$name" "last_result" "validator_blocked"
            continue
        fi

        # Discord notification signal in output
        check_and_notify "$name" "$output_file"
    done

    log "=== Dispatcher run complete ==="
}

main "$@" >> "$LOG_FILE" 2>&1
