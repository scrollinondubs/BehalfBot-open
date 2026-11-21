#!/usr/bin/env bash
# dispatcher-selftest.sh - prove every dispatcher control holds, before the
# dispatcher loop starts (compose runs this first and refuses to loop on a
# failure). CI runs it too.
#
# Each case drives REAL dispatcher ticks (heartbeat-dispatcher.sh, unmodified)
# in a throwaway state home, against a fake `opencode` that counts its
# invocations and emits a JSON event stream. Nothing reaches the network,
# Venice or Matrix: alerts land in a sandbox spool and are inspected.
#
#   halt         halt.json on: nothing fires, critical included
#   halt-expired an auto-lift in the past: fires
#   halt-garbage an unparseable halt.json: nothing fires (fail closed)
#   halt-midtick halt arriving during a tick: the next heartbeat does not fire,
#                nor the validator or notify of the run in progress
#   F1           unreadable, invalid or missing telemetry reads as cap reached
#   F2           an invalid state file stops the tick; bad writes are dropped
#   F4           an unarmed switch is checked before every run
#   F6           strict flag schema, orphan and held locks, cents in alerts
#   unarmed      CONTROL_REQUIRE_ARMED=1 with no armed.json: nothing fires,
#                one alert
#   fire-cap     max_fires_per_day: 1 holds across two ticks, one alert
#   default-cap  DISPATCHER_DEFAULT_MAX_FIRES_PER_DAY covers a heartbeat
#                that sets no cap
#   spend-cap    OpenCode reports $0; the token estimate is what trips the
#                daily cap, one alert
#   all-failed   failures across two heartbeats raise one alarm; the next
#                success posts a recovery
#   unmeasured   a run with no usage and no cost raises one alert
#   content-free no alert carries gather data or model output
#   state-lock   40 concurrent state writes, none lost
#   live         (SELFTEST_LIVE=1, in compose) the real control dir is
#                read-only and the real spool is writable
#
# Exit 0 only when every case passes.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DISPATCHER="$HERE/heartbeat-dispatcher.sh"
ROOT="$(mktemp -d "${TMPDIR:-/tmp}/dispatcher-selftest.XXXXXX")" || {
    echo "[dispatcher-selftest] FAIL cannot create a scratch directory" >&2
    exit 1
}
CANARY="SELFTEST-PRIVATE-CANARY"
fail=0

say() { printf '[dispatcher-selftest] %s\n' "$*"; }
ok() { say "ok   $*"; }
bad() { say "FAIL $*"; fail=1; }

# No recursive delete of a computed path, ever: `trash` where it exists
# (a workstation), otherwise the scratch dir stays in TMPDIR, which in the
# container is discarded with it.
cleanup() {
    if command -v trash >/dev/null 2>&1; then
        trash "$ROOT" 2>/dev/null || true
    else
        say "scratch left at $ROOT"
    fi
}
trap cleanup EXIT

# Fake opencode: count calls, fail while $SB/fail exists, else emit a text
# event and a step_finish with 1M input tokens and NO cost (what OpenCode
# reports for a model with no price in opencode.json).
mkdir -p "$ROOT/bin"
cat > "$ROOT/bin/opencode" <<'SH'
#!/usr/bin/env bash
echo x >> "$FAKE_SB/calls"
if [[ -f "$FAKE_SB/unarm-on-call" ]]; then
    printf '{"armed_at": 1}\n' > "$FAKE_SB/control/armed.json"
fi
if [[ -f "$FAKE_SB/badcost" ]]; then
    printf '%s\n' '{"type":"text","part":{"text":"FAKE-MODEL-OUTPUT"}}'
    printf '%s\n' '{"type":"step_finish","part":{"cost":-50,"tokens":{"input":"lots","output":0,"reasoning":0,"cache":{"read":0,"write":0}}}}'
    exit 0
fi
if [[ -f "$FAKE_SB/halt-on-call" ]]; then
    printf '{"enabled": true, "auto_lift_after": null, "reason": "mid-tick"}\n' > "$FAKE_SB/control/halt.json"
fi
if [[ -f "$FAKE_SB/nousage" ]]; then
    printf '%s\n' '{"type":"text","part":{"text":"FAKE-MODEL-OUTPUT"}}'
    printf '%s\n' '{"type":"step_finish","part":{"cost":0,"tokens":{"input":0,"output":0,"reasoning":0,"cache":{"read":0,"write":0}}}}'
    exit 0
fi
if [[ -f "$FAKE_SB/fail" ]]; then
    echo "fake opencode failure $FAKE_CANARY" >&2
    exit 1
fi
printf '%s\n' '{"type":"text","part":{"text":"FAKE-MODEL-OUTPUT"}}'
printf '%s\n' '{"type":"step_finish","part":{"cost":0,"tokens":{"input":1000000,"output":0,"reasoning":0,"cache":{"read":0,"write":0}}}}'
SH
chmod 755 "$ROOT/bin/opencode"
if ! FAKE_SB="$ROOT" "$ROOT/bin/opencode" >/dev/null 2>&1; then
    say "FAIL cannot execute the fake opencode in $ROOT (a noexec TMPDIR?); set TMPDIR to an exec-able directory"
    exit 1
fi
rm -f "$ROOT/calls"

# A clean PATH for the ticks, plus wherever timeout/gtimeout and jq live
# (Homebrew on macOS; /usr/bin in the image).
TICK_PATH="$ROOT/bin:/usr/local/bin:/usr/bin:/bin"
for tool in timeout gtimeout jq; do
    if command -v "$tool" >/dev/null 2>&1; then
        TICK_PATH="$TICK_PATH:$(dirname "$(command -v "$tool")")"
    fi
done

# new_sandbox <name> <heartbeats...>: each heartbeat is "name|extra yaml"
new_sandbox() {
    SB="$ROOT/$1"
    shift
    mkdir -p "$SB/home/scheduled-tasks" "$SB/state" "$SB/control" "$SB/spool"
    echo "Selftest prompt. Reply ok." > "$SB/home/scheduled-tasks/prompt.md"
    {
        echo "# HEARTBEATS"
        local hb name extra
        for hb in "$@"; do
            name="${hb%%|*}"
            extra="${hb#*|}"
            echo
            echo "## $name"
            echo
            echo '```yaml'
            echo "schedule: every 0m"
            echo "gather: echo '{\"count\": 1, \"note\": \"$CANARY\"}'"
            echo "condition: threshold count > 0"
            echo "prompt: scheduled-tasks/prompt.md"
            echo "model: venice/zai-org-glm-5-2"
            echo "criticality: critical"
            [[ -n "$extra" && "$extra" != "$hb" ]] && printf '%b\n' "$extra"
            echo '```'
        done
    } > "$SB/home/HEARTBEATS.md"
    : > "$SB/calls"
}

# tick [VAR=value ...]: one real dispatcher run in the sandbox, clean env.
tick() {
    env -i PATH="$TICK_PATH" HOME="$SB" LANG=C.UTF-8 \
        BEHALFBOT_HOME="$SB/home" BEHALFBOT_STATE_HOME="$SB/state" \
        CONTROL_DIR="$SB/control" ALERT_SPOOL_DIR="$SB/spool" \
        OPENCODE_BIN="$ROOT/bin/opencode" DISPATCHER_RETRY_BASE_SECONDS=0 \
        DISPATCHER_DEFAULT_MAX_FIRES_PER_DAY=0 DISPATCHER_MAX_USD_PER_DAY=1000 \
        FAKE_SB="$SB" FAKE_CANARY="$CANARY" "$@" \
        bash "$DISPATCHER" >/dev/null 2>&1
    return 0
}

calls() { wc -l < "$SB/calls" | tr -d ' '; }
alerts() { find "$SB/spool" -name "*-$1.json" 2>/dev/null | wc -l | tr -d ' '; }
logged() { grep -q -- "$1" "$SB"/state/logs/scheduled/*-dispatcher.log 2>/dev/null; }

halt_json() {
    printf '{"enabled": true, "enabled_at": "2026-01-01T00:00:00Z", "enabled_by": "selftest", "auto_lift_after": %s, "reason": "selftest"}\n' "$1" \
        > "$SB/control/halt.json"
}

# --- halt -----------------------------------------------------------------
new_sandbox halt "hb-a|"
halt_json null
tick
[[ "$(calls)" == 0 ]] && logged "HALTED - every heartbeat skipped" \
    && ok "halt: nothing fired, critical included" || bad "halt: $(calls) run(s) fired while halted"

new_sandbox halt-expired "hb-a|"
halt_json '"2001-01-01T00:00:00Z"'
tick
[[ "$(calls)" -ge 1 ]] && ok "halt with a past auto-lift: fired" || bad "halt with a past auto-lift still blocked"
grep -q '"enabled": true' "$SB/control/halt.json" && ok "halt-expired: the dispatcher did not rewrite the flag (jill-control owns it)" \
    || bad "halt-expired: the dispatcher rewrote halt.json"

new_sandbox halt-garbage "hb-a|"
echo '{"enabled": tru' > "$SB/control/halt.json"
tick
[[ "$(calls)" == 0 ]] && ok "unparseable halt.json: treated as halted" || bad "unparseable halt.json let $(calls) run(s) fire"

new_sandbox halt-badlift "hb-a|"
halt_json '"next tuesday"'
tick
[[ "$(calls)" == 0 ]] && ok "unparseable auto_lift_after: stays halted" || bad "unparseable auto_lift_after lifted the halt"

new_sandbox halt-midtick "hb-a|" "hb-b|" "hb-c|"
touch "$SB/halt-on-call"
tick
[[ "$(calls)" == 1 ]] && logged "HALTED" \
    && ok "halt mid-tick: the run in progress finished, the next two heartbeats did not fire" \
    || bad "halt mid-tick: $(calls) run(s) fired"

new_sandbox halt-retry "hb-a|"
touch "$SB/halt-on-call" "$SB/fail"
tick
[[ "$(calls)" == 1 ]] && logged "retry 2 of hb-a skipped" \
    && ok "halt during retries: no further attempt" || bad "halt during retries: $(calls) attempt(s)"

new_sandbox halt-validator "hb-a|output_validator: true"
touch "$SB/halt-on-call"
tick
[[ "$(calls)" == 1 ]] && logged "validator and notify for hb-a skipped" \
    && ok "F6 halt during a run: the validator model call and the notify are skipped" \
    || bad "F6 halt during a run: $(calls) model call(s)"

new_sandbox strict-flags "hb-a|"
for doc in '{"enabled": "true"}' '{"enabled": 1}' '{"enabled": true, "auto_lift_after": "2001-01-01"}' \
           '{"enabled": true, "auto_lift_after": "2001-01-01T00:00:00+00:00"}' '{"enabled": true, "auto_lift_after": 5}'; do
    printf '%s\n' "$doc" > "$SB/control/halt.json"
    tick
done
[[ "$(calls)" == 0 ]] && ok "F6 strict flag schema: 5 malformed halt files all read as halted" \
    || bad "F6 strict flag schema: $(calls) run(s) fired on a malformed halt.json"

# --- unarmed kill switch --------------------------------------------------
new_sandbox unarmed "hb-a|"
tick CONTROL_REQUIRE_ARMED=1
tick CONTROL_REQUIRE_ARMED=1
[[ "$(calls)" == 0 && "$(alerts unarmed)" == 1 ]] && ok "unarmed switch: nothing fired, one alert over two ticks" \
    || bad "unarmed switch: calls=$(calls) alerts=$(alerts unarmed)"
printf '{"armed_at": %s}\n' "$(date +%s)" > "$SB/control/armed.json"
tick CONTROL_REQUIRE_ARMED=1
[[ "$(calls)" -ge 1 ]] && ok "armed switch: fires" || bad "armed switch: still blocked"

new_sandbox unarmed-midtick "hb-a|" "hb-b|"
printf '{"armed_at": %s}\n' "$(date +%s)" > "$SB/control/armed.json"
touch "$SB/unarm-on-call"
tick CONTROL_REQUIRE_ARMED=1
[[ "$(calls)" == 1 ]] && ok "F4 switch going unarmed mid-tick: the next heartbeat did not fire" \
    || bad "F4 unarmed mid-tick: $(calls) run(s)"

# --- state file and lock ----------------------------------------------------
new_sandbox state-invalid "hb-a|"
mkdir -p "$SB/state/scheduled-tasks"
printf '[]\n' > "$SB/state/scheduled-tasks/heartbeat-state.json"
tick
tick
[[ "$(calls)" == 0 && "$(alerts state-invalid)" == 1 ]] \
    && [[ "$(cat "$SB/state/scheduled-tasks/heartbeat-state.json")" == "[]" ]] \
    && ok "F2 invalid state file: nothing fired, one alert, the file was left for a human" \
    || bad "F2 invalid state file: calls=$(calls) alerts=$(alerts state-invalid)"

new_sandbox state-empty-write "hb-a|"
(
    export BEHALFBOT_HOME="$SB/home" BEHALFBOT_STATE_HOME="$SB/state" DISPATCHER_TEST_SOURCE=1
    # shellcheck source=/dev/null
    source "$DISPATCHER"
    init_state
    set_state "keep" "v" "1"
    _state_update 'empty'
    _state_update '"a string"'
)
jq -e '.keep.v == "1"' "$SB/state/scheduled-tasks/heartbeat-state.json" >/dev/null 2>&1 \
    && ok "F2 an empty or non-object update never replaces the state file" \
    || bad "F2 an empty or non-object update replaced the state file"

new_sandbox orphan-lock "hb-a|"
mkdir -p "$SB/state/scheduled-tasks"
echo '{}' > "$SB/state/scheduled-tasks/heartbeat-state.json"
mkdir "$SB/state/scheduled-tasks/heartbeat-state.json.lock"
touch -t 202001010000 "$SB/state/scheduled-tasks/heartbeat-state.json.lock"
tick
[[ "$(calls)" == 1 && "$(alerts state-lock)" == 1 ]] && logged "orphaned state lock" \
    && ok "F6 orphaned lock (no pid): removed with an alert, then the tick ran" \
    || bad "F6 orphaned lock: calls=$(calls) alerts=$(alerts state-lock)"

new_sandbox held-lock "hb-a|"
mkdir -p "$SB/state/scheduled-tasks/heartbeat-state.json.lock"
echo '{}' > "$SB/state/scheduled-tasks/heartbeat-state.json"
echo $$ > "$SB/state/scheduled-tasks/heartbeat-state.json.lock/pid"
tick
rm -f "$SB/state/scheduled-tasks/heartbeat-state.json.lock/pid"
rmdir "$SB/state/scheduled-tasks/heartbeat-state.json.lock"
[[ "$(calls)" == 0 && "$(alerts state-lock)" == 1 ]] && logged "write refused" \
    && ok "F6 lock held by a live process: writes refused, nothing fired, one alert" \
    || bad "F6 held lock: calls=$(calls) alerts=$(alerts state-lock)"

# --- per-heartbeat fire cap -----------------------------------------------
new_sandbox fire-cap "hb-a|max_fires_per_day: 1"
tick
tick
tick
[[ "$(calls)" == 1 && "$(alerts fire-cap)" == 1 ]] && logged "CAPPED hb-a" \
    && ok "max_fires_per_day: 1 run over three ticks, one alert" \
    || bad "max_fires_per_day: calls=$(calls) alerts=$(alerts fire-cap)"

new_sandbox default-cap "hb-a|"
tick DISPATCHER_DEFAULT_MAX_FIRES_PER_DAY=2
tick DISPATCHER_DEFAULT_MAX_FIRES_PER_DAY=2
tick DISPATCHER_DEFAULT_MAX_FIRES_PER_DAY=2
[[ "$(calls)" == 2 ]] && ok "default per-heartbeat cap: 2 runs over three ticks" || bad "default cap: calls=$(calls)"

# --- daily spend cap --------------------------------------------------------
new_sandbox spend-cap "hb-a|" "hb-b|"
tick DISPATCHER_MAX_USD_PER_DAY=1
first=$(calls)
tick DISPATCHER_MAX_USD_PER_DAY=1
tick DISPATCHER_MAX_USD_PER_DAY=1
cost=$(jq -s '[.[].cost_usd] | add' "$SB"/state/logs/telemetry/*-usage.jsonl 2>/dev/null || echo 0)
reported=$(jq -s '[.[].reported_cost_usd] | add' "$SB"/state/logs/telemetry/*-usage.jsonl 2>/dev/null || echo 1)
[[ "$reported" == 0 ]] && awk -v c="$cost" 'BEGIN { exit !(c >= 1.39) }' \
    && ok "spend estimate: OpenCode reported \$0, telemetry records \$$cost from tokens" \
    || bad "spend estimate: reported=$reported recorded=$cost"
[[ "$first" == 1 && "$(calls)" == 1 && "$(alerts spend-cap)" == 1 ]] && logged "SPEND-CAPPED" \
    && ok "daily spend cap: tripped after the first \$1.40 run, nothing more fired, one alert" \
    || bad "daily spend cap: first=$first total=$(calls) alerts=$(alerts spend-cap)"

new_sandbox spend-half "hb-a|"
tick DISPATCHER_MAX_USD_PER_DAY=2
tick DISPATCHER_MAX_USD_PER_DAY=2
[[ "$(alerts spend-half)" == 1 ]] && ok "spend at 50% of the cap: one alert" || bad "spend-half: $(alerts spend-half) alert(s)"
if grep -hoE '\$[0-9]+\.[0-9]+' "$SB"/spool/*.json | grep -qvE '^\$[0-9]+\.[0-9]{2}$'; then
    bad "F6 an alert carries a dollar figure that is not rounded to cents"
else
    ok "F6 dollar figures in alerts are rounded to cents"
fi

# --- F1: telemetry that cannot be trusted reads as "cap reached" ------------
new_sandbox telemetry-garbage "hb-a|"
mkdir -p "$SB/state/logs/telemetry"
printf 'not json\n' > "$SB/state/logs/telemetry/$(date +%Y-%m-%d)-usage.jsonl"
tick
[[ "$(calls)" == 0 && "$(alerts spend-cap)" == 1 ]] && ok "F1 an unparseable telemetry row: capped, one alert" \
    || bad "F1 unparseable telemetry: calls=$(calls) alerts=$(alerts spend-cap)"

new_sandbox telemetry-negative "hb-a|"
mkdir -p "$SB/state/logs/telemetry"
printf '{"heartbeat":"x","cost_usd":-100}\n' > "$SB/state/logs/telemetry/$(date +%Y-%m-%d)-usage.jsonl"
tick
[[ "$(calls)" == 0 ]] && ok "F1 a negative cost row cannot offset spend: capped" || bad "F1 negative cost: $(calls) run(s)"

new_sandbox telemetry-badrun "hb-a|" "hb-b|"
touch "$SB/badcost"
tick
[[ "$(calls)" == 1 ]] && jq -e '.invalid == true and .cost_usd >= 0' "$SB"/state/logs/telemetry/*-usage.jsonl >/dev/null \
    && ok "F1 a run reporting a negative cost and string tokens is clamped, marked invalid, and caps the day" \
    || bad "F1 bad run telemetry: calls=$(calls)"

new_sandbox telemetry-missing "hb-a|" "hb-b|"
mkdir -p "$SB/state/logs/telemetry/$(date +%Y-%m-%d)-usage.jsonl"
tick
[[ "$(calls)" -le 1 ]] && logged "no telemetry row was recorded" \
    && ok "F1 a run that left no telemetry row: the rest of the day is capped" \
    || bad "F1 missing telemetry row: calls=$(calls)"
rmdir "$SB/state/logs/telemetry/$(date +%Y-%m-%d)-usage.jsonl" 2>/dev/null

# --- unmeasured spend -------------------------------------------------------
new_sandbox unmeasured "hb-a|" "hb-b|"
touch "$SB/nousage"
tick
tick
[[ "$(alerts spend-unmeasured)" == 1 ]] && logged "reported no token usage" \
    && ok "unmeasured spend: a run with no usage raised one alert over four runs" \
    || bad "unmeasured spend: $(alerts spend-unmeasured) alert(s)"

# --- all-runs-failed alarm --------------------------------------------------
new_sandbox all-failed "hb-a|" "hb-b|"
touch "$SB/fail"
tick OPENCODE_GLOBAL_FAIL_THRESHOLD=2
[[ "$(alerts all-failed)" == 1 ]] && ok "all-failed alarm: raised after failures across two heartbeats" \
    || bad "all-failed alarm: $(alerts all-failed) alert(s)"
rm -f "$SB/fail"
tick OPENCODE_GLOBAL_FAIL_THRESHOLD=2
[[ "$(alerts recovered)" == 1 ]] && ok "all-failed alarm: recovery posted on the next success" \
    || bad "all-failed alarm: $(alerts recovered) recovery alert(s)"

# --- content-free alerts ----------------------------------------------------
if grep -rlE "$CANARY|FAKE-MODEL-OUTPUT|fake opencode failure" "$ROOT"/*/spool >/dev/null 2>&1; then
    bad "an alert carried gather data, model output or opencode stderr"
else
    total=$(find "$ROOT"/*/spool -name '*.json' | wc -l | tr -d ' ')
    ok "content-free: none of $total alerts carries gather data, model output or stderr"
fi
if find "$ROOT"/*/spool -name '*.json' -exec jq -e '(.kind | type == "string") and (.text | type == "string")' {} \; >/dev/null 2>&1; then
    ok "alert spool records are well-formed"
else
    bad "a spool record is not {kind, text}"
fi

# --- state lock -------------------------------------------------------------
# 40 writers at once is far past what a tick does; give them time so the
# test measures lost updates, not the (correct) refusal after the wait.
new_sandbox state-lock "hb-a|"
(
    export BEHALFBOT_HOME="$SB/home" BEHALFBOT_STATE_HOME="$SB/state" DISPATCHER_TEST_SOURCE=1
    export DISPATCHER_STATE_LOCK_WAIT_SECONDS=120
    # shellcheck source=/dev/null
    source "$DISPATCHER"
    init_state
    for i in $(seq 1 20); do
        ( set_state "race-$i" "v" "$i"; echo "race-$i rc=$?" >> "$SB/writers.log" ) 2>> "$SB/writers.err" &
        ( increment_fire_count "count-$i"; echo "count-$i rc=$?" >> "$SB/writers.log" ) 2>> "$SB/writers.err" &
    done
    wait
)
lost=$(jq '[range(1;21) as $i | select(.["race-\($i)"].v != "\($i)" or .["count-\($i)"].fire_count != "1")] | length' \
    "$SB/state/scheduled-tasks/heartbeat-state.json" 2>/dev/null || echo 40)
logcount() { cat "$SB"/state/logs/scheduled/*-dispatcher.log 2>/dev/null | grep -c "$1"; }
[[ "$lost" == 0 ]] && ok "state lock: 40 concurrent writes, none lost" \
    || bad "state lock: $lost write(s) missing (refused: $(logcount "write refused"), discarded: $(logcount "discarded"), orphan removals: $(logcount "orphaned"), dead-holder recoveries: $(logcount "dead holder"), writers finished: $(wc -l < "$SB/writers.log" 2>/dev/null | tr -d ' ')/40, missing: $(jq -r '[range(1;21) as $i | select(.["race-\($i)"].v != "\($i)") | "race-\($i)"] + [range(1;21) as $i | select(.["count-\($i)"].fire_count != "1") | "count-\($i)"] | join(",")' "$SB/state/scheduled-tasks/heartbeat-state.json" 2>/dev/null), stderr: $(tr '\n' ' ' < "$SB/writers.err" 2>/dev/null | cut -c1-400))"

# --- live mounts (compose only) ---------------------------------------------
if [[ "${SELFTEST_LIVE:-0}" == 1 ]]; then
    : "${CONTROL_DIR:?}" "${ALERT_SPOOL_DIR:?}"
    if [[ -d "$CONTROL_DIR" ]] && ! touch "$CONTROL_DIR/.selftest-write" 2>/dev/null; then
        ok "live: $CONTROL_DIR is read-only to the dispatcher"
    else
        rm -f "$CONTROL_DIR/.selftest-write"
        bad "live: $CONTROL_DIR is missing or writable; only jill-control may write the flags"
    fi
    if touch "$ALERT_SPOOL_DIR/.selftest-write" 2>/dev/null; then
        rm -f "$ALERT_SPOOL_DIR/.selftest-write"
        ok "live: the alert spool is writable"
    else
        bad "live: cannot write the alert spool $ALERT_SPOOL_DIR"
    fi
fi

if [[ "$fail" != 0 ]]; then
    say "DISPATCHER SELF-TEST FAILED"
    exit 1
fi
say "all dispatcher controls held"
