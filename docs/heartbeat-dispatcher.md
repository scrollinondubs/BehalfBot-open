# Heartbeat dispatcher (OpenCode port)

Port of the behalf.bot chassis heartbeat framework onto OpenCode. This is Phase 3 of the porting plan (issue #4): the scheduled-work engine that turns a passive `opencode serve` into an always-on agent that does things without being prompted.

## Why gather-first

A naive scheduler that invokes the model every tick burns tokens on mostly-empty checks (~96 ticks/day at 15-minute cadence). The lesson the chassis paid for: put a deterministic check in front of every LLM call. The check is allowed to be wrong (a false-positive unnecessary fire is fine) - what matters is that it short-circuits cheaply. In practice ~96 dispatcher runs/day translate to ~4 model invocations.

```
tick (cron/launchd/compose loop, every 15 min)
  -> heartbeat-dispatcher.sh
       for each `## name` block in HEARTBEATS.md:
         schedule match?        (pure shell, free)
         -> gather script       (cheap local JSON emitter, free)
         -> condition           (threshold / always / ask_model via Ollama)
         -> FIRE: opencode run  (the only paid step)
```

## Files

| Path | Role |
|---|---|
| `scheduled-tasks/heartbeat-dispatcher.sh` | The dispatcher. Run once per tick. |
| `HEARTBEATS.md.template` | Schema docs + template. Copy to `HEARTBEATS.md` (gitignored) and register heartbeats there. |
| `scripts/gather-template.sh` | Starting point for new gather scripts. |
| `scripts/validate-heartbeats.sh` | Lints HEARTBEATS.md (paths, shebangs, missing files). Run before commit. |
| `scheduled-tasks/example-prompt.md` | Minimal prompt file for the template example. |

## State layout

All state lives under `BEHALFBOT_STATE_HOME` (defaults to the repo root; point it at a volume in Docker):

| Path | What |
|---|---|
| `scheduled-tasks/heartbeat-state.json` | Per-heartbeat last_checked / last_fired / last_result / fire_count / circuit-breaker state |
| `scheduled-tasks/conservation-mode.json` | `{"enabled": true, "reason": "...", "auto_lift_after": "ISO"}` - only `criticality: critical` heartbeats run while enabled. In compose this and `halt.json` live in `CONTROL_DIR` (the jill-control volume, read-only here) |
| `scheduled-tasks/halt.json` | Remote kill switch: every heartbeat skipped, `critical` included. Written only by jill-control from the Matrix control room (docs/control.md) |
| `logs/scheduled/YYYY-MM-DD-dispatcher.log` | Tick-by-tick decision log |
| `logs/telemetry/YYYY-MM-DD-usage.jsonl` | One JSON line per invocation: cost_usd, input/output/cache tokens, wall_seconds, exit_code |
| `briefings/YYYY-MM-DD-<name>.md` | Heartbeat output artifacts |

## The `claude -p` to `opencode run` mapping

| Chassis (`claude -p`) | This port (`opencode run`) |
|---|---|
| `--model opus\|sonnet\|haiku` | `-m <provider/model>`; aliases map via `HEARTBEAT_MODEL_OPUS` / `_SONNET` / `_HAIKU` env vars (defaults: `venice/zai-org-glm-5-2` for opus and sonnet, `venice/z-ai-glm-5-3-flash` for haiku; any non-`venice/` result is refused) |
| `--mcp-config .mcp.json` | Not needed - OpenCode loads the `mcp` block from `opencode.json` |
| `--max-budget-usd N` | No equivalent. `budget:` is advisory: the dispatcher sums `step_finish` costs post-run and logs a WARN on overage |
| `--dangerously-skip-permissions` | `--auto` (default on, `HEARTBEAT_OPENCODE_AUTO=0` to disable). Safety is enforced by `opencode.json` permission denies plus `.opencode/plugins/guardrails.ts`, which auto-loads and cannot silently unregister |
| `--output-format json` (single result object) | `--format json` (JSON event stream). Result text = concatenated `text` events; telemetry = summed `step_finish` events |
| MCP cold-boot per invocation | Set `OPENCODE_ATTACH_URL` (e.g. `http://opencode-serve:4747` in the compose stack) to attach runs to the long-lived serve and skip cold-boot entirely |

## Telemetry format

Same JSONL contract as the chassis, so downstream tooling ports unchanged:

```json
{"ts":"2026-07-07T09:00:12","heartbeat":"morning-briefing","model":"venice/zai-org-glm-5-2","cost_usd":0.0158,"input_tokens":11276,"output_tokens":25,"cache_read_tokens":0,"cache_create_tokens":0,"wall_seconds":14,"exit_code":0}
```

## Resilience features (carried over from the chassis)

- **Lockfile** - overlapping ticks exit immediately; stale locks (dead pid) are reaped.
- **Retry policy** - 3 attempts per FIRE with 20s / 60s backoff.
- **Circuit breaker** - after 2 consecutive failed FIREs (configurable via `OPENCODE_FAIL_CIRCUIT_THRESHOLD`), the heartbeat is skipped for an exponentially growing cooldown (capped at 32 ticks) so one broken heartbeat cannot serialize the whole dispatcher.
- **Conservation mode** - flip `scheduled-tasks/conservation-mode.json` to `{"enabled": true}` to pause everything except `criticality: critical` heartbeats. Optional `auto_lift_after` timestamp self-disables it.
- **Halt, daily caps, all-failed alarm, alerts** - the kill switch, `max_fires_per_day` / `max_usd_per_day`, the daily Venice spend cap, the cross-heartbeat failure alarm and the Matrix alert spool are documented in [control.md](control.md). `scheduled-tasks/dispatcher-selftest.sh` proves each of them with real ticks before the compose dispatcher loop starts.
- **Output validator** - heartbeats with `output_validator: true` get a small-model Five Failure Modes check; failing artifacts are quarantined (`.quarantined` suffix) and the ops webhook (`DISCORD_OPS_WEBHOOK_URL`) is alerted.
- **Fail-open ask_model** - if Ollama is unreachable, `condition: ask_model` fires rather than silently starving the heartbeat.
- **Recovery hooks** - drop `*.sh` files defining `behalfbot_recovery_*` functions into `scheduled-tasks/recovery-hooks.d/`; they run once per tick before the dispatch loop.

## Running it

Host, one-shot (for testing):

```bash
cp HEARTBEATS.md.template HEARTBEATS.md   # then register a heartbeat
bash scripts/validate-heartbeats.sh
DRY_RUN=true bash scheduled-tasks/heartbeat-dispatcher.sh
tail -20 logs/scheduled/$(date +%F)-dispatcher.log
```

Host, recurring: any 15-minute cron/launchd/systemd tick that runs the script.

Docker (canonical): the compose stack ships an opt-in `heartbeat-dispatcher` service behind the `dispatcher` profile. It loops the dispatcher every `DISPATCHER_INTERVAL_SECONDS` (default 900) and attaches runs to `opencode-serve` over the private network:

```bash
cp HEARTBEATS.md.template HEARTBEATS.md   # compose bind-mounts this file
docker compose --profile heartbeats up -d
```

## Triggers (deterministic keyword dispatch)

`scripts/dispatch-trigger.sh` is the companion inbound-message dispatcher: known-shape messages (keyword-prefixed commands) are matched against the `triggers.yaml` registry (copy `triggers.yaml.template`) and routed to shell handlers in milliseconds, without burning model tokens. Parsers live in `scripts/parsers/` (`passthrough`, `url-extract`); `scripts/discord-react.py` acks the source message with an emoji when `DISCORD_BOT_TOKEN` is set. Wire it into the Discord bridge (or any message source) by calling:

```bash
bash scripts/dispatch-trigger.sh <channel-id> <message-id> "<message body>"
```

Exit 1 means "no trigger matched - fall through to the LLM lane".
