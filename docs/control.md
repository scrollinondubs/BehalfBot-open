# Control: kill switch, spend ceiling, alerts, credential expiry

Jill v2 package C (#49, part of #46). Nothing here needs a model to work.
None of it gives Jill a new secret or a new way out of her container.

**Two facts first:**

- **Halt stops chat.** `venice-proxy` refuses every model call while Jill
  is halted, chat included, so a run already in progress fails at its next
  model step.
- **Heartbeats are off by default.** Jill launches with no scheduled work
  and runs only when Sean messages her (Sean, 2026-11-21). The dispatcher
  sits behind the `heartbeats` compose profile and does not start unless
  you ask for it.

## The pieces

```
Sean (Matrix control room, NOT encrypted)
   |  halt / resume / conserve / unconserve / status
   v
jill-control  (gateway/control.py)            holds MATRIX_CONTROL_TOKEN
   | writes                ^ reads                 ^ reads          ^ drains
   v                       |                       |                |
control-state            cred-venice,           venice-meter     alert-spool
 halt.json               cred-agentmail,        (venice-proxy    (dispatcher
 conservation-mode.json  cred-siyuan            writes)          writes, when
 armed.json              (one per gateway,                       heartbeats
   | read-only            each gateway writes                    are on)
   v                      only its own)
venice-proxy  -> refuses chat/completions while halted or unarmed;
                 meters every call; hard daily ceiling
dispatcher    -> (heartbeats profile only) skips everything while halted
                 or unarmed; caps; all-failed alarm
```

`opencode-serve` (Jill) mounts none of these volumes and cannot reach
`jill-control`. That sidecar is not on `jill-internal` and listens on no
port. `selftest/contain.sh` checks all of this from inside serve at every
boot.

## Kill switch

Send one of these as a whole message in the control room:

| Word | Effect |
|---|---|
| `halt [2h] [reason]` (also `mute`, `silence`) | `venice-proxy` refuses every model call, chat included. Heartbeats (if on) are skipped, `critical` too |
| `resume` (also `unmute`, `unhalt`) | Clears halt and conservation |
| `conserve [2h] [reason]` (also `throttle`, `conservation on`) | Heartbeats: only `critical` ones run. Chat is unaffected |
| `unconserve` (also `conservation off`) | Clears conservation |
| `status` | Reports both flags |

- **Duration.** A duration (`30m`, `2h`, `3d`, at least `1m`) sets an auto-lift. `halt 0m` is refused with an ack, because it would lift immediately. With no duration the flag stays until `resume`.
- **Who.** Only `MATRIX_PRINCIPAL` (your full Matrix user id) is obeyed. Display names are never compared.
- **Ignored entirely:** edits, a control word inside a sentence, and encrypted events.
- **Age rule.** `halt` and `conserve` are honoured at any age, in the order sent: a late stop is still a stop. `resume` and `unconserve` older than 10 minutes are NOT applied, and the room gets an ack saying so; send them again if you still mean them. A stale `status` is ignored silently.

**What halt does not stop:** a tool call already executing finishes. This
room keeps listening, so `resume` still works.

**Fail-closed rules**

- **Malformed flag file.** It reads as halted if it cannot be parsed, has an `enabled` that is not the boolean `true`/`false`, or has an `auto_lift_after` that is not exactly `YYYY-MM-DDTHH:MM:SSZ`.
- **Bad file types.** A flag, cursor, meter or probe file that is a symlink, a FIFO or larger than 64 KB is not read; a flag in that state reads as halted.
- **Unarmed switch.** `venice-proxy` and the dispatcher both need a fresh `armed.json` (`CONTROL_REQUIRE_ARMED=1`). `jill-control` rewrites it after every successful read of the control room. If it is older than 15 minutes, the switch is not listening, so model calls and heartbeats stop.
- **Boot.** `jill-control` retries its boot self-test with backoff (5s up to 5 min) until it passes: token valid, both rooms joined and unencrypted, control room readable. It reports healthy only after that.

### Why an unencrypted control room

Jill's chat room is end-to-end encrypted (Sean, 2026-11-20). `jill-control`
holds no Megolm keys, so it cannot read an encrypted room, and a switch that
silently never fires is worse than none. So the control room is a separate,
unencrypted room.

**The homeserver runs in Jax's Docker, so anything posted there is readable
on Jax's side, and a homeserver admin could forge a message from Sean.** For
the first reason, every alert is content-free: fixed templates with names,
counts and dollar figures only. The E2EE chat bridge (package D, #50) is
separate and can take over alert delivery later with no change to the spool
format.

## The Venice ceiling (the main spend control)

All of Jill's spend goes through `venice-proxy`, so the ceiling lives there:

| Setting | Default | What |
|---|---|---|
| `VENICE_MAX_USD_PER_DAY` | `5` | hard ceiling; past it every model call gets HTTP 429 until midnight UTC |
| `VENICE_ALERT_USD_PER_DAY` | `1` | one Matrix alert a day when spend crosses it (read by jill-control) |
| `VENICE_MAX_REQUESTS_PER_DAY` | `2000` | hard request ceiling |
| `VENICE_UNMETERED_USD_PER_REQUEST` | `0.05` | charged for a successful response that carries no `usage` |
| `VENICE_PRICES` | GLM 5.2 $1.40/$4.40/$0.26, GLM 5.3 Flash $0.17/$0.55/$0.03 per 1M tokens | in:out:cached; an unlisted model pays the highest listed rate |

**How metering works**

- **Count first.** A request is counted when it is forwarded.
- **Settle from usage.** Its cost is settled from the `usage` object of the response. The gateway sets `stream_options.include_usage` on every streamed request, so streams report it too.
- **No usage.** A response without usage is charged the flat amount, and jill-control alerts once that day.
- **Unreadable meter.** A meter file that cannot be read stops every call for the day, with an alert.
- **Overshoot.** A call that starts under the ceiling finishes, so the ceiling can be overshot by one call.

Prices are list prices seen 2026-11-21, partly from third-party pages.
Confirm them against venice.ai/pricing.

## Heartbeats (off by default)

To turn them on: `cp HEARTBEATS.md.template HEARTBEATS.md`, then
`docker compose --profile heartbeats up -d`. The dispatcher then:

- runs `scheduled-tasks/dispatcher-selftest.sh` first, and refuses to loop if it fails;
- skips everything while halted or unarmed, checked at tick start, before every run, before every retry, and before the validator and notification;
- refuses to run if `heartbeat-state.json` is not a JSON object (one alert), and never writes an empty or invalid state;
- requires `flock` for its state lock (the image has it): without it, the dispatcher refuses to start, sends one alert and exits non-zero. A lock held for 10s (`DISPATCHER_STATE_LOCK_WAIT_SECONDS`) refuses the write and stops the tick, with an alert;
- enforces caps:

| Setting | Default | Scope |
|---|---|---|
| `DISPATCHER_MAX_USD_PER_DAY` | `1`, alert at 50% | all heartbeats, `critical` included |
| `DISPATCHER_DEFAULT_MAX_FIRES_PER_DAY` | `24` | each heartbeat that sets no `max_fires_per_day`; `0` = off |
| `max_fires_per_day:` / `max_usd_per_day:` | none | one heartbeat |

**Telemetry**

- **Clamping.** Spend comes from the dispatcher's telemetry. Every cost and token value is clamped to a non-negative number.
- **Fail-closed.** Any of these reads as "cap reached", with an alert:
  - a row with a value that is not one;
  - an unparseable row;
  - an unreadable telemetry file;
  - a run that left no telemetry row.
- **Estimated cost.** OpenCode reports `cost: 0` for an unpriced model, so `cost_usd` is the larger of that and tokens x `VENICE_PRICES`.

**All-runs-failed alarm** (chassis 22fdfd4): it fires once (4h cooldown)
after 3 failed runs across at least 2 heartbeats. It never quotes stderr.

## Alerts

Two senders write to the alerts room (`MATRIX_ALERTS_ROOM`, default the
control room), as `[Jill] <text>`:

- **jill-control:**
  - the boot announcement and auto-lifts;
  - the Venice meter: alert line, hard ceiling, responses without usage, unreadable meter;
  - credential stage changes.
- **The dispatcher (heartbeats on only):** spool files (`spend-cap`, `spend-half`, `fire-cap`, `all-failed`, `recovered`, `unarmed`, `validator`, `spend-unmeasured`, `state-invalid`, `state-lock`, `no-flock`).

At most `ALERTS_PER_HOUR` (20) are posted. Undelivered alerts are retried.
Malformed spool files go to `rejected/`. Dollar figures are rounded to cents.

## Credential expiry

| id | probe (by the gateway holding the key) | stages beyond ok |
|---|---|---|
| `venice` | `GET /api/v1/api_keys/rate_limits` (free); `data.accessPermitted: false` is `exhausted` | rejected (401/403), exhausted (402 or no access), rate_limited (429) |
| `agentmail` | `GET /v0/inboxes/<inbox>` | same HTTP mapping |
| `siyuan` | `POST /api/notebook/lsNotebooks` | same HTTP mapping |
| `matrix` | `whoami` with the control token (jill-control) | rejected, unknown |
| anything | a date in `CREDENTIAL_EXPIRES`, e.g. `brave=2027-03-01` | t7, t1, expired |

Each gateway writes `{route, result, http_status, checked_at, last_ok_at}`
to its OWN volume. It writes through a random `O_EXCL|O_NOFOLLOW` temp
file. The record never holds the key or a response body.

`jill-control` mounts each volume read-only at
`/state/credentials/<gateway>/`, so no gateway can fake another's record.
It alerts on every stage change. A stage that does not resolve itself
(rejected, exhausted, rate_limited, expired, missing, unknown) is alerted
again every 3 days. A return to `ok` posts once.

`CREDENTIAL_EXPECT` defaults to `venice`. Add `agentmail` and `siyuan` once
their keys are set.

## Setup

1. Create a Matrix account for the switch, and an access token for it.
2. Create an **unencrypted** room. Invite the bot and yourself, and have the bot join.
3. In `.env`, set `MATRIX_CONTROL_TOKEN`, `MATRIX_PRINCIPAL` and `MATRIX_CONTROL_ROOM`. Optionally set the `VENICE_*` limits, `CREDENTIAL_EXPECT` and `CREDENTIAL_EXPIRES`.
4. `docker compose up -d`, then `docker logs behalfbot-jill-control`. It logs `ARMED`, or exactly what is wrong. Until it is armed, `venice-proxy` refuses model calls.
5. Say `status` in the room.

## Tests

```bash
python3 -m unittest discover -s tests/control -v   # jill-control vs a fake homeserver
python3 -m unittest discover -s tests/gateway -v   # incl. venice gate + meter, credential probe
bash scheduled-tasks/dispatcher-selftest.sh        # real dispatcher ticks, fake opencode
```
