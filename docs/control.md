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
Sean (Matrix control room, NOT encrypted)      Sean (Jill's chat room, E2EE)
   |  halt / conserve / unconserve /              |  halt / resume / status /
   |  status / reset meter                        |  reset meter [spend]
   v                                              v
jill-control  (gateway/control.py)            matrix-bridge (#50, bridge/WIRING.md)
holds MATRIX_CONTROL_TOKEN                    writes the same flags in control-state
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
`jill-control` or `matrix-bridge`. That sidecar is not on `jill-internal` and listens on no
port. `selftest/contain.sh` checks all of this from inside serve at every
boot.

## Kill switch

Send one of these as a whole message. "Where" says which room accepts it:

| Word | Where | Effect |
|---|---|---|
| `halt [2h] [reason]` (also `mute`, `silence`) | both | `venice-proxy` refuses every model call, chat included. Heartbeats (if on) are skipped, `critical` too |
| `resume` (also `unmute`, `unhalt`) | **chat room only** | Clears halt and conservation |
| `conserve [2h] [reason]` (also `throttle`, `conservation on`) | control room | Heartbeats: only `critical` ones run. Chat is unaffected |
| `unconserve` (also `conservation off`) | control room | Clears conservation |
| `status` | both | Reports both flags |
| `reset meter` | both | Zeroes today's Venice request count and rate window (spend is kept). The request is recorded in control-state; `venice-proxy` applies it once, on its next call |
| `reset meter spend` | **chat room only** | The same, and also zeroes today's dollar spend |

**Why two rooms (#50).** The control room is unencrypted on a homeserver Jill
does not control, so its admin can forge any message there.

- **Stops stay in the control room.** A forged `halt` only stops Jill, so
  `halt` works there.
- **Lifts move to the chat room.** The words that lift a stop or hand back
  budget (`resume`, `reset meter spend`) are refused in the control room,
  with an ack. They work only in Jill's end-to-end encrypted chat room.
- **What the chat room requires.** The bridge accepts a message only when it
  decrypts and comes from a device cross-signed by Sean's pinned key
  (`bridge/WIRING.md`). In that room every command must be under 10 minutes
  old; an older one is dropped.

- **Duration.** A duration (`30m`, `2h`, `3d`, at least `1m`) sets an auto-lift. `halt 0m` is refused with an ack, because it would lift immediately. With no duration the flag stays until `resume`.
- **Who.** Only `MATRIX_PRINCIPAL` (your full Matrix user id) is obeyed. Display names are never compared.
- **Ignored entirely:** edits, a control word inside a sentence, and encrypted events.
- **Age rule (control room).** `halt` and `conserve` are honoured at any age, in the order sent: a late stop is still a stop. `unconserve` and `reset meter` older than 10 minutes are NOT applied, and the room gets an ack saying so; send them again if you still mean them. A stale `status`, `resume` or `reset meter spend` is ignored silently.

**Break-glass resume (host only).** There is no Matrix path to `resume`
other than the encrypted chat room (Sean, 2026-11-21). If the bridge is
identity-locked, down, or Sean has no verified device, lift a halt from a
shell on Jill's host, as the macOS user that runs her Docker:

```bash
docker compose exec jill-control python3 /app/gateway/control.py resume
```

It clears halt and conservation and logs `BREAK-GLASS resume`. Neither Jill
nor the homeserver can reach it. Halt words stay live in the chat room on
purpose: a message starting with `halt`, `mute` or `silence` halts Jill
(fail-safe).

**What halt does not stop:** a tool call already executing finishes. Both
rooms keep listening, so `resume` (in the chat room) still works. While
halted, the chat bridge answers every non-command message with a refusal
and sends nothing to the model.

**Fail-closed rules**

- **Malformed flag file.** A flag file that exists reads as halted if it cannot be parsed, has no `enabled`, has an `enabled` that is not the boolean `true`/`false`, or has an `auto_lift_after` that is not exactly `YYYY-MM-DDTHH:MM:SSZ`. A flag file that does not exist is off.
- **Bad file types.** A flag, cursor, meter or probe file that is a symlink, a FIFO or larger than 64 KB is not read; a flag in that state reads as halted.
- **Unarmed switch.** `venice-proxy` and the dispatcher both need a fresh `armed.json` (`CONTROL_REQUIRE_ARMED=1`) with a numeric `armed_at`. NaN, Infinity and a time more than 60s in the future read as unarmed. `jill-control` rewrites it after every successful read of the control room (every 15s). If it is older than `CONTROL_ARMED_MAX_AGE_SECONDS` (default 90), the switch is not listening, so model calls and heartbeats stop.
- **Boot.** `jill-control` retries its boot self-test with backoff (5s up to 5 min) until it passes: token valid, both rooms joined and unencrypted, control room readable. It reports healthy only after that.

### Why an unencrypted control room

Jill's chat room is end-to-end encrypted (Sean, 2026-11-20). `jill-control`
holds no Megolm keys, so it cannot read an encrypted room, and a switch that
silently never fires is worse than none. So the control room is a separate,
unencrypted room.

**The homeserver runs in Jax's Docker, so anything posted there is readable
on Jax's side, and a homeserver admin could forge a message from Sean.** For
the first reason, every alert is content-free: fixed templates with names,
counts and dollar figures only. For the second, `resume` and `reset meter
spend` are accepted only in the E2EE chat room (#50). The chat bridge spools
its own content-free alerts here: an identity change, or a change to the
room.

## The Venice ceiling (the main spend control)

All of Jill's spend goes through `venice-proxy`, so the ceiling lives there:

| Setting | Default | What |
|---|---|---|
| `VENICE_MAX_USD_PER_DAY` | `5` | hard ceiling (finite, checked at boot) |
| `VENICE_ALERT_USD_PER_DAY` | `1` | one Matrix alert a day when settled spend crosses it (jill-control) |
| `VENICE_MAX_IN_FLIGHT` | `4` | calls open at once |
| `VENICE_MAX_REQUESTS_PER_MINUTE` | `30` | rate limit |
| `VENICE_MAX_REQUESTS_PER_DAY` | `2000` | request ceiling; one Matrix alert when reached |
| `VENICE_MAX_OUTPUT_TOKENS` | `8192` | output cap, sent as both `max_tokens` and `max_completion_tokens` (the latter covers reasoning); a larger caller value is clamped |
| `VENICE_MAX_PROMPT_TOKENS` | `1048576` | the context window: the most a hold can count as prompt |
| `VENICE_PRICES` | GLM 5.2 $1.40/$4.40/$0.26, GLM 5.3 Flash $0.17/$0.55/$0.03 per 1M tokens | in:out:cached. Every model in `VENICE_MODELS` must have a price, or the proxy refuses to start |

**How a call is metered**

1. **Hold.** At `reserve`, the proxy holds a pessimistic amount for the call. The prompt bound is min(context window, request bytes + 4096) tokens: a text prompt cannot have more tokens than bytes, and 4096 covers what Venice adds. Add the output cap, all at the model's prices. Examples for GLM 5.2:
   - an empty request: $0.042;
   - a 50 KB request: $0.11;
   - a 200 KB request: $0.33;
   - a request over about 1 MB: capped at the context window, $1.50.

   GLM 5.3 Flash: from $0.005.
2. **Refuse.** The call is refused (HTTP 429) if settled + held + its hold would pass the ceiling, if 4 calls are already in flight, past 30 calls a minute, or past the daily request ceiling.
3. **Settle.** When the response ends, the hold is swapped for the cost in its `usage`. Streams are made to report usage, and SSE lines are parsed as they pass, so a usage chunk at the end of any size of stream is seen. A JSON body over 4 MB is searched from its tail.
4. **No usage, or unknown outcome.** The whole hold is charged. That covers a missing, unusable or zero `usage`, an upstream that could not be read to the end, a call that ran past 15 minutes, and a crash.
5. **Non-2xx.** A response that Venice answers with an error status and no usage is charged $0. Venice does not bill a refused request; it still counts against the request limits.
6. **Caller hangs up, or stops reading.** If the caller hangs up, or does not read for 30s, it is treated as gone. The proxy keeps reading upstream for up to 60s and 64 MB to see the usage, and charges the hold otherwise.

**Tripwire.** A bill larger than its hold means the size bound is not holding. Each one raises a Matrix alert (once a day). After 2 in a day, the proxy holds the whole context window per call for the rest of that day.

**Restart.** Holds live in memory but are written to the meter on every change. When `venice-proxy` starts, it folds the last persisted holds into that day's spend and counts their calls as unmetered. A restart (or a kill) with calls in flight cannot hand back budget those calls may have spent.

**Boot checks.** The proxy refuses to start if the ceiling is above 0 but below one minimum hold, or if an allowed model has no price. The venice route accepts bodies up to 4 MB with at most 50,000 JSON arrays and objects. Every gateway runs under a 512 MB memory limit.

**`GET /api/v1/models`.** It is gated by halt, served from a 10-minute cache, and on a miss counted against the limits, with none of the caller's headers forwarded.

**Unreadable meter.** A meter file that cannot be read, or holds a non-finite or negative number, refuses every call for the day, with an alert.

**Resets.**

- `reset meter` clears today's request count and the rate window. Spend is kept.
- `reset meter spend` also clears today's dollar spend.
- Both are keyed on the Matrix event's own time, so a replayed message changes nothing.

**Allowed models.** Prices are list prices seen 2026-11-21, partly from third-party pages; confirm them against venice.ai/pricing. `zai-org-glm-5-1`, `kimi-k2-7-code` and `deepseek-v4-pro` were removed from the allowlist (here and in `opencode.json`), because no price could be sourced with confidence.

### Launch checklist (step F, #52)

Things only a real Venice call can show, to check on the first live calls:

- [ ] A streamed chat call ends with a `usage` chunk (`stream_options.include_usage` is honoured). If not, every streamed call is charged its full hold; the "charged its full hold" alert shows it.
- [ ] Venice accepts a request carrying both `max_tokens` and `max_completion_tokens`.
- [ ] Billed prompt tokens stay below request bytes + 4096 (the hold's bound). The tripwire alert fires if not.
- [ ] Prices in `VENICE_PRICES` match venice.ai/pricing for GLM 5.2 and GLM 5.3 Flash.
- [ ] `status`, `halt` and `reset meter` round-trip in the control room, and `resume` there is refused with an ack.

The encrypted chat bridge (#50, `bridge/WIRING.md`):

- [ ] Sean confirms the master-key fingerprint that `matrix-bridge setup` printed matches the one his own client shows for his account, compared on his device, not from a copy the server could supply.
- [ ] Element X shows Jill as cross-signed (verified, no warning shield) in the room.
- [ ] A real encrypted round trip: Sean sends a message, the log shows `accept event=...`, Jill replies, and Element X decrypts the reply. Then `halt`, a chat message (refused, no model call in the venice-proxy log), `resume` (lifts it), and `show draft` / `approve draft` on a test draft.
- [ ] A replayed event does nothing. Restart the bridge (`docker compose restart matrix-bridge`): no message is answered twice, and the log shows no new `accept` for old event ids.
- [ ] A message from a second, non-principal device is dropped. Log in to Sean's account on a new session, do NOT verify it, send a message: the log shows `drop event=... reason=device-not-cross-signed` and Jill does not answer. Then log out that session.

## Heartbeats (off by default)

To turn them on: `cp HEARTBEATS.md.template HEARTBEATS.md`, then
`docker compose --profile heartbeats up -d`. The dispatcher then:

- runs `scheduled-tasks/dispatcher-selftest.sh` first, and refuses to loop if it fails;
- skips everything while halted or unarmed, checked at tick start, before every run, before every retry, and before the validator and notification;
- refuses to run if `heartbeat-state.json` is empty or not a JSON object (one alert, before any other alert logic), and never writes an empty or invalid state;
- requires `flock` for its state lock (the image has it): without it, the dispatcher refuses to start, sends one alert and exits non-zero. A lock held for 10s (`DISPATCHER_STATE_LOCK_WAIT_SECONDS`) refuses the write and stops the tick, with an alert;
- enforces caps:

| Setting | Default | Scope |
|---|---|---|
| `DISPATCHER_MAX_USD_PER_DAY` | `1`, alert at 50% | all heartbeats, `critical` included |
| `DISPATCHER_DEFAULT_MAX_FIRES_PER_DAY` | `24` | each heartbeat that sets no `max_fires_per_day`; `0` = off |
| `max_fires_per_day:` / `max_usd_per_day:` | none | one heartbeat |

**Telemetry**

- **Clamping.** Spend comes from the dispatcher's telemetry. Every cost and token value is clamped to a non-negative number.
- **No usage.** A run that reports no tokens and no cost is charged `DISPATCHER_UNMEASURED_RUN_USD` (default $0.25) as its own telemetry row, so the caps count it, and alerted once a day.
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
  - the Venice meter: alert line, hard ceiling, request ceiling, calls charged their full hold, the over-hold tripwire, unreadable meter;
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
python3 -m unittest discover -s tests/bridge -v    # chat commands, halt gate, approval screen
(cd matrix-bridge && CGO_ENABLED=0 go test -tags goolm ./...)   # acceptance rule, pinned trust chain
python3 -m unittest discover -s tests/gateway -v   # incl. venice gate + meter, credential probe
bash scheduled-tasks/dispatcher-selftest.sh        # real dispatcher ticks, fake opencode
```
