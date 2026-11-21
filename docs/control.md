# Control: kill switch, caps, alerts, credential expiry

Jill v2 package C (#49, part of #46). Everything here works without a model.
None of it gives Jill a new secret or a new way out of her container.

## The pieces

```
Sean (Matrix control room, NOT encrypted)
   |  halt / resume / conserve / unconserve / status
   v
jill-control  (gateway/control.py)            holds MATRIX_CONTROL_TOKEN
   | writes                 ^ drains                  ^ reads
   v                        |                         |
control-state volume    alert-spool volume     credential-status volume
 halt.json                (dispatcher writes)    (venice/agentmail/siyuan
 conservation-mode.json                           proxies write status-only
 armed.json                                       probe results)
   | read-only
   v
heartbeat-dispatcher  -> skips everything while halted or unarmed,
                         enforces daily caps, raises the all-failed alarm
```

`opencode-serve` (Jill) mounts none of the three volumes and cannot reach
`jill-control`. That sidecar is not on `jill-internal` and listens on no
port. The boot self-test (`selftest/contain.sh`) checks all of this from
inside serve.

## Kill switch

Send one of these as a whole message in the control room:

| Word | Effect |
|---|---|
| `halt [2h] [reason]` (also `mute`, `silence`) | Every heartbeat is skipped from the next dispatcher tick, `critical` ones included |
| `resume` (also `unmute`, `unhalt`) | Clears halt and conservation |
| `conserve [2h] [reason]` (also `throttle`, `conservation on`) | Only `critical` heartbeats run |
| `unconserve` (also `conservation off`) | Clears conservation |
| `status` | Reports both flags |

A duration (`30m`, `2h`, `3d`) sets an auto-lift. With no duration the flag
stays set until you say `resume`.

Only `MATRIX_PRINCIPAL` (your full Matrix user id) is obeyed. Display names
are never compared. The following are ignored: messages older than 10
minutes, edits, a control word inside a sentence, and encrypted events.

**What halt does not stop:** chat with Jill through her bridge (only you
drive that), and a scheduled run already in progress (it finishes, up to
about an hour with retries). The halt gate is the dispatcher's. The ack
says so.

**Fail-closed rules**

- A `halt.json` that cannot be parsed, or whose auto-lift time cannot be
  parsed, reads as halted.
- In compose the dispatcher also needs a fresh `armed.json`
  (`CONTROL_REQUIRE_ARMED=1`). `jill-control` rewrites it after every
  successful read of the control room. If it is older than 15 minutes, the
  kill switch is not listening, so nothing fires and one alert goes out.
- The dispatcher does not start until `jill-control` passes its boot
  self-test and reports healthy.

### Why an unencrypted control room

Jill's chat room is end-to-end encrypted (Sean, 2026-11-20). `jill-control`
holds no Megolm keys, so it cannot read an encrypted room. A switch that
silently never fires is worse than none. It refuses to arm on an encrypted
room, the same rule as the chassis listener.

So the control room is a separate, unencrypted room. **The homeserver runs
in Jax's Docker, so anything posted there is readable on Jax's side.** That
is why every alert is content-free: fixed templates carrying heartbeat
names, counts and dollar figures only. Never model output, gather data,
prompt text or log lines. The E2EE chat bridge (package D, #50) is separate.
It can carry content, and it can take over alert delivery later without any
change to the spool format.

## Alerts

The dispatcher writes `{"kind": "...", "text": "..."}` files into the
spool. `jill-control` posts each one to `MATRIX_ALERTS_ROOM` (default: the
control room) as `[Jill] <text>` and deletes it. Files it cannot parse go to
`rejected/`. Undelivered alerts stay in the spool and are retried. At most
`ALERTS_PER_HOUR` (default 20) are posted per hour.

| kind | when |
|---|---|
| `spend-cap` | today's dispatcher spend reached `DISPATCHER_MAX_USD_PER_DAY` (once a day) |
| `fire-cap` | a heartbeat hit its daily fire cap (once per heartbeat per day) |
| `all-failed` | runs failing across several heartbeats (cooldown 4h) |
| `recovered` | the first success after an `all-failed` |
| `unarmed` | the kill switch stopped listening (once a day) |
| `validator` | the Five Failure Modes validator quarantined an artifact (mode only) |

`jill-control` posts its own alerts too: one at boot ("Kill switch armed"),
when an auto-lift clears a flag, and for credential stage changes.

`DISCORD_OPS_WEBHOOK_URL`, when set, gets the same text as well.

## Dispatcher caps

| Setting | Default | Scope |
|---|---|---|
| `DISPATCHER_MAX_USD_PER_DAY` | `5` | all heartbeats together, `critical` included |
| `DISPATCHER_DEFAULT_MAX_FIRES_PER_DAY` | `24` | each heartbeat that sets no `max_fires_per_day`; `0` turns the default off |
| `max_fires_per_day:` (HEARTBEATS.md) | none | one heartbeat |
| `max_usd_per_day:` (HEARTBEATS.md) | none | one heartbeat plus its validator runs |

Caps are absolute until the date rolls. A changed condition does not lift
one. A cap suppresses the model run, not just a notification.

**Spend is estimated from tokens.** `opencode.json` carries no prices, so
OpenCode reports `cost: 0`. A cap that sums zeros never trips. Each
telemetry row records `cost_usd` as the larger of OpenCode's figure and
`tokens x VENICE_PRICES`, plus `reported_cost_usd`. The default prices are
Venice list prices for GLM 5.2 ($1.40 in, $4.40 out, $0.26 cached per
million tokens) and GLM 5.3 Flash ($0.17 / $0.55 / $0.03), as seen
2026-11-21. A model missing from the table is priced at the highest rate
listed, so it is over-counted, never free.

**The cap covers the dispatcher only.** Chat through the bridge is not
counted or capped.

The chassis's alert dedup (`realert_after`, `dedupe_key`) and suppression
ledger are not ported.

## All-runs-failed alarm

Ported from chassis 22fdfd4. The alarm fires once (4h cooldown) after
`OPENCODE_GLOBAL_FAIL_THRESHOLD` (3) consecutive failed runs across at least
`OPENCODE_GLOBAL_DISTINCT_THRESHOLD` (2) different heartbeats. Without it,
each failing heartbeat opens its own circuit breaker and goes quiet, and the
install looks healthy from outside. The first success clears it and posts a
recovery. Unlike the chassis, the alert does not quote the last error line,
because opencode's stderr can carry prompt text.

## Credential expiry

Jill's keys live only in the gateways, so the gateways check them:

| id | how | where the key lives |
|---|---|---|
| `venice` | `GET /api/v1/api_keys/rate_limits` (free) every `CREDENTIAL_PROBE_SECONDS` | venice-proxy |
| `agentmail` | `GET /v0/inboxes/<inbox>` | agentmail-proxy |
| `siyuan` | `POST /api/notebook/lsNotebooks` | siyuan-proxy |
| `matrix` | `whoami` with the control token | jill-control |
| anything | an expiry date in `CREDENTIAL_EXPIRES`, e.g. `brave=2027-03-01,discord=2027-06-30` | n/a |

A gateway writes `{route, result, http_status, checked_at, last_ok_at}` to
`credential-status/<route>.json`. The record never holds the key or a
response body. `jill-control` turns these into stages:

- `rejected` - the upstream answered 401 or 403.
- `unknown` - no probe for 3 intervals, or no success for over a day.
- `missing` - a credential in `CREDENTIAL_EXPECT` has no record after 2 intervals.
- `t7` / `t1` / `expired` - from the dates in `CREDENTIAL_EXPIRES`.

It alerts once per stage change. `rejected`, `expired`, `missing` and
`unknown` re-alert every `CREDENTIAL_REALERT_DAYS` (3). A return to `ok`
posts once and clears the record.

`CREDENTIAL_EXPECT` defaults to `venice`. Add `agentmail` and `siyuan` once
their keys are set. Brave's key sits in `brave-mcp`, which is not a gateway
and cannot be probed, so give it a date in `CREDENTIAL_EXPIRES`.

No model is in this path on purpose. A dead Venice key means the model
cannot run, so an alert that needed the model would never arrive.

## Setup

1. Create a Matrix account for the switch (for example `@jill-control:<server>`) and an access token for it.
2. Create an **unencrypted** room, invite the bot and yourself, and have the bot join.
3. In `.env`: `MATRIX_CONTROL_TOKEN`, `MATRIX_PRINCIPAL` (your full user id), `MATRIX_CONTROL_ROOM` (the `!room:server` id). Optionally `MATRIX_HOMESERVER`, `MATRIX_ALERTS_ROOM`, `CREDENTIAL_EXPECT` and `CREDENTIAL_EXPIRES`.
4. `docker compose up -d jill-control`, then `docker logs behalfbot-jill-control`. It says `ARMED`, or it lists exactly what is wrong. "Kill switch armed" appears in the room.
5. Say `status` in the room to see the ack.

## Tests

```bash
python3 -m unittest discover -s tests/control -v   # jill-control vs a fake homeserver
python3 -m unittest discover -s tests/gateway -v   # includes the credential probe
bash scheduled-tasks/dispatcher-selftest.sh        # real dispatcher ticks, fake opencode
```

The dispatcher self-test also runs in compose before the dispatcher loop
starts (`SELFTEST_LIVE=1` adds the mount checks). A failure stops the
dispatcher.
