# Matrix bridge wiring

Puts Jill (OpenCode, GLM via Venice) one end-to-end encrypted Matrix message
away from Sean (#50). It replaces the Discord bridge.

```
Sean (Element X) --E2EE--> homeserver --> matrix-bridge --> api-proxy --> opencode-serve --> venice-proxy
                                          (Go: sync, crypto,   (Python worker:
                                           trust decision)      commands, halt gate,
                                                                approvals, documents)
```

## Threat model, in one paragraph

The homeserver is administered by someone else (Jax). Its admin can read
anything unencrypted, forge any unencrypted event, add devices to Sean's
account, change the room's members and state, and replay or delay events.
So the bridge trusts the server for nothing. It acts on a message only if
all of these hold:

- it decrypts;
- it is from `MATRIX_PRINCIPAL`;
- it came from a device that Sean's cross-signing key signed, and that
  master key is the one pinned at setup.

It encrypts only to those devices and Jill's own. Jill's keys, her access
token and the pin live in the `matrix-bridge-state` volume, which no other
service mounts. There is no server-side key backup, ever.

## What the bridge accepts

Every rule must hold, or the event is dropped. The bridge then logs one line
with the event id and the reason, never the content:

| Rule | Reason logged when it fails |
|---|---|
| room is exactly `MATRIX_JILL_ROOM` | `wrong-room` |
| room has its `m.room.encryption` state (read fresh from the server) | `room-not-encrypted` |
| event was encrypted (plaintext events are dropped) | `plaintext` |
| event decrypts | `undecryptable` |
| room members (joined, invited, knocking) are only Jill and the principal | `extra-members` |
| sender is `MATRIX_PRINCIPAL`, the full user id | `not-principal` |
| room key came straight from the sending device, not forwarded | `forwarded-keys` |
| the sending device is known | `unknown-sending-device` |
| not an edit (`m.replace` or `m.new_content`) | `edit` |
| under 10 minutes old, and not more than 1 minute in the future, checked after decryption | `stale`, `future-timestamp` |
| the principal's master key equals the pin (a fresh `/keys/query`) | `identity-changed` |
| the device is signed by a self-signing key that the pinned master key signed, and the device's own keys match the keys that encrypted the event | `device-not-cross-signed` |
| the event id was never handled before (persisted, so it survives restarts) | `replay` |

Megolm's own message-index check, also persisted in the crypto store, refuses
the same ciphertext under a different event id.

The cross-signing check is the bridge's own. It runs on the raw `/keys/query`
JSON against the pin. It does not use mautrix's trust levels: their "TOFU"
is relative to whatever master key the store first saw, and the server
supplied that.

### Identity change

If Sean's master key ever differs from the pin, the bridge locks:

- it refuses all chat and all commands;
- it discards the room's outbound key;
- it posts a content-free alert through jill-control's alerts room;
- it persists the lock in the state volume.

The alert travels through the homeserver admin's room and can be dropped,
so check on the host too: `docker compose exec matrix-bridge
/opt/jill/bin/matrix-bridge status` prints the pin and any lock and exits
non-zero when locked. `docker/cutover.sh` runs it.

Only `matrix-bridge setup` re-pins and clears the lock. If you reset your
own Matrix identity, you must re-run setup. If you did not, treat the alert
as an attack.

### Outbound

Before every send the bridge re-reads the room state and Sean's keys. It
refuses to send, and alerts, if any of these is true:

- the encryption state is missing;
- anyone other than Jill and Sean is in the room;
- Sean's master key no longer matches the pin;
- Sean has no device signed through the pin.

**Room keys go only to the principal and Jill.**

- Jill's user-signing key signed the pinned master key at setup, and
  `SendKeysMinTrust` is `cross-signed-verified`, so mautrix shares keys only
  with Sean's devices signed through that key.
- Key requests from other devices are refused.
- Replies are plain text, with no `formatted_body`.

**The outbound Megolm session is the bridge's own (red-team round 6 H1).**
mautrix reuses a session once it is shared. The bridge therefore never
keeps one longer than it can account for:

- it discards the session at the end of every setup (success or failure),
  at every start, and on an identity lock;
- it rotates it whenever the room's members, Sean's pinned-trusted devices
  or the pin change;
- it rotates after 50 messages or 24 hours, whatever the room's encryption
  settings say.

Setup refuses to run unless the room holds exactly Jill and Sean, and its
verification messages are encrypted to those two only.

## Commands in the encrypted room

These are whole messages, handled before any model call, one at a time in
the order received. They work while halted:

| Command | Effect |
|---|---|
| `halt [2h] [reason]` (`mute`, `silence`) | `venice-proxy` refuses every model call. Only tightens an existing halt. Cancels anything waiting for `confirm` |
| `conserve [2h]` | heartbeats: `critical` only |
| `status` | both flags |
| `new` (`/new`, `/reset`, `!reset`) | a fresh opencode session |
| `show draft <id>` | the approval screen, with a one-time code |
| `resume` (`unmute`, `unhalt`), `unconserve`, `reset meter`, `reset meter spend` | answered with `send confirm <code> within 5 minutes` |
| `approve draft <id> <sha256> <code>` | `<code>` from that draft's screen; answered with a confirm code |
| `confirm <code>` | runs the command it was issued for |

While halted, every other message gets a refusal and never reaches the
model. A message that starts with `show draft`, `approve` or `confirm` but
does not match exactly is answered as an error and never reaches the
model either.

**Confirm codes (round 6 H3).** The homeserver writes event timestamps and
can hold a message back, so a message's age proves nothing.

- Anything that lifts a stop, hands back budget or approves a send runs only
  after `confirm <code>`.
- The code is random, single-use, and valid for 5 minutes by the bridge's
  own clock.
- A code works only once the bridge has delivered the message carrying it,
  and a later `halt` cancels it.
- A held-back command can only ever produce a fresh code.

**Reply fallbacks** (quoted `> ` lines) are not stripped. Whether a message
is a reply comes from the unencrypted wrapper, which the server controls
(round 6 L3); Element X sends no fallback. An edit marker, from either the
wrapper or the payload, makes the bridge drop the message. That fails
closed: the server can make the bridge ignore a message, never act on one.

### The approval screen

`show draft <id>` reads agentmail-proxy's stored snapshot of the draft once,
read-only from the `agentmail-state` volume. The snapshot is exactly what a
send delivers. The bridge has no network path to the gateway, so it does
not use the `GET /_jill/drafts/<id>/digest` endpoint. The endpoint returns
the same snapshot.

- **Fields.** The screen shows every field in `approvals.SENDABLE`: to, cc,
  bcc, reply_to, subject, in_reply_to, labels, attachments, text and html.
  It also shows the headers a send adds (`In-Reply-To` and `References`,
  both from in_reply_to). An absent field reads `(not set)`; an empty one
  shows `""`.
- **Escaping in fields.** In addresses, subject, labels and headers every
  non-ASCII character shows as `\u{NNNN}`, look-alike letters included
  (round 6 M3).
- **Escaping in bodies.** C0 and C1 control characters show as `\xNN`.
  Bidi, zero-width, non-standard spaces and blank-rendering characters show
  as `\u{NNNN}`. Runs of spaces show as `\s{N}`, so padding cannot push text
  onto what looks like a new field. A backslash shows as `\\`. Body lines
  start with `| `.
- **Size.** Each body shows its first 2000 characters and its total length.
  The whole screen fits in one Matrix message, so no part can be withheld.
  A draft with a longer body, or whose screen would not fit, cannot be
  approved here.
- **Attachments.** They show as name, type, size and the sha256 of their
  bytes. A draft with attachments cannot be approved.
- **The code and the hash.** An approvable screen ends with
  `approve draft <id> <sha256> <code>` and then `sha256 <hex>`, which is
  `approvals.draft_digest` of that one read, the same digest the gateway
  checks at send.

`approve draft <id> <sha256> <code>` accepts only a code that this bridge
printed on a screen for exactly that `(id, sha256)`, under these conditions:

- the bridge delivered that screen;
- less than 15 minutes have passed;
- the code has not been used, and an attempt uses it up.

The model never sees bridge screens, so a screen Jill imitates in chat
carries no valid code (round 6 H2). After `confirm`, the approval is
written bound to the typed sha256 (TTL 15 minutes, `DRAFT_APPROVAL_TTL`),
without re-reading the draft. If Jill changes the draft after you looked,
the gateway's send check fails and the approval is used up.

### Worker isolation

The bridge runs as root with every capability dropped except
`SETUID`/`SETGID`, with no new privileges and a read-only root (round 6 M4).
It starts each Python worker as `node` (1000). The kernel switches the
child's uid before exec, and a non-root process has no capabilities, so the
worker cannot switch back.

- The bridge state (access token, pickle key, crypto store) is root `0700`.
  The worker cannot list or read it.
- The worker keeps its codes and sessions in the separate
  `matrix-worker-state` volume.
- Alerts are written through the worker, which owns the spool.
- The service has `mem_limit` 512m and `pids_limit` 128.
- PDF parsing happens only in the worker.

`matrix-bridge isolation-check` proves the isolation, and CI runs it in the
built image.

## Chat

- **Forwarding.** Text goes to opencode-serve through api-proxy, as the
  Discord bridge did: one session per room, replies in order, and the same
  health check and errors.
- **Attachments.** The bridge downloads encrypted PDF and text attachments,
  decrypts them (the hash is checked) and extracts them into the same
  UNTRUSTED DOCUMENT blocks. It refuses unencrypted media, because the
  server could read or replace it.
- **Long replies.** Replies are chunked at 6000 characters.

## Setup

1. **Accounts.** On the homeserver, create a user for Jill (for example
   `@jill:<server>`). Sean needs cross-signing (recovery) set up in Element X.
2. **The room.** In Element X, Sean creates a private room with
   encryption on, and invites Jill. Nobody else joins it, ever. Copy the room
   id (`!...:server`) from the room's settings.
3. **`.env`** (gitignored):

   ```
   MATRIX_HOMESERVER=http://host.docker.internal:8008   # as seen from the containers
   MATRIX_PRINCIPAL=@sean:<server>
   MATRIX_JILL_USER=@jill:<server>
   MATRIX_JILL_ROOM=!roomid:<server>
   OPENCODE_SERVER_PASSWORD=...                          # openssl rand -hex 32
   ```

   Jill's password and access token are never in `.env`.
4. **Run setup**, interactively, as the macOS user that runs Jill's Docker:

   ```
   docker compose build
   docker compose run --rm matrix-bridge-setup
   ```

   - **Login.** It asks for Jill's password (no echo) and logs in. The access
     token goes to the state volume.
   - **Cross-signing.** It creates Jill's cross-signing keys and signs her
     device.
   - **Recovery key.** It prints Jill's recovery key once, to the terminal
     only. The setup service has Docker logging off, so it is in no log.
     Store it in Jill's vault. Setup needs it to re-pin later.
   - **Joining.** It joins the room and checks that the room is encrypted.
   - **Fingerprint.** It prints the master-key fingerprint the server reports
     for Sean, as a secondary check.
   - **Emoji verification.** Jill sends Sean a verification request in the
     room. Sean accepts it in Element X. Both screens show seven emoji:
     Sean compares them, confirms in Element X, and types `yes` at the
     terminal. A homeserver that swapped Sean's keys would sit in the middle
     of the exchange and the emoji would differ. Setup gives up after 10
     minutes.
   - **Pin.** Only when the verification succeeds does it pin Sean's master
     key. That key was covered by the verification, and Jill's user-signing
     key has signed it.
5. **Start it:** `bash docker/cutover.sh` (or `docker compose up -d`).
   `docker compose logs matrix-bridge` shows `first sync done` and the
   pinned fingerprint.
6. **Verify:** run the step-F checklist in `docs/control.md`.

**Fallback.** `docker compose run --rm matrix-bridge-setup /opt/jill/bin/matrix-bridge setup --no-sas`
skips the emoji step. It pins after Sean compares the printed fingerprint
with the one his own client shows and types `yes`. Use it only if the
emoji verification cannot complete with Element X.

**Library workarounds.** The emoji step uses mautrix-go's
`verificationhelper`. Two bugs in its in-room flow (in v0.32.0 and v0.33.0)
are patched around in `matrix-bridge/sas.go`:

- the request is encrypted twice (`OnceCrypto`);
- replies are looked up by their own event id instead of the request they
  relate to (`FixInRoomVerificationIDs`).

`selftest/matrix-bridge-e2e.sh` proves the flow between two mautrix
clients. It has not yet been run against Element X.

### Re-pinning

Run setup again. It asks for Jill's recovery key instead of creating new
keys, then runs the emoji verification again. Do this after Sean resets his
identity.

## Troubleshooting

| Symptom | Check |
|---|---|
| No reply, log says `drop ... reason=device-not-cross-signed` | That device of Sean's is not verified. Verify it from another of his sessions |
| `drop ... reason=identity-changed`, or `IDENTITY LOCK` | Sean's master key changed. If he reset it, re-run setup; otherwise investigate |
| `drop ... reason=extra-members` / `refuse send reason=extra-members` | Someone else is in the room. Remove them; the bridge resumes on its own |
| Element X shows "unable to decrypt" for Jill's replies | Sean's device has no signature through the pinned key, or setup was not completed |
| Element X does not encrypt to Jill | Jill's device is not cross-signed. Re-run setup and look for the "Jill's own device is not cross-signed" warning |
| Bridge unhealthy, log says `run matrix-bridge setup first` | Setup has not run in this state volume |
| "opencode server is unreachable" reply | `docker compose ps`: are `api-proxy` and `opencode-serve` healthy? |
