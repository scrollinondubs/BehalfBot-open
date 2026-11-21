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
- it posts a content-free alert through jill-control's alerts room;
- it persists the lock in the state volume.

Only `matrix-bridge setup` re-pins and clears it. Reset your own Matrix
identity, and you must re-run setup. If you did not, treat the alert as an
attack.

### Outbound

Before every send the bridge re-reads the room state and Sean's keys. It
refuses to send, and alerts, if any of these is true:

- the encryption state is missing;
- anyone other than Jill and Sean is in the room;
- Sean's master key no longer matches the pin;
- Sean has no device signed through the pin.

Room keys go only to the principal and Jill. Jill's user-signing key signed
the pinned master key at setup, and `SendKeysMinTrust` is
`cross-signed-verified`, so mautrix shares keys only with Sean's devices
signed through that key. Key requests from other devices are refused.
Replies are plain text, with no `formatted_body`.

## Commands in the encrypted room

These are whole messages, handled before any model call, and they work while
halted:

| Command | Effect |
|---|---|
| `halt [2h] [reason]` (`mute`, `silence`) | `venice-proxy` refuses every model call |
| `resume` (`unmute`, `unhalt`) | clears halt and conservation. **Only here**, not in the unencrypted control room |
| `reset meter` | today's Venice request count |
| `reset meter spend` | and today's dollar spend. **Only here** |
| `status` | both flags |
| `new` (`/new`, `/reset`, `!reset`) | a fresh opencode session |
| `show draft <id>` | the approval screen for that draft |
| `approve draft <id> <sha256>` | approves exactly what that screen showed |

While halted, every other message gets a refusal and never reaches the
model. `conserve` and `unconserve` stay in the control room.

### The approval screen

`show draft <id>` reads agentmail-proxy's stored snapshot of the draft once,
read-only from the `agentmail-state` volume. The snapshot is exactly what a
send delivers. The bridge has no network path to the gateway, so it does not
use the `GET /_jill/drafts/<id>/digest` endpoint. The endpoint returns the same snapshot.

- **Fields.** The screen shows every field in `approvals.SENDABLE`: to, cc,
  bcc, reply_to, subject, in_reply_to, labels, attachments, text and html. It
  also shows the headers a send adds (`In-Reply-To` and `References`, both
  from in_reply_to). An absent field reads `(not set)`; an empty one shows `""`.
- **Escaping.** C0 and C1 control characters show as `\xNN`. Bidi, zero-width
  and other invisible characters show as `\u{NNNN}`. A backslash shows as
  `\\`. Body lines start with `| `, so body text cannot pose as a field line
  or as the hash line.
- **Attachments.** They show as name, type, size and the sha256 of their
  bytes. A draft with attachments cannot be approved.
- **The hash.** The last line is `sha256 <hex>`. It is
  `approvals.draft_digest` of that one read, the same digest the gateway
  checks at send.

`approve draft <id> <sha256>` never re-reads the draft. It accepts only an
`(id, sha256)` pair that this bridge showed you in the last hour, without
attachments, and writes the approval bound to the hash you typed (TTL 15
minutes, `DRAFT_APPROVAL_TTL`). If Jill changes the draft after you looked,
the gateway's send check fails and the approval is used up.

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
     for Sean. **Compare it with what Sean's own client shows for his
     account**, never with a copy from the server. Then type `yes`.
   - **Pin.** It pins that key and signs it with Jill's user-signing key.
5. **Start it:** `bash docker/cutover.sh` (or `docker compose up -d`).
   `docker compose logs matrix-bridge` shows `first sync done` and the
   pinned fingerprint.
6. **Verify:** run the step-F checklist in `docs/control.md`.

### Re-pinning

Run setup again; it asks for Jill's recovery key instead of creating new
keys. Do this after Sean resets his identity, and only after comparing the
new fingerprint out of band.

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
