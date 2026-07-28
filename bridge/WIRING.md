# Discord bridge wiring - 10 minutes

Puts the open-weight OpenCode "Jill" (GLM-5.2 via Venice) one Discord message away.

Architecture (Docker, the canonical run mode):

```
Discord -> discord-bridge container -> opencode-serve container -> venice/zai-org-glm-5-2
              (compose network: http://opencode-serve:4747)
```

The containers are the security isolation (issue #9): no host home mount, no
Docker socket, non-root user - the model process structurally cannot reach the
macOS Keychain, Vaultwarden, or /Users files. The opencode API is not
published to the host at all - see the `docker-compose.yml` header for why.
Reach it with `docker compose exec opencode-serve` when you need a smoke test.

## 1. Discord app setup (one time, ~3 min)

If the bot app already exists, skip to inviting it.

1. Go to https://discord.com/developers/applications and open the bot application
   (or New Application if starting from zero).
2. Left sidebar > Bot:
   - Copy the token into `.env` as `DISCORD_BOT_TOKEN=...` (Reset Token if needed).
   - Under Privileged Gateway Intents, enable **MESSAGE CONTENT INTENT**. Save.
     Without this the bridge connects but sees empty message bodies.
3. Left sidebar > OAuth2 > URL Generator:
   - Scopes: check `bot`.
   - Bot Permissions: check `View Channels`, `Send Messages`, `Read Message History`.
   - That produces an invite URL of the form:

     ```
     https://discord.com/oauth2/authorize?client_id=<APP_CLIENT_ID>&scope=bot&permissions=68608
     ```

     (`68608` = View Channels + Send Messages + Read Message History.)
4. Open that URL in a browser, pick the target server, Authorize.

## 2. Get the channel ID (~1 min)

1. Discord > User Settings > Advanced > enable Developer Mode.
2. Right-click the channel the bridge should live in > Copy Channel ID.
3. Put it in `.env` as `JAX_OPEN_CHANNEL_ID=...`.

The bridge responds ONLY in this channel and ONLY to `PRINCIPAL_USER_ID`
(defaults to Sean's Discord ID). Everyone and everywhere else is ignored.

## 3. Fill .env (~1 min)

In the repo root `.env` (gitignored - never commit it):

```
VENICE_API_KEY=...            # already present if the provider works
DISCORD_BOT_TOKEN=...
JAX_OPEN_CHANNEL_ID=...
BRIDGE_DRY_RUN=1              # 1 = bridge never opens a Discord gateway
                              # session (safe default); docker/cutover.sh
                              # flips it to 0 at go-live
# optional overrides:
# PRINCIPAL_USER_ID=925210608310312991
# DEFAULT_MODEL=venice/zai-org-glm-5-2
```

Compose interpolates these per service (least privilege: serve only gets
`VENICE_API_KEY`, the bridge only gets the Discord vars). Secrets are never
baked into the image - `.dockerignore` excludes `.env` from the build context.

## 4. Run it (Docker - canonical)

Colima is the Docker runtime on this Mac. One command, idempotent:

```
bash docker/boot.sh        # starts Colima if needed, then: docker compose up -d
```

or by hand:

```
colima start               # if not already running
docker compose up -d
```

What comes up:

| Service | Container | Notes |
|---|---|---|
| `opencode-serve` | `behalfbot-opencode-serve` | binds 0.0.0.0:4747 in-container; no host port published |
| `discord-bridge` | `behalfbot-discord-bridge` | reaches serve at `http://opencode-serve:4747` over the compose network |

State lives in named volumes (`opencode-data`, `bridge-state`, `serve-data`),
so sessions survive container restarts. Logs: `docker compose logs -f`.

Boot persistence: install the single launchd agent (replaces BOTH legacy
`com.jax.opencode-serve` + `com.jax.discord-bridge` agents):

```
sed "s|__REPO_ROOT__|$(pwd)|g" docker/com.jax.behalfbot-docker.plist \
  > ~/Library/LaunchAgents/com.jax.behalfbot-docker.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.jax.behalfbot-docker.plist
```

If Colima autostart is ever flaky, the fallback is simply running
`bash docker/boot.sh` after login - the compose `restart: unless-stopped`
policy handles everything else.

### Dry run vs live

With `BRIDGE_DRY_RUN=1` (the default) the bridge container starts, validates
its config, resolves + health-checks `opencode-serve` over the compose
network, logs `DRY RUN OK`, and idles WITHOUT connecting to Discord. That
makes the stack safe to run while a host bridge still holds the bot token
(one token = one gateway session).

Going live is the cutover script, which retires the host launchd agents
first, flips the flag, and verifies (with automatic rollback on failure):

```
bash docker/cutover.sh             # host launchd -> Docker
bash docker/cutover.sh --rollback  # back to host launchd
```

## 5. Legacy host run (pre-Docker, kept for rollback)

<details>
<summary>launchd/venv instructions (superseded by Docker)</summary>

```
python3 -m venv bridge/.venv
bridge/.venv/bin/pip install -U discord.py
bash bridge/opencode-serve.sh                      # terminal 1
bridge/.venv/bin/python bridge/discord_bridge.py   # terminal 2
```

Or survive-reboot via launchd:

```
REPO=$(pwd)   # run from the repo root
for f in com.jax.opencode-serve com.jax.discord-bridge; do
  sed "s|__REPO_ROOT__|$REPO|g" bridge/$f.plist > ~/Library/LaunchAgents/$f.plist
  launchctl load ~/Library/LaunchAgents/$f.plist
done
```

Logs land in `logs/opencode-serve.log` and `logs/discord-bridge.log`.

</details>

## 6. Smoke test

In the allowlisted channel, as the principal user, send:

```
hey, what model are you running on?
```

You should see the typing indicator, then a GLM-5.2 reply. `/reset` starts a
fresh opencode session (context wipe) for that channel.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Bot online but never replies | MESSAGE CONTENT INTENT not enabled, wrong `JAX_OPEN_CHANNEL_ID`, you are not `PRINCIPAL_USER_ID`, or `BRIDGE_DRY_RUN` is still 1 (check `docker compose logs discord-bridge` for "DRY RUN OK") |
| "opencode server is unreachable" reply | `docker compose ps` - is `behalfbot-opencode-serve` healthy? `docker compose logs opencode-serve` |
| Model errors mentioning auth | `VENICE_API_KEY` missing/expired in `.env`; `docker compose up -d` again to re-read it |
| Bridge exits immediately / restart loop | `docker compose logs discord-bridge` - it validates env vars on startup and says which one is missing |
| Two bots fighting / bot flapping online-offline | two gateway sessions on one token - make sure the host launchd bridge is booted out (`docker/cutover.sh` does this) |
| Nothing starts after reboot | `colima status` - if down, `bash docker/boot.sh` (or install the boot launchd agent, section 4) |
