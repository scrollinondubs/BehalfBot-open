# Discord bridge wiring - 10 minutes

Puts the open-weight OpenCode "Jax" (GLM-5.2 via Venice) one Discord message away.

Architecture: `Discord -> bridge/discord_bridge.py -> opencode serve (localhost:4747) -> venice/zai-org-glm-5-2`.

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
# optional overrides:
# PRINCIPAL_USER_ID=925210608310312991
# OPENCODE_SERVER_URL=http://127.0.0.1:4747
# DEFAULT_MODEL=venice/zai-org-glm-5-2
```

## 4. Python venv for the bridge (~2 min)

```
python3 -m venv bridge/.venv
bridge/.venv/bin/pip install -U discord.py
```

## 5. Run it

By hand (two terminals), from the repo root:

```
bash bridge/opencode-serve.sh
bridge/.venv/bin/python bridge/discord_bridge.py
```

Or survive-reboot via launchd (~2 min):

```
REPO=$(pwd)   # run from the repo root
for f in com.jax.opencode-serve com.jax.discord-bridge; do
  sed "s|__REPO_ROOT__|$REPO|g" bridge/$f.plist > ~/Library/LaunchAgents/$f.plist
  launchctl load ~/Library/LaunchAgents/$f.plist
done
```

Logs land in `logs/opencode-serve.log` and `logs/discord-bridge.log`.

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
| Bot online but never replies | MESSAGE CONTENT INTENT not enabled, wrong `JAX_OPEN_CHANNEL_ID`, or you are not `PRINCIPAL_USER_ID` |
| "opencode server is unreachable" reply | `opencode serve` not running - check `logs/opencode-serve.log`, reload the com.jax.opencode-serve agent |
| Model errors mentioning auth | `VENICE_API_KEY` missing/expired in `.env` |
| Bridge exits immediately | check `logs/discord-bridge.log` - it validates env vars on startup and says which one is missing |
