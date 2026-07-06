# BehalfBot-open

Proof-of-concept port of the behalf.bot assistant chassis ("Jax") from Claude Code onto the **OpenCode** harness (sst/opencode), with an env-gated path to open-weight models.

## Why OpenCode

The 2026-07-06 porting research compared 12 candidate harnesses. OpenCode won because it ships deliberate Claude Code compatibility:

- Reads `AGENTS.md` (and `CLAUDE.md`) natively as instruction files
- Skills system discovers `SKILL.md` files, including `.claude/skills/` paths
- `opencode run --format json` is a near-1:1 replacement for `claude -p`
- Full MCP support, markdown-defined agents/subagents, JS/TS plugins with `tool.execute.before/after` hooks (PreToolUse/PostToolUse analog)
- 75+ providers including Venice AI, OpenRouter, Ollama, and any OpenAI-compatible endpoint
- MIT license, very active (v1.17.13 as of this writing)

Runners-up and why not: Pi (rejects MCP, no permission system), Hermes Agent and OpenClaw (category competitors - adopting them means replacing the chassis, not porting it), jcode (bus-factor 1), OpenHands (CLI feature-frozen, sandbox-centric).

## MVP status (Phase 0)

What this repo proves today:

| Piece | Status |
|---|---|
| opencode installed (v1.17.13) and running headless | Done |
| `AGENTS.md` identity + hard limits read natively | Done |
| `.opencode/skills/brand-voice/SKILL.md` loads via the native skill tool | Done |
| `opencode.json` with providers, permissions, full MCP block from `.mcp.json` | Done |
| `.opencode/plugins/guardrails.ts` - TS port of the bash PreToolUse guards | Compiles and loads; parity testing pending (issue #3) |
| `.opencode/agents/software-engineering.md` subagent | Done |
| `scripts/run.sh` headless wrapper (the `claude -p` analog) | Done |
| Proof-of-loop run output | `mvp-run-output.json` |
| Open-weight model run | **Blocked on keys (issue #8)** |

## The open-weight blocker

The only provisioned model key today is Anthropic, so the MVP loop runs on `anthropic/claude-sonnet-4-5`. The Venice AI and OpenRouter provider blocks are already in `opencode.json`, env-gated via `{env:VENICE_API_KEY}` / `{env:OPENROUTER_API_KEY}` with open-weight model IDs staged (`zai-org-glm-5-1`, `kimi-k2-7-code`, `z-ai/glm-5.2`, `moonshotai/kimi-k2-thinking`). The swap is a one-liner once keys exist:

```bash
bash scripts/run.sh --model openrouter/z-ai/glm-5.2 "your prompt"
```

Provisioning tracked in **issue #8**. Verify exact model IDs against `opencode models venice-ai` / `opencode models openrouter` once keyed - IDs staged here come from the porting research and need confirmation against models.dev.

## Quick start

```bash
curl -fsSL https://opencode.ai/install | bash   # install opencode
cp .env.example .env                             # fill ANTHROPIC_API_KEY
bash scripts/run.sh "Read AGENTS.md and tell me who you are."
```

## Repo layout

```
AGENTS.md                          # Jax identity + hard limits (OpenCode reads this natively)
opencode.json                      # providers (anthropic active, venice/openrouter env-gated), mcp, permissions
.opencode/
  skills/brand-voice/SKILL.md      # first ported skill
  agents/software-engineering.md   # first ported subagent
  plugins/guardrails.ts            # TS port of the bash guardrail hooks
  instructions/response-style.md   # loaded via the instructions array
config/security-allowlist.json     # authorized security-scan targets
scripts/run.sh                     # headless wrapper (claude -p analog)
docs/PORTING.md                    # 6-phase plan + hardest gaps + issue links
mvp-run-output.json                # captured proof-of-loop JSON output
```

## Discord bridge (channel layer, Phase 4)

`bridge/` makes the open-weight Jax reachable from Discord:

- `bridge/opencode-serve.sh` - headless `opencode serve` on `127.0.0.1:4747`
- `bridge/discord_bridge.py` - discord.py relay: principal-only, single
  allowlisted channel, one persistent opencode session per channel,
  `/reset` for a fresh session, replies chunked to Discord's 2000-char limit
- `bridge/com.jax.opencode-serve.plist` + `bridge/com.jax.discord-bridge.plist` -
  launchd templates so both survive reboot
- `bridge/serve-smoke.json` - captured proof: `POST /session/:id/message`
  routed to `venice/zai-org-glm-5-2` answering over the serve API

Setup in under 10 minutes: [bridge/WIRING.md](bridge/WIRING.md).

## Porting plan

Six phases, tracked as issues #1-#6, gaps in #7-#8. Full detail in [docs/PORTING.md](docs/PORTING.md).

0. Proof of loop (this repo) - #1
1. Config translation - #2
2. Hooks rewrite bash to TS - #3
3. Dispatcher swap (`claude -p` to `opencode run --attach`) - #4
4. Channel layer - replace the Discord plugin (hardest) - #5
5. Shadow-run and cut over - #6

## Hard rules carried over

Same as the chassis: no pushes to main, no self-merged PRs, no secrets in commits, no em dashes (use " - "), DMs off-limits, security scans only against allowlisted Sean-owned targets. See `AGENTS.md`.
