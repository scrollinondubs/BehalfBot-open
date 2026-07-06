# Porting Plan: behalf.bot chassis -> OpenCode

Source: Fable porting research, 2026-07-06 (briefings/2026-07-06-fable-porting-research.md in the chassis repo). This doc tracks the 6-phase plan and the hardest gaps, mapped to GitHub issues in this repo.

## Phases

### Phase 0 - Proof of loop ([#1](https://github.com/jacketyjax/BehalfBot-open/issues/1))

Install OpenCode alongside Claude Code (they coexist; OpenCode even reads the same CLAUDE.md conventions). Configure providers in `opencode.json`. Run one headless prompt through `opencode run --format json` and capture the output. Status: **this repo**. Open-weight variant blocked on keys (#8); loop proven on the Anthropic key.

### Phase 1 - Config translation ([#2](https://github.com/jacketyjax/BehalfBot-open/issues/2))

Mechanical translation:
- `.mcp.json` -> `opencode.json` `mcp` block (same servers, env-var-referenced secrets). **Done here** - all 14 servers translated, `enabled: false` until keyed per install.
- `CLAUDE.md` -> `AGENTS.md` (AGENTS.md wins precedence in OpenCode). **Done here.**
- `.claude/agents/*.md` -> `.opencode/agents/*.md` with OpenCode frontmatter (description, mode, permission). First one (software-engineering) done here.
- Flat `skills/*.md` keep working as Read-target docs immediately; progressively convert hot-path skills to `.opencode/skills/<name>/SKILL.md` for native skill-tool loading. First one (brand-voice) done here.

### Phase 2 - Hooks rewrite ([#3](https://github.com/jacketyjax/BehalfBot-open/issues/3))

`.claude/hooks/guardrails.sh`, `security-target-allowlist.sh`, `discord-reply-guard.sh`, `principal-policy-reminder.sh` -> one TS plugin implementing `tool.execute.before` (+ `permission.asked`). Started here as `.opencode/plugins/guardrails.ts`. Remaining:
- Parity-test every guard (payload shapes, MCP tool naming `<server>_<tool>` vs `mcp__<server>__<tool>`)
- Port the mutating-HTTP allowlist + JAX_E2E_MODE escape hatch
- Port the Slack channel allowlist
- This is also the chance to structurally fix chassis audit finding #261 (hooks not registered = hard limits soft-only); in OpenCode the plugin directory is auto-loaded, so the guard cannot silently unregister.

### Phase 3 - Dispatcher swap ([#4](https://github.com/jacketyjax/BehalfBot-open/issues/4))

In the chassis dispatcher, replace `claude -p` with `opencode run --attach http://localhost:PORT` against a long-lived `opencode serve` (kills MCP cold-boot per 15-min tick). Rewrite `claude-p-with-telemetry.sh` cost parsing against OpenCode's JSON event stream and `opencode stats`. Map HEARTBEATS.md `model:` field (opus/sonnet) to `provider/model` strings.

### Phase 4 - Channel layer ([#5](https://github.com/jacketyjax/BehalfBot-open/issues/5)) - HARDEST

Replace `discord@claude-plugins-official`. Nothing in OpenCode covers message intake, attachment download, reply tool, requireMention gating. Options:
1. Thin Discord bot bridging Discord <-> `opencode serve` HTTP API
2. Adopt OpenClaw/Hermes gateway patterns as reference implementations
3. Chassis-level custom bridge (most control, most work)

Must re-solve the channel-routing safety rules (terminal-text auto-relay leak class) by design, not mitigation.

### Phase 5 - Shadow-run and cut over ([#6](https://github.com/jacketyjax/BehalfBot-open/issues/6))

Run OpenCode-Jax in parallel on background-criticality heartbeats for 2 weeks. Compare briefings and outreach drafts vs the sonnet baseline. Then flip normal -> critical tiers.

## Hardest gaps

1. **Discord plugin + channel routing (#5).** The single biggest net-new build.
2. **Hooks semantics, bash -> TS (#3).** Payload shapes, matchers, and deny semantics all differ. Miss one and a hard limit goes soft.
3. **Telemetry/budget accounting (#4).** Per-heartbeat budget enforcement parses Claude CLI cost output today; OpenCode emits different JSON. Venice/OpenRouter costs are ~10-30x cheaper, which softens the blow.
4. **No equivalent for Claude-official features:** `/loop`, cloud schedule routines, humanizer/caveman plugin skills, worktree-isolated background subagents, 1M-context sessions. Mitigations: cron/dispatcher patterns, port skill markdown into this repo, restructure orchestration prompts toward shorter explicit runs.
5. **Model quality regression risk ([#7](https://github.com/jacketyjax/BehalfBot-open/issues/7)).** Open-weight models are at or near Sonnet-class on coding but below Opus-class on long-horizon judgment and instruction-hierarchy adherence (hard limits!). More enforcement must move from prompt into hooks/permission config. Budget real eval time - this is the true risk.
6. **Open-weight keys not provisioned ([#8](https://github.com/jacketyjax/BehalfBot-open/issues/8)).** Venice + OpenRouter blocks are staged env-gated in `opencode.json`; activation is setting `VENICE_API_KEY` / `OPENROUTER_API_KEY`.

## Chassis note

All of this ultimately lands upstream in `scrollinondubs/behalfbot` (never edit the vendored `chassis/` copy in an install). A harness-pluggable chassis ("bring your own harness+model") is itself a Behalf.bot product feature - vendor independence sells, especially for enterprise installs.
