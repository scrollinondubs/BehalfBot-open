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

## Model provider: Venice only

Jill runs on Venice AI only (BehalfBot-open#46). `opencode.json` sets `enabled_providers: ["venice"]` and whitelists Venice models whose `privacy` is `private` (default `venice/zai-org-glm-5-2`, small model `venice/z-ai-glm-5-3-flash`). There is no Anthropic or OpenRouter block, and the heartbeat dispatcher and Matrix bridge both refuse any model that is not `venice/<id>`.

```bash
bash scripts/run.sh --model venice/z-ai-glm-5-3-flash "your prompt"
```

## Quick start (Docker - canonical)

The stack is Docker-native. The container boundary IS the security isolation
for the open-weight lane (issue #9): no host home mount, no Docker socket,
non-root user - the model process structurally cannot reach the macOS
Keychain, Vaultwarden, or /Users files.

```bash
cp .env.example .env        # fill VENICE_API_KEY, OPENCODE_SERVER_PASSWORD, MATRIX_* (bridge/WIRING.md)
bash docker/boot.sh         # ensures Colima is up, then docker compose up -d
```

Two services on a private compose network:

- `opencode-serve` - headless opencode v1.17.13, GLM-5.2 via Venice. Not
  published to the host at all: it is reachable only from inside the compose
  network, by service name. The API has no auth layer, so the publish was
  removed on 2026-07-27; the `docker-compose.yml` header is the source of
  truth on why. For a host-side smoke test use `docker compose exec`.
- `matrix-bridge` - end-to-end encrypted Matrix chat with the principal
  (#50), reaches serve through `api-proxy`; it needs a one-time interactive
  `docker compose run --rm matrix-bridge-setup` before it will listen

Proof the containerized serve answers GLM-5.2 end to end:
`docker/serve-container-smoke.json`. Full wiring + cutover + rollback:
[bridge/WIRING.md](bridge/WIRING.md).

## Quick start (bare host, legacy)

```bash
curl -fsSL https://opencode.ai/install | bash   # install opencode
cp .env.example .env                             # fill VENICE_API_KEY
bash scripts/run.sh "Read AGENTS.md and tell me who you are."
```

## Repo layout

```
AGENTS.md                          # Jill identity + hard limits (OpenCode reads this natively)
opencode.json                      # Venice-only provider, pinned MCP servers, permissions
mcp/package.json + lockfile        # MCP servers, exact versions, installed at image build
.opencode/
  skills/brand-voice/SKILL.md      # first ported skill
  agents/software-engineering.md   # first ported subagent
  plugins/guardrails.ts            # wires the guards into OpenCode (one export only)
  guards/policy.ts                 # the deny rules: secrets, egress, AgentMail, writes, rm, git
config/guards.json                 # egress hosts, write roots, AgentMail recipients (read-only in the image)
selftest/                          # boot self-test: real opencode run against a scripted model
gateway/gateway.py                 # gateways: Venice, AgentMail, SiYuan, Brave MCP, fetch, serve API
gateway/approvals.py               # Sean's one-shot approvals (draft send, URL fetch) + CLI
runtime/setup-netns.sh             # firewall for opencode-serve's network namespace (jill-netns)
runtime/jill-shell                 # the bash tool's shell: empty environment
tests/                             # unit tests (node --test) and shell tests
  instructions/response-style.md   # loaded via the instructions array
config/security-allowlist.json     # authorized security-scan targets
scripts/run.sh                     # headless wrapper (claude -p analog)
scripts/dispatch-trigger.sh        # deterministic keyword-trigger dispatcher (+ scripts/parsers/)
scripts/validate-heartbeats.sh     # HEARTBEATS.md linter
scripts/gather-template.sh         # starting point for heartbeat gather scripts
scheduled-tasks/
  heartbeat-dispatcher.sh          # gather-first scheduled-work engine (Phase 3, issue #4)
HEARTBEATS.md.template             # heartbeat schema + template (copy to HEARTBEATS.md)
triggers.yaml.template             # trigger registry template (copy to triggers.yaml)
memory/                            # file-based memory templates (MEMORY.md.template, WRITING_RULES.md)
Dockerfile                         # one image, three services, non-root, no baked secrets
docker-compose.yml                 # opencode-serve, gateways, matrix-bridge (+ opt-in heartbeat-dispatcher)
docker/
  boot.sh                          # ensure Colima up + compose up (single boot entrypoint)
  com.jax.behalfbot-docker.plist   # optional single launchd agent replacing both legacy agents
  cutover.sh                       # retire legacy host agents, start + verify the Matrix bridge
  serve-container-smoke.json       # proof: containerized serve answering GLM-5.2
docs/PORTING.md                    # 6-phase plan + hardest gaps + issue links
docs/heartbeat-dispatcher.md       # dispatcher architecture + claude-p -> opencode-run mapping
mvp-run-output.json                # captured proof-of-loop JSON output
```

## Heartbeat dispatcher (Phase 3)

The chassis's gather-first scheduled-work engine, ported to OpenCode (issue #4). Declarative heartbeats in `HEARTBEATS.md` fire `opencode run` only when a cheap gather script says there is work - ~96 ticks/day translate to ~4 model invocations. Supports schedule matching (interval/daily/weekly + jitter), threshold and Ollama-judged conditions, per-run telemetry (cost + tokens parsed from the JSON event stream), retry + circuit-breaker resilience, conservation mode, an opt-in Five Failure Modes output validator, and content-free Matrix alerts for notifications.

```bash
cp HEARTBEATS.md.template HEARTBEATS.md      # register heartbeats here
bash scripts/validate-heartbeats.sh          # lint before commit
DRY_RUN=true bash scheduled-tasks/heartbeat-dispatcher.sh   # host one-shot
docker compose --profile heartbeats up -d    # containerized 15-min loop (off by default)
```

Heartbeats are **off by default**: the dispatcher sits behind the `heartbeats` compose profile, and Jill runs only when Sean messages her. Halt and the daily Venice ceiling bind at `venice-proxy`, so they cover chat too. When enabled, the dispatcher only runs with an armed Matrix kill switch (`jill-control`). It also enforces daily fire and spend caps, alarms when every run is failing, and posts content-free alerts to Matrix. A boot self-test proves each of these first. See [docs/control.md](docs/control.md).

Full writeup: [docs/heartbeat-dispatcher.md](docs/heartbeat-dispatcher.md). The companion `scripts/dispatch-trigger.sh` routes keyword-prefixed inbound messages (registered in `triggers.yaml`) to shell handlers deterministically, without a model round trip.

## Matrix bridge (channel layer, #50)

Jill's chat with Sean is an end-to-end encrypted Matrix room. The homeserver
is administered by someone else, so the bridge trusts it for nothing:

- `matrix-bridge/` - Go (mautrix-go with its pure-Go `goolm` crypto, no cgo,
  no libolm). It owns sync, decryption, encryption and the trust decision:
  a message is acted on only if it decrypts, comes from the principal, and
  comes from a device cross-signed by the master key pinned at setup. It is
  also fresh, not an edit, and not a replay. Replies are encrypted only to
  those devices.
- `bridge/matrix_worker.py` - chat policy:
  commands (`halt`, `conserve`, `status`, `new`; `resume`, `unconserve`,
  `reset meter [spend]` and `approve draft` each need `confirm <code>`), the
  halt gate, the draft approval screen with one-time codes,
  opencode sessions, and PDF and text extraction from decrypted attachments.
- Keys, token and pin live in the `matrix-bridge-state` volume, mounted into
  no other service. No server-side key backup.

Setup, threat model and acceptance rules: [bridge/WIRING.md](bridge/WIRING.md).

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
