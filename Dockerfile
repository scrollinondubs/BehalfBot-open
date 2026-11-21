# BehalfBot-open runtime image - opencode serve + Discord bridge (Jill).
#
# One image, two services (see docker-compose.yml). Docker-native from the
# ground up: this container IS the security isolation for the open-weight
# lane (issue #9). It structurally cannot reach the host macOS Keychain,
# Vaultwarden, or /Users/jax - nothing from the host home is ever mounted.
#
# Secrets are NEVER baked in: no ARG/ENV carries a key, no .env is copied
# (.dockerignore excludes it). They arrive at runtime via compose.

FROM node:22-bookworm-slim

# python3 for the bridge, curl for the compose healthcheck, git because
# opencode prefers running inside a repo, ca-certificates for TLS, jq for the
# heartbeat dispatcher's JSON parsing, ripgrep for OpenCode's grep/glob tools
# (otherwise it downloads rg at runtime into a noexec tmpfs), iptables for
# the jill-netns container that firewalls opencode-serve's network namespace.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-pip curl git ca-certificates jq ripgrep iptables \
    && rm -rf /var/lib/apt/lists/*

# opencode pinned exactly. 1.19.6 differs from 1.19.5 only in
# session/message-v2.ts (image size bounding); the hook call sites the guards
# rely on (session/tools.ts, tool/shell.ts) were read on this tag.
RUN npm install -g opencode-ai@1.19.6 && npm cache clean --force

# MCP servers are installed here, at build time, from a committed lockfile.
# Nothing is fetched with npx at runtime, so a container start never pulls a
# new version with her keys in the environment. --ignore-scripts: none of the
# pinned packages declares an install script, so none is allowed to run.
COPY mcp/package.json mcp/package-lock.json /opt/mcp/
RUN cd /opt/mcp && npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && npm cache clean --force

# Bridge deps (Debian bookworm is PEP 668, hence --break-system-packages;
# this is a single-purpose container, not a shared host).
RUN pip3 install --no-cache-dir --break-system-packages \
        "discord.py>=2.4,<3" "aiohttp>=3.9,<4" "pypdf>=5,<7"

WORKDIR /app

# Only the repo files the runtime needs. No host mounts, no host home.
COPY opencode.json AGENTS.md ./
COPY .opencode/ ./.opencode/
COPY config/ ./config/
COPY selftest/ ./selftest/
COPY gateway/gateway.py gateway/approvals.py ./gateway/
COPY runtime/jill-shell /opt/jill/bin/bash
COPY runtime/setup-netns.sh /opt/jill/bin/setup-netns.sh
COPY bridge/discord_bridge.py ./bridge/discord_bridge.py

# opencode-serve runs as node (uid 1000), NON-ROOT, with NO capabilities,
# and holds NO secrets (round-2 red-team C1): no upstream key, no API
# password, no caller token. Anything the server can be tricked into reading
# (@file expansion, a raced symlink, /proc/1/environ) is therefore worth
# nothing. What protects the rest is structural, outside the container:
#   - its network namespace is owned and firewalled by jill-netns: no
#     loopback access to the API, no route to the Docker/Colima gateway
#     host, no route out except the gateway sidecars
#   - the API is reachable only from api-proxy, which requires a password
#     the serve container does not have and refuses MCP registration,
#     shells, PTY, config writes and upgrades
#
# Ownership:
#   /app, global config, /home/node   uid 65534 (nobody), read-only to all
#   /var/lib/opencode, /data          node 0700 (OpenCode data, memory MCP)
#   /workspace                        node (her files)
#   /state/{bridge,dispatcher,gateway,approvals}  node, per-container volumes
RUN git init -q /app \
    && git -C /app config user.email "jill-agent@agentmail.to" \
    && git -C /app config user.name "Jill" \
    && printf '%s\n' node_modules package.json package-lock.json bun.lock .gitignore > /app/.opencode/.gitignore \
    && git -C /app add -A && git -C /app commit -qm "image snapshot" \
    && mkdir -p /etc/opencode-xdg/opencode /var/lib/opencode/data /var/lib/opencode/state /var/cache/opencode \
        /data /workspace /home/node/.local/state /home/node/.cache \
        /state/bridge /state/dispatcher /state/gateway /state/approvals \
    && cp /app/.opencode/.gitignore /etc/opencode-xdg/opencode/.gitignore \
    && printf '{\n  "$schema": "https://opencode.ai/config.json"\n}\n' > /etc/opencode-xdg/opencode/opencode.jsonc \
    && chown -R 65534:65534 /app /etc/opencode-xdg /home/node \
    && chmod -R u=rwX,go=rX /app /etc/opencode-xdg /home/node /opt/jill \
    && chmod 0755 /opt/jill/bin/bash /opt/jill/bin/setup-netns.sh \
    && chown -R node:node /var/lib/opencode /var/cache/opencode /data /workspace \
        /home/node/.local/state /home/node/.cache /state \
    && chmod 0700 /var/lib/opencode /var/lib/opencode/data /var/lib/opencode/state /var/cache/opencode /data

USER node
ENV HOME=/home/node \
    npm_config_cache=/tmp/.npm \
    OPENCODE_CONFIG=/app/opencode.json \
    OPENCODE_CONFIG_DIR=/app/.opencode \
    OPENCODE_DISABLE_PROJECT_CONFIG=1 \
    OPENCODE_DISABLE_EXTERNAL_SKILLS=1 \
    OPENCODE_DISABLE_CLAUDE_CODE=1 \
    OPENCODE_DISABLE_MODELS_FETCH=1 \
    OPENCODE_AUTH_CONTENT={}

# Config is PINNED to the image, whatever directory a session runs in. By
# default OpenCode walks up from the session directory loading every
# opencode.json, .opencode/ (plugins, agents) and AGENTS.md it finds, and a
# session outside /app (a heartbeat cwd, a cloned repo in /workspace) would
# run with NO guard plugin, or with a plugin the repo brought along. The
# variables above load only /app's config and plugin dir, and turn off
# project-level config, .claude/.agents skills and CLAUDE.md discovery.
# AGENTS.md is listed in opencode.json "instructions" by absolute path.
# OPENCODE_AUTH_CONTENT={} makes OpenCode ignore auth.json entirely, so no
# "wellknown" entry can make it fetch remote config or plugins (red-team H1).

EXPOSE 4747

# No default CMD: docker-compose.yml picks the entrypoint per service.
CMD ["node", "-e", "console.error('Use docker compose: see docker-compose.yml services'); process.exit(64)"]
