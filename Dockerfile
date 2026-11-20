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
# heartbeat dispatcher's JSON parsing.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-pip curl git ca-certificates jq \
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
COPY bridge/discord_bridge.py ./bridge/discord_bridge.py

# Guard files are ROOT-owned and read-only to the runtime user (#33). The
# model runs as `node` with bash and file tools; if it could write
# .opencode/, opencode.json, AGENTS.md or config/ it could rewrite its own
# guard. So /app and $HOME stay root's, and `node` can write only:
#   /workspace                          her working files (volume)
#   /data                               memory + bridge state (volume)
#   ~/.local/share/opencode             sessions and history (volume)
#   ~/.local/state, ~/.cache, /tmp      scratch (tmpfs under compose)
# OpenCode's global config dir (~/.config/opencode) is root's as well: a
# config or plugin dropped there would load on the next start. The two files
# OpenCode writes at startup when absent are created here instead.
RUN git init -q /app \
    && git -C /app config user.email "jill-agent@agentmail.to" \
    && git -C /app config user.name "Jill" \
    && printf '%s\n' node_modules package.json package-lock.json bun.lock .gitignore > /app/.opencode/.gitignore \
    && git -C /app add -A && git -C /app commit -qm "image snapshot" \
    && mkdir -p /data /workspace /home/node/.config/opencode \
        /home/node/.local/share/opencode /home/node/.local/state /home/node/.cache \
    && cp /app/.opencode/.gitignore /home/node/.config/opencode/.gitignore \
    && printf '{\n  "$schema": "https://opencode.ai/config.json"\n}\n' > /home/node/.config/opencode/opencode.jsonc \
    && chown -R root:root /app /home/node \
    && chmod -R u=rwX,go=rX /app /home/node \
    && chown -R node:node /data /workspace /home/node/.local/share/opencode \
        /home/node/.local/state /home/node/.cache

# Non-root from here on. uid/gid 1000, no sudo in the image.
USER node
ENV HOME=/home/node \
    npm_config_cache=/tmp/.npm

EXPOSE 4747

# No default CMD: docker-compose.yml picks the entrypoint per service
# (opencode serve vs the bridge). Running the bare image does nothing.
CMD ["node", "-e", "console.error('Use docker compose: opencode-serve / discord-bridge services'); process.exit(64)"]
