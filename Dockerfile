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

# opencode pinned to the version validated on the host.
RUN npm install -g opencode-ai@1.17.13 && npm cache clean --force

# Bridge deps (Debian bookworm is PEP 668, hence --break-system-packages;
# this is a single-purpose container, not a shared host).
RUN pip3 install --no-cache-dir --break-system-packages \
        "discord.py>=2.4,<3" "aiohttp>=3.9,<4" "pypdf>=5,<7"

WORKDIR /app

# Only the repo files the runtime needs. No host mounts, no host home.
COPY opencode.json AGENTS.md ./
COPY .opencode/ ./.opencode/
COPY config/ ./config/
COPY bridge/discord_bridge.py ./bridge/discord_bridge.py

# Plugin deps for .opencode/plugins/guardrails.ts (lockfile is committed).
RUN cd .opencode && npm ci --omit=dev --no-audit --no-fund \
    && npm cache clean --force

# opencode prefers a git worktree; give it a throwaway one.
RUN git init -q /app \
    && git -C /app config user.email "jill@behalfbot.local" \
    && git -C /app config user.name "Jill (container)" \
    && git -C /app add -A && git -C /app commit -qm "image snapshot" \
    # /data backs the named volumes (sessions, memory). Pre-owning it as
    # `node` makes the named volume inherit non-root ownership on first use.
    && mkdir -p /data /home/node/.local/share/opencode \
    && chown -R node:node /app /data /home/node/.local

# Non-root from here on. uid/gid 1000, no sudo in the image.
USER node
ENV HOME=/home/node

EXPOSE 4747

# No default CMD: docker-compose.yml picks the entrypoint per service
# (opencode serve vs the bridge). Running the bare image does nothing.
CMD ["node", "-e", "console.error('Use docker compose: opencode-serve / discord-bridge services'); process.exit(64)"]
