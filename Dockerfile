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
# (otherwise it downloads rg at runtime into a noexec tmpfs).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-pip curl git ca-certificates jq ripgrep \
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
COPY gateway/gateway.py ./gateway/gateway.py
COPY runtime/jill-shell /opt/jill/bin/bash
COPY bridge/discord_bridge.py ./bridge/discord_bridge.py

# Two identities in opencode-serve (#46 red-team C1/C2/H1/H2/H6):
#
#   root, cap-dropped to SETUID/SETGID/KILL, no DAC_OVERRIDE: the OpenCode
#     server itself. It holds the API password and the Venice caller token,
#     owns its data dir, and is the only user that can run `opencode`.
#   node (1000): every bash tool command. /opt/jill/bin/bash (the shell
#     OpenCode is configured to use) drops to node with an empty environment
#     before running anything. node cannot read root's /proc/<pid>/environ,
#     cannot execute or read the opencode binary, and cannot write OpenCode's
#     data dir (no auth.json poisoning) or any guard file.
#
# Ownership, and why:
#   /app, global config,    uid 65534 (nobody), read-only to everyone: not
#   /home/node
#                           even root-without-DAC_OVERRIDE can change them
#   opencode binaries       root:ocrun 0750; the dispatcher gets group ocrun
#   /var/lib/opencode       root 0700 (data volume, auth.json, sessions)
#   /data                   root 0700 (memory MCP, runs as root in serve)
#   /state/{bridge,dispatcher}  node, for the containers that run as node
#   /workspace              node:jillwork 2775, root in jillwork, umask 002,
#                           so files made by the write tool (root) and by
#                           shell commands (node) are editable by both
RUN groupadd -g 1500 jillwork && groupadd -g 1600 ocrun \
    && usermod -aG jillwork node && usermod -aG jillwork root \
    && git init -q /app \
    && git -C /app config user.email "jill-agent@agentmail.to" \
    && git -C /app config user.name "Jill" \
    && printf '%s\n' node_modules package.json package-lock.json bun.lock .gitignore > /app/.opencode/.gitignore \
    && git -C /app add -A && git -C /app commit -qm "image snapshot" \
    && mkdir -p /etc/opencode-xdg/opencode /var/lib/opencode/data /var/lib/opencode/state /var/cache/opencode \
        /data /workspace /home/node/.local/state /home/node/.cache /state/bridge /state/dispatcher \
    && cp /app/.opencode/.gitignore /etc/opencode-xdg/opencode/.gitignore \
    && printf '{\n  "$schema": "https://opencode.ai/config.json"\n}\n' > /etc/opencode-xdg/opencode/opencode.jsonc \
    && chown -R 65534:65534 /app /etc/opencode-xdg \
    && chmod -R u=rwX,go=rX /app /etc/opencode-xdg /opt/jill \
    && chmod 0755 /opt/jill/bin/bash \
    && chown -R 65534:65534 /home/node && chown -R root:root /opt/jill && chmod -R u=rwX,go=rX /home/node \
    && chmod 0700 /var/lib/opencode /var/lib/opencode/data /var/lib/opencode/state /var/cache/opencode /data \
    && chown node:jillwork /workspace && chmod 2775 /workspace \
    && chown node:node /home/node/.local/state /home/node/.cache /state/bridge /state/dispatcher \
    && chown -R root:ocrun /usr/local/lib/node_modules/opencode-ai \
    && chmod -R o-rwx /usr/local/lib/node_modules/opencode-ai

# Default user for the bridge and dispatcher. opencode-serve runs as root
# with a reduced capability set (docker-compose.yml) and drops tool commands
# to node through /opt/jill/bin/bash.
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
