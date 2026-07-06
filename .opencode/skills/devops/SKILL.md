---
name: devops
description: DevOps tasks on BigPoppa (the Linux server hosting Vaultwarden, n8n, SiYuan) - restart services, check container health, view logs, troubleshoot the reverse proxy. Use when something on BigPoppa is misbehaving or Sean asks to deploy / restart a service. Ported from the Claude Code chassis skill on 2026-07-06.
---

# Skill: DevOps - BigPoppa Server Management

Manage services on BigPoppa, a GCP VM running Docker containers.

## When to activate

Any task referencing BigPoppa, server health, Docker containers, or these services: n8n, SiYuan (server-side), Nginx, Portainer, Cloudflare tunnels. Examples:
- "restart n8n"
- "check if SiYuan is up"
- "show me disk usage on BigPoppa"
- "what's running on the server"
- "check docker logs for nginx"
- "is BigPoppa healthy"

## Pre-flight

Before executing any command, fetch the current operational runbook:

```
get_file_contents("scrollinondubs/devops", "CLAUDE.md")
```

This contains the authoritative service inventory, container names, ports, and file paths. Always use current container names from the runbook - do not rely on memory.

> **Requires capability grant (deferred).** The chassis fetches this runbook via the `github` MCP, which is DISABLED for Jill (customer/prod GitHub reach is withheld until trust is built - do NOT enable it). Until granted, you cannot pull the authoritative container inventory. Options: ask Sean to paste the current runbook into the prompt, or use `gh` on the command line only if Sean has authorized read access for the `scrollinondubs/devops` repo. Do not act on stale or assumed container names - a wrong name on a restart is a real-world action against production.

## Connection

All commands go through SSH:

```bash
ssh bigpoppa "<command>"
```

- SSH config alias `bigpoppa` maps to Sean's GCP VM
- All Docker commands require `sudo`
- If SSH fails, report the error to Sean - do not retry repeatedly

> **Requires capability grant (deferred).** SSH to BigPoppa depends on Sean's SSH config alias and key being present in Jill's environment. Verify `ssh bigpoppa true` succeeds before relying on any command below; if it fails, this whole skill is inert until Sean provisions SSH access. This is production infrastructure - treat every mutating command as irreversible until proven otherwise.

## Command reference

**Health check:**
```bash
ssh bigpoppa "sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'"
```

**Restart a service:**
```bash
ssh bigpoppa "sudo docker restart <container_name>"
```

**View logs (last 50 lines):**
```bash
ssh bigpoppa "sudo docker logs <container_name> --tail 50"
```

**Follow logs (with timeout):**
```bash
ssh bigpoppa "sudo docker logs <container_name> -f --since 5m"
```

**System resources:**
```bash
ssh bigpoppa "df -h && echo '---' && free -h && echo '---' && uptime"
```

**Test Nginx config:**
```bash
ssh bigpoppa "sudo docker exec nginx-proxy nginx -t"
```

**Inspect a container:**
```bash
ssh bigpoppa "sudo docker inspect <container_name> --format '{{.State.Status}} since {{.State.StartedAt}}'"
```

## Recovery runbooks

Pre-tested step-by-step procedures, kept in `docs/runbooks/` in the chassis:

- `siyuan-recovery` - validate the latest nightly SiYuan backup by restoring it into a throwaway local Docker container. Use before any destructive SiYuan op or whenever Sean wants confidence the prod backup is intact.

When a runbook gets used in anger, log the timing and any deviations in a comment on the issue that triggered it. Updates to the runbook itself happen via PR.

## Safety rules

### Run freely (no approval needed)
- `docker ps`, `docker logs`, `docker inspect`
- `df`, `free`, `uptime`, `top -bn1`
- `nginx -t` (test only)
- Any read-only command

### Needs explicit ask from Sean
- `docker restart <container>` - only when Sean asks to restart or the context clearly implies it
- `docker start <container>` / `docker stop <container>`
- Editing config files (nginx.conf, docker-compose.yml)

### NEVER without explicit approval
- `docker rm`, `docker rmi`, `docker volume prune`, `docker system prune`
- Deleting files on the server
- Modifying firewall rules, DNS, or SSL certificates
- Restarting the VM itself
- Any command with `rm`, `drop`, `delete`, `prune`, or `--force`

When in doubt, ask Sean.

## Output format

**Only notify Sean when there's a problem.** If all services are healthy and checks pass, stay silent - no "all clear" messages.

When there IS a problem, report back with:
1. The command output in a code block
2. A one-line plain-English summary of what is wrong
3. A recommendation (restart, config fix, etc.)

## Troubleshooting

If a service is down:
1. Check logs: `sudo docker logs <container> --tail 100`
2. Check if it exited: `sudo docker ps -a --filter name=<container>`
3. Report findings to Sean with a recommendation
4. Only restart if Sean approves or explicitly asked for it

## Ported-skill capability summary

| Step | Chassis dependency | Status in Jill |
|---|---|---|
| Fetch authoritative runbook | `github` MCP (`scrollinondubs/devops`) | Requires capability grant (deferred) - MCP DISABLED, do not enable |
| SSH to the server | `ssh bigpoppa` alias + key | Requires capability grant (deferred) - verify before use |
| Read-only health / logs / inspect | SSH (once granted) | Safe to run once SSH is granted |
| Mutating ops (restart, stop, config edits) | SSH (once granted) | Needs explicit Sean approval every time |
