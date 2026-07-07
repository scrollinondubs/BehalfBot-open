/**
 * guardrails.ts - deterministic safety guardrails for Jax on OpenCode.
 *
 * Port of the Claude Code chassis PreToolUse hooks:
 *   .claude/hooks/guardrails.sh            (bash + MCP tool guards)
 *   .claude/hooks/security-target-allowlist.sh (security tool target gating)
 *
 * OpenCode plugin API: `tool.execute.before` fires before every tool call.
 * Throwing an Error denies the call and surfaces the message to the agent,
 * which is the analog of the PreToolUse permissionDecision: "deny" JSON.
 *
 * MCP tool naming (issue #3, RESOLVED - verified against opencode v1.17.13
 * source, the pinned version of this install):
 *   runtime tool name = sanitize(serverName) + "_" + sanitize(toolName)
 *   sanitize = (s) => s.replace(/[^a-zA-Z0-9_-]/g, "_")
 * (packages/opencode/src/mcp/catalog.ts toolName/sanitize; the registry key
 * is passed verbatim to this hook as input.tool in session/tools.ts.)
 * Hyphens and case are PRESERVED - only characters outside [a-zA-Z0-9_-]
 * become "_". So server "brave-search" + tool "brave_web_search" yields
 * "brave-search_brave_web_search" (hyphen intact, NOT "brave_search_..."),
 * and server "siyuan" yields "siyuan_sql_query" etc. The existing
 * /^turso_/ and /^remarkable_/ prefixes are correct because those server
 * names contain no hyphen.
 *
 * TODO(parity): payload shapes differ from Claude Code hooks. Each guard
 * below still wants a live parity test once real keys land (issue #3).
 */

import type { Plugin } from "@opencode-ai/plugin"
import * as fs from "node:fs"
import * as path from "node:path"

// ---------------------------------------------------------------------------
// Bash command guards (from guardrails.sh)
// ---------------------------------------------------------------------------

const BASH_DENY_RULES: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /^\s*rm\s+-rf\s+\/|^\s*sudo\s+rm|^\s*rm\s+-rf\s+~/i,
    reason:
      "Blocked: destructive filesystem deletion. Use 'trash' instead of 'rm -rf', or ask Sean for approval.",
  },
  {
    pattern: /git\s+push\s+.*--force(?!-with-lease)|git\s+push\s+-f\b/i,
    reason: "Blocked: force-push is prohibited. Use 'git revert' to undo commits safely.",
  },
  {
    pattern: /git\s+push\s+.*\b(main|master)\b/i,
    reason: "Blocked: pushing directly to main/master is prohibited. Create a PR instead.",
  },
  {
    pattern: /git\s+reset\s+--hard/i,
    reason: "Blocked: git reset --hard can destroy work. Use 'git stash' or 'git revert' instead.",
  },
  {
    pattern: /git\s+clean\s+-f/i,
    reason: "Blocked: git clean -f deletes untracked files permanently. Review files manually first.",
  },
  {
    pattern: /^\s*(mail|sendmail|mutt|msmtp)\s+/i,
    reason: "Blocked: sending email via CLI requires Sean's approval.",
  },
]

// Destructive SQL via any CLI. Exception: -preview databases.
const SQL_DESTRUCTIVE = /DROP\s+(TABLE|DATABASE|INDEX|SCHEMA)|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\S+\s*(;|$)/i
const PREVIEW_DB = /-preview([^a-zA-Z0-9]|$)/

// WhatsApp: raw wacli content/write paths must go through the safe wrapper.
const WACLI_RAW = /(^|[;&|`( ])wacli\s+(messages|send|media)\b/
const WACLI_SAFE = /wacli-safe\.sh/

// ---------------------------------------------------------------------------
// DM URL guards (from guardrails.sh Playwright section, issue #388 upstream)
// ---------------------------------------------------------------------------

const DM_URL_RULES: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /(twitter\.com|x\.com)\/messages/i,
    reason:
      "Blocked: Twitter/X DM inbox is off-limits. If Sean forwarded a DM, act on the forwarded content - do not navigate to the DM directly.",
  },
  {
    pattern: /linkedin\.com\/messaging\//i,
    reason: "Blocked: LinkedIn DM/messaging is off-limits. Forward DM content via Sean if needed.",
  },
  {
    pattern: /app\.slack\.com\/client\/[A-Z0-9]+\/D[A-Z0-9]+/,
    reason:
      "Blocked: Slack DM navigation is off-limits. Slack DMs carry an expectation of privacy from senders.",
  },
]
// TODO(parity): the bash hook also enforced a Slack channel allowlist
// (config/slack-channels.json) for non-DM channels. Port when Slack access
// is wired up on this harness.

// ---------------------------------------------------------------------------
// Security tool target allowlist (from security-target-allowlist.sh)
// ---------------------------------------------------------------------------

function stripUrlToHost(s: string): string {
  return s.replace(/^https?:\/\//, "").split("/")[0]
}

/** Extract the scan target from a security-tool command, or null if none. */
function extractSecurityTarget(cmd: string): string | null {
  let m: RegExpMatchArray | null

  if (/\bnmap\b/.test(cmd)) {
    const candidates = cmd
      .split(/\s+/)
      .filter((t) => t !== "nmap" && !t.startsWith("-") && !/^\d+$/.test(t))
    if (candidates.length) return candidates[candidates.length - 1]
  }
  if ((m = cmd.match(/\bsubfinder\b.*?-d\s+(\S+)/))) return m[1]
  if ((m = cmd.match(/\bhttpx\b.*?-u\s+(\S+)/))) return stripUrlToHost(m[1])
  if ((m = cmd.match(/\bnaabu\b.*?-host\s+(\S+)/))) return m[1]
  if (/\btrufflehog\b/.test(cmd) || /\bgitleaks\b/.test(cmd)) {
    m = cmd.match(/https?:\/\/(\S+)/)
    return m ? stripUrlToHost(m[1]) : null // local paths allowed
  }
  if ((m = cmd.match(/\btrivy\b.*?\bimage\b\s+(\S+)/))) {
    const registry = m[1].split("/")[0]
    return registry.includes(".") ? registry : null // local images allowed
  }
  if ((m = cmd.match(/\bnuclei\b.*?-u\s+(\S+)/))) return stripUrlToHost(m[1])
  if (/(@keygraph\/shannon|[/\s]shannon\b)/.test(cmd)) {
    m = cmd.match(/-u\s+(\S+)/)
    if (m) return stripUrlToHost(m[1])
  }
  return null
}

function loadAllowlist(worktree: string): string[] | null {
  const file = path.join(worktree, "config", "security-allowlist.json")
  if (!fs.existsSync(file)) return null
  try {
    const al = JSON.parse(fs.readFileSync(file, "utf8"))
    return [
      ...(al.domains ?? []),
      ...(al.hostnames_internal ?? []),
      ...(al.ips_internal ?? []),
    ].map((e: string) => e.toLowerCase().replace(/\.$/, ""))
  } catch {
    return null
  }
}

function targetAuthorized(target: string, allowlist: string[]): boolean {
  const t = target.toLowerCase().replace(/\.$/, "")
  return allowlist.some((e) => t === e || t.endsWith("." + e))
}

// ---------------------------------------------------------------------------
// SiYuan read-only guard (Jill) - shared 2nd brain, writes gated
// ---------------------------------------------------------------------------
// Sean's decision (Phase B): SiYuan is the SHARED 2nd brain. Jill gets READ
// access only - no writes to the canonical notes on day one. She is an
// unproven open-weight model and a prompt injection must not be able to
// alter Sean's authoritative knowledge base.
//
// Modeled on the reMarkable /Sean Private/ guard below, but implemented as
// DEFAULT-DENY with an explicit read allowlist: any siyuan tool not proven
// read-only is blocked, so new tools from a future siyuan-mcp version bump
// fail closed instead of open.
//
// Runtime names per the confirmed rule above: server "siyuan" exposes
// "siyuan_<tool>". We strip the server prefix and match on the tool SUFFIX
// so the guard survives a server rename (e.g. "siyuan-notes_<tool>" would
// still be caught, and an unrecognized suffix stays denied).
//
// Allowed (read/query only), full inventory of siyuan-mcp@1.0.4 reads:
//   sql_query, get_* (attrs/kramdown/child_blocks/file/hpath/ids/path/
//   notebook_conf/version/workspace_info/boot_progress/current_time),
//   list_notebooks, export_md_content, read_dir, check_siyuan_status,
//   render_sprig, render_template.
// Denied (state-changing), explicitly including Sean's list:
//   create_doc, create_notebook, insert_block, prepend_block, append_block,
//   update_block, delete_block, move_block, move_docs, move_docs_by_id,
//   set_block_attrs, put_file, remove_file, remove_doc, remove_doc_by_id,
//   rename_doc, rename_doc_by_id, rename_file, rename_notebook,
//   remove_notebook, upload_asset, transfer_block_ref, flush_transaction,
//   plus everything else default-denied: open_notebook, close_notebook,
//   set_notebook_conf, fold_block, unfold_block, push_msg, push_err_msg,
//   export_resources, pandoc_convert (the last two write server-side files).
const SIYUAN_TOOL_PREFIX = /^siyuan[a-z0-9-]*_/i
const SIYUAN_READ_ALLOW =
  /^(sql_query|get_[a-z0-9_]+|list_[a-z0-9_]+|export_md_content|read_dir|check_siyuan_status|render_sprig|render_template)$/

/** True when `tool` is a SiYuan MCP tool that Jill must not run (non-read). */
export function siyuanWriteDenied(tool: string): boolean {
  if (!SIYUAN_TOOL_PREFIX.test(tool)) return false
  const suffix = tool.replace(SIYUAN_TOOL_PREFIX, "")
  return !SIYUAN_READ_ALLOW.test(suffix)
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export const GuardrailsPlugin: Plugin = async ({ worktree }) => {
  return {
    "tool.execute.before": async (input, output) => {
      const tool = input.tool
      const args = (output.args ?? {}) as Record<string, unknown>

      // ---- Bash guards --------------------------------------------------
      if (tool === "bash") {
        const cmd = String(args.command ?? "")

        for (const rule of BASH_DENY_RULES) {
          if (rule.pattern.test(cmd)) throw new Error(rule.reason)
        }

        if (SQL_DESTRUCTIVE.test(cmd) && !PREVIEW_DB.test(cmd)) {
          throw new Error(
            "Blocked: destructive SQL operation detected. Database schema changes require Sean's approval. (Exception: -preview DBs are allowed.)",
          )
        }

        if (WACLI_RAW.test(cmd) && !WACLI_SAFE.test(cmd)) {
          throw new Error(
            "Blocked: raw 'wacli messages/send/media' is prohibited. Use the wacli-safe.sh wrapper which enforces the groups-only allowlist. DMs are off-limits.",
          )
        }

        // DM URLs typed into curl/wget etc. also get caught here.
        for (const rule of DM_URL_RULES) {
          if (rule.pattern.test(cmd)) throw new Error(rule.reason)
        }

        // Security tool target allowlist.
        const target = extractSecurityTarget(cmd)
        if (target) {
          const allowlist = loadAllowlist(worktree)
          if (!allowlist) {
            throw new Error(
              "Refused: config/security-allowlist.json not found or unreadable. Cannot authorize scan.",
            )
          }
          if (!targetAuthorized(target, allowlist)) {
            throw new Error(
              `Refused: target "${target}" is not on Sean's authorized allowlist (config/security-allowlist.json). Add it there or get per-incident authorization from Sean.`,
            )
          }
        }

        // TODO(parity): mutating-HTTP allowlist (curl -X POST to non-trusted
        // hosts) from guardrails.sh, including the JAX_E2E_MODE flag-file
        // escape hatch. Port in Phase 2 once the trusted-host list is
        // confirmed for this install.
      }

      // ---- Browser / webfetch DM guards --------------------------------
      // Covers the playwright MCP navigate tool and the built-in webfetch.
      // TODO(parity): confirm exact tool name once playwright MCP is enabled
      // (expected: "playwright_browser_navigate").
      const urlArg = String(args.url ?? "")
      if (urlArg && (tool === "webfetch" || /browser_navigate/.test(tool))) {
        for (const rule of DM_URL_RULES) {
          if (rule.pattern.test(urlArg)) throw new Error(rule.reason)
        }
      }

      // ---- GitHub MCP guards --------------------------------------------
      if (/merge_pull_request$/.test(tool)) {
        throw new Error(
          "Blocked: Jax cannot merge pull requests. PRs must be reviewed and merged by Sean.",
        )
      }
      if (/delete_repository$/.test(tool)) {
        throw new Error("Blocked: repository deletion is prohibited.")
      }

      // ---- Turso (production DB) guards ---------------------------------
      if (/^turso_/.test(tool)) {
        if (/delete_database$/.test(tool)) {
          throw new Error("Blocked: deleting a production database is prohibited. Ask Sean for approval.")
        }
        if (/execute_query$/.test(tool)) {
          const query = String(args.query ?? args.sql ?? "")
          const db = String(args.database ?? "")
          if (SQL_DESTRUCTIVE.test(query) && !/-preview$/.test(db)) {
            throw new Error(
              `Blocked: destructive SQL on production database (${db}). Requires Sean's approval. (Exception: -preview DBs are allowed.)`,
            )
          }
        }
      }

      // ---- SiYuan read-only guard (Jill) ---------------------------------
      if (siyuanWriteDenied(tool)) {
        throw new Error(
          "Blocked: SiYuan writes are gated for Jill. The SiYuan workspace is Sean's shared 2nd brain and Jill has read-only access on day one (unproven open-weight model - injection must not reach the canonical notes). Read/query tools are allowed: sql_query, get_*, list_*, export_md_content, read_dir, check_siyuan_status, render_sprig, render_template. TODO: a future Jill-owned subtree (dedicated notebook) could relax this to scoped writes once she is proven.",
        )
      }

      // ---- reMarkable private-folder guard -------------------------------
      if (/^remarkable_/.test(tool)) {
        const rmArgs = ["document", "path", "folder", "dest_folder", "parent", "query"]
          .map((k) => args[k])
          .filter((v) => typeof v === "string")
          .join(" ")
        if (/Sean[ _/-]*Private/i.test(rmArgs)) {
          throw new Error(
            "Blocked: /Sean Private/ on the reMarkable is off-limits to Jax. Enforced by REMARKABLE_ROOT_PATH=/Jax plus this guardrail.",
          )
        }
      }
    },
  }
}
