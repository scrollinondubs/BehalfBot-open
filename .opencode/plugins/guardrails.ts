/**
 * guardrails.ts - deterministic safety guardrails for Jill on OpenCode.
 *
 * The rules live in ../guards/policy.ts (pure, unit-tested in tests/guards/).
 * This file only wires them into OpenCode and must export exactly one
 * function: OpenCode's legacy plugin loader calls EVERY exported function in
 * a plugins/*.ts file as a plugin.
 *
 * Hooks (verified against opencode v1.19.6 source):
 *   tool.execute.before  fires for every model tool call in
 *                        session/tools.ts, for the `task` subagent launch in
 *                        session/prompt.ts, and for MCP tools called from code
 *                        mode (tool/code-mode.ts). Subagent sessions run their
 *                        tools through the same session/tools.ts path; the
 *                        boot self-test (selftest/) proves that end to end.
 *                        Throwing denies the call.
 *   shell.env            merged over process.env for every bash tool call
 *                        (tool/shell.ts). It cannot remove a variable, so
 *                        secret-looking variables are overridden with "".
 *
 * MCP tool naming: sanitize(server) + "_" + sanitize(tool), where sanitize
 * replaces anything outside [a-zA-Z0-9_-] with "_" (mcp/catalog.ts).
 *
 * The user-initiated shell (`!cmd`, POST /session/:id/shell) and the PTY API
 * fire no tool.execute.before, but they do fire shell.env, so shell.env
 * refuses any shell that is not an approved bash tool call. Both routes also
 * sit behind the server password, which tool shells cannot read (they run
 * as a different uid with an empty environment, see runtime/jill-shell).
 */

import type { Plugin } from "@opencode-ai/plugin"
import { defaultContext, evaluate, shellEnvOverrides } from "../guards/policy.ts"

export const GuardrailsPlugin: Plugin = async ({ directory }) => {
  const base = defaultContext(directory)
  // callIDs of bash tool calls this guard has approved. Every shell OpenCode
  // starts fires shell.env; one that does not belong to an approved bash
  // tool call (the session shell route, the PTY API) is refused there.
  const approved = new Set<string>()
  return {
    "tool.execute.before": async (input, output) => {
      const reason = evaluate(input.tool, (output.args ?? {}) as Record<string, unknown>, base)
      if (reason) throw new Error(reason)
      if (input.tool === "bash") approved.add(input.callID)
    },
    "shell.env": async (input, output) => {
      if (!input.callID || !approved.has(input.callID))
        throw new Error("[guardrails] Blocked: shells outside the bash tool (session shell, PTY) are disabled.")
      approved.delete(input.callID)
      Object.assign(output.env, shellEnvOverrides(process.env))
    },
  }
}
