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
 * Not covered by any hook: the user-initiated shell (`!cmd`, POST
 * /session/:id/shell) and the PTY API. Both need a caller on the OpenCode
 * API, which is unauthenticated and therefore never published; tools are
 * denied any call to it (policy.ts httpDenied).
 */

import type { Plugin } from "@opencode-ai/plugin"
import { defaultContext, evaluate, shellEnvOverrides } from "../guards/policy.ts"

export const GuardrailsPlugin: Plugin = async ({ directory }) => {
  const base = defaultContext(directory)
  return {
    "tool.execute.before": async (input, output) => {
      const reason = evaluate(input.tool, (output.args ?? {}) as Record<string, unknown>, base)
      if (reason) throw new Error(reason)
    },
    "shell.env": async (_input, output) => {
      Object.assign(output.env, shellEnvOverrides(process.env))
    },
  }
}
