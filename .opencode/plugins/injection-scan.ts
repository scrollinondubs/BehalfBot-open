/**
 * injection-scan.ts - ingest-time prompt-injection scanner (BehalfBot-open#51).
 *
 * The logic lives in ../guards/injection.ts (unit-tested in tests/guards/).
 * This file only wires it into OpenCode and must export exactly one
 * function: OpenCode's legacy plugin loader calls EVERY exported function in
 * a plugins/*.ts file as a plugin.
 *
 * Hook (verified against opencode v1.19.6 source):
 *   tool.execute.after  fires after every built-in tool (session/tools.ts),
 *                       every MCP tool (same file; output is the raw MCP
 *                       result, read for the model AFTER the hook), the
 *                       `task` subagent result (session/prompt.ts) and MCP
 *                       tools called from code mode (tool/code-mode.ts).
 *                       The output object is passed by reference, so
 *                       rewriting it here is what the model sees.
 *
 * Fail closed: handleToolOutput withholds on any scanner error. If even that
 * cannot run, this throws, which fails the tool call; OpenCode then reports
 * an error to the model, never the output. The boot self-test proves the
 * plugin is loaded (selftest/cases.json, "flagged" cases).
 *
 * Alerts go to INJECTION_ALERT_DIR (compose: the scan-alerts volume, which
 * jill-control drains). They carry no content (see writeAlert).
 */

import type { Plugin } from "@opencode-ai/plugin"
import { handleToolOutput, TAG, WITHHELD, writeAlert } from "../guards/injection.ts"

export const InjectionScanPlugin: Plugin = async () => {
  const alertDir = process.env.INJECTION_ALERT_DIR || "/state/scan-alerts"
  let warned = false
  const alert = (severity: "high" | "low" | "error", source: Parameters<typeof writeAlert>[2]) => {
    if (!writeAlert(alertDir, severity, source) && !warned) {
      warned = true
      console.error(`${TAG} could not write an alert to ${alertDir}; hits are still quarantined`)
    }
  }
  return {
    "tool.execute.after": async (input, output) => {
      let outcome
      try {
        outcome = handleToolOutput(input.tool, input.args, output)
      } catch {
        alert("error", "other")
        throw new Error(WITHHELD)
      }
      if (outcome.status === "flagged") alert(outcome.severity, outcome.source)
      else if (outcome.status === "withheld") alert("error", outcome.source)
    },
  }
}
