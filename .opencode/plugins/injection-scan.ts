/**
 * injection-scan.ts - ingest-time prompt-injection scanner (BehalfBot-open#51).
 *
 * The logic lives in ../guards/injection.ts (unit-tested in tests/guards/).
 * This file only wires it into OpenCode and must export exactly one
 * function: OpenCode's legacy plugin loader calls EVERY exported function in
 * a plugins/*.ts file as a plugin.
 *
 * Hooks (verified against opencode v1.19.6 source):
 *   tool.execute.after  every successful built-in tool, MCP tool, `task`
 *                       result and code-mode MCP call. The output object is
 *                       passed by reference, so rewriting it is what the
 *                       model sees.
 *   experimental.chat.messages.transform
 *                       runs on the session's messages before EVERY model
 *                       call (session/prompt.ts). Catches what the hook
 *                       above never sees: the error text of failed tools
 *                       (MCP errors, `read` suggestions) and the documents
 *                       the Matrix bridge puts in Sean's messages.
 *
 * Fail closed: an output the scanner cannot handle is withheld; if even that
 * fails, this throws and the tool call fails.
 *
 * Alerts: one empty file per hit in INJECTION_ALERT_DIR (compose: the
 * scan-alerts volume, create-only for this uid). If a write fails (the model
 * filled the volume), the output that needed the alert is withheld and the
 * alert is owed: retried on every later hook call and every 10 s, so the
 * only way to keep it out is to keep the volume full, which jill-control
 * reports as tampering (red-team round 7 R2-3).
 */

import type { Plugin } from "@opencode-ai/plugin"
import {
  handleToolOutput,
  newTransformState,
  noteOwnError,
  scanMessages,
  TAG,
  WITHHELD,
  withhold,
  writeAlert,
} from "../guards/injection.ts"

type Sev = "high" | "low" | "error"

export const InjectionScanPlugin: Plugin = async () => {
  const alertDir = process.env.INJECTION_ALERT_DIR || "/state/scan-alerts"
  const owed: Sev[] = []
  let warned = false
  const flush = () => {
    while (owed.length && writeAlert(alertDir, owed[0])) owed.shift()
    if (owed.length && !warned) {
      warned = true
      console.error(`${TAG} alert writes to ${alertDir} are failing; ${owed.length} owed, retrying`)
    }
    return owed.length === 0
  }
  const alert = (sev: Sev): boolean => {
    owed.push(sev)
    return flush()
  }
  const timer = setInterval(flush, 10_000)
  timer.unref?.()
  const transform = newTransformState()

  return {
    "tool.execute.after": async (input, output) => {
      flush()
      let outcome
      try {
        outcome = handleToolOutput(input.tool, input.args, output)
      } catch {
        alert("error")
        noteOwnError(input.callID)
        throw new Error(WITHHELD)
      }
      if (outcome.status === "flagged" || outcome.status === "withheld") {
        const sev = outcome.status === "flagged" ? outcome.severity : "error"
        if (!alert(sev)) withhold(output as Record<string, unknown>)
      }
    },
    "experimental.chat.messages.transform": async (_input, output) => {
      flush()
      for (const sev of scanMessages((output as { messages?: unknown }).messages, transform)) alert(sev)
    },
  }
}
