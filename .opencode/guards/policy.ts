/**
 * policy.ts - the deny rules behind .opencode/plugins/guardrails.ts.
 *
 * Pure functions: evaluate(tool, args, ctx) returns a deny reason or null.
 * The plugin throws the reason (which denies the call); the unit tests in
 * tests/guards/ and the boot self-test in selftest/ drive the same function.
 *
 * Lives outside .opencode/plugins/ on purpose: OpenCode loads every
 * plugins/*.ts file as a plugin and calls each exported function as one.
 *
 * Ported logic, not ported text:
 *   - chassis guardrails.sh and the reference install's guardrails.sh
 *     (rm, push, SQL, wacli, DM URLs, AgentMail gate, mutating HTTP)
 *   - the reference install's secret-print-guard.py
 *   - security-target-allowlist.sh
 * The mutating-HTTP rule matches the PARSED destination host exactly or on a
 * dot boundary. The reference install still greps a pattern over the whole
 * URL string, so `https://evil.example/?x=allowed.com` would pass there. It
 * does not pass here. There is no escape-hatch flag (BehalfBot-open#31).
 */

import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { fileURLToPath } from "node:url"

export const TAG = "[guardrails]"

export type GuardConfig = {
  egressHosts: string[]
  writeRoots: string[]
  agentmailRecipients: string[]
  securityTargets: string[]
}

export type GuardContext = {
  /** Session directory; relative file paths resolve against it. */
  directory: string
  /** Absolute path of the image's app root (holds AGENTS.md, config/, .opencode/). */
  appRoot: string
  home: string
  config: GuardConfig | null
}

const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..")

/**
 * Config is read from the image's own config/ directory, located relative to
 * this file, never from the session directory: a session opened somewhere
 * writable must not be able to supply its own allowlist. Unreadable config
 * returns null and every rule that needs it fails closed.
 */
export function loadConfig(appRoot: string = APP_ROOT): GuardConfig | null {
  try {
    const g = JSON.parse(fs.readFileSync(path.join(appRoot, "config", "guards.json"), "utf8"))
    let sec: string[] = []
    try {
      const al = JSON.parse(fs.readFileSync(path.join(appRoot, "config", "security-allowlist.json"), "utf8"))
      sec = [...(al.domains ?? []), ...(al.hostnames_internal ?? []), ...(al.ips_internal ?? [])]
    } catch {
      sec = []
    }
    const lower = (xs: unknown) => (Array.isArray(xs) ? xs.map((x) => String(x).toLowerCase().replace(/\.$/, "")) : [])
    return {
      egressHosts: lower(g.egress_hosts),
      writeRoots: Array.isArray(g.write_roots) ? g.write_roots.map((r: unknown) => path.resolve(String(r))) : [],
      agentmailRecipients: lower(g.agentmail_recipients),
      securityTargets: lower(sec),
    }
  } catch {
    return null
  }
}

export function defaultContext(directory: string): GuardContext {
  return { directory, appRoot: APP_ROOT, home: os.homedir(), config: loadConfig(APP_ROOT) }
}

const deny = (msg: string) => `${TAG} ${msg}`

// ---------------------------------------------------------------------------
// Shell text helpers
// ---------------------------------------------------------------------------

/**
 * Split a command line into simple commands on unquoted ; && || | & ( ) and
 * newlines. Command substitution ($( and backticks) also starts a new
 * command, inside double quotes too, because the shell runs it there.
 */
export function segments(cmd: string): string[] {
  const out: string[] = []
  let cur = ""
  let q: string | null = null
  const push = () => {
    if (cur.trim()) out.push(cur.trim())
    cur = ""
  }
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]
    if (q === "'") {
      if (c === "'") q = null
      cur += c
      continue
    }
    if (c === "\\" && i + 1 < cmd.length) {
      cur += c + cmd[++i]
      continue
    }
    if ((c === "$" && cmd[i + 1] === "(") || c === "`") {
      push()
      if (c === "$") i++
      continue
    }
    if (q === '"') {
      if (c === '"') q = null
      cur += c
      continue
    }
    if (c === "'" || c === '"') {
      q = c
      cur += c
      continue
    }
    if (";&|()\n".includes(c)) {
      push()
      continue
    }
    cur += c
  }
  push()
  return out
}

/** shlex-style tokenizer: honours single and double quotes and backslashes. */
export function tokens(s: string): string[] {
  const out: string[] = []
  let cur = ""
  let has = false
  let q: string | null = null
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (q) {
      if (c === q) q = null
      else if (c === "\\" && q === '"' && i + 1 < s.length) cur += s[++i]
      else cur += c
      continue
    }
    if (c === "'" || c === '"') {
      q = c
      has = true
    } else if (c === "\\" && i + 1 < s.length) {
      cur += s[++i]
      has = true
    } else if (/\s/.test(c)) {
      if (has) out.push(cur)
      cur = ""
      has = false
    } else {
      cur += c
      has = true
    }
  }
  if (has) out.push(cur)
  return out
}

const PREFIX_WORDS = new Set(["sudo", "command", "builtin", "exec", "nohup", "time", "nice", "env", "doas", "xargs"])

/** The command word of a simple command, skipping sudo/env/VAR=x prefixes. */
function commandWord(toks: string[]): { word: string; index: number; viaXargs: boolean } | null {
  let viaXargs = false
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) continue
    const base = t.split("/").pop() ?? t
    if (PREFIX_WORDS.has(base)) {
      if (base === "xargs") viaXargs = true
      continue
    }
    if (t.startsWith("-") && i > 0) continue
    return { word: base, index: i, viaXargs }
  }
  return null
}

// ---------------------------------------------------------------------------
// Recursive delete (ported from the reference install, new-jaxity#526)
// ---------------------------------------------------------------------------

function rmDenied(cmd: string, ctx: GuardContext): string | null {
  for (const seg of segments(cmd)) {
    const toks = tokens(seg)
    const cw = commandWord(toks)
    if (!cw || cw.word !== "rm") continue
    if (/^\s*(sudo|doas)\b/.test(seg)) return deny("Blocked: sudo rm is prohibited. Use 'trash', or ask Sean.")
    const args = toks.slice(cw.index + 1)
    let recursive = false
    const operands: string[] = []
    let endOfFlags = false
    for (const a of args) {
      if (!endOfFlags && a === "--") {
        endOfFlags = true
        continue
      }
      if (!endOfFlags && a.startsWith("-")) {
        if (a === "--recursive" || /^-[A-Za-z]*[rR]/.test(a)) recursive = true
        continue
      }
      operands.push(a)
    }
    if (!recursive) continue
    if (cw.viaXargs || operands.length === 0)
      return deny("Blocked: recursive delete whose targets come from stdin cannot be checked. Expand the paths, or use 'trash'.")
    // The raw segment (pre-tokenising) shows expansions the tokenizer kept as text.
    for (const raw of operands) {
      if (/[$`]/.test(raw))
        return deny(
          `Blocked: recursive delete of an unexpanded target (${raw}). A guard cannot see what a variable holds, and a stale one wiped a live install tree once (new-jaxity#526). Expand the path to a literal, or use 'trash'.`,
        )
      const bare = raw.replace(/\/+$/, "") || "/"
      if (/^[.*/]*$/.test(bare) || bare === "~" || bare.startsWith("~"))
        return deny(`Blocked: recursive delete of '${raw}'. Home, root, dot and bare-glob targets are refused. Use 'trash', or ask Sean.`)
      if (bare.startsWith("/") || bare.split("/").includes("..")) {
        const abs = path.resolve(ctx.directory, bare)
        const inside = (root: string) => abs.startsWith(root.replace(/\/+$/, "") + "/")
        const roots = ctx.config?.writeRoots ?? []
        if (!roots.some(inside))
          return deny(
            `Blocked: recursive delete of '${raw}', which is not strictly inside an allowed working directory (${roots.join(", ") || "none configured"}). Use 'trash', or ask Sean.`,
          )
      }
    }
  }
  return null
}

// ---------------------------------------------------------------------------
// git, SQL, mail CLIs, WhatsApp, DM URLs (ported, boundary-anchored)
// ---------------------------------------------------------------------------

function gitDenied(cmd: string): string | null {
  for (const seg of segments(cmd)) {
    const toks = tokens(seg)
    const cw = commandWord(toks)
    if (!cw || cw.word !== "git") continue
    const rest = toks.slice(cw.index + 1)
    const GIT_ARG_OPTS = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"])
    const subIdx = rest.findIndex((t, i) => !t.startsWith("-") && !(i > 0 && GIT_ARG_OPTS.has(rest[i - 1])))
    const sub = subIdx >= 0 ? rest[subIdx] : undefined
    if (sub === "push") {
      const after = rest.slice(subIdx + 1)
      if (after.some((t) => t === "-f" || t === "--force" || (/^-[A-Za-z]*f/.test(t) && !t.startsWith("--")) || /^\+/.test(t)))
        return deny("Blocked: force-push is prohibited. Use 'git revert' to undo commits safely.")
      if (after.some((t) => /^(main|master)$/.test(t) || /:(refs\/heads\/)?(main|master)$/.test(t)))
        return deny("Blocked: pushing directly to main/master is prohibited. Create a PR instead.")
    }
    if (sub === "reset" && rest.includes("--hard"))
      return deny("Blocked: git reset --hard can destroy work. Use 'git stash' or 'git revert' instead.")
    if (sub === "clean" && rest.some((t) => /^-[A-Za-z]*f/.test(t) || t === "--force"))
      return deny("Blocked: git clean -f deletes untracked files permanently. Review files manually first.")
  }
  return null
}

const SQL_DESTRUCTIVE = /DROP\s+(TABLE|DATABASE|INDEX|SCHEMA)|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\S+\s*(;|$)/i
const PREVIEW_DB = /-preview([^a-zA-Z0-9]|$)/
const MAIL_CLIS = new Set(["mail", "mailx", "sendmail", "mutt", "msmtp", "ssmtp"])
const RAW_SOCKETS = new Set(["nc", "ncat", "netcat", "socat", "telnet"])

const DM_URL_RULES: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /(twitter\.com|x\.com)\/messages/i,
    reason: "Blocked: Twitter/X DM inbox is off-limits. If Sean forwarded a DM, act on the forwarded content.",
  },
  { pattern: /linkedin\.com\/messaging\//i, reason: "Blocked: LinkedIn messaging is off-limits." },
  { pattern: /app\.slack\.com\/client\/[A-Z0-9]+\/D[A-Z0-9]+/, reason: "Blocked: Slack DM navigation is off-limits." },
]

// ---------------------------------------------------------------------------
// Secret printing (ported from secret-print-guard.py)
// ---------------------------------------------------------------------------

const SECRET_FILE =
  /(^|\/)(\.env(\.[A-Za-z0-9_-]+)?|\.mcp\.json|\.vw-[^/\s]*|id_(rsa|ed25519|ecdsa)|[^/\s]*credentials[^/\s]*\.json|token\.json|auth\.json|[^/\s]*\.pem|[^/\s]*\.key)$/
const SAFE_FILE = /(\.env\.example|\.env\.sample|\.env\.template|\.pub)$/
const PROC_SECRET = /\/proc\/[^\s'"]*\/(environ|cmdline|mem)\b/

export function isSecretPath(p: string): boolean {
  const s = p.trim().replace(/^["']|["']$/g, "")
  if (PROC_SECRET.test(s)) return true
  return SECRET_FILE.test(s) && !SAFE_FILE.test(s)
}

const DUMPERS = new Set([
  "cat", "head", "tail", "less", "more", "bat", "nl", "strings", "xxd", "od", "hexdump", "sed", "awk",
  "grep", "rg", "jq", "tac", "base64", "cut", "sort", "uniq", "diff", "cp", "python", "python3", "node", "perl",
])
const SECRET_MENTION =
  /(^|[\/'"\s(=])\.env(\.(?!example|sample|template)[A-Za-z0-9_-]+)?(?=$|[\s'")])|auth\.json|id_(rsa|ed25519|ecdsa)\b|\.mcp\.json|\.vw-|\/proc\/[^\s]*environ/
const SECRET_VAR = /(^|_)(KEYS?|APIKEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|PAT|CREDENTIALS?|AUTH)(_|$)/

export function isSecretVarName(name: string): boolean {
  return SECRET_VAR.test(name)
}

function secretBashDenied(cmd: string): string | null {
  if (/\/proc\b/.test(cmd) && /\b(environ|cmdline)\b/.test(cmd))
    return deny("secret-print-guard: reading another process's environment or command line prints its secrets. Name the one variable you need instead.")
  for (const seg of cmd.split(/;|&&|\|\||\n/)) {
    const s = seg.trim()
    if (!s) continue
    const pipes = s.split("|").map((p) => p.trim())
    const first = pipes[0]
    const rest = pipes.slice(1).join("|")
    const namesOnly = /(^|\s)(wc|cut\s+-d\s*=?\s*-f\s*1|cut\s+-d=\s+-f1)\b|grep\s+-[A-Za-z]*[clq]/.test(rest)
    // Environment dumps.
    if (/^(sudo\s+)?(env|printenv|export\s+-p|set|declare\s+-[xp]|compgen\s+-v)\s*$/.test(first) && !namesOnly)
      return deny("secret-print-guard: dumping the environment prints every secret in it. List names only (env | cut -d= -f1).")
    const toks = tokens(first)
    const cw = commandWord(toks)
    if (!cw) continue
    const args = toks.slice(cw.index + 1)
    if (cw.word === "printenv" && args.some((a) => isSecretVarName(a)))
      return deny("secret-print-guard: printing a secret variable puts its value in the transcript. Use it without printing it.")
    if ((cw.word === "echo" || cw.word === "printf") && /\$\{?[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASS|_PAT|AUTH)[A-Z0-9_]*\}?/.test(first))
      return deny("secret-print-guard: echoing a secret variable puts its value in the transcript.")
    if (INTERPRETERS.has(cw.word) && SECRET_MENTION.test(first))
      return deny("secret-print-guard: this script reads a secret-bearing file or process environment; its output lands in the session log.")
    const files = args.filter((a) => isSecretPath(a))
    if (files.length && (DUMPERS.has(cw.word) || /</.test(first))) {
      let safe = false
      if ((cw.word === "grep" || cw.word === "rg") && /(^|\s)-[A-Za-z]*[oclqL]/.test(args.join(" "))) safe = true
      if (cw.word === "jq" && /\bkeys\b|\|\s*length/.test(args.join(" "))) safe = true
      if (namesOnly) safe = true
      if (!safe)
        return deny(
          `secret-print-guard: this prints the contents of ${files[0]} into the session log. List names only (grep -o "^[A-Z_]*" FILE) or use the value without printing it.`,
        )
    }
    if (/<\s*\S/.test(first)) {
      const redirected = first.match(/<\s*(\S+)/)
      if (redirected && isSecretPath(redirected[1]))
        return deny(`secret-print-guard: this reads ${redirected[1]} into a command whose output lands in the session log.`)
    }
    if (/(bw-fetch\.sh|\bbw\s+get\s+(password|item|notes|totp))/.test(s))
      return deny("secret-print-guard: vault access is not available to Jill.")
  }
  return null
}

// ---------------------------------------------------------------------------
// HTTP: destination-host allowlist, OpenCode API, AgentMail gate
// ---------------------------------------------------------------------------

/** Exact host match, or a subdomain of an allowlisted entry on a dot boundary. */
export function hostAllowed(hostname: string, allow: string[]): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "")
  return allow.some((e) => h === e || h.endsWith("." + e))
}

function parseUrl(raw: string): URL | null {
  const s = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : "http://" + raw
  try {
    return new URL(s)
  } catch {
    return null
  }
}

const LOOPBACK = /^(localhost|127(\.\d{1,3}){3}|0\.0\.0\.0|::1?|::ffff:127(\.\d{1,3}){3}|opencode-serve)$/i
const SERVE_PORT = "4747"

function servesOpencodeApi(u: URL): boolean {
  const host = u.hostname.replace(/^\[|\]$/g, "")
  return u.port === SERVE_PORT || /^opencode-serve$/i.test(host) || (LOOPBACK.test(host) && u.port === "")
}

// curl/wget options that consume the next token.
const CURL_ARG_FLAGS = new Set([
  "-X", "--request", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json",
  "-F", "--form", "--form-string", "-H", "--header", "-o", "--output", "-u", "--user", "-A", "--user-agent",
  "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar", "-T", "--upload-file", "-m", "--max-time",
  "--connect-timeout", "-w", "--write-out", "--resolve", "--connect-to", "-x", "--proxy", "-K", "--config",
  "--retry", "-r", "--range", "-E", "--cert", "--key", "--cacert", "-U", "--proxy-user", "--url", "-z",
  "--time-cond", "-Y", "--speed-limit", "-y", "--speed-time", "--limit-rate", "--interface", "--dns-servers",
  "--output-dir", "--variable", "--expand-url", "--expand-data",
])
const CURL_DATA_FLAGS = new Set([
  "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json", "-F", "--form",
  "--form-string", "-T", "--upload-file", "--expand-data",
])
const WGET_MUTATING = /^--(post-data|post-file|body-data|body-file)(=|$)|^--method(=|$)/
const REDIRECTING_FLAGS = new Set(["--resolve", "--connect-to", "-x", "--proxy", "-K", "--config", "--variable"])
const INTERPRETERS = new Set(["python", "python3", "node", "nodejs", "perl", "ruby", "php", "bun", "deno"])

type HttpCall = { tool: string; urls: string[]; mutating: boolean; data: string[]; redirecting: boolean }

function httpCalls(cmd: string): HttpCall[] {
  const calls: HttpCall[] = []
  for (const seg of segments(cmd)) {
    const toks = tokens(seg)
    const cw = commandWord(toks)
    if (!cw) continue
    const args = toks.slice(cw.index + 1)
    if (cw.word === "curl") {
      const call: HttpCall = { tool: "curl", urls: [], mutating: false, data: [], redirecting: false }
      for (let i = 0; i < args.length; i++) {
        const a = args[i]
        const [flag, inline] = a.startsWith("--") && a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a, undefined]
        const shortJoined = /^-[XdFHTmxo]./.test(a) && !a.startsWith("--") ? [a.slice(0, 2), a.slice(2)] : null
        const f = shortJoined ? shortJoined[0] : flag
        const takes = CURL_ARG_FLAGS.has(f)
        const value = shortJoined ? shortJoined[1] : inline !== undefined ? inline : takes ? args[++i] : undefined
        if (f === "-X" || f === "--request") {
          if (value && !/^(GET|HEAD|OPTIONS)$/i.test(value)) call.mutating = true
        } else if (CURL_DATA_FLAGS.has(f)) {
          call.mutating = true
          if (value !== undefined) call.data.push(value)
        } else if (REDIRECTING_FLAGS.has(f)) {
          call.redirecting = true
        } else if (f === "--url") {
          if (value) call.urls.push(value)
        } else if (!a.startsWith("-") && !takes) {
          call.urls.push(a)
        }
      }
      calls.push(call)
    } else if (cw.word === "wget") {
      const call: HttpCall = { tool: "wget", urls: [], mutating: false, data: [], redirecting: false }
      for (let i = 0; i < args.length; i++) {
        const a = args[i]
        if (WGET_MUTATING.test(a)) {
          if (!/^--method(=|$)/.test(a) || !/=(GET|HEAD)$/i.test(a)) call.mutating = true
          const v = a.includes("=") ? a.slice(a.indexOf("=") + 1) : args[++i]
          if (v) call.data.push(v)
        } else if (/^-(e|-execute)$|^--proxy|^-Y$/.test(a)) {
          call.redirecting = true
        } else if (/^-(O|o|P|U|a|i|t|T|w)$/.test(a)) {
          i++
        } else if (!a.startsWith("-")) {
          call.urls.push(a)
        }
      }
      calls.push(call)
    } else if (INTERPRETERS.has(cw.word)) {
      const urls = seg.match(/https?:\/\/[^\s"'`)<>\\]+/gi) ?? []
      const mutating = /\b(post|put|patch|delete)\b|method\s*[:=]|data\s*=|urlopen\s*\(/i.test(seg)
      if (urls.length || /\b(requests|urllib|http\.client|fetch|axios|net\/http|socket)\b/.test(seg))
        calls.push({ tool: cw.word, urls, mutating, data: [], redirecting: !urls.length })
    } else if (RAW_SOCKETS.has(cw.word) || (cw.word === "openssl" && args.includes("s_client"))) {
      calls.push({ tool: cw.word, urls: [], mutating: true, data: [], redirecting: true })
    }
  }
  return calls
}

const AGENTMAIL_HOST = /(^|\.)agentmail\.to$/i
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g

/** Recipients of an AgentMail send payload, or null when they cannot be read. */
export function mailRecipients(payloads: string[]): string[] | null {
  if (!payloads.length) return null
  const out: string[] = []
  for (const p of payloads) {
    if (p.startsWith("@") || /[$`]/.test(p)) return null
    let parsed: unknown = undefined
    try {
      parsed = JSON.parse(p)
    } catch {
      parsed = undefined
    }
    if (parsed && typeof parsed === "object") {
      const o = parsed as Record<string, unknown>
      let found = false
      for (const k of ["to", "cc", "bcc"]) {
        const v = o[k]
        if (v === undefined || v === null) continue
        found = true
        const items = Array.isArray(v) ? v : [v]
        for (const it of items) {
          const addrs = String(typeof it === "object" && it ? ((it as Record<string, unknown>).email ?? (it as Record<string, unknown>).address ?? "") : it).match(EMAIL)
          if (!addrs) return null
          out.push(...addrs)
        }
      }
      if (!found) return null
    } else {
      const addrs = p.match(EMAIL)
      if (!addrs) return null
      out.push(...addrs)
    }
  }
  return out.length ? out.map((a) => a.toLowerCase()) : null
}

function agentmailSendDenied(pathname: string, payloads: string[], allowed: string[]): string | null {
  const p = pathname.toLowerCase()
  if (/\/(reply|reply-all|reply_all|forward)(\/|$)/.test(p) || /\/drafts\/[^/]+\/send(\/|$)/.test(p))
    return deny(
      "Blocked: AgentMail reply, forward and draft-send take their recipients from stored mail, so they cannot be checked. Jill may send only to Sean; anything else stays a draft for him.",
    )
  if (!/\/send(\/|$)/.test(p)) return null
  const rcpts = mailRecipients(payloads)
  if (!rcpts)
    return deny(
      "Blocked: AgentMail send whose recipients cannot be read from a literal payload (missing, from a file, or built from a variable). Write the to/cc/bcc addresses literally.",
    )
  const bad = rcpts.filter((r) => !allowed.includes(r))
  if (bad.length)
    return deny(
      `Blocked: AgentMail send to ${bad.join(", ")}. Jill may send email only to Sean (${allowed.join(", ") || "none configured"}); anything else is a draft for Sean to approve.`,
    )
  return null
}

function httpDenied(cmd: string, ctx: GuardContext): string | null {
  if (/(^|[^0-9])4747([^0-9]|$)/.test(cmd) || /opencode-serve/i.test(cmd))
    return deny("Blocked: the OpenCode server API (port 4747) is unauthenticated and exposes keys and session control. No tool may call it.")
  for (const call of httpCalls(cmd)) {
    const parsed = call.urls.map((u) => ({ raw: u, url: /[$`{}]/.test(u) ? null : parseUrl(u) }))
    for (const p of parsed) {
      if (p.url && servesOpencodeApi(p.url))
        return deny("Blocked: loopback calls to the OpenCode server API are not allowed from tools.")
    }
    if (!call.mutating) continue
    if (call.redirecting)
      return deny(
        `Blocked: mutating HTTP via ${call.tool} with a proxy, resolve override, config file or raw socket, so the real destination cannot be checked. Use curl with a literal URL.`,
      )
    if (!parsed.length || parsed.some((p) => !p.url))
      return deny(
        "Blocked: mutating HTTP request with no literal URL. The destination host cannot be checked against the allowlist. Write the full https://host/path literally.",
      )
    const allow = ctx.config?.egressHosts
    if (!allow) return deny("Blocked: config/guards.json is missing or unreadable, so no mutating HTTP is allowed.")
    for (const p of parsed) {
      const u = p.url as URL
      if (!/^https?:$/.test(u.protocol))
        return deny(`Blocked: mutating request over ${u.protocol} is not allowed.`)
      if (!hostAllowed(u.hostname, allow))
        return deny(`Blocked: mutating HTTP request to ${u.hostname}, which is not on config/guards.json egress_hosts. Ask Sean.`)
      if (AGENTMAIL_HOST.test(u.hostname)) {
        const r = agentmailSendDenied(u.pathname, call.data, ctx.config?.agentmailRecipients ?? [])
        if (r) return r
      }
    }
  }
  return null
}

// ---------------------------------------------------------------------------
// File writes: allowlisted roots, guard files denied at any path
// ---------------------------------------------------------------------------

const PROTECTED_NAMES = new Set(["opencode.json", "opencode.jsonc", "AGENTS.md", "CLAUDE.md", "tui.json"])

/** Resolve symlinks on the longest existing prefix so a link cannot launder a path. */
function realish(p: string): string {
  let cur = path.resolve(p)
  const tail: string[] = []
  for (;;) {
    try {
      return path.join(fs.realpathSync(cur), ...tail.reverse())
    } catch {
      const parent = path.dirname(cur)
      if (parent === cur) return path.resolve(p)
      tail.push(path.basename(cur))
      cur = parent
    }
  }
}

function protectedReason(abs: string, ctx: GuardContext): string | null {
  const parts = abs.split(path.sep)
  if (parts.includes(".opencode") || PROTECTED_NAMES.has(path.basename(abs)))
    return `${abs} is a guard or instruction file (.opencode/, opencode.json, AGENTS.md, CLAUDE.md). OpenCode would load it as config, so it is never writable from a session, at any path.`
  const within = (root: string) => abs === root || abs.startsWith(root.replace(/\/+$/, "") + "/")
  if (within(ctx.appRoot)) return `${abs} is inside the read-only app tree (${ctx.appRoot}).`
  if (within(path.join(ctx.home, ".config", "opencode")))
    return `${abs} is OpenCode's global config directory.`
  if (isSecretPath(abs)) return `${abs} is a secret-bearing file.`
  return null
}

export function writeDenied(target: string, ctx: GuardContext): string | null {
  if (!target) return deny("Blocked: file write with no path.")
  const expanded = target.startsWith("~") ? path.join(ctx.home, target.slice(1)) : target
  const abs = realish(path.isAbsolute(expanded) ? expanded : path.join(ctx.directory, expanded))
  const lexical = path.resolve(path.isAbsolute(expanded) ? expanded : path.join(ctx.directory, expanded))
  for (const p of [lexical, abs]) {
    const r = protectedReason(p, ctx)
    if (r) return deny(`Blocked: ${r}`)
  }
  const roots = ctx.config?.writeRoots
  if (!roots) return deny("Blocked: config/guards.json is missing or unreadable, so no file writes are allowed.")
  const under = (r: string) => abs === r || abs.startsWith(r.replace(/\/+$/, "") + "/")
  if (!roots.some((r) => under(r) || under(realish(r))))
    return deny(`Blocked: writing outside the allowed directories (${abs}). Allowed: ${roots.join(", ")}.`)
  return null
}

export function patchPaths(patchText: string): string[] {
  const out: string[] = []
  for (const line of patchText.split(/\r?\n/)) {
    const m = line.match(/^\*\*\*\s+(Add File|Update File|Delete File|Move to):\s*(.+?)\s*$/)
    if (m) out.push(m[2])
  }
  return out
}

const PROTECTED_IN_SHELL = /\.opencode\b|opencode\.jsonc?\b|AGENTS\.md|CLAUDE\.md|tui\.json|\.config\/opencode|\/app\/config\b/
const SHELL_WRITES =
  /\btee\b|\bcp\b|\bmv\b|\bln\b|\brm\b|\btouch\b|\bmkdir\b|\binstall\b|\bchmod\b|\bchown\b|\bsed\s+(-[A-Za-z]*i|--in-place)|\bperl\b|\bpython3?\b|\bnode\b|\bbun\b|\bdd\b|\brsync\b|\btruncate\b|\bpatch\b|\bunzip\b|\btar\b|\bgit\s+(checkout|restore|apply|am|mv|rm|clone|init|worktree)\b|\bcurl\b|\bwget\b/

function shellWriteToGuardDenied(cmd: string): string | null {
  if (!PROTECTED_IN_SHELL.test(cmd)) return null
  const noBenignRedirects = cmd.replace(/\d?>&\d|&?>+\s*\/dev\/null/g, "")
  if (/>/.test(noBenignRedirects) || SHELL_WRITES.test(cmd))
    return deny(
      "Blocked: this shell command names a guard or instruction file (.opencode/, opencode.json, AGENTS.md, CLAUDE.md, OpenCode's config dir, /app/config) together with a write. Those files are never writable from a session. Reading them is fine.",
    )
  return null
}

// ---------------------------------------------------------------------------
// Security tool target allowlist (from security-target-allowlist.sh)
// ---------------------------------------------------------------------------

function stripUrlToHost(s: string): string {
  return s.replace(/^https?:\/\//, "").split("/")[0]
}

function extractSecurityTarget(cmd: string): string | null {
  let m: RegExpMatchArray | null
  if (/\bnmap\b/.test(cmd)) {
    const c = cmd.split(/\s+/).filter((t) => t !== "nmap" && !t.startsWith("-") && !/^\d+$/.test(t))
    if (c.length) return c[c.length - 1]
  }
  if ((m = cmd.match(/\bsubfinder\b.*?-d\s+(\S+)/))) return m[1]
  if ((m = cmd.match(/\bhttpx\b.*?-u\s+(\S+)/))) return stripUrlToHost(m[1])
  if ((m = cmd.match(/\bnaabu\b.*?-host\s+(\S+)/))) return m[1]
  if (/\btrufflehog\b/.test(cmd) || /\bgitleaks\b/.test(cmd)) {
    m = cmd.match(/https?:\/\/(\S+)/)
    return m ? stripUrlToHost(m[1]) : null
  }
  if ((m = cmd.match(/\btrivy\b.*?\bimage\b\s+(\S+)/))) {
    const registry = m[1].split("/")[0]
    return registry.includes(".") ? registry : null
  }
  if ((m = cmd.match(/\bnuclei\b.*?-u\s+(\S+)/))) return stripUrlToHost(m[1])
  if (/(@keygraph\/shannon|[/\s]shannon\b)/.test(cmd)) {
    m = cmd.match(/-u\s+(\S+)/)
    if (m) return stripUrlToHost(m[1])
  }
  return null
}

// ---------------------------------------------------------------------------
// SiYuan read-only guard (Jill) - default deny with an explicit read list.
// Inventory verified against siyuan-mcp@1.0.4 (pinned in mcp/package.json).
// ---------------------------------------------------------------------------

const SIYUAN_TOOL_PREFIX = /^siyuan[a-z0-9-]*_/i
const SIYUAN_READ_ALLOW =
  /^(sql_query|get_[a-z0-9_]+|list_[a-z0-9_]+|export_md_content|read_dir|check_siyuan_status|render_sprig|render_template)$/

export function siyuanWriteDenied(tool: string): boolean {
  if (!SIYUAN_TOOL_PREFIX.test(tool)) return false
  return !SIYUAN_READ_ALLOW.test(tool.replace(SIYUAN_TOOL_PREFIX, ""))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function str(v: unknown): string {
  return typeof v === "string" ? v : v === undefined || v === null ? "" : String(v)
}

export function bashDenied(cmd: string, ctx: GuardContext): string | null {
  const checks = [
    () => shellWriteToGuardDenied(cmd),
    () => secretBashDenied(cmd),
    () => rmDenied(cmd, ctx),
    () => gitDenied(cmd),
    () => httpDenied(cmd, ctx),
  ]
  for (const c of checks) {
    const r = c()
    if (r) return r
  }
  for (const seg of segments(cmd)) {
    const cw = commandWord(tokens(seg))
    if (cw && MAIL_CLIS.has(cw.word)) return deny("Blocked: sending email via a CLI mailer is not allowed.")
  }
  if (SQL_DESTRUCTIVE.test(cmd) && !PREVIEW_DB.test(cmd))
    return deny("Blocked: destructive SQL operation detected. Schema changes require Sean's approval.")
  if (/(^|[;&|`( ])wacli\b/.test(cmd) || /whatsapp/i.test(cmd))
    return deny("Blocked: WhatsApp access is off-limits to Jill.")
  for (const rule of DM_URL_RULES) if (rule.pattern.test(cmd)) return deny(rule.reason)
  const target = extractSecurityTarget(cmd)
  if (target) {
    const al = ctx.config?.securityTargets
    if (!al || !al.length) return deny("Refused: config/security-allowlist.json not found or empty. Cannot authorize scan.")
    const t = target.toLowerCase().replace(/\.$/, "")
    if (!al.some((e) => t === e || t.endsWith("." + e)))
      return deny(`Refused: target "${target}" is not on Sean's authorized allowlist (config/security-allowlist.json).`)
  }
  return null
}

export function evaluate(tool: string, args: Record<string, unknown>, ctx: GuardContext): string | null {
  if (tool === "bash") {
    const wd = str(args.workdir)
    return bashDenied(str(args.command), wd ? { ...ctx, directory: path.resolve(ctx.directory, wd) } : ctx)
  }

  if (tool === "write" || tool === "edit") return writeDenied(str(args.filePath ?? args.file_path), ctx)
  if (tool === "apply_patch" || tool === "patch") {
    const paths = patchPaths(str(args.patchText ?? args.patch_text))
    if (!paths.length) return deny("Blocked: patch with no file headers; its targets cannot be checked.")
    for (const p of paths) {
      const r = writeDenied(p, ctx)
      if (r) return r
    }
    return null
  }

  if (tool === "read") {
    const p = str(args.filePath ?? args.file_path)
    if (isSecretPath(p) || isSecretPath(path.resolve(ctx.directory, p)))
      return deny(`secret-print-guard: reading ${p} would put secret values in the transcript.`)
    return null
  }
  if (tool === "grep") {
    const p = str(args.path)
    const inc = str(args.include)
    if ((p && isSecretPath(p)) || (inc && /\.env|auth\.json|\.pem|\.key|credentials|environ/.test(inc)))
      return deny("secret-print-guard: grepping secret-bearing files prints their values.")
    if (p && /^\/proc(\/|$)/.test(path.resolve(ctx.directory, p)))
      return deny("secret-print-guard: grepping /proc reads process environments.")
    return null
  }

  const urlArg = str(args.url)
  if (urlArg && (tool === "webfetch" || /browser_navigate/.test(tool))) {
    const u = parseUrl(urlArg)
    if (!u || servesOpencodeApi(u)) return deny("Blocked: tools may not call the OpenCode server API or loopback.")
    for (const rule of DM_URL_RULES) if (rule.pattern.test(urlArg)) return deny(rule.reason)
  }

  if (/agentmail/i.test(tool) && /send|reply|forward/i.test(tool)) {
    if (/reply|forward/i.test(tool) || /draft/i.test(tool))
      return deny("Blocked: AgentMail reply, forward and draft-send cannot be checked. Jill may send only to Sean.")
    const payload = JSON.stringify({ to: args.to, cc: args.cc, bcc: args.bcc })
    return agentmailSendDenied("/send", [payload], ctx.config?.agentmailRecipients ?? [])
  }

  if (/merge_pull_request$/.test(tool)) return deny("Blocked: Jill cannot merge pull requests. Sean merges.")
  if (/delete_repository$/.test(tool)) return deny("Blocked: repository deletion is prohibited.")

  if (siyuanWriteDenied(tool))
    return deny(
      "Blocked: SiYuan writes are gated for Jill; read-only access only. Allowed: sql_query, get_*, list_*, export_md_content, read_dir, check_siyuan_status, render_sprig, render_template.",
    )

  return null
}

/** Environment variables blanked in every tool shell (shell.env hook). */
export function shellEnvOverrides(env: Record<string, string | undefined>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const k of Object.keys(env)) if (isSecretVarName(k)) out[k] = ""
  return out
}
