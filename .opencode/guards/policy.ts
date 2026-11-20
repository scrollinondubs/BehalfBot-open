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
export function segments(cmd: string, keepPipes = false): string[] {
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
    if (c === "|" && keepPipes) {
      if (cmd[i + 1] === "|") {
        i++
        push()
      } else cur += c
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

/** Split one simple command on unquoted single pipes. */
function pipeline(seg: string): string[] {
  const out: string[] = []
  let cur = ""
  let q: string | null = null
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i]
    if (q) {
      if (c === q) q = null
      cur += c
      continue
    }
    if (c === "'" || c === '"') q = c
    if (c === "|" && !q) {
      out.push(cur.trim())
      cur = ""
      continue
    }
    cur += c
  }
  out.push(cur.trim())
  return out.filter(Boolean)
}

/** The command line with quoted text blanked out, for structural checks. */
function unquoted(cmd: string): string {
  let out = ""
  let q: string | null = null
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]
    if (q) {
      if (c === q) q = null
      out += c === q || q === null ? c : " "
      continue
    }
    if (c === "\\" && i + 1 < cmd.length) {
      out += "  "
      i++
      continue
    }
    if (c === "'" || c === '"') q = c
    out += c
  }
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

const SHELL_KEYWORDS = new Set(["if", "then", "else", "elif", "fi", "do", "done", "while", "until", "for", "case", "esac", "!", "{", "}", "time", "select", "coproc"])

// Commands that run another command: options that take a value, and how many
// positional arguments they consume before the wrapped command starts.
const WRAPPERS: Record<string, { valued: string[]; positionals: number }> = {
  sudo: { valued: ["-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "-D"], positionals: 0 },
  doas: { valued: ["-u", "-C"], positionals: 0 },
  env: { valued: ["-u", "--unset", "-C", "--chdir"], positionals: 0 },
  nice: { valued: ["-n", "--adjustment"], positionals: 0 },
  ionice: { valued: ["-c", "-n", "-p", "-t", "--class", "--classdata"], positionals: 0 },
  timeout: { valued: ["-s", "--signal", "-k", "--kill-after"], positionals: 1 },
  stdbuf: { valued: ["-i", "-o", "-e"], positionals: 0 },
  xargs: { valued: ["-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file", "--replace"], positionals: 0 },
  watch: { valued: ["-n", "--interval"], positionals: 0 },
  flock: { valued: ["-w", "--timeout", "-E"], positionals: 1 },
  exec: { valued: ["-a"], positionals: 0 },
  nohup: { valued: [], positionals: 0 },
  setsid: { valued: [], positionals: 0 },
  command: { valued: [], positionals: 0 },
  builtin: { valued: [], positionals: 0 },
  chronic: { valued: [], positionals: 0 },
  unbuffer: { valued: [], positionals: 0 },
  caffeinate: { valued: ["-t", "-w"], positionals: 0 },
}

const base = (t: string) => t.split("/").pop() ?? t

/**
 * The command a simple command actually runs: shell keywords, VAR=x
 * assignments and wrapper commands (sudo, env, timeout, nice, xargs, ...)
 * with their options are skipped. A bare wrapper (`env`) is its own command.
 */
function commandWord(toks: string[]): { word: string; index: number; viaXargs: boolean } | null {
  let viaXargs = false
  let lastWrapper: { word: string; index: number } | null = null
  let i = 0
  while (i < toks.length) {
    const t = toks[i]
    if (SHELL_KEYWORDS.has(t) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
      i++
      continue
    }
    const b = base(t)
    const w = WRAPPERS[b]
    if (!w) return { word: b, index: i, viaXargs }
    if (b === "xargs") viaXargs = true
    lastWrapper = { word: b, index: i }
    i++
    while (i < toks.length && toks[i].startsWith("-") && toks[i] !== "-") {
      if (w.valued.includes(toks[i])) i++
      i++
    }
    for (let p = 0; p < w.positionals && i < toks.length; p++) i++
  }
  return lastWrapper ? { ...lastWrapper, viaXargs } : null
}

/**
 * Index of the first token that runs one of `names`: the effective command
 * if it matches, else any later token with that basename (an unknown wrapper,
 * `find -exec`, and so on). Conservative: `echo rm -rf ~` counts as rm.
 */
function findCommand(toks: string[], names: Set<string>): { word: string; index: number; viaXargs: boolean } | null {
  const cw = commandWord(toks)
  if (cw && names.has(cw.word)) return cw
  const start = cw ? cw.index + 1 : 0
  for (let i = start; i < toks.length; i++) if (names.has(base(toks[i]))) return { word: base(toks[i]), index: i, viaXargs: !!cw?.viaXargs || toks.slice(0, i).some((t) => base(t) === "xargs") }
  return null
}

// ---------------------------------------------------------------------------
// Recursive delete (ported from the reference install, new-jaxity#526)
// ---------------------------------------------------------------------------

const RM = new Set(["rm", "rmdir", "unlink", "shred"])

function rmDenied(cmd: string, ctx: GuardContext): string | null {
  for (const seg of segments(cmd)) {
    const toks = tokens(seg)
    const cw = findCommand(toks, RM)
    if (!cw) continue
    if (toks.slice(0, cw.index).some((t) => base(t) === "sudo" || base(t) === "doas"))
      return deny("Blocked: sudo rm is prohibited. Use 'trash', or ask Sean.")
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
        if (a === "--recursive" || /^-[A-Za-z]*[rR]/.test(a) || cw.word === "shred") recursive = true
        continue
      }
      operands.push(a)
    }
    if (!recursive) continue
    if (cw.viaXargs || operands.length === 0)
      return deny("Blocked: recursive delete whose targets come from stdin cannot be checked. Expand the paths, or use 'trash'.")
    // The raw segment (pre-tokenising) shows expansions the tokenizer kept as text.
    for (const raw of operands) {
      if (raw === "+" || raw === ";") continue
      if (/[$`]|\{\}/.test(raw))
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

const GIT = new Set(["git"])

function gitDenied(cmd: string): string | null {
  for (const seg of segments(cmd)) {
    const toks = tokens(seg)
    const cw = findCommand(toks, GIT)
    if (!cw) continue
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
      if (after.some((t) => /:\/\//.test(t) || /^[^\s/]+@[^\s/]+:/.test(t) || /^(\.{0,2}\/|\/)/.test(t)))
        return deny("Blocked: git push to a URL or path remote. Push only to a configured named remote.")
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
  if (/\/proc\b/.test(cmd) && /envi|cmdl|\/proc\/[^\s]*[*?[]/.test(cmd))
    return deny("secret-print-guard: reading another process's environment or command line prints its secrets. Name the one variable you need instead.")
  for (const seg of segments(cmd, true)) {
    const s = seg
    const pipes = pipeline(s)
    const first = pipes[0] ?? ""
    const rest = pipes.slice(1).join("|")
    const namesOnly = /(^|\s)(wc|cut\s+-d\s*=?\s*-f\s*1|cut\s+-d=\s+-f1)\b|grep\s+-[A-Za-z]*[clq]/.test(rest)
    {
      const t = tokens(first)
      const c = commandWord(t)
      const a = c ? t.slice(c.index + 1) : []
      const dump =
        !!c &&
        (((c.word === "env" || c.word === "printenv") && a.filter((x) => !x.startsWith("-")).length === 0) ||
          (c.word === "export" && a.includes("-p")) ||
          (c.word === "set" && a.length === 0) ||
          (c.word === "declare" && a.some((x) => /^-[A-Za-z]*[xp]/.test(x))) ||
          (c.word === "compgen" && a.includes("-v")))
      if (dump && !namesOnly)
        return deny("secret-print-guard: dumping the environment prints every secret in it. List names only (env | cut -d= -f1).")
    }
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
    if (/<\s*\S/.test(first) && cw) {
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

const HTTP_CLIENTS = new Set(["curl", "wget"])

type HttpCall = { tool: string; urls: string[]; mutating: boolean; data: string[]; redirecting: boolean }

function httpCalls(cmd: string): HttpCall[] {
  const calls: HttpCall[] = []
  for (const seg of segments(cmd)) {
    const toks = tokens(seg)
    const cw = findCommand(toks, HTTP_CLIENTS) ?? commandWord(toks)
    if (!cw) continue
    const args = toks.slice(cw.index + 1)
    if (cw.word === "curl") {
      const call: HttpCall = { tool: "curl", urls: [], mutating: false, data: [], redirecting: false }
      const take = (f: string, value: string | undefined, raw: string) => {
        if (f === "-X" || f === "--request") {
          if (value === undefined || !/^(GET|HEAD|OPTIONS)$/i.test(value)) call.mutating = true
        } else if (CURL_DATA_FLAGS.has(f)) {
          call.mutating = true
          if (value !== undefined) call.data.push(value)
        } else if (REDIRECTING_FLAGS.has(f)) {
          call.redirecting = true
        } else if (f === "--url") {
          if (value) call.urls.push(value)
        } else if (!raw.startsWith("-")) {
          call.urls.push(raw)
        }
      }
      for (let i = 0; i < args.length; i++) {
        const a = args[i]
        if (a.startsWith("--")) {
          const eq = a.indexOf("=")
          const f = eq > 0 ? a.slice(0, eq) : a
          const value = eq > 0 ? a.slice(eq + 1) : CURL_ARG_FLAGS.has(f) ? args[++i] : undefined
          take(f, value, a)
        } else if (a.startsWith("-") && a.length > 1) {
          // Short flags cluster (-sSX POST, -sd x, -XPOST): the first flag that
          // takes a value consumes the rest of the token, or the next token.
          for (let j = 1; j < a.length; j++) {
            const f = "-" + a[j]
            if (CURL_ARG_FLAGS.has(f)) {
              const restOf = a.slice(j + 1)
              take(f, restOf.length ? restOf : args[++i], f)
              break
            }
            take(f, undefined, f)
          }
        } else {
          take(a, undefined, a)
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

const AGENTMAIL_HOST = /(^|\.)agentmail\.to$|^agentmail-proxy$/i
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
  let p = pathname
  for (let i = 0; i < 5; i++) {
    let next = p
    try {
      next = decodeURIComponent(p)
    } catch {
      return deny("Blocked: AgentMail path with malformed percent-encoding.")
    }
    if (next === p) break
    p = next
  }
  p = p.toLowerCase()
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

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish", "su"])

/** Scripts a shell will run from this command line (sh -c, eval, env -S). */
function nestedScripts(cmd: string): string[] {
  const out: string[] = []
  for (const seg of segments(cmd)) {
    const toks = tokens(seg)
    for (let i = 0; i < toks.length; i++) {
      const b = base(toks[i])
      if (SHELLS.has(b)) {
        for (let j = i + 1; j < toks.length && toks[j].startsWith("-"); j++) {
          if (/^-[A-Za-z]*c[A-Za-z]*$/.test(toks[j]) && j + 1 < toks.length) out.push(toks[j + 1])
        }
      } else if (b === "eval") {
        out.push(toks.slice(i + 1).join(" "))
      } else if (b === "env" && (toks[i + 1] === "-S" || toks[i + 1] === "--split-string") && toks[i + 2]) {
        out.push(toks[i + 2])
      }
    }
  }
  return out
}

const SHELL_FROM_STDIN =
  /\|\s*(?:sudo\s+)?(?:\S*\/)?(?:ba|z|da|k|a|mk)?sh\b(?!\s+-[A-Za-z]*c)|\b(?:(?:ba|z|da|k|a|mk)?sh|source)\s+<[(<]|(?:^|[;&|]\s*)\.\s+<\(/

export function bashDenied(cmd: string, ctx: GuardContext, depth = 0): string | null {
  if (depth > 4) return deny("Blocked: shell scripts nested this deep cannot be checked.")
  if (SHELL_FROM_STDIN.test(unquoted(cmd)))
    return deny("Blocked: piping or feeding text into a shell hides the command from the guard. Run the command directly.")
  for (const inner of nestedScripts(cmd)) {
    const r = bashDenied(inner, ctx, depth + 1)
    if (r) return r
  }
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
  for (const k of Object.keys(env)) if (isSecretVarName(k) || /(^|_)proxy$|^CURL_HOME$|^CURLOPT/i.test(k)) out[k] = ""
  return out
}
