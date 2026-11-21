/**
 * nodump.ts - make the OpenCode server process non-dumpable (#51, red-team
 * round 7 round 3, R3-1).
 *
 * Tool shells run as the server's uid, so a text rule in the bash guard is
 * the only thing between them and /proc/<server pid>/environ, and a variable
 * plus a glob (`d=/pro; ${d}c/[0-9]*\/en?iron`) gets past any text rule.
 * prctl(PR_SET_DUMPABLE, 0) makes the kernel hand the server's /proc files
 * that matter (environ, mem, maps, fd) to root, mode 0400, so a same-uid
 * process cannot read them in any spelling. The flag is per process and an
 * execve resets it, so it covers the server and not the shells it starts.
 * It does not hide cmdline, which is world-readable by design.
 *
 * OpenCode is a Bun binary, so this uses bun:ffi. Loaded with a dynamic
 * import so Node (the unit tests) never touches it. Throws on failure: the
 * guard plugin then fails to load and the boot self-test refuses to serve.
 */

const PR_SET_DUMPABLE = 4
const PR_GET_DUMPABLE = 3

export async function makeNonDumpable(): Promise<void> {
  if (process.platform !== "linux") return
  const ffi = await import("bun:ffi")
  const { dlopen, FFIType } = ffi as unknown as {
    dlopen: (name: string, symbols: Record<string, { args: unknown[]; returns: unknown }>) => {
      symbols: { prctl: (...a: Array<number | bigint>) => number }
    }
    FFIType: Record<string, unknown>
  }
  const t = FFIType
  const lib = dlopen("libc.so.6", {
    prctl: { args: [t.i32, t.u64, t.u64, t.u64, t.u64], returns: t.i32 },
  })
  if (lib.symbols.prctl(PR_SET_DUMPABLE, 0n, 0n, 0n, 0n) !== 0) throw new Error("[guardrails] prctl(PR_SET_DUMPABLE, 0) failed")
  if (lib.symbols.prctl(PR_GET_DUMPABLE, 0n, 0n, 0n, 0n) !== 0) throw new Error("[guardrails] the server is still dumpable")
}
