/**
 * guardrails.test.ts - unit tests for the SiYuan read-only guard (Phase B).
 *
 * No test framework in this repo; uses node's built-in runner. Run with:
 *
 *   cd .opencode/plugins
 *   node --experimental-strip-types --test guardrails.test.ts
 *
 * (node >= 22.6; the repo's Docker image is node:22.)
 */

import { test } from "node:test"
import assert from "node:assert/strict"
import { GuardrailsPlugin, siyuanWriteDenied } from "./guardrails.ts"

// Tool names as opencode v1.17.13 exposes them: sanitize(server) + "_" +
// sanitize(tool), hyphens and case preserved (see guardrails.ts header).

const SIYUAN_MUTATING = [
  "create_doc",
  "create_notebook",
  "insert_block",
  "prepend_block",
  "append_block",
  "update_block",
  "delete_block",
  "move_block",
  "move_docs",
  "move_docs_by_id",
  "set_block_attrs",
  "put_file",
  "remove_file",
  "remove_doc",
  "remove_doc_by_id",
  "rename_doc",
  "rename_doc_by_id",
  "rename_file",
  "rename_notebook",
  "remove_notebook",
  "upload_asset",
  "transfer_block_ref",
  "flush_transaction",
  // default-deny extras (state-changing or server-side file writers)
  "open_notebook",
  "close_notebook",
  "set_notebook_conf",
  "fold_block",
  "unfold_block",
  "push_msg",
  "push_err_msg",
  "export_resources",
  "pandoc_convert",
]

const SIYUAN_READONLY = [
  "sql_query",
  "get_block_attrs",
  "get_block_kramdown",
  "get_child_blocks",
  "get_file",
  "get_hpath_by_id",
  "get_hpath_by_path",
  "get_ids_by_hpath",
  "get_notebook_conf",
  "get_path_by_id",
  "get_version",
  "get_workspace_info",
  "get_boot_progress",
  "get_current_time",
  "list_notebooks",
  "export_md_content",
  "read_dir",
  "check_siyuan_status",
  "render_sprig",
  "render_template",
]

test("siyuanWriteDenied blocks every mutating siyuan tool", () => {
  for (const t of SIYUAN_MUTATING) {
    assert.equal(siyuanWriteDenied(`siyuan_${t}`), true, `siyuan_${t} must be denied`)
  }
})

test("siyuanWriteDenied allows every read/query siyuan tool", () => {
  for (const t of SIYUAN_READONLY) {
    assert.equal(siyuanWriteDenied(`siyuan_${t}`), false, `siyuan_${t} must be allowed`)
  }
})

test("siyuanWriteDenied fails closed on unknown siyuan tools", () => {
  assert.equal(siyuanWriteDenied("siyuan_some_future_tool"), true)
})

test("siyuanWriteDenied ignores non-siyuan tools", () => {
  for (const t of ["bash", "webfetch", "memory_create_entities", "brave-search_brave_web_search", "turso_execute_query"]) {
    assert.equal(siyuanWriteDenied(t), false, `${t} must not trip the siyuan guard`)
  }
})

test("plugin hook throws on a siyuan mutate and passes a siyuan read", async () => {
  const hooks = await GuardrailsPlugin({ worktree: process.cwd() } as never)
  const before = hooks["tool.execute.before"]!

  await assert.rejects(
    () =>
      before(
        { tool: "siyuan_create_doc", sessionID: "s", callID: "c" },
        { args: { notebook: "x", path: "/inbox", markdown: "hi" } },
      ),
    /SiYuan writes are gated for Jill/,
  )

  // read passes (no throw)
  await before(
    { tool: "siyuan_sql_query", sessionID: "s", callID: "c" },
    { args: { query: "SELECT id FROM blocks LIMIT 1" } },
  )

  // brave-search tools pass untouched (hyphenated server prefix)
  await before(
    { tool: "brave-search_brave_web_search", sessionID: "s", callID: "c" },
    { args: { query: "vibecode lisboa" } },
  )
})
