---
name: content-research
description: Researching topics and writing blog stubs for the Vibecode Lisboa content engine. Use when Sean asks for a topic brief, content radar, or a stubbed blog post. Ported from the Claude Code chassis skill on 2026-07-06.
---

# Skill: Content Research and Blog Stub

Produce a blog post stub ready for Sean to expand and publish on Substack (scrollinondubs). A stub is architecture, not prose - Sean writes the words.

## Trigger

A GitHub issue labeled `jax` requesting a blog post, or an autonomous session where content research is the assigned task.

## Step 1 - Check memory first

Search memory for `topic:<slug>` before doing new research. If prior research exists and is recent (<30 days), skip to Step 3. (Memory MCP is available to Jill.)

## Step 2 - Research the topic

Use web search to:
1. Find the 3-5 most relevant recent articles / discussions
2. Identify the **dominant narrative** (what everyone else is saying)
3. Identify a **contrarian or underexplored angle** - this is Sean's sweet spot
4. Find 2-3 concrete examples, data points, or stories to anchor the post
5. Check what Sean has already written: search `scrollinondubs.substack.com`

> **Requires capability grant (deferred).** The chassis does this with `brave-search` and `tavily`. Both are staged in Jill's `opencode.json` but DISABLED, and their enablement is owned by a separate open PR. Until then, Jill cannot do live topic research. If web search is unavailable, either work from material Sean provides in the prompt, or stop and tell Sean the search grant is the blocker. Do not invent sources, statistics, or "recent articles" - fabricated citations are a hard-limit violation.

Store in memory:
- Entity: `topic:<slug>`
- Observations: dominant narrative, Sean's angle, key sources, anchor examples, related prior posts, date

## Step 3 - Write the stub

A stub is NOT a full draft. It is a structured outline for Sean to work from. Read the `brand-voice` skill first - especially headline and hook style.

Format:
```
# [Working headline - specific and punchy]

**Angle:** [1-2 sentences on Sean's take - what makes this different]

**Hook:** [Scene, question, or surprising fact to open with]

## Section 1: [Subheading]
- Key point
- Supporting example or data

## Section 2: [Subheading]
- Key point
- Supporting example or data

## Section 3: [Conclusion]
- Main takeaway
- CTA or bridge to Vibecode Lisboa / Confabulator

**Suggested sources:** [URL + 1-line note each]

**Tone notes:** [Relevant guidance from the brand-voice skill]
```

## Step 4 - Add to the content pipeline

In the chassis, the stub is created as a sub-document under the **1 Researching** node in SiYuan, and content moves through five pipeline stages as sub-documents. Stages are identified by stable block ID, never by hardcoded hpath (folder names and hpaths get renamed or moved by Sean).

> **Requires capability grant (deferred).** The whole pipeline lives in the `siyuan` MCP, which is staged but DISABLED for Jill (enablement owned by a separate open PR). Until SiYuan is granted, deliver the stub as markdown text in your report to the main session (or write it to a file if Sean asks) rather than creating a SiYuan doc. The pipeline mechanics below are preserved so the port is faithful and re-activation is a one-step flip.

**Content pipeline stages** (chassis, parent block IDs stable, verified 2026-04-20):

| Stage | Parent block ID (stable) | When to move here |
|---|---|---|
| 1 Researching | `20260405100932-75nlyr4` | New research stub created |
| 2 Writing | `20260405101053-eako973` | Research turned into a blog post - move doc here, append the draft |
| 3 Published | `20260405101021-p1j0qbn` | Published on Substack - move doc here |
| 4 Draft Socials Created | `20260416180737-wlhswzt` | Social posts drafted for review - move doc here |
| 5 Promoted | `20260405101308-f6jxu52` | Promoted via social - move doc here, append a "Promoted" section with links |

Chassis mechanics (for when SiYuan is granted):
- Create the sub-document with `create_doc`. Query the `notebook` and parent `hpath` at runtime from the 1-Researching block ID (`SELECT box, hpath FROM blocks WHERE id = '20260405100932-75nlyr4'`), then append `/{Post Title}`. This survives rename and move.
- To list pipeline content, match the SiYuan `path` column against the stage IDs (`path LIKE '%/<stage_id>/' || id || '.sy'`). Do NOT use `parent_id` (empty for doc blocks) or `get_child_blocks` on a stage node (returns the stage's own paragraphs, a false-empty).
- To move a doc between stages, use `move_docs_by_id` with the doc block ID and target parent node ID.

Keep content in SiYuan where Sean reviews and expands it. Do NOT create GitHub issues for content stubs - GitHub is for software-development issues only.

If the task originated from a GitHub issue labeled `jax`, close that issue with a comment noting where the stub was delivered.

## Notes

- 1 stub per session unless tasked otherwise
- Prioritize topics connecting to Vibecode Lisboa's products (Claude Code, building with AI, community)
- Always read the `brand-voice` skill before writing
- Do not write a full post - Sean writes the prose, you prepare the architecture

## Ported-skill capability summary

| Step | Chassis dependency | Status in Jill |
|---|---|---|
| Live topic research | `brave-search` / `tavily` | Requires capability grant (deferred) - staged, owned by a separate open PR |
| Pipeline create / move / list | `siyuan` MCP | Requires capability grant (deferred) - staged, owned by a separate open PR |
| Prior-research lookup, storing findings | `memory` MCP | Available |
| Voice, headline, hook | `brand-voice` skill | Available (ported) |
