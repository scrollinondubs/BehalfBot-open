# Contributing to BehalfBot-open

Thanks for looking. This document exists so you know the bar before you spend a
weekend on something, and so a "no" from us is a link rather than an argument.

## Read this first: this is a proof of concept

BehalfBot-open is a **port**, not a product. It moves the Behalf.bot chassis from
Claude Code onto the [OpenCode](https://github.com/sst/opencode) harness, with an
env-gated path to open-weight models. The README's MVP table is the honest
status - some of this works, some of it is scaffolding.

Two consequences worth knowing before you write code:

- **Upstream is `scrollinondubs/behalfbot`.** If your change is really about the
  chassis rather than the port, it belongs there. A fix applied here that should
  have gone upstream gets reverted the next time the port re-syncs.
- **Harness-compatibility changes need a reason attached.** The port exists
  because OpenCode ships deliberate Claude Code compatibility - `AGENTS.md`,
  `SKILL.md` discovery, `opencode run --format json` as a near-1:1 replacement
  for `claude -p`. A change that drifts away from that compatibility surface
  needs to say what it buys.

## Licence and the sign-off

This repo is under the **O'Saasy Licence** (see [`LICENSE`](LICENSE)), which is
source-available rather than OSI-approved open source. That matters for
contributions: with MIT or Apache there is a well-understood convention that a
contribution arrives under the project's licence. There is no such convention
for a custom licence, so we ask for it explicitly.

We use the [Developer Certificate of Origin](https://developercertificate.org/).
**This is not a CLA.** No form, no signing ceremony, no copyright assignment -
you keep your copyright. It is one line in your commit message:

```
Signed-off-by: Your Name <your@email.com>
```

`git commit -s` adds it for you. It records that you wrote the change, or have
the right to submit it, and are submitting it under this project's licence.

CI checks it. If you forget:

```bash
git commit --amend -s --no-edit        # most recent commit
git rebase --signoff origin/main       # every commit on your branch
git push --force-with-lease
```

## Before you open a PR

**Open an issue first for anything non-trivial.** A typo fix or a clearly-scoped
bug fix can go straight to a PR. Anything that adds a dependency, changes the
bridge, or alters how the harness is invoked should start as an issue - partly
so it does not duplicate work, and partly because this repo is a moving target
and your change may already be planned differently.

## What CI will check

| Check | What it wants |
|---|---|
| `shellcheck` | Shell scripts pass at `severity: error` |
| `dco` | Every non-merge commit has a `Signed-off-by` line |

Both run on every PR regardless of what it touches, so a docs-only change still
gets a green tick rather than hanging on a check that never reports.

The shell bar is "contains no real bug", not "matches our style" - do not spend
time on lint preferences.

## What gets a PR declined

- A chassis change that belongs upstream in `scrollinondubs/behalfbot`
- Committed credentials, tokens, or install-specific values
- A new provider integration with no way to run it without paid credentials.
  Open-weight and local paths (Ollama, OpenRouter, Venice) are the point of this
  repo; something only testable with a proprietary key is a hard sell.
- Broad reformatting or style-only churn mixed into a functional change
- Drifting away from Claude Code compatibility without saying what it buys

## Security

**Do not open a public issue for a vulnerability.** See
[`SECURITY.md`](SECURITY.md) for the private disclosure channel.

## Review, and what to expect

Small project, one maintainer. Reviews are best-effort, not same-day. A PR that
sits for a few days has not been ignored.

An assistant does a first pass on inbound PRs - size, paths touched, CI state,
whether it duplicates earlier work - and surfaces a summary. **Every merge
decision is a human one.** Nothing is merged by a bot.
