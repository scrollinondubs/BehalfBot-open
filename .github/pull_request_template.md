<!--
Thanks for contributing. CONTRIBUTING.md has the full detail; this template is
just the shape a reviewer needs. Delete any section that does not apply rather
than writing "n/a" in it.
-->

## What this changes

<!-- One or two sentences. What is different after this merges? -->

## Why

<!-- The problem, not the patch. Link an issue if there is one - anything
non-trivial should have started as one. -->

## Does this belong here or upstream?

<!-- This repo is a PORT of scrollinondubs/behalfbot. If the change is really
about the chassis rather than the OpenCode port, it belongs upstream, and a fix
applied here gets reverted on the next re-sync. Say which it is and why. -->

## How it was verified

<!-- What you actually ran or observed, not what you expect to happen. If it
touches a provider path, say which provider and whether it can be exercised
without paid credentials. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`) - CI enforces this, see CONTRIBUTING.md
- [ ] No credentials, tokens, or install-specific values (names, channel IDs, home paths)
- [ ] This is a port-level change, not a chassis change that belongs upstream
- [ ] If it touches the harness interface, I said what the drift from Claude Code compatibility buys
- [ ] I read CONTRIBUTING.md's "what gets a PR declined" list

## Anything you are unsure about

<!-- Genuinely useful. Naming the part you are least confident in gets you a
better review than presenting it as finished. -->
