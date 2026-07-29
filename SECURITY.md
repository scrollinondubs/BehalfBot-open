# Security policy

## Reporting a vulnerability

**Do not open a public issue.** A public issue discloses the problem to everyone
at the same moment, including anyone who would use it.

Use GitHub's private vulnerability reporting instead:

**[Report a vulnerability](https://github.com/scrollinondubs/BehalfBot-open/security/advisories/new)**

It is enabled on this repo. The report stays visible only to the maintainer until
a fix is ready, and it gives us a private thread to ask questions in.

Expect a first response within a few days. Small project, one maintainer - please
do not read silence as dismissal. If a week passes with nothing, nudge by opening
a public issue that says only "I filed a private report, please look", with no
detail in it.

## Scope note: this is a proof of concept

BehalfBot-open is a port of the Behalf.bot chassis onto the OpenCode harness, and
the README is honest that parts of it are scaffolding. Please do not spend your
time enumerating things that are simply unfinished. A missing feature is not a
vulnerability.

**If the flaw is in the chassis rather than the port**, report it against
[`scrollinondubs/behalfbot`](https://github.com/scrollinondubs/behalfbot/security/advisories/new)
instead - that is where the fix lands and where other installs pick it up.

## What is in scope

This project runs an always-on agent with broad access on someone's own machine,
so the interesting failures are about **the boundary between untrusted input and
privileged action** rather than memory safety.

Particularly wanted:

- **Prompt injection that reaches a privileged action.** The agent reads email,
  web pages, chat messages and documents, all attacker-controlled. Getting it to
  *say* something silly is a curiosity. Getting it to send, delete, push, spend
  or exfiltrate is a vulnerability.
- **A way around the plugin hook layer.** OpenCode's `tool.execute.before/after`
  hooks are this port's analog of the Claude Code PreToolUse guardrails. A
  command shape that reaches a blocked action anyway is the highest-value report
  here.
- **Credential exposure**, including anything that puts a key into a prompt sent
  to a model provider. This repo routes to third-party and local inference
  endpoints, so "which provider just received that string" is a live question in
  a way it is not upstream.
- **Privilege escalation across the install boundary** - a component reaching
  data or credentials outside its declared scope.
- **Anything that lets a third party reach an installed agent** without the
  operator's involvement.

## What is out of scope

- Unimplemented functionality. See the MVP status table in the README.
- Findings that require an attacker to already have shell access on the machine
  running the agent. At that point they have everything.
- Missing hardening with no exploit path attached, particularly automated scanner
  output pasted verbatim.
- Vulnerabilities in OpenCode itself, or in any model provider. Report those to
  their maintainers; we will happily take a PR bumping a pinned version.
- Social engineering of the maintainer.

## Disclosure

We would rather fix it and credit you than argue about a timeline. Tell us what
schedule you are working to and we will try to meet it. If you would like credit,
say so and how you want to be named.
