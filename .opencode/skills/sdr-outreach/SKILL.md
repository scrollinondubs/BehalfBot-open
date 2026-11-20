---
name: sdr-outreach
description: Activating leads (warm and cold) and drafting outreach emails. Use when Sean asks to nurture a lead, draft a follow-up, or activate a stale Build School / Confabulator / cohort signup. Drafts only - Sean approves before send. Ported from the Claude Code chassis skill on 2026-07-06.
---

# Skill: SDR / Lead Activation

Identify and activate leads in the Vibecode Lisboa funnel. Every outreach is a draft for Sean to approve - never sent autonomously.

## Who Jill handles vs Sean handles

| Jill handles | Sean handles |
|---|---|
| Individual course inquiries | Whale / partner-level prospects |
| Stale Confabulator signups | Grid7 investment conversations |
| Community members who engaged but did not convert | Corporate training proposals |
| Remote course inquiries | Any prospect with significant strategic value |

When in doubt, flag for Sean.

## Lead qualification - mandatory exclusion check

**If they have paid us, they are NOT a lead.** Before proposing anyone as a prospect, run this query against the `vibecodelisboa` Turso DB:

```sql
SELECT u.name, u.email,
  cp.status as purchase_status,
  bsa.status as app_status, bsa.paid_at,
  s.status as sub_status
FROM users u
LEFT JOIN content_purchases cp ON u.id = cp.user_id AND cp.status = 'completed'
LEFT JOIN build_school_applications bsa ON u.id = bsa.user_id AND bsa.paid_at IS NOT NULL
LEFT JOIN subscriptions s ON u.id = s.user_id AND s.status IN ('active', 'trialing')
WHERE u.email = '<lead_email>'
  AND u.email_bounced_at IS NULL
  AND u.nurture_opted_out = 0
```

**Exclude if ANY of these are true:**
- `purchase_status = 'completed'` - bought content
- `bsa.paid_at IS NOT NULL` - paid for Build School (current or alumni)
- `sub_status IN ('active', 'trialing')` - has a subscription
- `email_bounced_at IS NOT NULL` - email bounced (bad address)
- `nurture_opted_out = 1` - user opted out of emails

Run this for every candidate. No exceptions. Batch-check all candidates before building the prospect list.

> **Requires capability grant (deferred).** The Turso MCP (`turso`) is the customer production DB and is DISABLED for Jill until trust is built. Every step below that reads or writes Turso - the exclusion check, lead sourcing, cohort availability, and outreach logging - cannot run until Sean grants the Turso capability. Do not fabricate query results or proceed on an unverified prospect list. If asked to run outreach today, stop at this gate and tell Sean the Turso grant is the blocker.

## Lead sources

1. **Turso DB** (`vibecodelisboa`) - **requires capability grant (deferred), MCP disabled.** Query for:
   - Confabulator users who signed up >14 days ago with no course enrollment
   - Users who started Claude Code 101 checkout but did not complete
   - Community members who attended a meetup but are not in any course
2. **Memory** - check for leads with `status: needs-follow-up` (memory MCP is available to Jill)
3. **GitHub issue** - Sean may provide a specific list

All candidates from every source must pass the exclusion check before being proposed.

## Step 1 - Research the lead

1. Check memory for prior context (`lead:firstname-lastname`)
2. Check Turso for their activity history - **requires capability grant (deferred)**
3. Quick web search for professional context (LinkedIn) if no prior info - **requires capability grant (deferred): brave-search / tavily are staged but disabled (owned by a separate open PR)**

Update memory with current status and any new context found.

## Step 2 - Draft the outreach

Principles:
- **One clear ask** per message - never combine multiple CTAs
- **Acknowledge what they did** - reference the specific thing they engaged with
- **Low pressure** - the goal is a reply, not a sale
- **Short** - under 150 words
- **Plain** - no marketing language, no emojis. Run the draft through the `brand-voice` skill.
- **Human-sounding** - after brand-voice, strip AI tells (em dashes, synonym cycling, filler phrases)
- **From Jill** - drafts only, from `jill-agent@agentmail.to`. Sign off as `Jill / Sean's assistant`. Never sign as Sean, and never send: the AgentMail gate only lets mail go to Sean.
- **Check cohort availability** - before mentioning Build School, query Turso for the next upcoming cohort (start date in the future) and open spots. Only mention it if signups are actually open with available space. Reference the correct cohort number and start date. Never mention a cohort already in progress. **Requires capability grant (deferred): Turso.**

Templates:

*Confabulator user, no course purchase:*
Subject: Quick question about your project
Body: Reference the tool -> Ask if they got unstuck -> Mention Claude Code 101 naturally if relevant

*Course inquiry (no purchase):*
Subject: Re: [their original inquiry topic]
Body: Revisit their question -> Give a useful answer -> Make the ask

*Stale community member:*
Subject: [Something specific to last meetup or recent Vibecode news]
Body: Personal note -> What's coming up -> Soft invite

## Step 3 - Deliver for review

- **In morning briefing:** drafts are embedded in the Top Build School Prospects section, numbered. Sean replies `approve N`.
- **Standalone outreach:** post drafts to the leads channel with numbered format. Sean replies `approve N`.

> **Requires capability grant (deferred).** Email sending goes through Gmail draft-only in the chassis; Jill has no email or channel-delivery MCP enabled yet. Deliver drafts as text in your report to the main session until Sean grants an outbound channel. Never send human-facing email autonomously under any grant.

In all cases, update memory: `lead:<name>` -> observation: `outreach drafted, pending Sean approval, [date]`

## Step 4 - After Sean approves

- Update memory: `lead:<name>` -> observation: `outreach sent [date], awaiting reply`
- Log to `users.last_outreach_at` and the `email_outreach_log` table - **requires capability grant (deferred): Turso.**

## Volume

Default: no more than 5 drafts per session. Quality over quantity.

## Ported-skill capability summary

| Step | Chassis dependency | Status in Jill |
|---|---|---|
| Exclusion check, lead sourcing, cohort check, outreach logging | `turso` MCP (customer prod DB) | Requires capability grant (deferred) - MCP disabled |
| Web research on a lead | `brave-search` / `tavily` | Requires capability grant (deferred) - staged, owned by a separate open PR |
| Draft delivery / send | Gmail draft-only + channel delivery | Requires capability grant (deferred) - no MCP enabled |
| Prior-context lookup, status tracking | `memory` MCP | Available |
| Voice / humanizing | `brand-voice` skill | Available (ported) |
