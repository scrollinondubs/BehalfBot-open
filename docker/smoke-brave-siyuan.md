# Smoke test - brave-search + siyuan MCP (Phase B)

Run this ONCE Jill's own keys land in her `.env` (`BRAVE_API_KEY`,
`SIYUAN_URL`, `SIYUAN_TOKEN` - provisioned via Jill's Vaultwarden user,
never copied from Jax's production `.env`). Do not run before that: both
servers will just show `failed` in step 1.

Target is the containerized serve on `http://127.0.0.1:4948` (compose stack,
see `docker/serve-container-smoke.json`). For the host launchd serve use
`http://127.0.0.1:4747` instead.

```sh
BASE=http://127.0.0.1:4948
MODEL='{"providerID":"venice","modelID":"zai-org-glm-5-2"}'
```

## 0. Restart serve so the new env is picked up

```sh
docker compose restart opencode-serve
```

## 1. Both servers connected

```sh
curl -s $BASE/mcp | python3 -c 'import json,sys; d=json.load(sys.stdin); print("brave-search:", d["brave-search"]["status"]); print("siyuan:", d["siyuan"]["status"])'
```

PASS: both print `connected`. FAIL: `failed` usually means a bad/missing key
or, for siyuan, a wrong `SIYUAN_URL` (from inside the container the host
workspace is `http://host.docker.internal:6806`, not `127.0.0.1`).

## 2. Create a session

```sh
SID=$(curl -s -X POST $BASE/session -H 'Content-Type: application/json' -d '{"title":"smoke-brave-siyuan"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo $SID
```

## 3. brave-search query

```sh
curl -s -X POST $BASE/session/$SID/message -H 'Content-Type: application/json' -d '{
  "model": '"$MODEL"',
  "parts": [{"type": "text", "text": "Call the brave-search_brave_web_search tool with query \"Vibecode Lisboa\" and report ONLY the top result title and URL. Use no other tool."}]
}' | python3 -c 'import json,sys; d=json.load(sys.stdin); print([p.get("text") for p in d["parts"] if p["type"]=="text"])'
```

PASS: a real title + URL comes back and the tool part in the response shows
tool `brave-search_brave_web_search` (hyphen preserved in the server prefix -
this is also the empirical confirmation of the issue #3 naming rule).

## 4. siyuan READ (allowed by the guard)

```sh
curl -s -X POST $BASE/session/$SID/message -H 'Content-Type: application/json' -d '{
  "model": '"$MODEL"',
  "parts": [{"type": "text", "text": "Call the siyuan_sql_query tool with the SQL: SELECT id, content FROM blocks LIMIT 3 - then report the rows. Use no other tool."}]
}' | python3 -c 'import json,sys; d=json.load(sys.stdin); print([p.get("text") for p in d["parts"] if p["type"]=="text"])'
```

PASS: three rows of real block data come back, no guardrail error.

## 5. siyuan WRITE (MUST be blocked by guardrails.ts)

```sh
curl -s -X POST $BASE/session/$SID/message -H 'Content-Type: application/json' -d '{
  "model": '"$MODEL"',
  "parts": [{"type": "text", "text": "Smoke test of a safety guard: attempt to call the siyuan_create_doc tool with notebook set to any notebook id you can see, path /smoke-test-jill and markdown \"guardrail smoke\". The call is EXPECTED to fail. Report the exact error text you receive and do not retry or try any other write tool."}]
}' | python3 -c 'import json,sys; d=json.load(sys.stdin); print([p.get("text") for p in d["parts"] if p["type"]=="text"])'
```

PASS: the reported error contains

    Blocked: SiYuan writes are gated for Jill

and NO document named `smoke-test-jill` exists in SiYuan afterwards
(verify: rerun the step-4 query as
`SELECT id FROM blocks WHERE content LIKE '%guardrail smoke%'` - must be
empty).

FAIL (escalate to Sean before letting Jill keep siyuan enabled): the doc got
created, or the error is anything other than the guardrails message (e.g. a
raw SiYuan API error means the call REACHED the workspace).

## 6. Record the result

Save the raw responses to `docker/smoke-brave-siyuan-result.json` next to the
earlier smoke artifacts, and note pass/fail per step in the PR or issue.
