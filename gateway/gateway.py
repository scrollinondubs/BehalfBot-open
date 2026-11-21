#!/usr/bin/env python3
"""Egress and control gateways for Jill. Stdlib only.

One process per route, each in its own container (docker-compose.yml):

  venice     POST /api/v1/chat/completions: model on the private-model
             allowlist, request fields and venice parameters on allowlists,
             no remote media (image_url must be a data: URL); GET /api/v1/models
  agentmail  READ her inbox (threads, messages, drafts, attachments);
             CREATE / EDIT / DELETE drafts to anyone (no scheduling fields);
             SEND a draft only with Sean's one-shot approval of that draft as
             it is now (gateway/approvals.py); every other send path refused
  siyuan     read-only endpoints; SQL a single SELECT; file reads only inside
             notebook folders (/data/<notebook-id>/...)
  mcp        an HTTP MCP server on a private network (Brave), /mcp only
  fetch      GET exactly one URL Sean approved, once, not following
             redirects, never to a private address; POST /request records
             a URL Jill would like Sean to approve
  api        the opencode serve API, for the bridge and dispatcher only:
             basic auth, a route allowlist (no MCP registration, no shell,
             no PTY, no config writes, no upgrade)

Every JSON body is parsed strictly (duplicate keys refused, including
case variants, at every depth), validated, and RE-SERIALISED: the upstream
receives the checked object, never the caller's bytes. Paths are
percent-decoded until stable, checked, and re-encoded by this process.
Repeated security-relevant headers are refused. Bodies and headers are
never logged.
"""
import base64
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import approvals  # noqa: E402

MAX_BODY = 20 * 1024 * 1024
MAX_FETCH = 10 * 1024 * 1024
FWD_REQ_HEADERS = ("content-type", "accept", "mcp-session-id", "mcp-protocol-version", "last-event-id")
SINGLE_HEADERS = FWD_REQ_HEADERS + ("authorization", "content-length", "transfer-encoding", "host")
FWD_RESP_HEADERS = ("content-type", "cache-control", "mcp-session-id", "retry-after")
EMAIL = re.compile(r"^[^@\s<>,;]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class Deny(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class Forward:
    """What to send upstream after a policy approved the request."""

    def __init__(self, method, path, body=None, query=None, raw=None, after=None, release=None):
        self.method = method
        self.path = path
        self.body = body  # a validated Python object, re-serialised on send
        self.query = query or []
        self.raw = raw  # bytes, only for the trusted api route
        self.after = after  # called with (status, response bytes) before replying
        self.release = release  # called once the upstream exchange is over


class Local:
    """A response the gateway answers itself."""

    def __init__(self, status, obj):
        self.status = status
        self.obj = obj


# --- parsing ---------------------------------------------------------------

def canonical_path(raw):
    path = raw.split("?", 1)[0].split("#", 1)[0] or "/"
    for _ in range(5):
        nxt = unquote(path)
        if nxt == path:
            break
        path = nxt
    else:
        raise Deny(400, "path is encoded too many times")
    if not path.startswith("/") or "\\" in path or "//" in path or any(ord(c) < 0x21 for c in path):
        raise Deny(400, "malformed path")
    if any(seg in (".", "..") for seg in path.split("/")):
        raise Deny(400, "path traversal")
    return path


def _no_dupes(pairs):
    seen = set()
    for k, _ in pairs:
        low = k.lower()
        if low in seen:
            raise Deny(400, "duplicate or case-variant JSON key")
        seen.add(low)
    return dict(pairs)


def strict_json(body, allow_empty=False):
    if not body:
        if allow_empty:
            return {}
        raise Deny(400, "body required")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise Deny(400, "body must be UTF-8 JSON")
    if text.startswith("﻿"):
        raise Deny(400, "byte-order mark not accepted")
    try:
        data = json.loads(text, object_pairs_hook=_no_dupes)
    except Deny:
        raise
    except ValueError:
        raise Deny(400, "body is not JSON")
    if not isinstance(data, dict):
        raise Deny(400, "body must be a JSON object")
    return data


def only_keys(obj, allowed, what):
    if not isinstance(obj, dict):
        raise Deny(400, f"{what} must be an object")
    extra = sorted(k for k in obj if k not in allowed)
    if extra:
        raise Deny(403, f"{what} has fields this gateway does not allow: {', '.join(extra)}")


def query_pairs(raw, allowed):
    q = raw.split("?", 1)[1] if "?" in raw else ""
    pairs = parse_qsl(q, keep_blank_values=True)
    names = [k for k, _ in pairs]
    if len(set(names)) != len(names):
        raise Deny(400, "repeated query parameter")
    bad = [k for k in names if k not in allowed]
    if bad:
        raise Deny(403, "query parameter not allowed: " + ", ".join(sorted(bad)))
    return pairs


# --- venice ----------------------------------------------------------------

VENICE_TOP = {
    "model", "messages", "stream", "stream_options", "max_tokens", "max_completion_tokens", "temperature",
    "top_p", "tools", "tool_choice", "parallel_tool_calls", "stop", "seed", "frequency_penalty",
    "presence_penalty", "reasoning_effort", "response_format", "venice_parameters", "veniceParameters",
}
VENICE_PARAMS = {"disableThinking", "disable_thinking", "stripThinkingResponse", "strip_thinking_response",
                 "include_venice_system_prompt", "includeVeniceSystemPrompt"}
MESSAGE_KEYS = {"role", "content", "name", "tool_calls", "tool_call_id", "reasoning_content"}


def venice_policy(ctx, method, path, body):
    if method == "GET" and path == "/api/v1/models":
        return Forward("GET", path)
    if method != "POST" or path != "/api/v1/chat/completions":
        raise Deny(403, "only chat/completions (POST) and models (GET) are forwarded")
    data = strict_json(body)
    only_keys(data, VENICE_TOP, "request")
    if data.get("model") not in ctx["models"]:
        raise Deny(403, "model is not on the private-model allowlist")
    for k in ("venice_parameters", "veniceParameters"):
        if k in data:
            only_keys(data[k], VENICE_PARAMS, k)
            if any(not isinstance(v, bool) for v in data[k].values()):
                raise Deny(400, f"{k} values must be booleans")
    msgs = data.get("messages")
    if not isinstance(msgs, list):
        raise Deny(400, "messages must be a list")
    for m in msgs:
        only_keys(m, MESSAGE_KEYS, "message")
        content = m.get("content")
        if isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    raise Deny(400, "content parts must be objects")
                kind = part.get("type")
                if kind == "text":
                    only_keys(part, {"type", "text", "cache_control"}, "text part")
                elif kind == "image_url":
                    only_keys(part, {"type", "image_url"}, "image part")
                    url = part["image_url"].get("url", "") if isinstance(part["image_url"], dict) else part["image_url"]
                    if not str(url).startswith("data:"):
                        raise Deny(403, "remote media is not forwarded; inline it as a data: URL")
                else:
                    raise Deny(403, f"content part type {kind!r} is not forwarded")
        elif content is not None and not isinstance(content, str):
            raise Deny(400, "message content must be text or parts")
    return Forward("POST", path, body=data)


# --- agentmail -------------------------------------------------------------

DRAFT_KEYS = {"to", "cc", "bcc", "reply_to", "subject", "text", "html", "labels", "attachments", "in_reply_to"}
ATTACHMENT_KEYS = {"filename", "content_type", "content", "content_disposition", "content_id"}
READ_QUERY = {"limit", "page_token", "labels", "before", "after", "ascending"}


# C0 controls and DEL. Bodies may carry newlines and tabs; nothing else may
# carry any control character (round-4 red-team N1: CR/LF in subject,
# labels, attachment names or in_reply_to could become extra MIME headers).
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
BODY_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MESSAGE_ID = re.compile(r"^<[^<>\s\x00-\x1f\x7f]{1,250}>$")


def _text(v, what, body=False):
    if not isinstance(v, str):
        raise Deny(400, f"{what} must be a string")
    if (BODY_CONTROL if body else CONTROL).search(v):
        raise Deny(400, f"{what} contains control characters")
    return v


def _addresses(v, what):
    """Plain addresses only; returned stripped, with the domain lower-cased."""
    items = v if isinstance(v, list) else [v]
    out = []
    for it in items:
        if not isinstance(it, str):
            raise Deny(400, f"{what} must be plain email addresses")
        a = it.strip(" ")
        if CONTROL.search(a) or not EMAIL.match(a):
            raise Deny(400, f"{what} must be plain email addresses")
        local, _, domain = a.rpartition("@")
        out.append(f"{local}@{domain.lower()}")
    return out if isinstance(v, list) else out[0]


def validate_draft(data):
    """Validate and NORMALISE a draft; the normalised form is what is
    forwarded, snapshotted, digested and sent."""
    only_keys(data, DRAFT_KEYS, "draft")
    out = {}
    for k in ("to", "cc", "bcc", "reply_to"):
        if k in data:
            out[k] = _addresses(data[k], k)
    if "subject" in data:
        out["subject"] = _text(data["subject"], "subject")
    for k in ("text", "html"):
        if k in data:
            out[k] = _text(data[k], k, body=True)
    if "in_reply_to" in data:
        v = _text(data["in_reply_to"], "in_reply_to")
        if not MESSAGE_ID.match(v):
            raise Deny(400, "in_reply_to must be a single message id like <id@host>")
        out["in_reply_to"] = v
    if "labels" in data:
        if not isinstance(data["labels"], list):
            raise Deny(400, "labels must be a list of strings")
        out["labels"] = [_text(x, "label") for x in data["labels"]]
    if "attachments" in data:
        atts = data["attachments"]
        if not isinstance(atts, list):
            raise Deny(400, "attachments must be a list")
        clean = []
        for a in atts:
            only_keys(a, ATTACHMENT_KEYS, "attachment")
            c = {}
            for k in ("filename", "content_type", "content_disposition", "content_id"):
                if k in a:
                    c[k] = _text(a[k], f"attachment {k}")
            if "content" in a:
                content = a["content"]
                if not isinstance(content, str) or not re.fullmatch(r"[A-Za-z0-9+/=\r\n]*", content):
                    raise Deny(400, "attachment content must be base64")
                c["content"] = content
            clean.append(c)
        out["attachments"] = clean
    return out


# Per-draft locks: a draft's edit, delete and send never overlap. A fixed
# set of striped locks keeps memory bounded whatever ids callers send.
_STRIPES = [threading.Lock() for _ in range(256)]


def draft_lock(draft_id):
    return _STRIPES[int(approvals.key_for("draft", draft_id)[:8], 16) % len(_STRIPES)]


SNAPSHOT_TTL = 30 * 24 * 3600
SNAPSHOT_QUOTA = 512 * 1024 * 1024


def _snapshot_path(ctx, draft_id):
    return os.path.join(ctx["state_dir"], "drafts", approvals.key_for("draft", draft_id) + ".json")


def load_snapshot(ctx, draft_id):
    try:
        with open(_snapshot_path(ctx, draft_id)) as f:
            rec = json.load(f)
    except (OSError, ValueError):
        return None
    return rec["content"] if rec.get("draft_id") == draft_id else None


def prune_snapshots(ctx, keep=None):
    """Drop snapshots older than SNAPSHOT_TTL, then oldest-first past the quota."""
    d = os.path.join(ctx["state_dir"], "drafts")
    try:
        entries = [(e.stat().st_mtime, e.stat().st_size, e.path) for e in os.scandir(d) if e.is_file()]
    except OSError:
        return
    now = time.time()
    total = 0
    for mtime, size, path_ in sorted(entries, reverse=True):
        total += size
        if path_ != keep and (now - mtime > SNAPSHOT_TTL or total > SNAPSHOT_QUOTA):
            try:
                os.remove(path_)
            except OSError:
                pass


def remove_snapshot(ctx, draft_id):
    try:
        os.remove(_snapshot_path(ctx, draft_id))
    except FileNotFoundError:
        pass


def save_snapshot(ctx, draft_id, content):
    p = _snapshot_path(ctx, draft_id)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"draft_id": draft_id, "content": approvals.sendable(content)}, f)
    os.replace(tmp, p)
    prune_snapshots(ctx, keep=p)


def send_body(content):
    """The approved snapshot as a messages/send request (AgentMail API)."""
    body = {k: v for k, v in content.items() if k != "in_reply_to"}
    if content.get("in_reply_to"):
        body["headers"] = {"In-Reply-To": content["in_reply_to"], "References": content["in_reply_to"]}
    return body


def agentmail_policy(ctx, method, path, body):
    """Drafts to anyone; a send delivers the gateway's own snapshot of the draft.

    Round-3 red-team C1: binding an approval to a digest of AgentMail's copy
    of the draft, then asking AgentMail to send "the draft", let a PATCH
    land between the check and the send. Now:
      - every draft written through this gateway is snapshotted here (the
        validated, normalised content, attachment bytes included); a draft
        made elsewhere becomes sendable only through a gateway PATCH, and
        then what goes out is that snapshot, never the outside draft;
        Sean approves the sha256 of that snapshot (GET /_jill/.../digest)
      - a send verifies the approval against the snapshot and then POSTs
        the snapshot itself to messages/send: AgentMail's draft is not what
        gets sent, so editing it cannot change what goes out
      - edits and deletes are refused while a live approval exists
      - edit, delete and send of one draft are serialised by a lock
      - any send attempt that reaches the approval burns it
    """
    base = "/v0/inboxes/" + ctx["inbox"]
    seg = r"[^/]+"
    if path.startswith("/_jill/drafts/") and path.endswith("/digest") and method == "GET":
        draft_id = path[len("/_jill/drafts/"):-len("/digest")]
        with draft_lock(draft_id):
            content = load_snapshot(ctx, draft_id)
        if content is None:
            raise Deny(404, "no snapshot of this draft: only drafts written through this gateway can be sent")
        return Local(200, {"draft_id": draft_id, "content": content, "sha256": approvals.draft_digest(content)})
    if not path.startswith(base + "/") and path != base:
        raise Deny(403, "only Jill's own inbox is reachable")
    rest = path[len(base):]
    if method == "GET" and re.fullmatch(
            rf"(/(threads|messages|drafts)(/{seg})?|/(threads|messages)/{seg}/attachments/{seg}|/threads/{seg}/messages)?", rest):
        return Forward("GET", path, query=query_pairs(ctx["raw_path"], READ_QUERY))

    if method == "POST" and rest == "/drafts":
        draft = validate_draft(strict_json(body))

        def remember(status, resp):
            if 200 <= status < 300:
                try:
                    draft_id = json.loads(resp)["draft_id"]
                except (ValueError, KeyError, TypeError):
                    return
                with draft_lock(draft_id):
                    if approvals.status("draft", draft_id, [ctx["consumed_dir"]], base=ctx["approvals_dir"]) == "live":
                        raise Deny(409, "AgentMail returned the id of a draft Sean has approved; its snapshot was not changed")
                    save_snapshot(ctx, draft_id, draft)

        return Forward("POST", path, body=draft, after=remember)

    m = re.fullmatch(rf"/drafts/({seg})", rest)
    if m and method in ("PATCH", "DELETE"):
        draft_id = m.group(1)
        patch = validate_draft(strict_json(body)) if method == "PATCH" else None
        lock = draft_lock(draft_id)
        lock.acquire()
        try:
            if approvals.status("draft", draft_id, [ctx["consumed_dir"]], base=ctx["approvals_dir"]) == "live":
                raise Deny(409, "Sean has approved this draft as it is; it cannot change until it is sent or the approval expires")
        except BaseException:
            lock.release()
            raise

        def update(status, resp):
            if not 200 <= status < 300:
                return
            if method == "DELETE":
                remove_snapshot(ctx, draft_id)
            else:
                merged = dict(load_snapshot(ctx, draft_id) or {})
                merged.update(patch)
                save_snapshot(ctx, draft_id, merged)

        return Forward(method, path, body=patch, after=update, release=lock.release)

    m = re.fullmatch(rf"/drafts/({seg})/send", rest)
    if m and method == "POST":
        if strict_json(body, allow_empty=True):
            raise Deny(400, "draft send takes no body")
        draft_id = m.group(1)
        lock = draft_lock(draft_id)
        lock.acquire()
        try:
            content = load_snapshot(ctx, draft_id)
            if content is None:
                raise Deny(404, "no snapshot of this draft: only drafts written through this gateway can be sent")
            digest = approvals.draft_digest(content)

            def same_draft(rec):
                if rec.get("sha256") != digest:
                    raise LookupError("the draft is not the one Sean approved; this approval is now used up")

            try:
                approvals.check_and_consume("draft", draft_id, ctx["consumed_dir"], base=ctx["approvals_dir"],
                                            verify=same_draft)
            except LookupError as e:
                raise Deny(403, f"not sent: {e}. Ask Sean to approve draft {draft_id}")
        except BaseException:
            lock.release()
            raise

        def cleanup(status, resp):
            # Sent: the draft and its snapshot are done (round-4 N6).
            if 200 <= status < 300:
                remove_snapshot(ctx, draft_id)
                try:
                    ctx["upstream_call"]("DELETE", f"{base}/drafts/{draft_id}")
                except Deny:
                    pass

        return Forward("POST", f"{base}/messages/send", body=send_body(content), after=cleanup, release=lock.release)

    raise Deny(403, "not allowed: Jill reads her inbox and writes drafts; sending needs Sean's approval of the draft")


# --- siyuan ----------------------------------------------------------------

SIYUAN_READ = {
    "/api/query/sql", "/api/attr/getBlockAttrs", "/api/block/getBlockKramdown", "/api/block/getChildBlocks",
    "/api/export/exportMdContent", "/api/file/getFile", "/api/file/readDir", "/api/filetree/getHPathByID",
    "/api/filetree/getHPathByPath", "/api/filetree/getIDsByHPath", "/api/filetree/getPathByID",
    "/api/notebook/getNotebookConf", "/api/notebook/lsNotebooks", "/api/system/bootProgress",
    "/api/system/currentTime", "/api/system/version",
}
NOTEBOOK_PATH = re.compile(r"^/data/\d{14}-[a-z0-9]{7}(/[^/]+)*/?$")


def siyuan_policy(ctx, method, path, body):
    if method != "POST" or path not in SIYUAN_READ:
        raise Deny(403, "only read-only SiYuan endpoints are forwarded")
    data = strict_json(body, allow_empty=True)
    if path == "/api/query/sql":
        stmt = str(data.get("stmt", "")).strip().rstrip(";").strip()
        if not re.match(r"(?is)^(select|with)\b", stmt) or ";" in stmt:
            raise Deny(403, "SQL must be a single SELECT")
        if re.search(r"(?i)\b(insert|update|delete|drop|alter|create|replace|attach|detach|pragma|vacuum)\b", stmt):
            raise Deny(403, "SQL must be read-only")
    if path in ("/api/file/getFile", "/api/file/readDir"):
        p = str(data.get("path", ""))
        if not NOTEBOOK_PATH.match(p) or ".." in p.split("/"):
            raise Deny(403, "file reads are limited to notebook folders (/data/<notebook-id>/...)")
    return Forward("POST", path, body=data)


# --- mcp -------------------------------------------------------------------

def mcp_policy(ctx, method, path, body):
    if path != "/mcp" or method not in ("GET", "POST", "DELETE"):
        raise Deny(403, "only /mcp is forwarded")
    if method == "POST":
        try:
            data = json.loads(body.decode("utf-8"), object_pairs_hook=_no_dupes)
        except Deny:
            raise
        except (UnicodeDecodeError, ValueError):
            raise Deny(400, "body is not JSON")
        return Forward("POST", path, body=data)
    return Forward(method, path)


# --- fetch -----------------------------------------------------------------

def public_address(host, port):
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        raise Deny(502, "host does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            raise Deny(403, "approved URL resolves to a private or local address")
    return infos[0][4][0]


def fetch_policy(ctx, method, path, body):
    if method == "POST" and path == "/request":
        data = strict_json(body)
        only_keys(data, {"url", "reason"}, "request")
        url = str(data.get("url", ""))
        if not re.match(r"^https?://", url) or len(url) > 2048:
            raise Deny(400, "url must be an absolute http(s) URL")
        line = json.dumps({"ts": time.time(), "url": url, "reason": str(data.get("reason", ""))[:500]})
        os.makedirs(ctx["state_dir"], exist_ok=True)
        with open(os.path.join(ctx["state_dir"], "requests.jsonl"), "a") as f:
            f.write(line + "\n")
        return Local(202, {"status": "requested", "note": "Sean has to approve this exact URL before you can fetch it"})
    if method != "POST" or path != "/fetch":
        raise Deny(403, "POST /fetch {url} or POST /request {url, reason}")
    data = strict_json(body)
    only_keys(data, {"url"}, "fetch")
    url = str(data.get("url", ""))
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise Deny(400, "url must be an absolute http(s) URL without credentials")
    try:
        approvals.check_and_consume("url", url, ctx["consumed_dir"], base=ctx["approvals_dir"])
    except LookupError as e:
        raise Deny(403, f"not fetched: {e}. POST /request {{url, reason}} and ask Sean to approve that exact URL")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    ip = public_address(parts.hostname, port)
    return Local("fetch", {"url": url, "ip": ip, "port": port, "parts": parts})


# --- api (opencode serve, bridge and dispatcher only) ----------------------

API_ROUTES = [
    ("GET", r"/global/health"),
    ("GET", r"/(global/)?event"),
    ("GET", r"/(config|config/providers|provider|agent|command|mcp|lsp|formatter|path|project/current|vcs|app|session/status|global/config)"),
    ("GET", r"/session(/[^/]+)?"),
    ("GET", r"/session/[^/]+/(message|message/[^/]+|children|todo|diff)"),
    ("POST", r"/session"),
    ("POST", r"/session/[^/]+/(message|prompt_async|abort|init|summarize)"),
    ("PATCH", r"/session/[^/]+"),
    ("DELETE", r"/session/[^/]+"),
    ("POST", r"/session/[^/]+/permissions/[^/]+"),
    ("POST", r"/permission/[^/]+/reply"),
    ("POST", r"/question/[^/]+/(reply|reject)"),
    ("GET", r"/(permission|question)"),
    ("POST", r"/log"),
]
API_DENY_NOTE = "not allowed through the API gateway (no MCP registration, shell, PTY, config writes or upgrades)"


def api_policy(ctx, method, path, body):
    for m, rx in API_ROUTES:
        if m == method and re.fullmatch(rx, path):
            q = ctx["raw_path"].split("?", 1)[1] if "?" in ctx["raw_path"] else ""
            return Forward(method, path, raw=body, query=parse_qsl(q, keep_blank_values=True))
    raise Deny(403, API_DENY_NOTE)


ROUTES = {
    "venice": {"policy": venice_policy, "upstream": "https://api.venice.ai", "auth": "Bearer {key}"},
    "agentmail": {"policy": agentmail_policy, "upstream": "https://api.agentmail.to", "auth": "Bearer {key}"},
    "siyuan": {"policy": siyuan_policy, "upstream": None, "auth": "token {key}"},
    "mcp": {"policy": mcp_policy, "upstream": None, "auth": None},
    "fetch": {"policy": fetch_policy, "upstream": "none://", "auth": None},
    "api": {"policy": api_policy, "upstream": None, "auth": None},
}


def load_config(env=os.environ):
    name = env.get("GATEWAY_ROUTE", "")
    if name not in ROUTES:
        raise SystemExit(f"GATEWAY_ROUTE must be one of {', '.join(ROUTES)}")
    route = ROUTES[name]
    upstream = env.get("UPSTREAM_URL") or route["upstream"]
    if not upstream:
        raise SystemExit(f"UPSTREAM_URL is required for route {name}")
    split = lambda v: [x.strip().lower() if "@" in x else x.strip() for x in (v or "").split(",") if x.strip()]
    if route["auth"] and not env.get("UPSTREAM_KEY"):
        raise SystemExit("UPSTREAM_KEY is required")
    cfg = {
        "name": name,
        "policy": route["policy"],
        "upstream": urlsplit(upstream),
        "auth": route["auth"].format(key=env["UPSTREAM_KEY"]) if route["auth"] else None,
        "basic_password": env.get("GATEWAY_BASIC_PASSWORD") or None,
        "models": set(split(env.get("VENICE_MODELS"))),
        "inbox": env.get("AGENTMAIL_INBOX", ""),
        "approvals_dir": env.get("APPROVALS_DIR", "/state/approvals"),
        "consumed_dir": os.path.join(env.get("GATEWAY_STATE_DIR", "/state/gateway"), "consumed"),
        "state_dir": env.get("GATEWAY_STATE_DIR", "/state/gateway"),
        "credential_dir": env.get("CREDENTIAL_STATUS_DIR") or None,
    }
    if name == "venice" and not cfg["models"]:
        raise SystemExit("VENICE_MODELS is required")
    if name == "agentmail" and not cfg["inbox"]:
        raise SystemExit("AGENTMAIL_INBOX is required")
    if name == "api" and not cfg["basic_password"]:
        raise SystemExit("GATEWAY_BASIC_PASSWORD is required for the api route")
    return cfg


def connect(up, timeout=600):
    if up.scheme == "https":
        return http.client.HTTPSConnection(up.hostname, up.port or 443, timeout=timeout,
                                           context=ssl.create_default_context())
    return http.client.HTTPConnection(up.hostname, up.port or 80, timeout=timeout)


def make_handler(cfg):
    up = cfg["upstream"]

    def upstream_headers(extra=None):
        h = {"host": up.netloc}
        if cfg["auth"]:
            h["authorization"] = cfg["auth"]
        h.update(extra or {})
        return h

    def upstream_json(method, path):
        conn = connect(up, timeout=30)
        try:
            conn.request(method, (up.path.rstrip("/") + quote(path, safe="/@:")) or "/",
                         headers=upstream_headers({"accept": "application/json"}))
            resp = conn.getresponse()
            data = resp.read(MAX_BODY)
        except OSError:
            raise Deny(502, "upstream unreachable")
        finally:
            conn.close()
        if resp.status != 200:
            raise Deny(resp.status if resp.status in (403, 404) else 502, "upstream refused the lookup")
        try:
            return json.loads(data)
        except ValueError:
            raise Deny(502, "upstream returned non-JSON")

    def upstream_call(method, path):
        conn = connect(up, timeout=30)
        try:
            conn.request(method, (up.path.rstrip("/") + quote(path, safe="/@:")) or "/", headers=upstream_headers())
            resp = conn.getresponse()
            resp.read(MAX_BODY)
            return resp.status
        except OSError:
            raise Deny(502, "upstream unreachable")
        finally:
            conn.close()

    class Handler(BaseHTTPRequestHandler):
        server_version = "jill-gateway"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def _log(self, status, path, note=""):
            sys.stderr.write(f"[gateway:{cfg['name']}] {self.command} {path} -> {status} {note}\n")

        def _json(self, status, obj, path, note=""):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self._log(status, path, note)

        def _check_headers(self):
            for h in SINGLE_HEADERS:
                if len(self.headers.get_all(h) or []) > 1:
                    raise Deny(400, f"repeated {h} header")
            if cfg["basic_password"]:
                got = self.headers.get("authorization", "")
                want = "Basic " + base64.b64encode(f"opencode:{cfg['basic_password']}".encode()).decode()
                if not hmac.compare_digest(got.encode(), want.encode()):
                    raise Deny(401, "caller is not authorized")

        def _read_body(self):
            if self.command not in ("POST", "PUT", "PATCH"):
                return b""
            if self.headers.get("transfer-encoding"):
                raise Deny(411, "chunked request bodies are not accepted")
            n = int(self.headers.get("content-length") or "0")
            if n > MAX_BODY:
                raise Deny(413, "body too large")
            return self.rfile.read(n)

        def _handle(self):
            shown = "?"
            try:
                path = canonical_path(self.path)
                shown = path
                self._check_headers()
                body = self._read_body()
                ctx = dict(cfg, raw_path=self.path, upstream_json=upstream_json, upstream_call=upstream_call)
                decision = cfg["policy"](ctx, self.command, path, body)
            except Deny as d:
                return self._json(d.status, {"error": d.reason}, shown, d.reason)
            except (ValueError, OSError, TypeError, AttributeError, KeyError):
                return self._json(400, {"error": "bad request"}, shown)
            if isinstance(decision, Local):
                if decision.status == "fetch":
                    return self._fetch(decision.obj, shown)
                return self._json(decision.status, decision.obj, shown)

            try:
                headers = {k: v for k, v in self.headers.items() if k.lower() in FWD_REQ_HEADERS}
                if decision.raw is not None:
                    payload = decision.raw
                elif decision.body is not None:
                    payload = json.dumps(decision.body).encode()
                    headers["content-type"] = "application/json"
                else:
                    payload = b""
                headers = upstream_headers(headers)
                if payload or decision.method in ("POST", "PUT", "PATCH"):
                    headers["content-length"] = str(len(payload))
                target = (up.path.rstrip("/") + quote(decision.path, safe="/@:")) or "/"
                if decision.query:
                    target += "?" + urlencode(decision.query)
                try:
                    conn = connect(up)
                    conn.request(decision.method, target, body=payload or None, headers=headers)
                    resp = conn.getresponse()
                except OSError:
                    return self._json(502, {"error": "upstream unreachable"}, shown)
                if decision.after:
                    data = resp.read(MAX_BODY)
                    conn.close()
                    try:
                        decision.after(resp.status, data)
                    except Deny as d:
                        return self._json(d.status, {"error": d.reason}, shown, d.reason)
                    self.send_response(resp.status)
                    for k, v in resp.getheaders():
                        if k.lower() in FWD_RESP_HEADERS:
                            self.send_header(k, v)
                    self.send_header("content-length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    self._log(resp.status, shown)
                    return
                self._relay(resp, conn, shown, cap=None)
            finally:
                if decision.release:
                    decision.release()

        def _relay(self, resp, conn, shown, cap):
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() in FWD_RESP_HEADERS or k.lower().startswith("x-ratelimit"):
                    self.send_header(k, v)
            self.send_header("connection", "close")
            self.end_headers()
            sent = 0
            try:
                while True:
                    chunk = resp.read1(65536)
                    if not chunk:
                        break
                    if cap is not None and sent + len(chunk) > cap:
                        self.wfile.write(chunk[: cap - sent])
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    sent += len(chunk)
            except OSError:
                pass
            finally:
                conn.close()
            self._log(resp.status, shown)

        def _fetch(self, f, shown):
            parts = f["parts"]
            target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
            try:
                # Connect to the address that was vetted as public (no second DNS
                # lookup to rebind), and verify TLS against the hostname.
                conn = http.client.HTTPConnection(parts.hostname, f["port"], timeout=20)
                sock = socket.create_connection((f["ip"], f["port"]), timeout=20)
                if parts.scheme == "https":
                    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=parts.hostname)
                conn.sock = sock
                conn.request("GET", target, headers={"host": parts.netloc.split("@")[-1],
                                                      "user-agent": "jill-fetch/1", "accept": "*/*"})
                resp = conn.getresponse()
            except (OSError, ssl.SSLError):
                return self._json(502, {"error": "fetch failed"}, shown)
            # Redirects are returned, not followed: a new URL needs its own approval.
            self._relay(resp, conn, shown, cap=MAX_FETCH)

        do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = do_HEAD = do_OPTIONS = _handle

    return Handler


# --- credential probe (Jill v2 C, #49) -------------------------------------
#
# The keys live only in the gateways, so only a gateway can tell whether its
# key still works. With CREDENTIAL_STATUS_DIR set, a key-holding gateway makes
# one cheap authenticated call upstream every CREDENTIAL_PROBE_SECONDS and
# writes a status-only record to <dir>/<route>.json: result, HTTP status and
# timestamps, never the key or any response body. jill-control reads those
# records (read-only) and alerts. Nothing Jill sends can trigger a probe.

PROBES = {
    "venice": ("GET", "/api/v1/api_keys/rate_limits", None),
    "agentmail": ("GET", "/v0/inboxes/{inbox}", None),
    "siyuan": ("POST", "/api/notebook/lsNotebooks", {}),
}


def probe_once(cfg, call):
    """call(method, path, body) -> HTTP status, raising Deny when unreachable."""
    method, path, body = PROBES[cfg["name"]]
    try:
        status = call(method, path.format(inbox=cfg["inbox"]), body)
    except Deny:
        return "error", 0
    if 200 <= status < 300:
        return "ok", status
    if status in (401, 403):
        return "rejected", status
    return "error", status


def write_probe(cfg, result, status, now=None):
    now = int(now if now is not None else time.time())
    path = os.path.join(cfg["credential_dir"], cfg["name"] + ".json")
    try:
        with open(path) as f:
            prev = json.load(f)
        last_ok = prev.get("last_ok_at") if isinstance(prev, dict) else None
    except (OSError, ValueError):
        last_ok = None
    rec = {"route": cfg["name"], "result": result, "http_status": status, "checked_at": now,
           "last_ok_at": now if result == "ok" else last_ok}
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f)
    os.replace(tmp, path)
    return rec


def probe_loop(cfg, call, interval):
    while True:
        result, status = probe_once(cfg, call)
        try:
            write_probe(cfg, result, status)
        except OSError as e:
            sys.stderr.write(f"[gateway:{cfg['name']}] credential probe could not write its status: {e}\n")
        sys.stderr.write(f"[gateway:{cfg['name']}] credential probe: {result} {status}\n")
        time.sleep(interval)


def main():
    cfg = load_config()
    host, _, port = os.environ.get("GATEWAY_LISTEN", "0.0.0.0:8080").rpartition(":")
    server = ThreadingHTTPServer((host or "0.0.0.0", int(port)), make_handler(cfg))
    server.daemon_threads = True
    if cfg["credential_dir"] and cfg["name"] in PROBES:
        up = cfg["upstream"]

        def call(method, path, body):
            conn = connect(up, timeout=30)
            try:
                payload = json.dumps(body).encode() if body is not None else None
                headers = {"host": up.netloc, "authorization": cfg["auth"], "accept": "application/json"}
                if payload is not None:
                    headers["content-type"] = "application/json"
                    headers["content-length"] = str(len(payload))
                conn.request(method, (up.path.rstrip("/") + quote(path, safe="/@:")) or "/", body=payload,
                             headers=headers)
                resp = conn.getresponse()
                resp.read(MAX_BODY)
                return resp.status
            except OSError:
                raise Deny(502, "upstream unreachable")
            finally:
                conn.close()

        interval = max(60, int(os.environ.get("CREDENTIAL_PROBE_SECONDS", "3600")))
        threading.Thread(target=probe_loop, args=(cfg, call, interval), daemon=True).start()
    sys.stderr.write(f"[gateway:{cfg['name']}] listening on {host}:{port}, upstream {cfg['upstream'].netloc}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
