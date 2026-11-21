#!/usr/bin/env python3
"""Key-holding egress gateway for Jill. Stdlib only.

One process per upstream, each in its own container (docker-compose.yml):

  venice     POST /api/v1/chat/completions (private-model allowlist), GET /api/v1/models
  agentmail  POST /v0/inboxes/<her inbox>/drafts
             POST /v0/inboxes/<her inbox>/messages/send  only when every to/cc/bcc is allowed
  siyuan     read-only SiYuan API endpoints; SQL must be a SELECT; file reads under /data/
  mcp        an HTTP MCP server on a private network (Brave), path /mcp only

opencode-serve sits on an internal network with no route out. These
containers are its only exits, and they hold the keys: the serve container,
where tool shells run, holds none. Policy is enforced here, on the decoded
request, so nothing a tool shell can type (encoded paths, proxies, a
nested client) gets around it.

Every request path is percent-decoded until stable, checked, and then
re-encoded by this process before it goes upstream, so the upstream sees
exactly the path that was checked. Query strings are dropped. Anything not
explicitly allowed gets 403. Bodies and headers are never logged.

  GATEWAY_ROUTE         venice | agentmail | siyuan | mcp
  GATEWAY_LISTEN        host:port (default 0.0.0.0:8080)
  GATEWAY_CALLER_TOKEN  optional; callers must send Authorization: Bearer <it>
                        (or "token <it>", the form siyuan-mcp uses)
  UPSTREAM_KEY          the real credential (not used by mcp)
  UPSTREAM_URL          override the upstream base (siyuan and mcp require it)
  VENICE_MODELS         comma-separated model ids allowed through
  AGENTMAIL_INBOX       her inbox id, e.g. jill-agent@agentmail.to
  AGENTMAIL_RECIPIENTS  comma-separated addresses a send may go to
"""
import hmac
import http.client
import json
import os
import re
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlsplit

MAX_BODY = 20 * 1024 * 1024
FWD_REQ_HEADERS = ("content-type", "accept", "mcp-session-id", "mcp-protocol-version", "last-event-id")
FWD_RESP_HEADERS = ("content-type", "cache-control", "mcp-session-id", "retry-after")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


class Deny(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def canonical_path(raw):
    """Decode until stable; refuse traversal and oddities. Returns the decoded path."""
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


def json_body(body):
    try:
        data = json.loads(body or b"null")
    except ValueError:
        raise Deny(400, "body is not JSON")
    if not isinstance(data, dict):
        raise Deny(400, "body must be a JSON object")
    return data


def recipients(value):
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    out = []
    for it in items:
        if isinstance(it, dict):
            it = it.get("email") or it.get("address") or ""
        found = EMAIL.findall(str(it))
        if not found:
            raise Deny(403, "a recipient is not a literal email address")
        out += [a.lower() for a in found]
    return out


# --- route policies: (method, decoded path, body) -> upstream path ---------

def venice_policy(cfg, method, path, body):
    if method == "GET" and path == "/api/v1/models":
        return path
    if method == "POST" and path == "/api/v1/chat/completions":
        data = json_body(body)
        model = data.get("model")
        if model not in cfg["models"]:
            raise Deny(403, "model is not on the private-model allowlist")
        vp = data.get("venice_parameters") or {}
        if not isinstance(vp, dict):
            raise Deny(400, "venice_parameters must be an object")
        if vp.get("enable_web_search") not in (None, "off", False) or vp.get("enable_web_scraping") not in (None, False):
            raise Deny(403, "Venice web search and scraping are disabled")
        return path
    raise Deny(403, "only chat/completions (POST) and models (GET) are forwarded")


def agentmail_policy(cfg, method, path, body):
    inbox = cfg["inbox"]
    base = "/v0/inboxes/" + inbox
    if method != "POST":
        raise Deny(403, "only draft creation and send-to-Sean are forwarded")
    if path == base + "/drafts":
        json_body(body)
        return path
    if path == base + "/messages/send":
        data = json_body(body)
        rcpts = recipients(data.get("to")) + recipients(data.get("cc")) + recipients(data.get("bcc"))
        if not rcpts:
            raise Deny(403, "send has no recipients")
        bad = sorted({r for r in rcpts if r not in cfg["recipients"]})
        if bad:
            raise Deny(403, "send to an address that is not Sean's; make it a draft instead")
        return path
    raise Deny(403, "only draft creation and send-to-Sean are forwarded")


SIYUAN_READ = {
    "/api/query/sql", "/api/attr/getBlockAttrs", "/api/block/getBlockKramdown", "/api/block/getChildBlocks",
    "/api/export/exportMdContent", "/api/file/getFile", "/api/file/readDir", "/api/filetree/getHPathByID",
    "/api/filetree/getHPathByPath", "/api/filetree/getIDsByHPath", "/api/filetree/getPathByID",
    "/api/notebook/getNotebookConf", "/api/notebook/lsNotebooks", "/api/system/bootProgress",
    "/api/system/currentTime", "/api/system/version",
}


def siyuan_policy(cfg, method, path, body):
    if method != "POST" or path not in SIYUAN_READ:
        raise Deny(403, "only read-only SiYuan endpoints are forwarded")
    data = json_body(body) if body else {}
    if path == "/api/query/sql":
        stmt = str(data.get("stmt", "")).strip().rstrip(";").strip()
        if not re.match(r"(?is)^(select|with)\b", stmt) or ";" in stmt:
            raise Deny(403, "SQL must be a single SELECT")
        if re.search(r"(?i)\b(insert|update|delete|drop|alter|create|replace|attach|detach|pragma|vacuum)\b", stmt):
            raise Deny(403, "SQL must be read-only")
    if path in ("/api/file/getFile", "/api/file/readDir"):
        p = str(data.get("path", ""))
        if not p.startswith("/data/") or ".." in p.split("/"):
            raise Deny(403, "file reads are limited to /data/ (no conf, no tokens)")
    return path


def mcp_policy(cfg, method, path, body):
    if path != "/mcp" or method not in ("GET", "POST", "DELETE"):
        raise Deny(403, "only /mcp is forwarded")
    return path


ROUTES = {
    "venice": {"policy": venice_policy, "upstream": "https://api.venice.ai", "auth": "Bearer {key}"},
    "agentmail": {"policy": agentmail_policy, "upstream": "https://api.agentmail.to", "auth": "Bearer {key}"},
    "siyuan": {"policy": siyuan_policy, "upstream": None, "auth": "token {key}"},
    "mcp": {"policy": mcp_policy, "upstream": None, "auth": None},
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
    cfg = {
        "name": name,
        "policy": route["policy"],
        "upstream": urlsplit(upstream),
        "auth": route["auth"].format(key=env["UPSTREAM_KEY"]) if route["auth"] else None,
        "caller_token": env.get("GATEWAY_CALLER_TOKEN") or None,
        "models": set(split(env.get("VENICE_MODELS"))),
        "inbox": env.get("AGENTMAIL_INBOX", ""),
        "recipients": set(split(env.get("AGENTMAIL_RECIPIENTS"))),
    }
    if route["auth"] and not env.get("UPSTREAM_KEY"):
        raise SystemExit("UPSTREAM_KEY is required")
    if name == "venice" and not cfg["models"]:
        raise SystemExit("VENICE_MODELS is required")
    if name == "agentmail" and (not cfg["inbox"] or not cfg["recipients"]):
        raise SystemExit("AGENTMAIL_INBOX and AGENTMAIL_RECIPIENTS are required")
    return cfg


def make_handler(cfg):
    up = cfg["upstream"]

    class Handler(BaseHTTPRequestHandler):
        server_version = "jill-gateway"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def _log(self, status, path, note=""):
            sys.stderr.write(f"[gateway:{cfg['name']}] {self.command} {path} -> {status} {note}\n")

        def _reply(self, status, reason, path):
            data = json.dumps({"error": reason}).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self._log(status, path, reason)

        def _handle(self):
            shown = "?"
            try:
                path = canonical_path(self.path)
                shown = path
                if cfg["caller_token"]:
                    got = self.headers.get("authorization", "").encode()
                    # siyuan-mcp sends "token <x>"; everything else "Bearer <x>".
                    ok = [hmac.compare_digest(got, (p + cfg["caller_token"]).encode()) for p in ("Bearer ", "token ")]
                    if not any(ok):
                        raise Deny(401, "caller is not authorized")
                body = b""
                if self.command in ("POST", "PUT", "PATCH"):
                    if self.headers.get("transfer-encoding"):
                        raise Deny(411, "chunked request bodies are not accepted")
                    n = int(self.headers.get("content-length") or "0")
                    if n > MAX_BODY:
                        raise Deny(413, "body too large")
                    body = self.rfile.read(n)
                upath = cfg["policy"](cfg, self.command, path, body)
            except Deny as d:
                return self._reply(d.status, d.reason, shown)
            except ValueError:
                return self._reply(400, "bad request", shown)

            target = (up.path.rstrip("/") + quote(upath, safe="/@:")) or "/"
            headers = {k: v for k, v in self.headers.items() if k.lower() in FWD_REQ_HEADERS}
            headers["host"] = up.netloc
            if cfg["auth"]:
                headers["authorization"] = cfg["auth"]
            if body:
                headers["content-length"] = str(len(body))
            try:
                if up.scheme == "https":
                    conn = http.client.HTTPSConnection(up.hostname, up.port or 443, timeout=600,
                                                       context=ssl.create_default_context())
                else:
                    conn = http.client.HTTPConnection(up.hostname, up.port or 80, timeout=600)
                conn.request(self.command, target, body=body or None, headers=headers)
                resp = conn.getresponse()
            except OSError:
                return self._reply(502, "upstream unreachable", shown)
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() in FWD_RESP_HEADERS or k.lower().startswith("x-ratelimit"):
                    self.send_header(k, v)
            self.send_header("connection", "close")
            self.end_headers()
            try:
                while True:
                    chunk = resp.read1(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except OSError:
                pass
            finally:
                conn.close()
            self._log(resp.status, shown)

        do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = do_HEAD = do_OPTIONS = _handle

    return Handler


def main():
    cfg = load_config()
    host, _, port = os.environ.get("GATEWAY_LISTEN", "0.0.0.0:8080").rpartition(":")
    server = ThreadingHTTPServer((host or "0.0.0.0", int(port)), make_handler(cfg))
    server.daemon_threads = True
    sys.stderr.write(f"[gateway:{cfg['name']}] listening on {host}:{port}, upstream {cfg['upstream'].netloc}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
