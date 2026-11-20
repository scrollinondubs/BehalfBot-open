"""Tests for gateway/gateway.py. Stdlib only:

    python3 -m unittest discover -s tests/gateway -v

Policies are tested directly, then each route is run for real against a fake
upstream on loopback to prove key injection, caller auth, path
canonicalisation and streaming.
"""
import http.client
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "gateway"))
import gateway as g  # noqa: E402

SEAN = "sean@grid7.com"
INBOX = "jill-agent@agentmail.to"


def cfg(route, **env):
    base = {"GATEWAY_ROUTE": route, "UPSTREAM_KEY": "real-key-not-for-callers"}
    if route == "venice":
        base["VENICE_MODELS"] = "zai-org-glm-5-2,z-ai-glm-5-3-flash"
    if route == "agentmail":
        base.update(AGENTMAIL_INBOX=INBOX, AGENTMAIL_RECIPIENTS=SEAN)
    if route in ("siyuan", "mcp"):
        base["UPSTREAM_URL"] = "http://127.0.0.1:1"
    base.update(env)
    return g.load_config(base)


def check(c, method, raw, body=b""):
    path = g.canonical_path(raw)
    return c["policy"](c, method, path, body)


class Policies(unittest.TestCase):
    def deny(self, c, method, raw, body=b""):
        with self.assertRaises(g.Deny, msg=f"{method} {raw} {body[:80]!r}"):
            check(c, method, raw, body)

    def test_canonical_path_decodes_and_refuses_traversal(self):
        self.assertEqual(g.canonical_path("/v0/inboxes/x/messages/%73end?x=1"), "/v0/inboxes/x/messages/send")
        self.assertEqual(g.canonical_path("/a/%2573end"), "/a/send")
        for bad in ("/a/../b", "/a/%2e%2e/b", "//evil", "/a\\b", "/a/%00b"):
            with self.assertRaises(g.Deny):
                g.canonical_path(bad)

    def test_venice_private_model_allowlist(self):
        c = cfg("venice")
        ok = json.dumps({"model": "zai-org-glm-5-2", "messages": []}).encode()
        self.assertEqual(check(c, "POST", "/api/v1/chat/completions", ok), "/api/v1/chat/completions")
        self.assertEqual(check(c, "GET", "/api/v1/models"), "/api/v1/models")
        self.deny(c, "POST", "/api/v1/chat/completions", json.dumps({"model": "z-ai-glm-5-turbo"}).encode())
        self.deny(c, "POST", "/api/v1/chat/completions", json.dumps({"model": "gemini-4-carbon"}).encode())
        self.deny(c, "POST", "/api/v1/chat/completions", b"{}")
        self.deny(c, "POST", "/api/v1/chat/completions", b"not json")
        self.deny(c, "POST", "/api/v1/chat/completions",
                  json.dumps({"model": "zai-org-glm-5-2", "venice_parameters": {"enable_web_search": "on"}}).encode())
        for path in ("/api/v1/api_keys", "/api/v1/image/generate", "/api/v1/chat/completions/../api_keys"):
            self.deny(c, "POST", path, ok)
        self.deny(c, "GET", "/api/v1/chat/completions")

    def test_agentmail_drafts_and_send_to_sean_only(self):
        c = cfg("agentmail")
        send = f"/v0/inboxes/{INBOX}/messages/send"
        body = lambda **k: json.dumps(k).encode()
        self.assertTrue(check(c, "POST", f"/v0/inboxes/{INBOX}/drafts", body(to=["lead@x.com"], subject="s")))
        self.assertTrue(check(c, "POST", send, body(to=[SEAN], subject="s")))
        self.assertTrue(check(c, "POST", send, body(to="Sean <SEAN@grid7.com>", cc=[SEAN])))
        self.assertTrue(check(c, "POST", f"/v0/inboxes/jill-agent%40agentmail.to/messages/send", body(to=[SEAN])))
        self.deny(c, "POST", send, body(to=["lead@x.com"]))
        self.deny(c, "POST", send, body(to=[SEAN], bcc=["leak@x.com"]))
        self.deny(c, "POST", send, body(to=[SEAN], cc="leak@x.com"))
        self.deny(c, "POST", send, body(to=["sean@grid7.com.evil.net"]))
        self.deny(c, "POST", send, body(subject="no recipients"))
        self.deny(c, "POST", send, body(to=["$TARGET"]))
        # The red-team bypass: an encoded "send" is decoded and then checked.
        self.deny(c, "POST", f"/v0/inboxes/{INBOX}/messages/%73end", body(to=["lead@x.com"]))
        self.deny(c, "POST", f"/v0/inboxes/{INBOX}/messages/%2573end", body(to=["lead@x.com"]))
        for path in (f"/v0/inboxes/{INBOX}/messages/m1/reply", f"/v0/inboxes/{INBOX}/messages/m1/forward",
                     f"/v0/inboxes/{INBOX}/drafts/d1/send", "/v0/inboxes/other@agentmail.to/messages/send",
                     f"/v0/inboxes/{INBOX}/threads", "/v0/inboxes", "/v0/api-keys"):
            self.deny(c, "POST", path, body(to=[SEAN]))
        self.deny(c, "GET", f"/v0/inboxes/{INBOX}/threads")
        self.deny(c, "DELETE", f"/v0/inboxes/{INBOX}")

    def test_siyuan_read_only(self):
        c = cfg("siyuan")
        j = lambda **k: json.dumps(k).encode()
        self.assertTrue(check(c, "POST", "/api/query/sql", j(stmt="SELECT id FROM blocks LIMIT 1")))
        self.assertTrue(check(c, "POST", "/api/notebook/lsNotebooks", b""))
        self.assertTrue(check(c, "POST", "/api/file/getFile", j(path="/data/20260101/x.sy")))
        self.deny(c, "POST", "/api/query/sql", j(stmt="DELETE FROM blocks"))
        self.deny(c, "POST", "/api/query/sql", j(stmt="SELECT 1; DROP TABLE blocks"))
        self.deny(c, "POST", "/api/query/sql", j(stmt="WITH x AS (SELECT 1) DELETE FROM blocks"))
        self.deny(c, "POST", "/api/file/getFile", j(path="/conf/conf.json"))
        self.deny(c, "POST", "/api/file/getFile", j(path="/data/../conf/conf.json"))
        for p in ("/api/block/updateBlock", "/api/filetree/createDocWithMd", "/api/file/putFile",
                  "/api/notification/pushMsg", "/api/template/render"):
            self.deny(c, "POST", p, b"{}")
        self.deny(c, "GET", "/api/query/sql")

    def test_mcp_path_only(self):
        c = cfg("mcp")
        self.assertEqual(check(c, "POST", "/mcp", b"{}"), "/mcp")
        self.deny(c, "POST", "/admin", b"{}")
        self.deny(c, "PUT", "/mcp", b"{}")

    def test_config_refuses_to_start_without_policy_inputs(self):
        with self.assertRaises(SystemExit):
            g.load_config({"GATEWAY_ROUTE": "venice", "UPSTREAM_KEY": "k"})
        with self.assertRaises(SystemExit):
            g.load_config({"GATEWAY_ROUTE": "agentmail", "UPSTREAM_KEY": "k", "AGENTMAIL_INBOX": INBOX})
        with self.assertRaises(SystemExit):
            g.load_config({"GATEWAY_ROUTE": "nope"})


class Upstream(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def _any(self):
        n = int(self.headers.get("content-length") or 0)
        self.rfile.read(n)
        Upstream.seen.append({"path": self.path, "auth": self.headers.get("authorization"),
                              "host": self.headers.get("host"), "cookie": self.headers.get("cookie")})
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("set-cookie", "upstream=secret")
        self.end_headers()
        for i in range(3):
            self.wfile.write(f"data: chunk{i}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.05)

    do_GET = do_POST = do_DELETE = _any


def serve(handler):
    s = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up = serve(Upstream)
        upurl = f"http://127.0.0.1:{cls.up.server_port}"
        cls.venice = serve(g.make_handler(cfg("venice", UPSTREAM_URL=upurl, GATEWAY_CALLER_TOKEN="caller-token")))
        cls.mail = serve(g.make_handler(cfg("agentmail", UPSTREAM_URL=upurl)))

    def req(self, server, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), data

    def test_venice_needs_caller_token_and_injects_key(self):
        body = json.dumps({"model": "zai-org-glm-5-2", "messages": []})
        st, _, _ = self.req(self.venice, "POST", "/api/v1/chat/completions", body, {"content-type": "application/json"})
        self.assertEqual(st, 401)
        st, _, _ = self.req(self.venice, "POST", "/api/v1/chat/completions", body,
                            {"authorization": "Bearer wrong", "content-type": "application/json"})
        self.assertEqual(st, 401)
        Upstream.seen.clear()
        st, hdrs, data = self.req(self.venice, "POST", "/api/v1/chat/completions?leak=x", body,
                                  {"authorization": "Bearer caller-token", "content-type": "application/json",
                                   "cookie": "a=b"})
        self.assertEqual(st, 200)
        self.assertEqual(data, b"data: chunk0\n\ndata: chunk1\n\ndata: chunk2\n\n")
        self.assertEqual(Upstream.seen[-1]["auth"], "Bearer real-key-not-for-callers")
        self.assertEqual(Upstream.seen[-1]["path"], "/api/v1/chat/completions")
        self.assertIsNone(Upstream.seen[-1]["cookie"])
        self.assertNotIn("set-cookie", hdrs)

    def test_agentmail_encoded_send_to_stranger_never_reaches_upstream(self):
        Upstream.seen.clear()
        st, _, _ = self.req(self.mail, "POST", f"/v0/inboxes/{INBOX}/messages/%73end",
                            json.dumps({"to": ["lead@x.com"]}), {"content-type": "application/json"})
        self.assertEqual(st, 403)
        self.assertEqual(Upstream.seen, [])
        st, _, _ = self.req(self.mail, "POST", f"/v0/inboxes/{INBOX}/messages/%73end",
                            json.dumps({"to": [SEAN]}), {"content-type": "application/json"})
        self.assertEqual(st, 200)
        self.assertEqual(Upstream.seen[-1]["path"], f"/v0/inboxes/{INBOX}/messages/send")
        self.assertEqual(Upstream.seen[-1]["auth"], "Bearer real-key-not-for-callers")


if __name__ == "__main__":
    unittest.main()
