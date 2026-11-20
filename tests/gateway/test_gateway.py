"""Tests for gateway/gateway.py and gateway/approvals.py. Stdlib only:

    python3 -m unittest discover -s tests/gateway -v

Policies are tested directly, then routes run for real against a fake
upstream on loopback: key injection, re-serialisation, approvals, streaming.
"""
import base64
import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "gateway"))
import approvals  # noqa: E402
import gateway as g  # noqa: E402

SEAN = "sean@grid7.com"
INBOX = "jill-agent@agentmail.to"
BASE = f"/v0/inboxes/{INBOX}"


def cfg(route, tmp=None, **env):
    e = {"GATEWAY_ROUTE": route, "UPSTREAM_KEY": "real-key-not-for-callers"}
    if route == "venice":
        e["VENICE_MODELS"] = "zai-org-glm-5-2,z-ai-glm-5-3-flash"
    if route == "agentmail":
        e["AGENTMAIL_INBOX"] = INBOX
    if route in ("siyuan", "mcp", "api"):
        e["UPSTREAM_URL"] = "http://127.0.0.1:1"
    if route == "api":
        e["GATEWAY_BASIC_PASSWORD"] = "api-pw"
    if tmp:
        e["APPROVALS_DIR"] = os.path.join(tmp, "approvals")
        e["GATEWAY_STATE_DIR"] = os.path.join(tmp, "state")
    e.update(env)
    return g.load_config(e)


def run(c, method, raw, body=b"", upstream_json=None):
    path = g.canonical_path(raw)
    ctx = dict(c, raw_path=raw, upstream_json=upstream_json or (lambda *a: {}))
    return c["policy"](ctx, method, path, body)


J = lambda **k: json.dumps(k).encode()


class Strictness(unittest.TestCase):
    def test_duplicate_and_case_variant_keys_refused_at_any_depth(self):
        for raw in (b'{"to":["a@x.com"],"to":["sean@grid7.com"]}', b'{"to":["sean@grid7.com"],"To":["e@x.com"]}',
                    b'{"a":{"b":1,"B":2}}', b'\xff\xfe{"a":1}', '﻿{"a":1}'.encode()):
            with self.assertRaises(g.Deny, msg=raw):
                g.strict_json(raw)

    def test_canonical_path(self):
        self.assertEqual(g.canonical_path("/v0/x/%2573end?q=1"), "/v0/x/send")
        for bad in ("/a/../b", "/a/%2e%2e/b", "//evil", "/a\\b", "/a/%00b"):
            with self.assertRaises(g.Deny):
                g.canonical_path(bad)


class Venice(unittest.TestCase):
    def setUp(self):
        self.c = cfg("venice")

    def ok(self, **body):
        body.setdefault("model", "zai-org-glm-5-2")
        body.setdefault("messages", [{"role": "user", "content": "hi"}])
        return run(self.c, "POST", "/api/v1/chat/completions", J(**body))

    def deny(self, **body):
        with self.assertRaises(g.Deny, msg=body):
            self.ok(**body)

    def test_what_opencode_sends_passes(self):
        f = self.ok(stream=True, stream_options={"include_usage": True}, max_tokens=100, tools=[], tool_choice="auto")
        self.assertEqual(f.body["model"], "zai-org-glm-5-2")
        self.ok(veniceParameters={"disableThinking": True}, temperature=0.5)
        self.ok(messages=[{"role": "user", "content": [{"type": "text", "text": "x"},
                                                       {"type": "image_url", "image_url": {"url": "data:image/png;base64,AA"}}]}])

    def test_models_params_and_media(self):
        self.deny(model="z-ai-glm-5-turbo")
        self.deny(model="gemini-4-carbon")
        self.deny(venice_parameters={"enable_web_search": "on"})
        self.deny(venice_parameters={"enable_x_search": True})
        self.deny(venice_parameters={"enable_web_citations": True})
        self.deny(veniceParameters={"disableThinking": "yes"})
        self.deny(web_search_options={})
        self.deny(messages=[{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://evil.example/x?d=secret"}}]}])
        self.deny(messages=[{"role": "user", "content": [{"type": "input_audio", "input_audio": {}}]}])
        self.deny(messages=[{"role": "user", "content": "x", "extra": 1}])
        with self.assertRaises(g.Deny):
            run(self.c, "POST", "/api/v1/api_keys", J(model="zai-org-glm-5-2", messages=[]))


class AgentMail(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.c = cfg("agentmail", self.tmp)
        self.draft = {"draft_id": "d1", "to": ["lead@x.com"], "subject": "Hi", "text": "body"}

    def up(self, method, path):
        self.assertEqual(path, f"{BASE}/drafts/d1")
        return dict(self.draft)

    def deny(self, method, raw, body=b""):
        with self.assertRaises(g.Deny, msg=f"{method} {raw} {body[:90]!r}"):
            run(self.c, method, raw, body, self.up)

    def test_reads_allowed_in_her_inbox_only(self):
        for p in ("", "/threads", "/threads/t1", "/messages/m1", "/drafts", "/drafts/d1", "/messages/m1/attachments/a1"):
            self.assertIsInstance(run(self.c, "GET", BASE + p + "?limit=5"), g.Forward)
        self.deny("GET", f"{BASE}/threads?evil=1")
        self.deny("GET", "/v0/inboxes/other@agentmail.to/threads")
        self.deny("GET", "/v0/api-keys")

    def test_drafts_to_anyone_but_no_scheduling_or_unknown_fields(self):
        f = run(self.c, "POST", BASE + "/drafts", J(to=["lead@x.com"], subject="s", text="t"))
        self.assertEqual(f.body, {"to": ["lead@x.com"], "subject": "s", "text": "t"})
        self.assertIsInstance(run(self.c, "PATCH", BASE + "/drafts/d1", J(text="new")), g.Forward)
        self.assertIsInstance(run(self.c, "DELETE", BASE + "/drafts/d1"), g.Forward)
        for body in (J(to=["a@x.com"], send_at="2026-11-21T00:00:00Z"), J(to=["a@x.com"], sendAt="x"),
                     J(to=["a@x.com"], scheduled_at="x"), J(to=["a@x.com"], headers={"Bcc": "e@x.com"}),
                     J(to=[{"email": SEAN, "address": "e@x.com"}]), J(to=["Sean <sean@grid7.com>, e@x.com"]),
                     b'{"to":["e@x.com"],"to":["sean@grid7.com"]}', b'{"to":["sean@grid7.com"],"BCC":"e@x.com"}',
                     J(attachments=[{"filename": "x", "url": "https://evil.example/x"}])):
            self.deny("POST", BASE + "/drafts", body)
            self.deny("PATCH", BASE + "/drafts/d1", body)

    def test_every_direct_send_path_refused(self):
        for p in ("/messages/send", "/messages/%73end", "/messages/m1/reply", "/messages/m1/reply-all",
                  "/messages/m1/forward", "/threads/t1/reply"):
            self.deny("POST", BASE + p, J(to=[SEAN]))

    def test_draft_send_needs_a_fresh_matching_one_shot_approval(self):
        send = BASE + "/drafts/d1/send"
        self.deny("POST", send)  # no approval
        digest = approvals.draft_digest(self.draft)
        adir = os.path.join(self.tmp, "approvals")
        approvals.write_approval("draft", "d1", 60, {"sha256": digest}, base=adir)
        self.assertIsInstance(run(self.c, "POST", send, b"", self.up), g.Forward)
        self.deny("POST", send)  # one approval, one send
        approvals.write_approval("draft", "d1", 60, {"sha256": digest}, base=adir)
        self.draft["to"] = ["attacker@evil.example"]  # edited after approval
        self.deny("POST", send)
        self.draft["to"] = ["lead@x.com"]
        self.assertIsInstance(run(self.c, "POST", send, b"", self.up), g.Forward)  # not burned by the mismatch
        approvals.write_approval("draft", "d1", 1, {"sha256": digest}, base=adir)
        time.sleep(1.2)
        self.deny("POST", send)  # expired
        self.deny("POST", BASE + "/drafts/d1/send", J(to=["e@x.com"]))  # no body allowed

    def test_digest_endpoint(self):
        out = run(self.c, "GET", "/_jill/drafts/d1/digest", b"", self.up)
        self.assertEqual(out.obj["sha256"], approvals.draft_digest(self.draft))


class SiYuan(unittest.TestCase):
    def test_notebook_folders_only(self):
        c = cfg("siyuan")
        self.assertIsInstance(run(c, "POST", "/api/file/getFile", J(path="/data/20260101120000-abcdefg/x.sy")), g.Forward)
        self.assertIsInstance(run(c, "POST", "/api/query/sql", J(stmt="SELECT 1")), g.Forward)
        for body in (J(path="/data/storage/petal/plugin/conf.json"), J(path="/conf/conf.json"),
                     J(path="/data/plugins/x"), J(path="/data/20260101120000-abcdefg/../../conf/conf.json"),
                     J(path="/data/snippets/x")):
            with self.assertRaises(g.Deny, msg=body):
                run(c, "POST", "/api/file/getFile", body)
        for stmt in ("DELETE FROM blocks", "SELECT 1; DROP TABLE blocks", "WITH x AS (SELECT 1) DELETE FROM blocks"):
            with self.assertRaises(g.Deny):
                run(c, "POST", "/api/query/sql", J(stmt=stmt))
        with self.assertRaises(g.Deny):
            run(c, "POST", "/api/block/updateBlock", b"{}")


class Fetch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.c = cfg("fetch", self.tmp)

    def test_exact_url_once(self):
        url = "https://example.com/report.pdf"
        with self.assertRaises(g.Deny):
            run(self.c, "POST", "/fetch", J(url=url))
        approvals.write_approval("url", url, 60, base=os.path.join(self.tmp, "approvals"))
        with self.assertRaises(g.Deny):
            run(self.c, "POST", "/fetch", J(url=url + "?x=1"))  # not the approved URL
        try:
            out = run(self.c, "POST", "/fetch", J(url=url))
            self.assertEqual(out.status, "fetch")
        except g.Deny as d:  # no DNS in a sandboxed test run
            self.assertIn(d.status, (502, 403))
        with self.assertRaises(g.Deny):
            run(self.c, "POST", "/fetch", J(url=url))  # used

    def test_private_targets_refused_even_when_approved(self):
        for url in ("http://127.0.0.1:4747/config", "http://10.231.0.1/", "http://169.254.169.254/latest"):
            approvals.write_approval("url", url, 60, base=os.path.join(self.tmp, "approvals"))
            with self.assertRaises(g.Deny):
                run(self.c, "POST", "/fetch", J(url=url))

    def test_request_is_recorded(self):
        out = run(self.c, "POST", "/request", J(url="https://example.com/a", reason="tax form"))
        self.assertEqual(out.status, 202)
        with open(os.path.join(self.tmp, "state", "requests.jsonl")) as f:
            self.assertIn("example.com/a", f.read())


class Api(unittest.TestCase):
    def test_route_allowlist(self):
        c = cfg("api")
        for m, p in (("GET", "/global/health"), ("POST", "/session"), ("POST", "/session/ses_1/message"),
                     ("GET", "/event"), ("GET", "/session/ses_1")):
            self.assertIsInstance(run(c, m, p, b"{}"), g.Forward)
        for m, p in (("POST", "/mcp"), ("POST", "/session/ses_1/shell"), ("POST", "/pty"), ("PATCH", "/global/config"),
                     ("PATCH", "/config"), ("POST", "/global/upgrade"), ("PUT", "/auth/venice"),
                     ("POST", "/experimental/worktree"), ("POST", "/session/ses_1/command")):
            with self.assertRaises(g.Deny, msg=f"{m} {p}"):
                run(c, m, p, b"{}")


class Upstream(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def _any(self):
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n)
        Upstream.seen.append({"method": self.command, "path": self.path, "auth": self.headers.get("authorization"),
                              "body": body})
        if self.command == "GET" and "/drafts/" in self.path:
            data = json.dumps({"draft_id": "d1", "to": ["lead@x.com"], "subject": "Hi", "text": "body"}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("set-cookie", "upstream=secret")
        self.end_headers()
        for i in range(3):
            self.wfile.write(f"data: chunk{i}\n\n".encode())
            self.wfile.flush()
            time.sleep(0.05)

    do_GET = do_POST = do_DELETE = do_PATCH = _any


def serve(handler):
    s = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.up = serve(Upstream)
        upurl = f"http://127.0.0.1:{cls.up.server_port}"
        cls.venice = serve(g.make_handler(cfg("venice", UPSTREAM_URL=upurl)))
        cls.mail = serve(g.make_handler(cfg("agentmail", cls.tmp, UPSTREAM_URL=upurl)))
        cls.api = serve(g.make_handler(cfg("api", UPSTREAM_URL=upurl)))

    def req(self, server, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.read()

    def test_venice_reserialises_and_injects_key(self):
        Upstream.seen.clear()
        raw = '{"model": "zai-org-glm-5-2",   "messages": [], "stream": true}'
        st, hdrs, data = self.req(self.venice, "POST", "/api/v1/chat/completions?leak=x", raw,
                                  {"content-type": "application/json", "authorization": "Bearer caller", "cookie": "a"})
        self.assertEqual(st, 200)
        self.assertEqual(data, b"data: chunk0\n\ndata: chunk1\n\ndata: chunk2\n\n")
        seen = Upstream.seen[-1]
        self.assertEqual(seen["auth"], "Bearer real-key-not-for-callers")
        self.assertEqual(seen["path"], "/api/v1/chat/completions")
        self.assertEqual(json.loads(seen["body"]), {"model": "zai-org-glm-5-2", "messages": [], "stream": True})
        self.assertNotEqual(seen["body"], raw.encode())
        self.assertNotIn("set-cookie", hdrs)

    def test_repeated_headers_refused(self):
        c = http.client.HTTPConnection("127.0.0.1", self.venice.server_port, timeout=10)
        c.putrequest("POST", "/api/v1/chat/completions")
        c.putheader("content-type", "application/json")
        c.putheader("content-type", "text/plain")
        c.putheader("content-length", "2")
        c.endheaders(b"{}")
        self.assertEqual(c.getresponse().status, 400)

    def test_agentmail_send_flow_end_to_end(self):
        Upstream.seen.clear()
        st, _, _ = self.req(self.mail, "POST", f"{BASE}/drafts/d1/send", b"")
        self.assertEqual(st, 403)
        self.assertFalse([s for s in Upstream.seen if s["method"] == "POST"])
        st, _, data = self.req(self.mail, "GET", "/_jill/drafts/d1/digest")
        digest = json.loads(data)["sha256"]
        approvals.write_approval("draft", "d1", 60, {"sha256": digest}, base=os.path.join(self.tmp, "approvals"))
        st, _, _ = self.req(self.mail, "POST", f"{BASE}/drafts/d1/send", b"")
        self.assertEqual(st, 200)
        posts = [s for s in Upstream.seen if s["method"] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]["path"], f"{BASE}/drafts/d1/send")
        st, _, _ = self.req(self.mail, "POST", f"{BASE}/drafts/d1/send", b"")
        self.assertEqual(st, 403)

    def test_api_needs_password_and_blocks_mcp(self):
        auth = {"authorization": "Basic " + base64.b64encode(b"opencode:api-pw").decode()}
        self.assertEqual(self.req(self.api, "GET", "/global/health")[0], 401)
        self.assertEqual(self.req(self.api, "GET", "/global/health", headers=auth)[0], 200)
        st, _, _ = self.req(self.api, "POST", "/mcp", json.dumps({"name": "z", "config": {"type": "local", "command": ["id"]}}),
                            dict(auth, **{"content-type": "application/json"}))
        self.assertEqual(st, 403)


class Cli(unittest.TestCase):
    def test_cli_round_trip(self):
        tmp = tempfile.mkdtemp()
        env = dict(os.environ, APPROVALS_DIR=tmp)
        cli = [sys.executable, os.path.join(HERE, "..", "..", "gateway", "approvals.py")]
        subprocess.run(cli + ["approve-url", "https://example.com/x", "--ttl", "30"], env=env, check=True, capture_output=True)
        out = subprocess.run(cli + ["list"], env=env, check=True, capture_output=True, text=True).stdout
        self.assertIn("https://example.com/x", out)
        bad = subprocess.run(cli + ["approve-draft", "d1", "--sha256", "nothex"], env=env, capture_output=True)
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
