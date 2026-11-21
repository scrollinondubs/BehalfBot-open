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
    if route == "venice" and not tmp:
        e["GATEWAY_STATE_DIR"] = tempfile.mkdtemp(prefix="gw-meter-")
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
        self.ctx = dict(self.c, raw_path="", upstream_json=lambda *a: {})
        self.draft = {"to": ["lead@x.com"], "subject": "Hi", "text": "body"}
        g.save_snapshot(self.ctx, "d1", self.draft)
        self.adir = os.path.join(self.tmp, "approvals")

    def deny(self, method, raw, body=b""):
        with self.assertRaises(g.Deny, msg=f"{method} {raw} {body[:90]!r}"):
            run(self.c, method, raw, body)

    def approve(self, content=None, ttl=60):
        approvals.write_approval("draft", "d1", ttl, {"sha256": approvals.draft_digest(content or self.draft)},
                                 base=self.adir)

    def send(self):
        f = run(self.c, "POST", BASE + "/drafts/d1/send", b"")
        if f.release:
            f.release()
        return f

    def test_reads_allowed_in_her_inbox_only(self):
        for p in ("", "/threads", "/threads/t1", "/messages/m1", "/drafts", "/drafts/d1", "/messages/m1/attachments/a1"):
            self.assertIsInstance(run(self.c, "GET", BASE + p + "?limit=5"), g.Forward)
        self.deny("GET", f"{BASE}/threads?evil=1")
        self.deny("GET", "/v0/inboxes/other@agentmail.to/threads")
        self.deny("GET", "/v0/api-keys")

    def test_drafts_to_anyone_but_no_scheduling_or_unknown_fields(self):
        f = run(self.c, "POST", BASE + "/drafts", J(to=["lead@x.com"], subject="s", text="t"))
        self.assertEqual(f.body, {"to": ["lead@x.com"], "subject": "s", "text": "t"})
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

    def test_send_delivers_the_approved_snapshot_once(self):
        self.deny("POST", BASE + "/drafts/d1/send")  # no approval
        self.approve()
        f = self.send()
        self.assertEqual(f.path, BASE + "/messages/send")
        self.assertEqual(f.body, self.draft)
        self.deny("POST", BASE + "/drafts/d1/send")  # one approval, one send

    def test_a_refused_attempt_burns_the_approval(self):
        self.approve()
        g.save_snapshot(self.ctx, "d1", dict(self.draft, to=["attacker@evil.example"]))
        self.deny("POST", BASE + "/drafts/d1/send")  # content differs
        g.save_snapshot(self.ctx, "d1", self.draft)  # restore and retry
        self.deny("POST", BASE + "/drafts/d1/send")  # burned: no free retry
        self.approve(ttl=1)
        time.sleep(1.2)
        self.deny("POST", BASE + "/drafts/d1/send")  # expired

    def test_edits_frozen_while_an_approval_is_live(self):
        self.approve()
        self.deny("PATCH", BASE + "/drafts/d1", J(to=["attacker@evil.example"]))
        self.deny("DELETE", BASE + "/drafts/d1")
        self.send()
        f = run(self.c, "PATCH", BASE + "/drafts/d1", J(text="after the send"))  # used: editable again
        f.release()

    def test_drafts_not_written_through_the_gateway_cannot_be_sent(self):
        approvals.write_approval("draft", "elsewhere", 60, {"sha256": "0" * 64}, base=self.adir)
        self.deny("POST", BASE + "/drafts/elsewhere/send")

    def test_digest_covers_every_deliverable_field_and_attachment_bytes(self):
        base_ = dict(self.draft, attachments=[{"filename": "a.pdf", "content_type": "application/pdf", "content": "QUJD"}])
        d0 = approvals.draft_digest(base_)
        for change in ({"attachments": [{"filename": "a.pdf", "content_type": "application/pdf", "content": "WFla"}]},
                       {"in_reply_to": "<m1@x>"}, {"labels": ["x"]}, {"reply_to": ["e@x.com"]}, {"html": "<p>x</p>"},
                       {"bcc": ["e@x.com"]}):
            self.assertNotEqual(approvals.draft_digest(dict(base_, **change)), d0, change)
        out = run(self.c, "GET", "/_jill/drafts/d1/digest")
        self.assertEqual(out.obj["sha256"], approvals.draft_digest(self.draft))
        self.assertEqual(out.obj["content"], self.draft)

    def test_control_characters_refused_in_every_header_bound_field(self):
        bad = [
            J(to=["sean@grid7.com\n"]), J(to=["sean@grid7.com\x00"]), J(to=["\tsean@grid7.com"]),
            J(subject="hi\r\nBcc: attacker@evil.example"), J(subject="a\x00b"), J(labels=["x\ny"]),
            J(in_reply_to="<a@b>\r\nBcc: attacker@evil.example"), J(in_reply_to="a@b"), J(in_reply_to="<a@b> <c@d>"),
            J(attachments=[{"filename": "a\r\nX: y", "content": "QUJD"}]),
            J(attachments=[{"content_type": "text/plain\n", "content": "QUJD"}]),
            J(attachments=[{"filename": "a", "content": "not base64!"}]),
            J(text="ok\x00"), J(html="<p>\x1b[31m</p>"),
            J(attachments=5), J(attachments=[5]), J(attachments=[{"filename": 5}]), J(labels="x"), J(subject=5),
        ]
        for body in bad:
            self.deny("POST", BASE + "/drafts", body)
            self.deny("PATCH", BASE + "/drafts/d1", body)

    def test_addresses_and_bodies_are_normalised_and_forwarded_normalised(self):
        f = run(self.c, "POST", BASE + "/drafts",
                J(to=[" Lead@Example.COM "], cc="Sean@GRID7.com", text="line 1\nline 2\ttabbed", in_reply_to="<m1@x>"))
        self.assertEqual(f.body, {"to": ["Lead@example.com"], "cc": "Sean@grid7.com",
                                  "text": "line 1\nline 2\ttabbed", "in_reply_to": "<m1@x>"})

    def test_post_cannot_overwrite_a_live_approved_snapshot(self):
        self.approve()
        f = run(self.c, "POST", BASE + "/drafts", J(to=["attacker@evil.example"], subject="x"))
        with self.assertRaises(g.Deny):
            f.after(200, json.dumps({"draft_id": "d1"}).encode())  # upstream reuses the id
        self.assertEqual(g.load_snapshot(self.ctx, "d1"), self.draft)

    def test_lock_map_is_bounded(self):
        self.assertEqual(len({id(g.draft_lock(f"x{i}")) for i in range(5000)}), len(g._STRIPES))
        self.assertIs(g.draft_lock("same"), g.draft_lock("same"))

    def test_old_snapshots_are_pruned(self):
        for i in range(3):
            g.save_snapshot(self.ctx, f"old{i}", self.draft)
        old = g._snapshot_path(self.ctx, "old0")
        os.utime(old, (time.time() - g.SNAPSHOT_TTL - 10,) * 2)
        g.save_snapshot(self.ctx, "fresh", self.draft)
        self.assertFalse(os.path.exists(old))
        self.assertIsNotNone(g.load_snapshot(self.ctx, "old1"))

    def test_in_reply_to_becomes_threading_headers(self):
        self.assertEqual(g.send_body({"to": ["a@x.com"], "in_reply_to": "<m1@x>"}),
                         {"to": ["a@x.com"], "headers": {"In-Reply-To": "<m1@x>", "References": "<m1@x>"}})


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
        self.assertEqual(json.loads(seen["body"]), {"model": "zai-org-glm-5-2", "messages": [], "stream": True,
                                                  "stream_options": {"include_usage": True},
                                                  "max_completion_tokens": 8192, "max_tokens": 8192})
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

    def test_api_needs_password_and_blocks_mcp(self):
        auth = {"authorization": "Basic " + base64.b64encode(b"opencode:api-pw").decode()}
        self.assertEqual(self.req(self.api, "GET", "/global/health")[0], 401)
        self.assertEqual(self.req(self.api, "GET", "/global/health", headers=auth)[0], 200)
        st, _, _ = self.req(self.api, "POST", "/mcp", json.dumps({"name": "z", "config": {"type": "local", "command": ["id"]}}),
                            dict(auth, **{"content-type": "application/json"}))
        self.assertEqual(st, 403)


class FakeAgentMail(BaseHTTPRequestHandler):
    """Stateful: drafts can be created and patched; sends are recorded as delivered."""
    drafts = {}
    delivered = []
    lock = threading.Lock()
    counter = [0]

    def log_message(self, *a):
        pass

    def _reply(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _any(self):
        n = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        with self.lock:
            if self.command == "POST" and self.path.endswith("/drafts"):
                self.counter[0] += 1
                did = f"d{self.counter[0]}"
                self.drafts[did] = body
                return self._reply({"draft_id": did})
            if self.command == "PATCH" and "/drafts/" in self.path:
                did = self.path.rsplit("/", 1)[1]
                self.drafts.setdefault(did, {}).update(body)
                return self._reply({"draft_id": did})
            if self.command == "DELETE" and "/drafts/" in self.path:
                self.drafts.pop(self.path.rsplit("/", 1)[1], None)
                return self._reply({})
            if self.command == "POST" and self.path.endswith("/messages/send"):
                self.delivered.append(body)
                return self._reply({"message_id": f"m{len(self.delivered)}"})
            if self.command == "POST" and self.path.endswith("/send"):
                # what the round-2 design did: AgentMail sends its CURRENT draft
                did = self.path.split("/drafts/")[1].split("/")[0]
                self.delivered.append(dict(self.drafts.get(did, {})))
                return self._reply({"message_id": "m"})
        self._reply({})

    do_GET = do_POST = do_PATCH = do_DELETE = _any


class DraftSendRace(unittest.TestCase):
    """Round-3 red-team C1 as a regression: parallel PATCH + send attempts
    against approved drafts must never deliver anything Sean did not approve."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.up = serve(FakeAgentMail)
        cls.mail = serve(g.make_handler(cfg("agentmail", cls.tmp, UPSTREAM_URL=f"http://127.0.0.1:{cls.up.server_port}")))

    def req(self, method, path, obj=None):
        c = http.client.HTTPConnection("127.0.0.1", self.mail.server_port, timeout=20)
        body = json.dumps(obj) if obj is not None else None
        c.request(method, path, body=body, headers={"content-type": "application/json"} if body else {})
        r = c.getresponse()
        return r.status, r.read()

    def test_parallel_patch_and_send_never_deliver_changed_content(self):
        approved_contents = []
        for rnd in range(25):
            good = {"to": [SEAN], "subject": f"Weekly summary {rnd}", "text": "benign"}
            st, data = self.req("POST", f"{BASE}/drafts", good)
            self.assertEqual(st, 200)
            did = json.loads(data)["draft_id"]
            st, data = self.req("GET", f"/_jill/drafts/{did}/digest")
            digest = json.loads(data)["sha256"]
            approvals.write_approval("draft", did, 60, {"sha256": digest}, base=os.path.join(self.tmp, "approvals"))
            approved_contents.append(good)
            evil = {"to": ["attacker@evil.example"], "subject": "exfil", "text": "FAKE-NOTES-CONTENT"}
            results = []

            def patch():
                for _ in range(5):
                    results.append(("patch", self.req("PATCH", f"{BASE}/drafts/{did}", evil)[0]))

            def send():
                for _ in range(3):
                    results.append(("send", self.req("POST", f"{BASE}/drafts/{did}/send")[0]))

            threads = [threading.Thread(target=f) for f in (patch, send, patch, send, patch)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            sends_ok = [r for r in results if r == ("send", 200)]
            self.assertLessEqual(len(sends_ok), 1, f"round {rnd}: one approval sent more than once")
        for msg in FakeAgentMail.delivered:
            self.assertIn(msg, approved_contents, "a delivered message differs from everything Sean approved")
            self.assertNotIn("attacker@evil.example", json.dumps(msg))
        self.assertGreater(len(FakeAgentMail.delivered), 0)


class SendCleanup(unittest.TestCase):
    def test_draft_and_snapshot_removed_after_a_send(self):
        tmp = tempfile.mkdtemp()
        up = serve(FakeAgentMail)
        mail = serve(g.make_handler(cfg("agentmail", tmp, UPSTREAM_URL=f"http://127.0.0.1:{up.server_port}")))

        def req(method, path, obj=None):
            c = http.client.HTTPConnection("127.0.0.1", mail.server_port, timeout=10)
            body = json.dumps(obj) if obj is not None else None
            c.request(method, path, body=body, headers={"content-type": "application/json"} if body else {})
            r = c.getresponse()
            return r.status, r.read()

        st, data = req("POST", f"{BASE}/drafts", {"to": [SEAN], "subject": "cleanup", "text": "x"})
        did = json.loads(data)["draft_id"]
        digest = json.loads(req("GET", f"/_jill/drafts/{did}/digest")[1])["sha256"]
        approvals.write_approval("draft", did, 60, {"sha256": digest}, base=os.path.join(tmp, "approvals"))
        self.assertEqual(req("POST", f"{BASE}/drafts/{did}/send")[0], 200)
        self.assertNotIn(did, FakeAgentMail.drafts)
        self.assertEqual(req("GET", f"/_jill/drafts/{did}/digest")[0], 404)

    def test_bridge_digest_cli_reads_the_snapshot_mount(self):
        tmp = tempfile.mkdtemp()
        ctx = {"state_dir": tmp}
        content = {"to": [SEAN], "subject": "s", "text": "t"}
        g.save_snapshot(ctx, "d9", content)
        env = dict(os.environ, SNAPSHOT_DIR=os.path.join(tmp, "drafts"))
        cli = [sys.executable, os.path.join(HERE, "..", "..", "gateway", "approvals.py")]
        out = json.loads(subprocess.run(cli + ["digest", "d9"], env=env, check=True, capture_output=True, text=True).stdout)
        self.assertEqual(out["sha256"], approvals.draft_digest(content))
        self.assertEqual(out["content"], content)


class Cli(unittest.TestCase):
    def test_list_shows_used_and_expired(self):
        tmp = tempfile.mkdtemp()
        consumed = os.path.join(tmp, "consumed")
        approvals.write_approval("url", "https://example.com/used", 60, base=tmp)
        approvals.write_approval("url", "https://example.com/live", 60, base=tmp)
        approvals.write_approval("url", "https://example.com/old", 1, base=tmp)
        approvals.check_and_consume("url", "https://example.com/used", consumed, base=tmp)
        time.sleep(1.2)
        env = dict(os.environ, APPROVALS_DIR=tmp, CONSUMED_DIRS=consumed)
        cli = [sys.executable, os.path.join(HERE, "..", "..", "gateway", "approvals.py")]
        out = subprocess.run(cli + ["list"], env=env, check=True, capture_output=True, text=True).stdout
        lines = {l.split("\t")[1]: l.split("\t")[2] for l in out.strip().splitlines()}
        self.assertEqual(lines["https://example.com/used"], "used")
        self.assertEqual(lines["https://example.com/old"], "expired")
        self.assertTrue(lines["https://example.com/live"].startswith("live"))

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
