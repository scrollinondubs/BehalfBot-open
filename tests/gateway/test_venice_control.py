"""venice-proxy as the main control (#49, red-team F1): halt and an unarmed
kill switch refuse chat model calls, and a daily meter enforces a hard
spend and request ceiling from the responses' own usage.

    python3 -m unittest discover -s tests/gateway -v
"""
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "gateway"))
import control_flags as flags  # noqa: E402
import gateway as g  # noqa: E402

MODEL = "zai-org-glm-5-2"
CHAT = json.dumps({"model": MODEL, "messages": [{"role": "user", "content": "hi"}]}).encode()


def cfg(tmp, **env):
    e = {"GATEWAY_ROUTE": "venice", "UPSTREAM_KEY": "k", "VENICE_MODELS": MODEL,
         "GATEWAY_STATE_DIR": os.path.join(tmp, "state"), "CONTROL_DIR": os.path.join(tmp, "control")}
    e.update(env)
    os.makedirs(e["CONTROL_DIR"], exist_ok=True)
    return g.load_config(e)


def run(c, body=CHAT):
    ctx = dict(c, raw_path="/api/v1/chat/completions")
    return c["policy"](ctx, "POST", "/api/v1/chat/completions", body)


class Gate(unittest.TestCase):
    def test_halt_refuses_chat(self):
        with tempfile.TemporaryDirectory() as d:
            c = cfg(d)
            run(c)
            flags.write(os.path.join(c["control_dir"], "halt.json"), True, "t", None, "r")
            with self.assertRaises(g.Deny) as e:
                run(c)
            self.assertEqual(e.exception.status, 423)
            flags.write(os.path.join(c["control_dir"], "halt.json"), True, "t", "2001-01-01T00:00:00Z", "r")
            run(c)  # expired auto-lift reads as off

    def test_garbage_halt_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            c = cfg(d)
            with open(os.path.join(c["control_dir"], "halt.json"), "w") as f:
                f.write("{nope")
            with self.assertRaises(g.Deny):
                run(c)

    def test_models_list_is_not_gated(self):
        with tempfile.TemporaryDirectory() as d:
            c = cfg(d)
            flags.write(os.path.join(c["control_dir"], "halt.json"), True, "t", None, "r")
            ctx = dict(c, raw_path="/api/v1/models")
            self.assertEqual(c["policy"](ctx, "GET", "/api/v1/models", b"").path, "/api/v1/models")

    def test_unarmed_refuses_and_missing_mount_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            c = cfg(d, CONTROL_REQUIRE_ARMED="1")
            with self.assertRaises(g.Deny) as e:
                run(c)
            self.assertEqual(e.exception.status, 503)
            g.safe_write_json(os.path.join(c["control_dir"], "armed.json"), {"armed_at": time.time()})
            run(c)
            g.safe_write_json(os.path.join(c["control_dir"], "armed.json"), {"armed_at": time.time() - 3600})
            with self.assertRaises(g.Deny):
                run(c)
            c2 = cfg(d, CONTROL_DIR=os.path.join(d, "control"))
            c2["control_dir"] = os.path.join(d, "not-mounted")
            with self.assertRaises(g.Deny):
                run(c2)

    def test_stream_requests_ask_for_usage(self):
        with tempfile.TemporaryDirectory() as d:
            body = json.dumps({"model": MODEL, "messages": [], "stream": True,
                               "stream_options": {"include_usage": False}}).encode()
            fwd = run(cfg(d), body)
            self.assertEqual(fwd.body["stream_options"], {"include_usage": True})


class MeterUnit(unittest.TestCase):
    def meter(self, d, **kw):
        args = dict(max_usd=1.0, max_requests=100, prices=g.parse_prices(g.DEFAULT_PRICES), unmetered_usd=0.05)
        args.update(kw)
        return g.Meter(d, **args)

    def test_cost_from_usage_and_cached_tokens(self):
        with tempfile.TemporaryDirectory() as d:
            m = self.meter(d)
            self.assertAlmostEqual(m.cost(MODEL, {"prompt_tokens": 1_000_000, "completion_tokens": 0}), 1.40)
            self.assertAlmostEqual(m.cost(MODEL, {"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000,
                                                  "prompt_tokens_details": {"cached_tokens": 1_000_000}}), 0.26 + 4.40)
            self.assertIsNone(m.cost(MODEL, {"prompt_tokens": -5, "completion_tokens": 1}))
            self.assertIsNone(m.cost(MODEL, {"prompt_tokens": "9", "completion_tokens": 1}))
            self.assertEqual(m.price("unknown-model"), (1.40, 4.40, 0.26), "unlisted models pay the top rate")

    def test_hard_usd_ceiling(self):
        with tempfile.TemporaryDirectory() as d:
            m = self.meter(d)
            m.reserve()
            m.settle(MODEL, 200, {"prompt_tokens": 1_000_000, "completion_tokens": 0})
            with self.assertRaises(g.Deny) as e:
                m.reserve()
            self.assertEqual(e.exception.status, 429)

    def test_request_ceiling_and_unmetered_charge(self):
        with tempfile.TemporaryDirectory() as d:
            m = self.meter(d, max_requests=2)
            m.reserve()
            m.settle(MODEL, 200, None)
            m.reserve()
            with self.assertRaises(g.Deny):
                m.reserve()
            rec = json.load(open(m._path()))
            self.assertEqual(rec["requests"], 2)
            self.assertAlmostEqual(rec["usd"], 0.05)
            self.assertEqual(rec["unmetered"], 1)
            self.assertEqual(rec["ceiling_usd"], 1.0)

    def test_unreadable_meter_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            m = self.meter(d)
            m.reserve()
            with open(m._path(), "w") as f:
                f.write("{broken")
            with self.assertRaises(g.Deny) as e:
                m.reserve()
            self.assertEqual(e.exception.status, 503)
            g.safe_write_json(m._path(), {"requests": 1, "usd": -3})
            with self.assertRaises(g.Deny):
                m.reserve()

    def test_tap_reads_json_and_sse_usage(self):
        with tempfile.TemporaryDirectory() as d:
            m = self.meter(d)
            t = g.UsageTap(m, MODEL)
            t.feed(b'{"choices": [], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}')
            self.assertEqual(t.usage()["prompt_tokens"], 10)
            t = g.UsageTap(m, MODEL)
            for line in (b'data: {"choices":[{"delta":{"content":"hi"}}]}\n\n',
                         b'data: {"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}\n\n',
                         b"data: [DONE]\n\n"):
                t.feed(line)
            self.assertEqual(t.usage()["completion_tokens"], 3)


class MeterLive(unittest.TestCase):
    """Through the real handler against a fake Venice."""

    @classmethod
    def setUpClass(cls):
        class Up(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("content-length") or 0))
                body = json.dumps({"choices": [], "usage": {"prompt_tokens": 600_000, "completion_tokens": 0}}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        cls.up = ThreadingHTTPServer(("127.0.0.1", 0), Up)
        threading.Thread(target=cls.up.serve_forever, daemon=True).start()
        cls.tmp = tempfile.TemporaryDirectory()
        c = cfg(cls.tmp.name, UPSTREAM_URL="http://127.0.0.1:%d" % cls.up.server_address[1],
                VENICE_MAX_USD_PER_DAY="1")
        cls.cfg = c
        cls.gw = ThreadingHTTPServer(("127.0.0.1", 0), g.make_handler(c))
        threading.Thread(target=cls.gw.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.gw.shutdown()
        cls.up.shutdown()
        cls.tmp.cleanup()

    def post(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.gw.server_address[1], timeout=10)
        conn.request("POST", "/api/v1/chat/completions", body=CHAT, headers={"content-type": "application/json"})
        r = conn.getresponse()
        r.read()
        conn.close()
        return r.status

    def test_ceiling_binds_at_the_gateway(self):
        self.assertEqual(self.post(), 200)  # $0.84
        self.assertEqual(self.post(), 200)  # $1.68 (was under the ceiling when it started)
        self.assertEqual(self.post(), 429)
        rec = json.load(open(self.cfg["meter"]._path()))
        self.assertAlmostEqual(rec["usd"], 1.68, places=4)
        self.assertEqual(rec["requests"], 2)


if __name__ == "__main__":
    unittest.main()
