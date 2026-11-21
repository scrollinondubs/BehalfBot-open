"""venice-proxy as the main control (#49): halt and an unarmed kill switch
refuse model calls, and a daily meter holds a pessimistic amount per call so
the hard ceiling holds under concurrency (red-team round 2: N1, N2, N3, N5,
N6).

    python3 -m unittest discover -s tests/gateway -v
"""
import http.client
import json
import math
import os
import socket
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
CHAT = {"model": MODEL, "messages": [{"role": "user", "content": "hi"}]}


def cfg(tmp, **env):
    e = {"GATEWAY_ROUTE": "venice", "UPSTREAM_KEY": "k", "VENICE_MODELS": MODEL,
         "GATEWAY_STATE_DIR": os.path.join(tmp, "state"), "CONTROL_DIR": os.path.join(tmp, "control")}
    e.update(env)
    os.makedirs(e["CONTROL_DIR"], exist_ok=True)
    return g.load_config(e)


def run(c, body=CHAT):
    ctx = dict(c, raw_path="/api/v1/chat/completions")
    return c["policy"](ctx, "POST", "/api/v1/chat/completions", json.dumps(body).encode())


# --- a configurable fake Venice ---------------------------------------------

UP = {}
LOCK = threading.Lock()


def up_reset(**kw):
    UP.clear()
    UP.update(mode="json", delay=0.0, usage="auto", pad=0, chunks=3, chunk_pad=10, chunk_delay=0.0,
              status=200, hits=[], headers=[], bodies=[], live=0, peak=0)
    UP.update(kw)


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        UP["headers"].append({k.lower(): v for k, v in self.headers.items()})
        b = b'{"data": []}'
        self.send_response(200)
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length") or 0))
        req = json.loads(raw)
        UP["bodies"].append(req)
        with LOCK:
            UP["live"] += 1
            UP["peak"] = max(UP["peak"], UP["live"])
        time.sleep(UP["delay"])
        with LOCK:
            UP["live"] -= 1
        usage = UP["usage"]
        if usage == "auto":  # a usage Venice could really bill: within the hold
            usage = {"prompt_tokens": len(raw), "completion_tokens": req.get("max_completion_tokens", 0)}
        if UP["status"] != 200:
            b = b'{"error": "bad"}'
            self.send_response(UP["status"])
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if UP["mode"] == "json":
            body = {"choices": [{"message": {"content": "x" * UP["pad"]}}]}
            if usage is not None:
                body["usage"] = usage
            b = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        try:
            for _ in range(UP["chunks"]):
                self.wfile.write(b"data: " + json.dumps({"choices": [{"delta": {"content": "y" * UP["chunk_pad"]}}]}).encode()
                                 + b"\n\n")
                self.wfile.flush()
                time.sleep(UP["chunk_delay"])
            if usage is not None:
                self.wfile.write(b"data: " + json.dumps({"choices": [], "usage": usage}).encode() + b"\n\n")
            self.wfile.write(b"data: [DONE]\n\n")
        except OSError:
            pass


class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        cls.up.daemon_threads = True
        threading.Thread(target=cls.up.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.up.shutdown()

    def setUp(self):
        up_reset()
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def gateway(self, **env):
        e = {"UPSTREAM_URL": "http://127.0.0.1:%d" % self.up.server_address[1],
             "VENICE_MAX_REQUESTS_PER_MINUTE": "1000"}
        e.update(env)
        c = cfg(self.tmp.name, **e)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), g.make_handler(c))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return c, srv.server_address[1]

    def call(self, port, body=None, method="POST", path="/api/v1/chat/completions", headers=None):
        raw = json.dumps(body if body is not None else CHAT).encode() if method == "POST" else None
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        h = {"content-type": "application/json"}
        h.update(headers or {})
        conn.request(method, path, body=raw, headers=h)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, data

    def meter(self, c):
        return json.load(open(c["meter"]._path()))

    def parallel(self, port, n, body=None):
        out = []
        threads = [threading.Thread(target=lambda: out.append(self.call(port, body)[0])) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return out

    # N1 ---------------------------------------------------------------------

    def test_n1_parallel_calls_never_pass_the_ceiling(self):
        # The red team's shape: every call really costs $0.84 (600k prompt
        # tokens, whatever the body), upstream is slow, many calls at once.
        for n in (40, 60):
            with self.subTest(n=n):
                up_reset(delay=0.3, usage={"prompt_tokens": 600_000, "completion_tokens": 0})
                self.tmp.cleanup()
                self.tmp = tempfile.TemporaryDirectory()
                c, port = self.gateway(VENICE_MAX_USD_PER_DAY="5", VENICE_MAX_IN_FLIGHT="8")
                codes = self.parallel(port, n)
                rec = self.meter(c)
                self.assertLessEqual(rec["usd"], 5.0, "settled spend passed the ceiling")
                self.assertGreater(codes.count(429), 0)
                self.assertGreater(codes.count(200), 0)
                self.assertEqual(rec["in_flight"], 0)
                self.assertAlmostEqual(rec["held_usd"], 0.0)

    def test_n1_in_flight_cap(self):
        up_reset(delay=0.5)
        c, port = self.gateway(VENICE_MAX_IN_FLIGHT="4", VENICE_MAX_USD_PER_DAY="100")
        codes = self.parallel(port, 8)
        self.assertLessEqual(UP["peak"], 4, "more than VENICE_MAX_IN_FLIGHT calls reached Venice at once")
        self.assertGreater(codes.count(429), 0)
        self.assertEqual(c["meter"].in_flight, 0)

    def test_n1_output_cap_is_injected_and_clamped(self):
        c, port = self.gateway(VENICE_MAX_OUTPUT_TOKENS="1000")
        self.call(port)
        self.call(port, {"model": MODEL, "messages": [], "max_tokens": 50_000})
        self.call(port, {"model": MODEL, "messages": [], "max_completion_tokens": 300})
        first, second, third = UP["bodies"]
        self.assertEqual(first["max_completion_tokens"], 1000)
        self.assertNotIn("max_tokens", first)
        self.assertEqual((second["max_tokens"], second["max_completion_tokens"]), (1000, 1000))
        self.assertEqual(third["max_completion_tokens"], 300)
        status, _ = self.call(port, {"model": MODEL, "messages": [], "max_tokens": -1})
        self.assertEqual(status, 400)

    def test_n1_reasoning_reported_apart_is_charged(self):
        with tempfile.TemporaryDirectory() as d:
            m = g.Meter(d, 5, 100, g.parse_prices(g.DEFAULT_PRICES))
            inside = m.cost(MODEL, {"prompt_tokens": 0, "completion_tokens": 1000,
                                    "completion_tokens_details": {"reasoning_tokens": 800}})
            apart = m.cost(MODEL, {"prompt_tokens": 0, "completion_tokens": 100,
                                   "completion_tokens_details": {"reasoning_tokens": 900}})
            self.assertAlmostEqual(inside, 1000 * 4.40 / 1e6)
            self.assertAlmostEqual(apart, 1000 * 4.40 / 1e6)

    # N2 ---------------------------------------------------------------------

    def test_n2_stream_over_4mb_settles_from_its_usage(self):
        up_reset(mode="sse", chunks=90, chunk_pad=50_000, usage={"prompt_tokens": 10, "completion_tokens": 20})
        c, port = self.gateway()
        status, data = self.call(port, dict(CHAT, stream=True))
        self.assertEqual(status, 200)
        self.assertGreater(len(data), 4 * 1024 * 1024)
        rec = self.meter(c)
        self.assertAlmostEqual(rec["usd"], (10 * 1.40 + 20 * 4.40) / 1e6, places=9)
        self.assertEqual(rec["unmetered"], 0)

    def test_n2_json_over_4mb_settles_from_its_usage(self):
        up_reset(pad=5 * 1024 * 1024, usage={"prompt_tokens": 10, "completion_tokens": 20})
        c, port = self.gateway()
        self.assertEqual(self.call(port)[0], 200)
        self.assertAlmostEqual(self.meter(c)["usd"], (10 * 1.40 + 20 * 4.40) / 1e6, places=9)

    def test_n2_missing_usage_is_charged_the_full_hold(self):
        up_reset(usage=None)
        c, port = self.gateway()
        self.call(port)
        rec = self.meter(c)
        hold = c["meter"].hold_for(MODEL, len(json.dumps(dict(CHAT, max_completion_tokens=8192))))
        self.assertAlmostEqual(rec["usd"], hold, places=6)
        self.assertGreater(rec["usd"], 0.03)
        self.assertEqual(rec["unmetered"], 1)

    def hangup(self, port, body):
        s = socket.create_connection(("127.0.0.1", port))
        raw = json.dumps(body).encode()
        s.sendall(b"POST /api/v1/chat/completions HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\n"
                  b"content-length: %d\r\n\r\n" % len(raw) + raw)
        s.recv(100)
        s.close()

    def wait_settled(self, c):
        for _ in range(100):
            if c["meter"].in_flight == 0:
                return
            time.sleep(0.1)

    def test_n2_mid_stream_hangup_still_reads_the_usage(self):
        up_reset(mode="sse", chunks=20, chunk_pad=20_000, chunk_delay=0.05,
                 usage={"prompt_tokens": 10, "completion_tokens": 20})
        c, port = self.gateway()
        self.hangup(port, dict(CHAT, stream=True))
        time.sleep(0.3)
        self.wait_settled(c)
        rec = self.meter(c)
        self.assertAlmostEqual(rec["usd"], (10 * 1.40 + 20 * 4.40) / 1e6, places=9)

    def test_n2_hangup_past_the_drain_bound_charges_the_hold(self):
        up_reset(mode="sse", chunks=40, chunk_pad=10, chunk_delay=0.1, usage={"prompt_tokens": 1, "completion_tokens": 1})
        old = g.DRAIN_SECONDS
        g.DRAIN_SECONDS = 0.5
        self.addCleanup(setattr, g, "DRAIN_SECONDS", old)
        c, port = self.gateway()
        self.hangup(port, dict(CHAT, stream=True))
        time.sleep(0.3)
        self.wait_settled(c)
        self.assertGreater(self.meter(c)["usd"], 0.03, "an unfinished stream must be charged the hold")

    # N3 ---------------------------------------------------------------------

    def test_n3_per_minute_rate_limit(self):
        up_reset(status=400)
        c, port = self.gateway(VENICE_MAX_REQUESTS_PER_MINUTE="30")
        codes = [self.call(port)[0] for _ in range(35)]
        self.assertEqual(codes.count(400), 30)
        self.assertEqual(codes.count(429), 5)
        self.assertEqual(self.meter(c)["usd"], 0)

    def test_n3_reset_meter_request_zeroes_today_once(self):
        up_reset(usage={"prompt_tokens": 1_000_000, "completion_tokens": 0})
        c, port = self.gateway(VENICE_MAX_USD_PER_DAY="2")
        self.assertEqual(self.call(port)[0], 200)
        self.assertEqual(self.call(port)[0], 429)
        g.safe_write_json(os.path.join(c["control_dir"], "meter-reset.json"), {"requested_at": time.time()})
        self.assertEqual(self.call(port)[0], 200)
        rec = self.meter(c)
        self.assertEqual(rec["requests"], 1)
        self.assertIn("reset_applied_at", rec)

    # N5 ---------------------------------------------------------------------

    def test_n5_models_is_gated_counted_and_strips_caller_headers(self):
        c, port = self.gateway()
        status, _ = self.call(port, method="GET", path="/api/v1/models",
                              headers={"accept": "x/evil", "mcp-session-id": "s", "x-evil": "1"})
        self.assertEqual(status, 200)
        sent = UP["headers"][-1]
        for h in ("accept", "mcp-session-id", "x-evil"):
            self.assertNotEqual(sent.get(h), {"accept": "x/evil", "mcp-session-id": "s", "x-evil": "1"}[h])
        self.assertEqual(self.meter(c)["requests"], 1)
        flags.write(os.path.join(c["control_dir"], "halt.json"), True, "t", None, None)
        self.assertEqual(self.call(port, method="GET", path="/api/v1/models")[0], 423)

    # N6 ---------------------------------------------------------------------

    def test_n6_bad_content_length_is_refused(self):
        c, port = self.gateway()
        for value in (b"-5", b"abc", b"1e3"):
            s = socket.create_connection(("127.0.0.1", port))
            s.sendall(b"POST /api/v1/chat/completions HTTP/1.1\r\nhost: x\r\ncontent-length: " + value + b"\r\n\r\n{}")
            self.assertIn(b" 400 ", s.recv(200), value)
            s.close()


class Gate(unittest.TestCase):
    def test_halt_refuses_chat(self):
        with tempfile.TemporaryDirectory() as d:
            c = cfg(d)
            run(c)
            flags.write(os.path.join(c["control_dir"], "halt.json"), True, "t", None, "r")
            with self.assertRaises(g.Deny) as e:
                run(c)
            self.assertEqual(e.exception.status, 423)

    def test_n6_halt_without_or_with_bad_enabled_is_halted(self):
        with tempfile.TemporaryDirectory() as d:
            c = cfg(d)
            for doc in ("{}", '{"reason": "x"}', '{"enabled": "false"}', '{"enabled": 0}'):
                with open(os.path.join(c["control_dir"], "halt.json"), "w") as f:
                    f.write(doc)
                with self.assertRaises(g.Deny, msg=doc):
                    run(c)

    def test_unarmed_refuses_and_default_age_is_90s(self):
        with tempfile.TemporaryDirectory() as d:
            c = cfg(d, CONTROL_REQUIRE_ARMED="1")
            self.assertEqual(c["armed_max_age"], 90)
            with self.assertRaises(g.Deny):
                run(c)
            g.safe_write_json(os.path.join(c["control_dir"], "armed.json"), {"armed_at": time.time()})
            run(c)
            g.safe_write_json(os.path.join(c["control_dir"], "armed.json"), {"armed_at": time.time() - 120})
            with self.assertRaises(g.Deny):
                run(c)

    def test_n6_boot_refuses_unpriced_models_and_non_finite_ceilings(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit):
                cfg(d, VENICE_MODELS=MODEL + ",deepseek-v4-pro")
            for bad in ("nan", "inf", "-1"):
                with self.assertRaises(SystemExit, msg=bad):
                    cfg(d, VENICE_MAX_USD_PER_DAY=bad)
            self.assertNotIn("x", g.parse_prices("x=nan:1:1"))

    def test_n6_cost_overflow_and_garbage_are_unusable(self):
        with tempfile.TemporaryDirectory() as d:
            m = g.Meter(d, 5, 100, g.parse_prices(g.DEFAULT_PRICES))
            self.assertIsNone(m.cost(MODEL, {"prompt_tokens": 10 ** 400, "completion_tokens": 1}))
            self.assertIsNone(m.cost(MODEL, {"prompt_tokens": -5, "completion_tokens": 1}))
            self.assertIsNone(m.cost(MODEL, {"prompt_tokens": "9", "completion_tokens": 1}))
            self.assertIsNone(m.cost(MODEL, {"prompt_tokens": 0, "completion_tokens": 0}), "zero usage is unusable")

    def test_unreadable_meter_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            m = g.Meter(d, 5, 100, g.parse_prices(g.DEFAULT_PRICES))
            hold, day = m.reserve(MODEL, 10)
            m.settle(MODEL, hold, 200, {"prompt_tokens": 1, "completion_tokens": 1}, day)
            with open(m._path(), "w") as f:
                f.write("{broken")
            with self.assertRaises(g.Deny) as e:
                m.reserve(MODEL, 10)
            self.assertEqual(e.exception.status, 503)
            g.safe_write_json(m._path(), {"requests": 1, "usd": float("nan")})
            with self.assertRaises(g.Deny):
                m.reserve(MODEL, 10)


if __name__ == "__main__":
    unittest.main()


class Rollover(unittest.TestCase):
    def test_a_call_settles_on_the_day_it_was_reserved(self):
        with tempfile.TemporaryDirectory() as d:
            now = [1_700_000_000 - (1_700_000_000 % 86400) + 86399]  # 23:59:59 UTC
            m = g.Meter(d, 5, 100, g.parse_prices(g.DEFAULT_PRICES), clock=lambda: now[0])
            hold, day = m.reserve(MODEL, 10)
            now[0] += 2
            m.settle(MODEL, hold, 200, {"prompt_tokens": 1_000_000, "completion_tokens": 0}, day)
            self.assertAlmostEqual(json.load(open(m._path(day)))["usd"], 1.40)
            self.assertFalse(os.path.exists(m._path()), "the new day must start clean")
