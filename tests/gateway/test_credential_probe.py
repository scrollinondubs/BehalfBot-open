"""Credential probe in gateway/gateway.py (Jill v2 C, #49).

    python3 -m unittest discover -s tests/gateway -v
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "gateway"))
import gateway as g  # noqa: E402

KEY = "real-key-not-for-callers"


def cfg(route, tmp, **env):
    e = {"GATEWAY_ROUTE": route, "UPSTREAM_KEY": KEY, "CREDENTIAL_STATUS_DIR": tmp}
    if route == "venice":
        e["VENICE_MODELS"] = "zai-org-glm-5-2"
    if route == "agentmail":
        e["AGENTMAIL_INBOX"] = "jill-agent@agentmail.to"
    if route == "siyuan":
        e["UPSTREAM_URL"] = "http://127.0.0.1:1"
    e.update(env)
    return g.load_config(e)


class Probe(unittest.TestCase):
    def test_result_mapping(self):
        with tempfile.TemporaryDirectory() as d:
            c = cfg("venice", d)
            self.assertEqual(g.probe_once(c, lambda m, p, b: 200), ("ok", 200))
            self.assertEqual(g.probe_once(c, lambda m, p, b: 401), ("rejected", 401))
            self.assertEqual(g.probe_once(c, lambda m, p, b: 403), ("rejected", 403))
            self.assertEqual(g.probe_once(c, lambda m, p, b: 503), ("error", 503))

            def down(m, p, b):
                raise g.Deny(502, "upstream unreachable")

            self.assertEqual(g.probe_once(c, down), ("error", 0))

    def test_each_route_probes_a_read_only_authenticated_endpoint(self):
        seen = {}
        with tempfile.TemporaryDirectory() as d:
            for route in ("venice", "agentmail", "siyuan"):
                g.probe_once(cfg(route, d), lambda m, p, b, r=route: seen.setdefault(r, (m, p)) and 200)
        self.assertEqual(seen["venice"], ("GET", "/api/v1/api_keys/rate_limits"))
        self.assertEqual(seen["agentmail"], ("GET", "/v0/inboxes/jill-agent@agentmail.to"))
        self.assertEqual(seen["siyuan"], ("POST", "/api/notebook/lsNotebooks"))

    def test_status_record_is_status_only_and_keeps_last_ok(self):
        with tempfile.TemporaryDirectory() as d:
            c = cfg("venice", d)
            g.write_probe(c, "ok", 200, now=1000)
            rec = g.write_probe(c, "rejected", 401, now=2000)
            self.assertEqual(rec["last_ok_at"], 1000)
            raw = open(os.path.join(d, "venice.json")).read()
            self.assertNotIn(KEY, raw)
            self.assertEqual(set(json.loads(raw)), {"route", "result", "http_status", "checked_at", "last_ok_at"})

    def test_routes_without_a_probe_and_unset_dir(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertNotIn("fetch", g.PROBES)
            self.assertNotIn("api", g.PROBES)
        c = g.load_config({"GATEWAY_ROUTE": "venice", "UPSTREAM_KEY": KEY, "VENICE_MODELS": "m"})
        self.assertIsNone(c["credential_dir"])


if __name__ == "__main__":
    unittest.main()
