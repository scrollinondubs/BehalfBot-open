"""Tests for gateway/control.py and gateway/control_flags.py. Stdlib only:

    python3 -m unittest discover -s tests/control -v

The Matrix side runs against a fake homeserver on loopback, so the real
HTTP code path (auth header, txn ids, pagination) is exercised.
"""
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "gateway"))
import control as c  # noqa: E402
import control_flags as flags  # noqa: E402

TOKEN = "syt_fake_control_token"
PRINCIPAL = "@principal:example.org"
ROOM = "!control:example.org"


class FakeHomeserver:
    """Just enough of the client-server API for the control process."""

    def __init__(self):
        self.events = []  # each a dict; position in list is the stream token
        self.sent = []  # (room, body)
        self.encrypted = set()
        self.joined = {ROOM}
        self.token = TOKEN
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, status, obj):
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _auth(self):
                if self.headers.get("authorization") != "Bearer " + fake.token:
                    self._reply(401, {"errcode": "M_UNKNOWN_TOKEN"})
                    return False
                return True

            def do_GET(self):
                if not self._auth():
                    return
                u = urlsplit(self.path)
                parts = [unquote(p) for p in u.path.split("/")]
                if u.path.endswith("/account/whoami"):
                    return self._reply(200, {"user_id": "@jill-control:example.org"})
                room = parts[5] if len(parts) > 5 else ""
                if room not in fake.joined:
                    return self._reply(403, {"errcode": "M_FORBIDDEN"})
                if u.path.endswith("/joined_members"):
                    return self._reply(200, {"joined": {}})
                if u.path.endswith("/state/m.room.encryption"):
                    if room in fake.encrypted:
                        return self._reply(200, {"algorithm": "m.megolm.v1.aes-sha2"})
                    return self._reply(404, {"errcode": "M_NOT_FOUND"})
                if u.path.endswith("/messages"):
                    q = parse_qs(u.query)
                    n = len(fake.events)
                    if q.get("dir") == ["b"]:
                        return self._reply(200, {"start": "s9223372036854775807", "end": "t%d" % n,
                                                 "chunk": fake.events[-1:]})
                    frm = int(q["from"][0][1:]) if q.get("from", [""])[0].startswith("t") else n
                    return self._reply(200, {"start": "t%d" % frm, "end": "t%d" % n, "chunk": fake.events[frm:]})
                self._reply(404, {"errcode": "M_UNRECOGNIZED"})

            def do_PUT(self):
                if not self._auth():
                    return
                n = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(n))
                room = unquote(self.path.split("/")[5])
                fake.sent.append((room, body.get("body")))
                self._reply(200, {"event_id": "$sent%d" % len(fake.sent)})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def say(self, body, sender=PRINCIPAL, age_s=0, **extra):
        content = {"msgtype": "m.text", "body": body}
        content.update(extra.pop("content", {}))
        ev = {"type": "m.room.message", "sender": sender, "content": content,
              "origin_server_ts": int((time.time() - age_s) * 1000), "event_id": "$e%d" % len(self.events)}
        ev.update(extra)
        self.events.append(ev)

    def close(self):
        self.server.shutdown()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.hs = FakeHomeserver()
        d = self.tmp.name
        env = {"MATRIX_CONTROL_TOKEN": TOKEN, "MATRIX_PRINCIPAL": PRINCIPAL, "MATRIX_CONTROL_ROOM": ROOM,
               "MATRIX_HOMESERVER": self.hs.url, "CONTROL_DIR": os.path.join(d, "control"),
               "ALERT_SPOOL_DIR": os.path.join(d, "spool"), "CREDENTIAL_STATUS_DIR": os.path.join(d, "creds"),
               "CREDENTIAL_EXPECT": "venice"}
        for k in ("CONTROL_DIR", "ALERT_SPOOL_DIR", "CREDENTIAL_STATUS_DIR"):
            os.makedirs(env[k])
        self.cfg, problems = c.load_config(env)
        self.assertEqual(problems, [])
        self.ctl = c.Control(self.cfg, c.Matrix(self.hs.url, TOKEN))
        self.halt = os.path.join(self.cfg["control_dir"], "halt.json")
        self.cons = os.path.join(self.cfg["control_dir"], "conservation-mode.json")

    def tearDown(self):
        self.hs.close()
        self.tmp.cleanup()

    def spool(self, name, obj):
        with open(os.path.join(self.cfg["spool_dir"], name), "w") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj))


class Parsing(unittest.TestCase):
    def test_lexicon_whole_message_only(self):
        self.assertEqual(c.parse_command("halt")[0], "halt")
        self.assertEqual(c.parse_command("Mute!")[0], "halt")
        self.assertEqual(c.parse_command("conservation on")[0], "conserve")
        self.assertEqual(c.parse_command("resume")[0], "resume")
        self.assertIsNone(c.parse_command("we should probably halt the drift alert"))
        self.assertIsNone(c.parse_command("resume the tax doc please"))
        self.assertIsNone(c.parse_command("status report"))
        self.assertIsNone(c.parse_command(""))

    def test_duration_and_reason(self):
        cmd, lift, reason = c.parse_command("halt 2h travelling")
        self.assertEqual(cmd, "halt")
        self.assertAlmostEqual(flags.parse_iso(lift) - time.time(), 7200, delta=5)
        self.assertEqual(reason, "travelling")

    def test_event_rules(self):
        now = int(time.time() * 1000)
        ev = lambda **k: dict({"type": "m.room.message", "sender": PRINCIPAL, "origin_server_ts": now,
                               "content": {"msgtype": "m.text", "body": "halt"}}, **k)
        self.assertEqual(c.parse_event(ev(), PRINCIPAL), ("halt", ""))
        self.assertEqual(c.parse_event(ev(sender="@mallory:example.org"), PRINCIPAL)[1], "sender")
        self.assertEqual(c.parse_event(ev(type="m.room.encrypted"), PRINCIPAL)[1], "encrypted")
        self.assertEqual(c.parse_event(ev(origin_server_ts=now - 11 * 60 * 1000), PRINCIPAL)[1], "stale")
        edit = ev(content={"msgtype": "m.text", "body": "halt", "m.relates_to": {"rel_type": "m.replace"}})
        self.assertEqual(c.parse_event(edit, PRINCIPAL)[1], "edit")
        self.assertEqual(c.parse_event(ev(content={"msgtype": "m.notice", "body": "halt"}), PRINCIPAL)[1], "msgtype")
        mention = ev(content={"msgtype": "m.text", "body": "@jill-control:example.org: halt"})
        self.assertEqual(c.parse_event(mention, PRINCIPAL)[0], "halt")

    def test_config_fails_closed(self):
        _, problems = c.load_config({})
        self.assertEqual(len(problems), 4)
        _, problems = c.load_config({"MATRIX_CONTROL_TOKEN": "x", "MATRIX_PRINCIPAL": "Sean",
                                     "MATRIX_CONTROL_ROOM": "#alias:example.org"})
        self.assertTrue(any("full Matrix user id" in p for p in problems))
        self.assertTrue(any("room id" in p for p in problems))


class Flags(unittest.TestCase):
    def test_states_and_failure_direction(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "halt.json")
            self.assertEqual(flags.state(p), "off")
            flags.write(p, True, "t", None, "r")
            self.assertEqual(flags.state(p), "on")
            flags.write(p, True, "t", "2001-01-01T00:00:00Z", "r")
            self.assertEqual(flags.state(p), "expired")
            self.assertTrue(flags.lift_expired(p))
            self.assertEqual(flags.state(p), "off")
            flags.write(p, True, "t", "next tuesday", "r")
            self.assertEqual(flags.state(p), "on", "an unparseable auto-lift must keep the flag on")
            with open(p, "w") as f:
                f.write('{"enabled": tru')
            self.assertEqual(flags.state(p), "on", "an unreadable flag must read as on")


class KillSwitch(Base):
    def test_first_poll_takes_position_and_acts_on_nothing(self):
        self.hs.say("halt")  # sent before the listener ever looked
        self.assertTrue(self.ctl.poll_room())
        self.assertEqual(flags.state(self.halt), "off")
        self.assertEqual(self.hs.sent, [])
        self.assertNotIn("9223372036854775807", self.ctl.cursor, "must not keep conduwuit's sentinel start")

    def test_halt_status_resume_round_trip(self):
        self.ctl.poll_room()
        self.hs.say("halt 30m flying")
        self.ctl.poll_room()
        self.assertEqual(flags.state(self.halt), "on")
        data, _ = flags.read(self.halt)
        self.assertEqual(data["reason"], "flying")
        self.assertTrue(data["enabled_by"].endswith(PRINCIPAL))
        self.assertIn("HALTED", self.hs.sent[-1][1])
        self.assertIn("NOT covered by halt", self.hs.sent[-1][1])
        self.hs.say("status")
        self.ctl.poll_room()
        self.assertIn("halt: ON", self.hs.sent[-1][1])
        self.hs.say("conserve")
        self.hs.say("resume")
        self.ctl.poll_room()
        self.assertEqual(flags.state(self.halt), "off")
        self.assertEqual(flags.state(self.cons), "off")
        self.assertIn("RESUMED", self.hs.sent[-1][1])

    def test_ignores_others_sentences_edits_and_stale(self):
        self.ctl.poll_room()
        self.hs.say("halt", sender="@mallory:example.org")
        self.hs.say("we should halt this")
        self.hs.say("halt", age_s=3600)
        self.hs.say("halt", content={"m.relates_to": {"rel_type": "m.replace"}})
        self.hs.say("halt", type="m.room.encrypted")
        self.ctl.poll_room()
        self.assertEqual(flags.state(self.halt), "off")
        self.assertEqual(self.hs.sent, [])

    def test_cursor_survives_restart(self):
        self.ctl.poll_room()
        self.hs.say("halt")
        self.ctl.poll_room()
        self.hs.say("resume")
        again = c.Control(self.cfg, c.Matrix(self.hs.url, TOKEN))
        again.poll_room()
        self.assertEqual(flags.state(self.halt), "off", "the restarted listener must pick up from its cursor")
        self.assertEqual(sum("HALTED" in b for _, b in self.hs.sent), 1, "halt must not be replayed")

    def test_listen_once_marks_armed_and_lifts_expired(self):
        flags.write(self.halt, True, "t", "2001-01-01T00:00:00Z", None)
        self.ctl.listen_once()
        armed, _ = flags.read(os.path.join(self.cfg["control_dir"], "armed.json"))
        self.assertAlmostEqual(armed["armed_at"], time.time(), delta=5)
        self.assertEqual(flags.state(self.halt), "off")
        self.assertIn("auto-lifted", self.hs.sent[-1][1])

    def test_boot_refuses_encrypted_or_unjoined_rooms(self):
        self.assertEqual(c.boot(self.ctl), [])
        self.hs.encrypted.add(ROOM)
        self.assertTrue(any("encrypted" in f for f in c.boot(self.ctl)))
        self.hs.encrypted.clear()
        self.hs.joined.clear()
        self.assertTrue(any("not joined" in f for f in c.boot(self.ctl)))
        self.hs.token = "rotated"
        self.assertTrue(any("refused" in f for f in c.boot(self.ctl)))


class Alerts(Base):
    def test_spool_is_posted_then_deleted(self):
        self.spool("1-a.json", {"kind": "spend-cap", "text": "Daily spend cap reached."})
        self.assertEqual(self.ctl.drain_spool(), 1)
        self.assertEqual(self.hs.sent, [(ROOM, "[Jill] Daily spend cap reached.")])
        self.assertEqual([n for n in os.listdir(self.cfg["spool_dir"]) if n.endswith(".json")], [])

    def test_malformed_records_are_rejected_not_posted(self):
        self.spool("1.json", "{not json")
        self.spool("2.json", {"kind": "Bad Kind!", "text": "x"})
        self.spool("3.json", {"kind": "ok", "text": 42})
        self.spool("4.json.tmp", {"kind": "ok", "text": "half written"})
        self.assertEqual(self.ctl.drain_spool(), 0)
        self.assertEqual(self.hs.sent, [])
        self.assertEqual(len(os.listdir(os.path.join(self.cfg["spool_dir"], "rejected"))), 3)

    def test_control_chars_and_length_are_bounded(self):
        self.spool("1.json", {"kind": "x", "text": "a\x1b[2Jb\x00" + "y" * 5000})
        self.ctl.drain_spool()
        body = self.hs.sent[0][1]
        self.assertNotIn("\x1b", body)
        self.assertLess(len(body), c.MAX_ALERT_CHARS + 40)

    def test_rate_limit_holds_the_rest_in_the_spool(self):
        self.cfg["alerts_per_hour"] = 2
        for i in range(4):
            self.spool("%d.json" % i, {"kind": "x", "text": "alert %d" % i})
        self.assertEqual(self.ctl.drain_spool(), 2)
        self.assertEqual(len([n for n in os.listdir(self.cfg["spool_dir"]) if n.endswith(".json")]), 2)

    def test_undeliverable_alerts_stay_spooled(self):
        self.hs.token = "rotated"
        self.spool("1.json", {"kind": "x", "text": "keep me"})
        self.assertEqual(self.ctl.drain_spool(), 0)
        self.assertTrue(os.path.exists(os.path.join(self.cfg["spool_dir"], "1.json")))


class Credentials(Base):
    def status(self, route, **rec):
        with open(os.path.join(self.cfg["cred_dir"], route + ".json"), "w") as f:
            json.dump(dict({"route": route}, **rec), f)

    def test_stages(self):
        now = time.time()
        self.status("venice", result="ok", http_status=200, checked_at=now, last_ok_at=now)
        self.assertEqual(self.ctl.credential_stages()["venice"][0], "ok")
        self.status("venice", result="rejected", http_status=401, checked_at=now, last_ok_at=now - 10)
        self.assertEqual(self.ctl.credential_stages()["venice"][0], "rejected")
        self.status("venice", result="ok", http_status=200, checked_at=now - 4 * 3600, last_ok_at=now - 4 * 3600)
        self.assertEqual(self.ctl.credential_stages()["venice"][0], "unknown")
        self.cfg["cred_expires"] = {"brave": time.strftime("%Y-%m-%d", time.gmtime(now + 3 * 86400)),
                                    "discord": "2001-01-01"}
        st = self.ctl.credential_stages()
        self.assertEqual(st["brave"][0], "t7")
        self.assertEqual(st["discord"][0], "expired")

    def test_missing_only_after_grace(self):
        self.assertNotIn("venice", self.ctl.credential_stages())
        self.ctl.started -= 3 * self.cfg["probe_interval"]
        self.assertEqual(self.ctl.credential_stages()["venice"][0], "missing")

    def test_alerts_on_change_once_then_renags_and_recovers(self):
        now = time.time()
        self.status("venice", result="rejected", http_status=401, checked_at=now, last_ok_at=None)
        self.ctl.check_credentials()
        self.ctl.check_credentials()
        self.assertEqual(len(self.hs.sent), 1)
        self.assertIn("venice", self.hs.sent[0][1])
        self.assertIn("REJECTED", self.hs.sent[0][1])
        self.ctl.clock = lambda: now + 4 * 86400
        self.status("venice", result="rejected", http_status=401, checked_at=now + 4 * 86400, last_ok_at=None)
        self.ctl.check_credentials()
        self.assertEqual(len(self.hs.sent), 2, "rejected re-nags after CREDENTIAL_REALERT_DAYS")
        self.status("venice", result="ok", http_status=200, checked_at=now + 4 * 86400, last_ok_at=now + 4 * 86400)
        self.ctl.check_credentials()
        self.assertIn("healthy again", self.hs.sent[-1][1])

    def test_matrix_token_probe(self):
        self.ctl.probe_matrix()
        self.assertEqual(self.ctl.credential_stages()["matrix"][0], "ok")
        self.hs.token = "rotated"
        self.ctl.probe_matrix()
        self.assertEqual(self.ctl.credential_stages()["matrix"][0], "rejected")

    def test_no_secret_in_any_alert(self):
        now = time.time()
        self.status("venice", result="rejected", http_status=401, checked_at=now, last_ok_at=None)
        self.ctl.check_credentials()
        self.assertTrue(all(TOKEN not in b for _, b in self.hs.sent))


if __name__ == "__main__":
    unittest.main()
