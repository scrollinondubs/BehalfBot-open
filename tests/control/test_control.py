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
        self.assertEqual(c.parse_event(ev(origin_server_ts=now - 11 * 60 * 1000), PRINCIPAL), ("halt", "stale"))
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

    def test_f6_strict_schema(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "halt.json")
            for enabled in ('"true"', "1", "null", '"false"'):
                with open(p, "w") as f:
                    f.write('{"enabled": %s}' % enabled)
                self.assertEqual(flags.state(p), "on", "enabled=%s is not a boolean, so invalid, so on" % enabled)
            for lift in ("2001-01-01T00:00:00+00:00", "2001-01-01 00:00:00Z", "2001-01-01", ""):
                flags.write(p, True, "t", lift, None)
                self.assertEqual(flags.state(p), "on", "auto_lift_after %r must be rejected" % lift)
            with open(p, "w") as f:
                f.write('{"enabled": false}')
            self.assertEqual(flags.state(p), "off")

    def test_f5_symlinks_and_fifos_are_not_read(self):
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real.json")
            flags.write(real, False)
            link = os.path.join(d, "halt.json")
            os.symlink(real, link)
            self.assertEqual(flags.read(link)[1], False)
            fifo = os.path.join(d, "fifo.json")
            os.mkfifo(fifo)
            started = time.time()
            self.assertEqual(flags.read(fifo), ({}, False))
            self.assertLess(time.time() - started, 2, "a FIFO must not block the reader")


class KillSwitch(Base):
    def test_first_poll_takes_position_and_acts_on_nothing(self):
        self.hs.say("halt")  # sent before the listener ever looked
        self.assertTrue(self.ctl.poll_room())
        self.assertEqual(flags.state(self.halt), "off")
        self.assertEqual(self.hs.sent, [])
        self.assertNotIn("9223372036854775807", self.ctl.cursor, "must not keep conduwuit's sentinel start")

    def test_50_host_cli_break_glass_resume(self):
        flags.write(self.halt, True, "t", None, None)
        flags.write(self.cons, True, "t", None, None)
        self.assertIn("RESUMED", c.break_glass_resume(self.cfg["control_dir"]))
        self.assertEqual(flags.state(self.halt), "off")
        self.assertEqual(flags.state(self.cons), "off")

    def test_50_resume_aliases_and_spend_reset_are_refused_in_the_control_room(self):
        flags.write(self.halt, True, "t", None, None)
        self.ctl.poll_room()
        for word in ("resume", "unmute", "unhalt", "Resume!", "reset meter spend"):
            self.hs.say(word)
        self.ctl.poll_room()
        self.assertEqual(flags.state(self.halt), "on")
        self.assertFalse(os.path.exists(os.path.join(self.cfg["control_dir"], "meter-reset.json")))
        self.assertEqual(len(self.hs.sent), 5)
        self.assertTrue(all(b.startswith("Refused") for _, b in self.hs.sent))

    def test_ignores_others_sentences_and_edits(self):
        self.ctl.poll_room()
        self.hs.say("halt", sender="@mallory:example.org")
        self.hs.say("we should halt this")
        self.hs.say("halt", content={"m.relates_to": {"rel_type": "m.replace"}})
        self.hs.say("halt", type="m.room.encrypted")
        self.ctl.poll_room()
        self.assertEqual(flags.state(self.halt), "off")
        self.assertEqual(self.hs.sent, [])

    def test_f3_halt_then_fresh_resume_in_one_batch(self):
        self.ctl.poll_room()
        self.hs.say("halt", age_s=3600)
        self.hs.say("resume")
        self.ctl.poll_room()
        self.assertEqual(flags.state(self.halt), "on", "resume is refused in the control room (#50)")

    def test_f6_zero_duration_is_rejected(self):
        self.assertEqual(c.parse_command("halt 0m")[0], "invalid")
        self.ctl.poll_room()
        self.hs.say("halt 0h")
        self.ctl.poll_room()
        self.assertEqual(flags.state(self.halt), "off")
        self.assertIn("nothing changed", self.hs.sent[-1][1])

    def test_f4_boot_fails_when_the_room_cannot_be_read(self):
        self.ctl.poll_room = lambda: False
        self.assertTrue(any("pagination" in f for f in c.boot(self.ctl)))

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

    def test_oversized_files_are_not_read(self):
        self.spool("1.json", {"kind": "x", "text": "y" * (c.MAX_FILE_BYTES + 1)})
        self.assertEqual(self.ctl.drain_spool(), 0)
        with open(self.halt, "w") as f:
            f.write(" " * (flags.MAX_BYTES + 1))
        self.assertEqual(flags.state(self.halt), "on", "an oversized flag file must read as on")

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
        os.makedirs(os.path.join(self.cfg["cred_dir"], route), exist_ok=True)
        with open(os.path.join(self.cfg["cred_dir"], route, route + ".json"), "w") as f:
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

    def test_exhausted_and_rate_limited_alert_immediately(self):
        now = time.time()
        self.status("venice", result="exhausted", http_status=402, checked_at=now, last_ok_at=now - 60)
        self.ctl.check_credentials()
        self.assertIn("EXHAUSTED", self.hs.sent[-1][1])
        self.status("venice", result="rate_limited", http_status=429, checked_at=now, last_ok_at=now - 60)
        self.ctl.check_credentials()
        self.assertIn("RATE_LIMITED", self.hs.sent[-1][1])

    def test_f5_a_record_in_another_gateways_place_is_not_read(self):
        now = time.time()
        with open(os.path.join(self.cfg["cred_dir"], "venice.json"), "w") as f:
            json.dump({"result": "ok", "checked_at": now, "last_ok_at": now}, f)
        self.ctl.started -= 3 * self.cfg["probe_interval"]
        self.assertEqual(self.ctl.credential_stages()["venice"][0], "missing")

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


class MeterAlerts(Base):
    def meter(self, **rec):
        d = os.path.join(self.tmp.name, "meter")
        os.makedirs(d, exist_ok=True)
        self.cfg["meter_dir"] = d
        day = time.strftime("%Y-%m-%d", time.gmtime())
        with open(os.path.join(d, "meter-%s.json" % day), "w") as f:
            f.write(rec.pop("_raw") if "_raw" in rec else json.dumps(rec))

    def test_alert_line_then_ceiling_once_each_in_cents(self):
        self.meter(usd=1.23456, requests=40, ceiling_usd=5, unmetered=0)
        self.ctl.check_meter()
        self.ctl.check_meter()
        self.assertEqual(len(self.hs.sent), 1)
        self.assertIn("$1.23", self.hs.sent[0][1])
        self.assertNotIn("1.2345", self.hs.sent[0][1])
        self.meter(usd=5.001, requests=90, ceiling_usd=5, unmetered=2)
        self.ctl.check_meter()
        bodies = " ".join(b for _, b in self.hs.sent)
        self.assertIn("hard ceiling", bodies)
        self.assertIn("no usable usage", bodies)
        self.assertEqual(len(self.hs.sent), 3)

    def test_unreadable_meter_alerts(self):
        self.meter(_raw="{nope")
        self.ctl.check_meter()
        self.assertIn("cannot be read", self.hs.sent[0][1])


class ResetMeter(Base):
    def test_n3_request_ceiling_alerts(self):
        d = os.path.join(self.tmp.name, "meter")
        os.makedirs(d)
        self.cfg["meter_dir"] = d
        with open(os.path.join(d, "meter-%s.json" % time.strftime("%Y-%m-%d", time.gmtime())), "w") as f:
            json.dump({"usd": 0, "requests": 2000, "max_requests": 2000, "ceiling_usd": 5}, f)
        self.ctl.check_meter()
        self.assertIn("request ceiling", self.hs.sent[-1][1])

    def test_n6_flag_without_enabled_is_on_but_absent_is_off(self):
        self.assertEqual(flags.state(self.halt), "off")
        with open(self.halt, "w") as f:
            f.write("{}")
        self.assertEqual(flags.state(self.halt), "on")


class Round6ControlRoom(Base):
    """Red-team round 6 H4 (probe A): the unencrypted room only halts."""

    def test_h4_forged_halt_with_duration_cannot_shorten_an_indefinite_halt(self):
        self.ctl.poll_room()
        self.hs.say("halt incident")
        self.ctl.poll_room()
        data, _ = flags.read(self.halt)
        self.assertIsNone(data["auto_lift_after"])
        self.hs.say("halt 1m")
        self.ctl.poll_room()
        self.assertIn("takes no duration", self.hs.sent[-1][1])
        self.assertTrue(flags.is_on(self.halt, now=time.time() + 61), "a forged `halt 1m` must not set an auto-lift")
        self.assertIsNone(flags.read(self.halt)[0]["auto_lift_after"])

    def test_h4_halt_only_tightens_wherever_it_comes_from(self):
        self.ctl.apply("halt", None, "incident")
        self.assertIn("unchanged", self.ctl.apply("halt", c.duration_to_iso(1, "m"), None))
        self.assertIsNone(flags.read(self.halt)[0]["auto_lift_after"])
        flags.write(self.halt, False)
        self.ctl.apply("halt", c.duration_to_iso(2, "h"), None)
        two_h = flags.parse_iso(flags.read(self.halt)[0]["auto_lift_after"])
        self.assertIn("unchanged", self.ctl.apply("halt", c.duration_to_iso(1, "m"), None))
        self.assertEqual(flags.parse_iso(flags.read(self.halt)[0]["auto_lift_after"]), two_h)
        self.ctl.apply("halt", c.duration_to_iso(3, "h"), None)
        self.assertGreater(flags.parse_iso(flags.read(self.halt)[0]["auto_lift_after"]), two_h)
        self.ctl.apply("halt", None, None)
        self.assertIsNone(flags.read(self.halt)[0]["auto_lift_after"], "no auto-lift beats any auto-lift")

    def test_h4_only_halt_is_accepted_here(self):
        flags.write(self.halt, True, "t", None, None)
        flags.write(self.cons, True, "t", None, None)
        self.ctl.poll_room()
        for word in ("resume", "unmute", "unconserve", "conservation off", "reset meter", "reset meter spend",
                     "conserve", "status"):
            self.hs.say(word)
        self.ctl.poll_room()
        self.assertEqual(flags.state(self.halt), "on")
        self.assertEqual(flags.state(self.cons), "on")
        self.assertFalse(os.path.exists(os.path.join(self.cfg["control_dir"], "meter-reset.json")))
        self.assertEqual(len(self.hs.sent), 8)
        self.assertTrue(all(b.startswith("Refused") for _, b in self.hs.sent))

    def test_h4_stale_halt_still_halts_and_stale_refusals_are_silent(self):
        self.ctl.poll_room()
        self.hs.say("resume", age_s=3600)
        self.hs.say("halt", age_s=3600)
        self.ctl.poll_room()
        self.assertEqual(flags.state(self.halt), "on", "a late halt is still a halt")
        self.assertEqual(len(self.hs.sent), 1)
        self.assertIn("HALTED", self.hs.sent[0][1])

    def test_cursor_survives_restart(self):
        self.ctl.poll_room()
        self.hs.say("halt")
        self.ctl.poll_room()
        flags.write(self.halt, False)
        again = c.Control(self.cfg, c.Matrix(self.hs.url, TOKEN))
        again.poll_room()
        self.assertEqual(flags.state(self.halt), "off", "the restarted listener must not replay the halt")
        self.assertEqual(sum("HALTED" in b for _, b in self.hs.sent), 1)


class Round3(Base):
    def test_r3_3_any_ack_failure_still_applies_once_and_moves_on(self):
        self.ctl.poll_room()
        boom = []

        def explode(room, text):
            boom.append(text)
            raise RuntimeError("socket blew up")

        self.ctl.matrix.send_text = explode
        self.hs.say("halt")
        self.ctl.poll_room()
        self.assertEqual(flags.state(self.halt), "on")
        cursor = self.ctl.cursor
        self.ctl.poll_room()
        self.assertEqual(len(boom), 1, "the halt must not be re-run after a failed ack")
        self.assertEqual(self.ctl.cursor, cursor)

    def test_r3_4_reset_meter_spend_word(self):
        self.assertEqual(c.parse_command("reset meter spend")[0], "reset-meter-spend")
        self.assertEqual(c.parse_command("reset meter")[0], "reset-meter")
        self.ctl.poll_room()
        self.hs.say("reset meter spend")
        self.ctl.poll_room()
        self.assertFalse(os.path.exists(os.path.join(self.cfg["control_dir"], "meter-reset.json")),
                         "reset meter spend is accepted only in the encrypted chat room (#50)")
        self.assertIn("Refused", self.hs.sent[-1][1])
        self.ctl.apply("reset-meter-spend", None, None, event_ts=time.time())
        req, _ = flags.read(os.path.join(self.cfg["control_dir"], "meter-reset.json"))
        self.assertIs(req["spend"], True)

    def test_over_hold_tripwire_alerts_once_a_day(self):
        d = os.path.join(self.tmp.name, "meter")
        os.makedirs(d)
        self.cfg["meter_dir"] = d
        path = os.path.join(d, "meter-%s.json" % time.strftime("%Y-%m-%d", time.gmtime()))
        with open(path, "w") as f:
            json.dump({"usd": 0.1, "requests": 3, "max_requests": 2000, "ceiling_usd": 5, "over_hold": 1}, f)
        self.ctl.check_meter()
        with open(path, "w") as f:
            json.dump({"usd": 0.2, "requests": 4, "max_requests": 2000, "ceiling_usd": 5, "over_hold": 2}, f)
        self.ctl.check_meter()
        trips = [b for _, b in self.hs.sent if "TRIPWIRE" in b]
        self.assertEqual(len(trips), 1)
