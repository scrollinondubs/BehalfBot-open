"""Matrix bridge policy worker: approval screen, approve binding, commands,
halt gate. Stdlib only (the chat path's aiohttp is never imported here)."""
import asyncio
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "bridge"))
sys.path.insert(0, os.path.join(ROOT, "gateway"))

import approvals  # noqa: E402
import control_flags as flags  # noqa: E402
import matrix_worker as w  # noqa: E402

DRAFT = "draft_abc123"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.saved = {k: getattr(w, k) for k in ("CONTROL_DIR", "APPROVALS_DIR", "SNAPSHOT_DIR", "WORKER_STATE",
                                                 "SESSIONS_FILE", "PRINCIPAL")}
        w.CONTROL_DIR = os.path.join(d, "control")
        w.APPROVALS_DIR = os.path.join(d, "approvals")
        w.SNAPSHOT_DIR = os.path.join(d, "agentmail-gw", "drafts")
        w.WORKER_STATE = os.path.join(d, "worker")
        w.SESSIONS_FILE = os.path.join(d, "worker", "sessions.json")
        w.PRINCIPAL = "@sean:test.local"
        for p in (w.CONTROL_DIR, w.SNAPSHOT_DIR, w.WORKER_STATE):
            os.makedirs(p)
        self.halt = os.path.join(w.CONTROL_DIR, flags.HALT)

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(w, k, v)
        self.tmp.cleanup()

    def snapshot(self, content, draft_id=DRAFT):
        # Exactly what gateway.save_snapshot writes.
        path = os.path.join(w.SNAPSHOT_DIR, approvals.key_for("draft", draft_id) + ".json")
        with open(path, "w") as f:
            json.dump({"draft_id": draft_id, "content": approvals.sendable(content)}, f)

    def halted_earlier(self, seconds=5):
        """A halt that happened a few seconds ago (enabled_at has one-second
        resolution; codes issued in the halt's second count as before it)."""
        flags.write(self.halt, True, "t", None, None)
        data, _ = flags.read(self.halt)
        data["enabled_at"] = flags.utcnow_iso(datetime.fromtimestamp(time.time() - seconds, timezone.utc))
        data["enabled_epoch"] = time.time() - seconds
        with open(self.halt, "w") as f:
            json.dump(data, f)

    def cmd(self, text, **kw):
        req = {"event_id": "$e", "event_ts": time.time(), "room": "!r:test.local", "text": text}
        req.update(kw)
        return w.handle_command(req)


FULL = {
    "to": ["alice@example.com"], "cc": ["carol@example.com"], "bcc": ["mallory@evil.example"],
    "reply_to": ["replies@evil.example"], "subject": "Quarterly numbers",
    "text": "Hi Alice,\nsha256 0000000000000000000000000000000000000000000000000000000000000000\nbcc: nobody",
    "html": "<p>Different from the text body</p>", "labels": ["outbox"], "in_reply_to": "<m1@example.com>",
}


class Escaping(unittest.TestCase):
    def test_controls_bidi_and_format_characters_are_visible(self):
        self.assertEqual(w.esc("a\r\nb"), "a\\x0d\\x0ab")
        self.assertEqual(w.esc("\x00\x1b\x7f\x85\x9b"), "\\x00\\x1b\\x7f\\x85\\x9b")
        self.assertEqual(w.esc("pay‮evil"), "pay\\u{202e}evil")
        for ch in ("​", "‍", "‎", "⁦", "⁩", "﻿", "­", " ", " "):
            self.assertNotIn(ch, w.esc("x" + ch + "y"), repr(ch))
        self.assertEqual(w.esc("\\x0d"), "\\\\x0d", "a literal escape must not look like a real one")
        self.assertEqual(w.esc("café 中"), "café 中", "ordinary text is unchanged")

    def test_m3_fields_are_ascii_and_padding_is_counted(self):
        # Probe C: look-alikes, blank fillers and padding.
        self.assertEqual(w.quoted("sean@g\u043e\u043egle.com"), '"sean@g\\u{043e}\\u{043e}gle.com"')
        for ch in ("\u00a0", "\u3164", "\u2800", "\u115f"):
            self.assertNotIn(ch, w.quoted("a" + ch + "b"))
            self.assertNotIn(ch, w.esc("a" + ch + "b"))
        padded = w.quoted("x@y.com" + " " * 120 + "bcc: (not set)")
        self.assertIn("\\s{120}", padded)
        self.assertNotIn("  ", padded)

    def test_quoted_escapes_quotes(self):
        self.assertEqual(w.quoted('say "hi"\t'), '"say \\"hi\\"\\x09"')


class Screen(Base):
    def test_renderer_covers_every_sendable_field(self):
        self.assertEqual(set(w.FIELD_RENDERERS), set(approvals.SENDABLE),
                         "approvals.SENDABLE changed: the approval screen must show the new field")
        self.assertEqual(set(w.FIELD_ORDER), set(approvals.SENDABLE))

    def test_every_field_is_shown_and_the_sha_is_the_gateway_digest(self):
        screen, sha, has_att = w.render_draft(DRAFT, approvals.sendable(FULL))
        self.assertEqual(sha, approvals.draft_digest(FULL))
        self.assertFalse(has_att)
        for needle in ('"alice@example.com"', '"carol@example.com"', '"mallory@evil.example"',
                       '"replies@evil.example"', '"Quarterly numbers"', "<p>Different from the text body</p>",
                       '"outbox"', '"<m1@example.com>"', "In-Reply-To:", "References:"):
            self.assertIn(needle, screen)
        self.assertEqual(screen.splitlines()[-1], "sha256 " + sha, "the screen must END with the sha256")

    def test_body_cannot_imitate_a_field_or_the_sha_line(self):
        screen, sha, _ = w.render_draft(DRAFT, approvals.sendable(FULL))
        lines = screen.splitlines()
        self.assertIn("  | bcc: nobody", lines)
        self.assertNotIn("bcc: nobody", lines)
        self.assertEqual([l for l in lines if l.startswith("sha256 ")], ["sha256 " + sha])

    def test_absent_and_empty_are_distinct(self):
        screen, _, _ = w.render_draft(DRAFT, {"to": ["a@example.com"], "subject": ""})
        self.assertIn('subject: ""', screen)
        self.assertIn("bcc: (not set)", screen)
        self.assertIn("html: (not set)", screen)
        self.assertIn("headers added at send: (none)", screen)

    def test_hostile_characters_in_fields_are_escaped(self):
        screen, _, _ = w.render_draft(DRAFT, {"to": ["a@example.com"], "subject": "Invoice‮gpj.exe",
                                              "text": "line\rBcc: x@evil.example"})
        self.assertNotIn("‮", screen)
        self.assertNotIn("\r", screen)
        self.assertIn("Invoice\\u{202e}gpj.exe", screen)
        self.assertIn("  | line\\x0dBcc: x@evil.example", screen)

    def test_attachments_show_name_type_size_sha_never_base64(self):
        data = b"%PDF-1.4 hello"
        b64 = base64.b64encode(data).decode()
        content = {"to": ["a@example.com"], "attachments": [
            {"filename": "inv‮fdp.exe", "content_type": "application/pdf", "content": b64}]}
        screen, _, has_att = w.render_draft(DRAFT, content)
        self.assertTrue(has_att)
        self.assertIn("size=%d bytes" % len(data), screen)
        self.assertIn("sha256=" + hashlib.sha256(data).hexdigest(), screen)
        self.assertIn('type="application/pdf"', screen)
        self.assertIn("inv\\u{202e}fdp.exe", screen)
        self.assertNotIn(b64, screen)
        self.assertIn("NOT APPROVABLE HERE: it has attachments", screen)

    def test_screen_is_plain_text_from_one_snapshot_read(self):
        self.snapshot(FULL)
        replies = self.cmd("show draft " + DRAFT)["replies"]
        self.assertEqual(len(replies), 1)
        self.assertTrue(replies[0].endswith("sha256 " + approvals.draft_digest(FULL)))

    def test_missing_snapshot(self):
        self.assertIn("No snapshot", self.cmd("show draft nope_1")["replies"][0])


class Approve(Base):
    """Round 6 H2 and H3: a screen code binds the approval to a screen this
    bridge delivered, and `confirm` must follow on the bridge's own clock."""

    def approval(self):
        path = os.path.join(w.APPROVALS_DIR, "draft", approvals.key_for("draft", DRAFT) + ".json")
        with open(path) as f:
            return json.load(f)

    def show(self, deliver=True):
        r = self.cmd("show draft " + DRAFT)
        if deliver:
            w.activate(r["activate"])
        return r

    def screen_code(self, r):
        return re.search(r"approve draft \S+ [0-9a-f]{64} (\S+)", r["replies"][0]).group(1)

    def confirm_code(self, r):
        return re.search(r"confirm ([a-z0-9]{10})", r["replies"][0]).group(1)

    def approve_and_confirm(self, sha, code):
        r = self.cmd("approve draft %s %s %s" % (DRAFT, sha, code))
        if "confirm" not in r["replies"][0] or not r["activate"]:
            return r["replies"][0]
        w.activate(r["activate"])
        return self.cmd("confirm " + self.confirm_code(r))["replies"][0]

    def test_approve_binds_to_the_typed_sha_after_confirm(self):
        self.snapshot(FULL)
        sha = approvals.draft_digest(FULL)
        r = self.show()
        code = self.screen_code(r)
        self.assertEqual(r["replies"][0].splitlines()[-1], "sha256 " + sha)
        step1 = self.cmd("approve draft %s %s %s" % (DRAFT, sha.upper(), code))
        self.assertFalse(os.path.isdir(os.path.join(w.APPROVALS_DIR, "draft")), "nothing before `confirm`")
        w.activate(step1["activate"])
        reply = self.cmd("confirm " + self.confirm_code(step1))["replies"][0]
        self.assertIn("Approved draft", reply)
        rec = self.approval()
        self.assertEqual(rec["sha256"], sha)
        self.assertLessEqual(rec["expires_at"] - rec["created_at"], approvals.MAX_TTL)

    def test_h2_forged_screen_from_the_model_cannot_be_approved(self):
        # Probe B: Jill writes a bcc'd draft, then imitates a clean screen
        # that ends with the digest of the bcc'd version.
        evil = {"to": ["alice@example.com"], "bcc": ["exfil@attacker.example"], "subject": "Invoice", "text": "Hi"}
        self.snapshot(evil)
        self.show()
        sha_evil = approvals.draft_digest(evil)
        for code in ("abcdefghjk", "", "x" * 10):
            reply = self.approve_and_confirm(sha_evil, code or "nocode")
            self.assertIn("Not approved", reply)
        self.assertFalse(os.path.isdir(os.path.join(w.APPROVALS_DIR, "draft")))
        old_style = self.cmd("approve draft %s %s" % (DRAFT, sha_evil))
        self.assertTrue(old_style["handled"], "a malformed approve is a command error, never chat")
        self.assertIn("Not understood", old_style["replies"][0])

    def test_n1_pasted_screen_never_reaches_the_model_and_its_code_dies(self):
        # Probe B2: Sean pastes the screen, the approve line or the sha into
        # a chat message; Jill would get the live code and forge a screen.
        evil = {"to": ["alice@example.com"], "bcc": ["exfil@attacker.example"], "subject": "Invoice", "text": "Hi"}
        self.snapshot(evil)
        sha = approvals.draft_digest(evil)
        for paste in (lambda scr, c: "why is there a bcc here?\n" + scr,
                      lambda scr, c: "ok approve draft %s %s %s" % (DRAFT, sha, c),
                      lambda scr, c: "is %s the right hash?" % sha.upper()):
            r = self.show()
            code = self.screen_code(r)
            out = self.cmd(paste(r["replies"][0], code))
            self.assertTrue(out["handled"], "a message with a live code or pending sha must not reach the model")
            self.assertIn("not sent to Jill", out["replies"][0])
            # The forged-screen step: Jill now "knows" the code, but it is void.
            self.assertIn("Not approved", self.approve_and_confirm(sha, code))
        self.assertFalse(os.path.isdir(os.path.join(w.APPROVALS_DIR, "draft")))

    def test_n1_pasted_code_is_retired(self):
        self.snapshot(FULL)
        code = self.screen_code(self.show())
        self.assertIn("not sent to Jill", self.cmd("what does %s mean?" % code)["replies"][0])
        self.assertIn("Not approved", self.approve_and_confirm(approvals.draft_digest(FULL), code))
        r = self.cmd("approve draft %s %s %s" % (DRAFT, approvals.draft_digest(FULL), self.screen_code(self.show())))
        w.activate(r["activate"])
        ccode = re.search(r"confirm ([a-z0-9]{10})", r["replies"][0]).group(1)
        self.assertIn("not sent to Jill", self.cmd("should I send confirm %s ?" % ccode)["replies"][0])
        self.assertIn("Nothing to confirm", self.cmd("confirm " + ccode)["replies"][0])

    def test_n1_a_newer_screen_retires_the_older_code(self):
        self.snapshot(FULL)
        old = self.screen_code(self.show())
        new = self.screen_code(self.show())
        self.assertNotEqual(old, new)
        self.assertIn("Not approved", self.approve_and_confirm(approvals.draft_digest(FULL), old))
        self.assertIn("Approved", self.approve_and_confirm(approvals.draft_digest(FULL), new))

    def test_h2_screen_code_is_bound_to_its_id_and_sha(self):
        self.snapshot(FULL)
        code = self.screen_code(self.show())
        self.assertIn("Not approved", self.approve_and_confirm("a" * 64, code))
        self.assertIn("Not approved", self.approve_and_confirm(approvals.draft_digest(FULL), code),
                      "a failed attempt with a code uses it up")

    def test_h2_code_is_single_use_and_expires(self):
        self.snapshot(FULL)
        sha = approvals.draft_digest(FULL)
        code = self.screen_code(self.show())
        self.assertIn("Approved", self.approve_and_confirm(sha, code))
        self.assertIn("Not approved", self.approve_and_confirm(sha, code))
        code2 = self.screen_code(self.show())
        self.assertIsNone(w.take_code(code2, "screen", w.SCREEN_TTL, now=time.time() + w.SCREEN_TTL + 1))

    def test_m3_undelivered_screen_is_not_approvable(self):
        self.snapshot(FULL)
        code = self.screen_code(self.show(deliver=False))
        self.assertIn("Not approved", self.approve_and_confirm(approvals.draft_digest(FULL), code))

    def test_h3_confirm_expires_on_the_bridge_clock(self):
        self.snapshot(FULL)
        sha = approvals.draft_digest(FULL)
        r = self.cmd("approve draft %s %s %s" % (DRAFT, sha, self.screen_code(self.show())))
        w.activate(r["activate"])
        late = time.time() + w.CONFIRM_TTL + 1
        self.assertIn("Nothing to confirm", w.confirm(self.confirm_code(r), now=late)[0])
        self.assertFalse(os.path.isdir(os.path.join(w.APPROVALS_DIR, "draft")))

    def test_approve_never_rereads_the_draft(self):
        self.snapshot(FULL)
        sha = approvals.draft_digest(FULL)
        code = self.screen_code(self.show())
        changed = dict(FULL, bcc=["other@evil.example"])
        self.snapshot(changed)
        self.assertIn("Approved", self.approve_and_confirm(sha, code))
        self.assertEqual(self.approval()["sha256"], sha, "the approval carries what Sean saw, not the new draft")
        consumed = os.path.join(self.tmp.name, "consumed")

        def same_draft(rec):
            if rec.get("sha256") != approvals.draft_digest(changed):
                raise LookupError("not the draft Sean approved")

        with self.assertRaises(LookupError):
            approvals.check_and_consume("draft", DRAFT, consumed, base=w.APPROVALS_DIR, verify=same_draft)
        self.assertEqual(approvals.status("draft", DRAFT, [consumed], base=w.APPROVALS_DIR), "used")

    def test_drafts_with_attachments_or_long_bodies_get_no_code(self):
        content = dict(FULL, attachments=[{"filename": "a.txt", "content_type": "text/plain",
                                           "content": base64.b64encode(b"x").decode()}])
        self.snapshot(content)
        r = self.show()
        self.assertEqual(r["activate"], [])
        self.assertIn("NOT APPROVABLE HERE", r["replies"][0])
        self.snapshot(dict(FULL, text="x " * 5_000_000))
        r = self.show()
        self.assertEqual(r["activate"], [])
        self.assertEqual(len(r["replies"]), 1, "probe D: a 10 MB body is one screen, not 1,667 messages")
        self.assertLessEqual(len(r["replies"][0]), w.MATRIX_CHUNK)
        self.assertIn("TOO LONG TO APPROVE", r["replies"][0])


class Commands(Base):
    def confirm_last(self, r):
        w.activate(r["activate"])
        code = re.search(r"confirm ([a-z0-9]{10})", r["replies"][0]).group(1)
        return self.cmd("confirm " + code)["replies"][0]

    def test_halt_is_immediate_lifts_need_confirm(self):
        self.assertIn("HALTED", self.cmd("halt 2h travelling")["replies"][0])
        data, _ = flags.read(self.halt)
        self.assertEqual(data["enabled_by"], "matrix-bridge:@sean:test.local")
        self.assertEqual(data["reason"], "travelling")
        status = self.cmd("status")["replies"][0]
        self.assertIn("halt: ON", status)
        self.halted_earlier()
        r = self.cmd("resume")
        self.assertIn("confirm", r["replies"][0])
        self.assertEqual(flags.state(self.halt), "on", "resume alone changes nothing (round 6 H3)")
        self.assertIn("RESUMED", self.confirm_last(r))
        self.assertEqual(flags.state(self.halt), "off")
        before = time.time()
        self.assertIn("AND spend", self.confirm_last(self.cmd("reset meter spend", event_ts=1.0)))
        req, _ = flags.read(os.path.join(w.CONTROL_DIR, "meter-reset.json"))
        self.assertIs(req["spend"], True)
        self.assertGreaterEqual(req["requested_at"], before, "keyed on the bridge clock, not the event time")
        self.assertIn("METER RESET", self.confirm_last(self.cmd("reset meter")))

    def test_m1_halt_cancels_a_pending_unsafe_action(self):
        self.halted_earlier()
        r = self.cmd("resume")
        w.activate(r["activate"])
        code = re.search(r"confirm ([a-z0-9]{10})", r["replies"][0]).group(1)
        self.cmd("halt")
        self.assertIn("Nothing to confirm", self.cmd("confirm " + code)["replies"][0])
        self.assertEqual(flags.state(self.halt), "on")

    def test_h3_held_back_resume_cannot_lift_a_halt(self):
        # RT1: a `resume` delivered late gets only a challenge; nothing
        # changes without a fresh `confirm`.
        self.cmd("halt")
        r = self.cmd("resume", event_ts=time.time())
        self.assertEqual(flags.state(self.halt), "on")
        self.assertIn("confirm", r["replies"][0])
        self.assertIn("Nothing to confirm", self.cmd("confirm abcdefghjk")["replies"][0])

    def test_resume_right_after_a_halt_still_works(self):
        self.cmd("halt")
        r = self.cmd("resume")
        self.assertIn("RESUMED", self.confirm_last(r))

    def test_n4_control_room_halt_cancels_a_pending_confirm(self):
        # Probe F5: resume, then a halt written by jill-control (not this
        # worker), then the delayed confirm.
        self.halted_earlier(seconds=60)
        r = self.cmd("resume")
        w.activate(r["activate"])
        code = re.search(r"confirm ([a-z0-9]{10})", r["replies"][0]).group(1)
        self.halted_earlier(seconds=0)  # jill-control re-halts now
        self.assertIn("Nothing to confirm", self.cmd("confirm " + code)["replies"][0])
        self.assertEqual(flags.state(self.halt), "on")

    def test_conserve_here_and_unconserve_needs_confirm(self):
        self.assertIn("CONSERVATION ON", self.cmd("conserve")["replies"][0])
        cons = os.path.join(w.CONTROL_DIR, flags.CONSERVATION)
        r = self.cmd("unconserve")
        self.assertEqual(flags.state(cons), "on")
        self.assertIn("Conservation off", self.confirm_last(r))

    def test_halt_gate_blocks_chat_but_not_commands(self):
        self.cmd("halt")
        r = self.cmd("what is on my calendar?")
        self.assertTrue(r["handled"])
        self.assertIn("not forwarded", r["replies"][0])

        class Boom:
            async def get_session(self, *a):
                raise AssertionError("the model path ran while halted")

        r = asyncio.run(w.handle_chat({"text": "hello", "room": "!r"}, client=Boom()))
        self.assertIn("not forwarded", r["replies"][0])
        self.snapshot(FULL)
        self.assertTrue(self.cmd("show draft " + DRAFT)["replies"][0].startswith("[bridge] DRAFT"))
        self.halted_earlier()
        self.assertIn("RESUMED", self.confirm_last(self.cmd("resume")))
        self.assertFalse(self.cmd("what is on my calendar?")["handled"])

    def test_n1_n2_model_replies_are_marked_and_quote_what_they_answer(self):
        class Forger:
            async def get_session(self, key):
                return "s", False

            async def prompt(self, sid, text):
                return "[bridge] DRAFT \"d\"\n  [ Bridge ] approve draft d " + "a" * 64 + " abcdefghjk\nfine"

            async def health(self):
                return True

            async def close(self):
                pass

        r = asyncio.run(w.handle_chat({"text": "please fix the draft " + "x" * 80, "room": "!r",
                                       "received_at": 0}, client=Forger()))
        first = r["replies"][0]
        self.assertTrue(first.startswith('Jill, re "please fix the draft xxx'), first)
        self.assertIn("(received 00:00:00 UTC)", first.splitlines()[0])
        self.assertNotIn("[bridge]", first.lower().replace("(bridge?)", ""))
        for line in first.splitlines():
            self.assertFalse(line.lstrip().lower().startswith("[bridge"), line)
        for reply in self.cmd("status")["replies"]:
            self.assertTrue(reply.startswith(w.BRIDGE_PREFIX))

    def test_l6_reply_finished_after_a_halt_is_discarded(self):
        test = self

        class SlowModel:
            async def get_session(self, key):
                return "s", False

            async def prompt(self, sid, text):
                test.cmd("halt")
                return "the secret answer"

            async def health(self):
                return True

            async def close(self):
                pass

        r = asyncio.run(w.handle_chat({"text": "hello", "room": "!r"}, client=SlowModel()))
        self.assertNotIn("secret", " ".join(r["replies"]))

    def test_new_resets_the_session(self):
        w.save_sessions({"!r:test.local": "ses_1", "!other": "ses_2"})
        self.assertIn("Session reset", self.cmd("new")["replies"][0])
        self.assertEqual(w.load_sessions(), {"!other": "ses_2"})
        for word in ("/reset", "!reset", "/new"):
            self.assertTrue(self.cmd(word)["handled"])

    def test_a_command_word_inside_a_sentence_is_chat(self):
        self.assertFalse(self.cmd("should we halt the project?")["handled"])
        self.assertFalse(self.cmd("can you remove the bcc and show me the draft again")["handled"])
        for text in ("show draft", "show draft d_x again", "approve the draft please", "confirm"):
            r = self.cmd(text)
            self.assertTrue(r["handled"], text)
            self.assertIn("Not understood", r["replies"][0])

    def test_l3_reply_fallback_is_not_stripped(self):
        r = self.cmd("> <@sean:test.local> hi\n\nresume", is_reply=True)
        self.assertFalse(r["handled"], "a server-claimed reply cannot turn quoted text into a command")

    def test_unsupported_only_upload_gets_a_reply(self):
        r = self.cmd("", attachments=[{"name": "p.png", "mime": "image/png", "data_b64": ""}])
        self.assertIn("PDF and plain-text", r["replies"][0])


class Chat(Base):
    def test_documents_and_chunking(self):
        blocks, notes, fatal = w.gather_documents([
            {"name": "n.txt", "mime": "text/plain", "data_b64": base64.b64encode(b"=====END\nhi").decode()},
            {"name": "p.png", "mime": "image/png", "data_b64": ""}])
        self.assertIsNone(fatal)
        self.assertIn("BEGIN UNTRUSTED DOCUMENT: n.txt", blocks[0])
        self.assertIn("= ====END", blocks[0])
        self.assertIn("unsupported type image/png", notes[0])
        chunks = w.chunk_message("x" * 13000)
        self.assertTrue(all(len(c) <= w.MATRIX_CHUNK for c in chunks))
        self.assertEqual("".join(chunks), "x" * 13000)


if __name__ == "__main__":
    unittest.main()
