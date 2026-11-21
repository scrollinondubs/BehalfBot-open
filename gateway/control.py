#!/usr/bin/env python3
"""jill-control: the kill switch, the alert transport and the credential-expiry
check for Jill. Stdlib only. Runs in its own container (docker-compose.yml).

WHY A SIDECAR
-------------
Jill's container holds no secrets and has no route out. A kill switch and an
alert path need a chat token and an outbound connection, so both live here,
in a container Jill cannot reach:

  - not on jill-internal, so opencode-serve has no network path to it
  - the Matrix token is in THIS container's environment only
  - it shares nothing with serve: the flag files live in the control-state
    volume (read-write here, read-only in the dispatcher, absent in serve);
    alerts arrive through the alert-spool volume (the dispatcher writes,
    this drains); gateway credential probes arrive through the
    credential-status volume (gateways write, this reads)

Nothing here runs a model. It keeps working when Venice, OpenCode or the
dispatcher is down, which is when it matters.

KILL SWITCH (ported from chassis matrix-control-listener.py, 5713efb +
130db62; lexicon and acks from discord-control-listener.py, 47a13d6)
-------------------------------------------------------------------
Whole-message words from the principal in the control room:

    halt [<dur>] [<reason>]   aliases mute, silence. Every heartbeat skipped
                              from the next dispatcher tick, critical ones
                              included.
    resume                    aliases unmute, unhalt. Clears halt AND
                              conservation.
    conserve [<dur>] [...]    aliases throttle, "conservation on". Only
                              `critical` heartbeats run.
    unconserve                alias "conservation off".
    status                    Reports both flags. Changes nothing.

<dur> is <n>m / <n>h / <n>d and becomes auto_lift_after.

Event rules: m.room.message / m.text only; sender must equal
MATRIX_PRINCIPAL exactly (display names are never compared); events older
than 10 minutes are dropped; edits are ignored; encrypted events are never
acted on, and an encrypted control room refuses to arm. Polling uses
/rooms/{id}/messages with a stored cursor, never /sync, so it does not
consume to-device messages meant for another client on the same account
(the E2EE chat bridge, package D).

ALERTS
------
The dispatcher drops JSON files in the spool: {"kind": "...", "text": "..."}.
This posts each to the alerts room and deletes it. The control room is NOT
end-to-end encrypted (this process holds no keys), and the homeserver is
not Jill's, so alert text must carry no private material: callers send
fixed templates with heartbeat names and counts, never model output, gather
data or log lines. This process cannot enforce that; it enforces length,
control characters and a rate limit.

CREDENTIAL EXPIRY
-----------------
Each key-holding gateway probes its upstream with its own key and writes a
status-only record (result, HTTP status, timestamps; never the key) to the
credential-status volume. This reads those, adds non-secret expiry dates
from CREDENTIAL_EXPIRES, probes its own Matrix token, and alerts on stage
changes (ok, t7, t1, unknown, missing, rejected, expired). See
docs/control.md.

EXIT CODES
----------
78  configuration error. The process then stays up, unhealthy and loud,
    rather than restart-looping (see main()).
"""
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import control_flags as flags  # noqa: E402

EX_CONFIG = 78
MAX_EVENT_AGE_S = 600
USER_AGENT = "jill-control"
MXID_RE = re.compile(r"^@[^:\s]+:\S+$")
LEADING_MENTION_RE = re.compile(r"^@[^:\s]+:[A-Za-z0-9.\-\[\]]+(?::\d+)?:?\s*")
DURATION_RE = re.compile(r"^(\d+)([mhd])$", re.IGNORECASE)
KIND_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
CONTROL_CHARS = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")
MAX_ALERT_CHARS = 1500
MAX_FILE_BYTES = 64 * 1024

COMMANDS = {
    "halt": "halt",
    "mute": "halt",
    "silence": "halt",
    "resume": "resume",
    "unmute": "resume",
    "unhalt": "resume",
    "conserve": "conserve",
    "throttle": "conserve",
    "conservation on": "conserve",
    "unconserve": "unconserve",
    "conservation off": "unconserve",
    "status": "status",
}

STAGE_RANK = {"ok": 0, "t7": 1, "t1": 2, "unknown": 3, "missing": 4, "rejected": 5, "expired": 6}
RENAG_STAGES = ("unknown", "missing", "rejected", "expired")


def log(msg):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print("[%s] [jill-control] %s" % (stamp, msg), flush=True)


def write_json_atomic(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


# --- command parsing (chassis discord-control-listener.py) -----------------

def duration_to_iso(amount, unit, now=None):
    delta = {"m": timedelta(minutes=amount), "h": timedelta(hours=amount), "d": timedelta(days=amount)}[unit]
    return flags.utcnow_iso((now or datetime.now(timezone.utc)) + delta)


def parse_command(content):
    """(command, auto_lift_iso, reason) or None. Whole-message match: a control
    word inside a sentence is conversation, not an instruction."""
    if not content:
        return None
    text = content.strip().strip("!.?,;:").strip()
    if not text:
        return None
    parts = text.split()
    lowered = [p.lower() for p in parts]
    command, rest = None, []
    if len(lowered) >= 2 and "%s %s" % (lowered[0], lowered[1]) in COMMANDS:
        command, rest = COMMANDS["%s %s" % (lowered[0], lowered[1])], parts[2:]
    elif lowered[0] in COMMANDS:
        command, rest = COMMANDS[lowered[0]], parts[1:]
    if command is None:
        return None
    if command in ("resume", "unconserve", "status") and rest:
        return None
    duration = None
    if rest:
        m = DURATION_RE.match(rest[0])
        if m:
            duration = duration_to_iso(int(m.group(1)), m.group(2).lower())
            rest = rest[1:]
    reason = " ".join(rest).strip() or None
    if reason:
        reason = CONTROL_CHARS.sub(" ", reason)[:200]
    return command, duration, reason


# --- event rules (chassis matrix-control-listener.py) ----------------------

def strip_reply_fallback(body):
    lines = body.split("\n")
    if not lines or not lines[0].startswith(">"):
        return body
    i = 0
    while i < len(lines) and lines[i].startswith(">"):
        i += 1
    if i < len(lines) and lines[i].strip() == "":
        i += 1
    return "\n".join(lines[i:])


def parse_event(ev, principal, now_ms=None, max_age_s=MAX_EVENT_AGE_S):
    """(body, "") when the event should be matched against the lexicon, else
    (None, reason). Reasons go to the log and never carry a body."""
    etype = ev.get("type")
    sender = str(ev.get("sender") or "")
    if etype == "m.room.encrypted":
        return None, "encrypted"
    if etype != "m.room.message":
        return None, "type"
    if sender != principal:
        return None, "sender"
    content = ev.get("content")
    if not isinstance(content, dict) or not content:
        return None, "redacted"
    rel = content.get("m.relates_to") if isinstance(content.get("m.relates_to"), dict) else {}
    if rel.get("rel_type") == "m.replace" or "m.new_content" in content:
        return None, "edit"
    ts = ev.get("origin_server_ts")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return None, "no-timestamp"
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    if (now_ms - ts) / 1000 > max_age_s:
        return None, "stale"
    if content.get("msgtype") != "m.text":
        return None, "msgtype"
    body = content.get("body") if isinstance(content.get("body"), str) else ""
    if isinstance(rel.get("m.in_reply_to"), dict):
        body = strip_reply_fallback(body)
    body = LEADING_MENTION_RE.sub("", body.strip())
    return body, ""


# --- Matrix REST -----------------------------------------------------------

class MatrixError(Exception):
    def __init__(self, message, status=0, retry_after_ms=None):
        super().__init__(message)
        self.status = status
        self.retry_after_ms = retry_after_ms


class Matrix:
    def __init__(self, base, token, timeout=30):
        self.base = base.rstrip("/")
        self._token = token
        self.timeout = timeout
        self._txn = 0
        self._lock = threading.Lock()

    def _request(self, method, path, body=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", "Bearer %s" % self._token)
        req.add_header("User-Agent", USER_AGENT)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = {}
            try:
                detail = json.loads(exc.read().decode("utf-8", errors="replace"))
            except Exception:
                pass
            raise MatrixError("HTTP %d %s" % (exc.code, detail.get("errcode", "")), exc.code,
                              detail.get("retry_after_ms"))
        except (urllib.error.URLError, OSError) as exc:
            raise MatrixError("unreachable: %s" % getattr(exc, "reason", exc))
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            raise MatrixError("non-JSON response")

    @staticmethod
    def q(value):
        return urllib.parse.quote(value, safe="")

    def whoami(self):
        return self._request("GET", "/_matrix/client/v3/account/whoami").get("user_id", "")

    def joined(self, room_id):
        self._request("GET", "/_matrix/client/v3/rooms/%s/joined_members" % self.q(room_id))

    def room_encrypted(self, room_id):
        try:
            self._request("GET", "/_matrix/client/v3/rooms/%s/state/m.room.encryption" % self.q(room_id))
        except MatrixError as exc:
            if exc.status == 404:
                return False
            raise
        return True

    def messages(self, room_id, from_token=None, direction="f", limit=50):
        params = {"dir": direction, "limit": limit}
        if from_token:
            params["from"] = from_token
        return self._request("GET", "/_matrix/client/v3/rooms/%s/messages?%s"
                             % (self.q(room_id), urllib.parse.urlencode(params)))

    def send_text(self, room_id, text):
        # A repeated txn id is silently deduplicated by the homeserver.
        with self._lock:
            self._txn += 1
            txn = "jill-control-%d-%d-%d" % (int(time.time() * 1000), os.getpid(), self._txn)
        path = "/_matrix/client/v3/rooms/%s/send/m.room.message/%s" % (self.q(room_id), txn)
        event = self._request("PUT", path, {"msgtype": "m.text", "body": text}).get("event_id")
        if not event:
            raise MatrixError("send returned no event_id")
        return event


# --- the control process ---------------------------------------------------

class Control:
    SOURCE = "jill-control"

    def __init__(self, cfg, matrix, clock=time.time):
        self.cfg = cfg
        self.matrix = matrix
        self.clock = clock
        self.halt_file = os.path.join(cfg["control_dir"], flags.HALT)
        self.conservation_file = os.path.join(cfg["control_dir"], flags.CONSERVATION)
        self.cursor_file = os.path.join(cfg["control_dir"], "matrix-control-cursor.json")
        self.armed_file = os.path.join(cfg["control_dir"], "armed.json")
        self.cred_state_file = os.path.join(cfg["control_dir"], "credential-expiry-state.json")
        stored, _ = flags.read(self.cursor_file)
        room = cfg["control_room"]
        self.cursor = stored.get(room) if isinstance(stored.get(room), str) else None
        self.started = clock()
        self.sent = []  # alert send times, for the rate limit

    # -- acks ---------------------------------------------------------------

    def describe_state(self):
        def line(label, path):
            data, ok = flags.read(path)
            st = flags.state(path)
            if not ok:
                return "%s: ON (file unreadable, so treated as on)" % label
            if st == "off":
                return "%s: off" % label
            if st == "expired":
                return "%s: expired, clears on the next check" % label
            bits = ["%s: ON since %s" % (label, data.get("enabled_at") or "unknown")]
            if data.get("reason"):
                bits.append("reason: %s" % data["reason"])
            bits.append("auto-lift: %s" % (data.get("auto_lift_after") or "none"))
            return " - ".join(bits)

        return "\n".join([line("halt", self.halt_file), line("conservation", self.conservation_file), "",
                          "halt | resume | conserve | unconserve | status"])

    def apply(self, command, duration, reason):
        by = "%s:%s" % (self.SOURCE, self.cfg["principal"])
        if command == "status":
            return self.describe_state()
        if command == "halt":
            flags.write(self.halt_file, True, by, duration, reason)
            lift = "Auto-lift %s." % duration if duration else "No auto-lift - stays halted until you say `resume`."
            return ("HALTED. No further Jill heartbeat runs, critical ones included. The dispatcher checks "
                    "before every run and every retry.\n"
                    "%s\n"
                    "Still possible for a short while: the one scheduled run already in progress finishes "
                    "(up to about 20 minutes).\n"
                    "NOT covered by halt: chat with Jill through her bridge, which only you drive.\n"
                    "Say `resume` to lift, `status` to check." % lift)
        if command == "conserve":
            flags.write(self.conservation_file, True, by, duration, reason)
            lift = "Auto-lift %s." % duration if duration else "No auto-lift - stays on until you say `resume`."
            return ("CONSERVATION ON. Heartbeats marked `normal` and `background` are skipped from the next "
                    "tick; `critical` ones still run.\n%s\nIf you want everything to stop, say `halt`." % lift)
        if command == "unconserve":
            flags.write(self.conservation_file, False)
            return "Conservation off. Normal and background heartbeats resume at the next tick."
        flags.write(self.halt_file, False)
        flags.write(self.conservation_file, False)
        return "RESUMED. Halt and conservation both cleared. Heartbeats resume at the next tick."

    def _save_cursor(self):
        try:
            write_json_atomic(self.cursor_file, {self.cfg["control_room"]: self.cursor})
        except OSError as exc:
            log("WARN: could not persist cursor: %s" % exc)

    def _mark_armed(self):
        try:
            write_json_atomic(self.armed_file, {"armed_at": int(self.clock()), "room": "control"})
        except OSError as exc:
            log("WARN: could not write armed.json: %s" % exc)

    # -- listener -----------------------------------------------------------

    def poll_room(self):
        room = self.cfg["control_room"]
        if not self.cursor:
            # First sight: take the position, act on nothing. The backward
            # page's `end`, not its `start` (conduwuit returns a sentinel
            # `start` a forward page never moves past - chassis 130db62), then
            # one forward page skipped so a server that repeats the newest
            # event (Synapse) does not act on it.
            data = self.matrix.messages(room, direction="b", limit=1)
            token = data.get("end") or data.get("start")
            if not token:
                log("ERROR: the control room returned no pagination token; the kill switch cannot read it")
                return False
            ahead = self.matrix.messages(room, from_token=token)
            self.cursor = ahead.get("end") or token
            self._save_cursor()
            return True
        data = self.matrix.messages(room, from_token=self.cursor)
        for ev in data.get("chunk") or []:
            body, why = parse_event(ev, self.cfg["principal"], now_ms=int(self.clock() * 1000))
            if body is None:
                if why == "encrypted":
                    log("WARN: encrypted event ignored - the kill switch cannot read encrypted rooms")
                continue
            parsed = parse_command(body)
            if parsed is None:
                continue
            command, duration, reason = parsed
            log("COMMAND %s from the principal (event %s)" % (command, ev.get("event_id")))
            try:
                text = self.apply(command, duration, reason)
            except OSError as exc:
                log("ERROR: could not write state for %s: %s" % (command, exc))
                text = "Could not apply `%s` - writing the flag file failed." % command
            try:
                self.matrix.send_text(room, text)
            except MatrixError as exc:
                log("WARN: ack failed: %s" % exc)
        end = data.get("end")
        if end and end != self.cursor:
            self.cursor = end
            self._save_cursor()
        return True

    def lift_expired(self):
        for label, path in (("halt", self.halt_file), ("conservation", self.conservation_file)):
            try:
                if flags.lift_expired(path, self.clock()):
                    log("%s auto-lift reached, flag cleared" % label)
                    self.post("%s auto-lifted as scheduled." % label.capitalize())
            except OSError as exc:
                log("WARN: could not clear expired %s: %s" % (label, exc))

    def listen_once(self):
        try:
            if self.poll_room():
                self._mark_armed()
        except MatrixError as exc:
            if exc.status == 429 and isinstance(exc.retry_after_ms, (int, float)):
                time.sleep(min(exc.retry_after_ms / 1000, 60))
            log("WARN: control room poll failed: %s" % exc)
        self.lift_expired()

    # -- alerts -------------------------------------------------------------

    def post(self, text):
        """Send one alert to the alerts room. True when delivered."""
        now = self.clock()
        self.sent = [t for t in self.sent if now - t < 3600]
        if len(self.sent) >= self.cfg["alerts_per_hour"]:
            return False
        try:
            self.matrix.send_text(self.cfg["alerts_room"], "[Jill] " + text)
        except MatrixError as exc:
            log("WARN: alert not delivered: %s" % exc)
            return False
        self.sent.append(now)
        return True

    def drain_spool(self):
        spool = self.cfg["spool_dir"]
        try:
            names = sorted(n for n in os.listdir(spool) if n.endswith(".json"))
        except OSError as exc:
            log("WARN: cannot list the alert spool: %s" % exc)
            return 0
        delivered = 0
        for name in names:
            path = os.path.join(spool, name)
            text = self._spooled_text(path)
            if text is None:
                self._reject(path, name)
                continue
            if not self.post(text):
                break
            delivered += 1
            try:
                os.remove(path)
            except OSError:
                pass
        return delivered

    @staticmethod
    def _spooled_text(path):
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                return None
            with open(path, encoding="utf-8") as fh:
                rec = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(rec, dict) or not isinstance(rec.get("text"), str):
            return None
        if not KIND_RE.match(str(rec.get("kind", ""))):
            return None
        text = CONTROL_CHARS.sub(" ", rec["text"]).strip()
        if not text:
            return None
        if len(text) > MAX_ALERT_CHARS:
            text = text[:MAX_ALERT_CHARS] + " [truncated]"
        return text

    def _reject(self, path, name):
        log("WARN: malformed spool file %s moved to rejected/" % name)
        try:
            os.makedirs(os.path.join(self.cfg["spool_dir"], "rejected"), exist_ok=True)
            os.replace(path, os.path.join(self.cfg["spool_dir"], "rejected", name))
        except OSError:
            pass

    # -- credential expiry --------------------------------------------------

    def credential_stages(self):
        """{id: (stage, detail)} for every credential this install watches."""
        now = self.clock()
        out = {}
        probe_every = self.cfg["probe_interval"]
        for cid in self.cfg["cred_expect"]:
            rec, ok = flags.read(os.path.join(self.cfg["cred_dir"], "%s.json" % cid))
            if not ok or not rec:
                if now - self.started > 2 * probe_every:
                    out[cid] = ("missing", "no probe result from its gateway; is the %s gateway running?" % cid)
                continue
            status = rec.get("http_status")
            status = status if isinstance(status, int) and not isinstance(status, bool) and 0 <= status < 1000 else "?"
            checked = rec.get("checked_at") if isinstance(rec.get("checked_at"), (int, float)) else 0
            last_ok = rec.get("last_ok_at") if isinstance(rec.get("last_ok_at"), (int, float)) else 0
            if rec.get("result") == "rejected":
                out[cid] = ("rejected", "the upstream refused the key (HTTP %s)" % status)
            elif now - checked > 3 * probe_every:
                out[cid] = ("unknown", "the gateway has not probed for %dh" % ((now - checked) // 3600))
            elif rec.get("result") != "ok" and now - last_ok > 86400:
                out[cid] = ("unknown", "the probe has not succeeded for over a day (HTTP %s)" % status)
            else:
                out[cid] = ("ok", "")
        if self.cfg.get("matrix_probe") is not None:
            out["matrix"] = self.cfg["matrix_probe"]
        for cid, expires in self.cfg["cred_expires"].items():
            epoch = flags.parse_iso(expires if "T" in expires else expires + "T00:00:00Z")
            if epoch is None:
                stage = ("unknown", "CREDENTIAL_EXPIRES has an unparseable date for it")
            else:
                days = (epoch - now) / 86400
                if days <= 0:
                    stage = ("expired", "its recorded expiry date %s has passed" % expires)
                elif days <= self.cfg["urgent_days"]:
                    stage = ("t1", "expires %s, within %d day(s)" % (expires, self.cfg["urgent_days"]))
                elif days <= self.cfg["warn_days"]:
                    stage = ("t7", "expires %s, within %d days" % (expires, self.cfg["warn_days"]))
                else:
                    stage = ("ok", "")
            prior = out.get(cid)
            if prior is None or STAGE_RANK[stage[0]] > STAGE_RANK[prior[0]]:
                out[cid] = stage
        return out

    def probe_matrix(self):
        try:
            self.matrix.whoami()
            self.cfg["matrix_probe"] = ("ok", "")
        except MatrixError as exc:
            if exc.status in (401, 403):
                self.cfg["matrix_probe"] = ("rejected", "the homeserver refused the control token (HTTP %d)" % exc.status)
            else:
                self.cfg["matrix_probe"] = ("unknown", "the homeserver is unreachable")

    def check_credentials(self):
        """Alert on a stage change; re-nag the stages that do not self-resolve."""
        now = self.clock()
        state, _ = flags.read(self.cred_state_file)
        changed = False
        for cid, (stage, detail) in sorted(self.credential_stages().items()):
            rec = state.get(cid) if isinstance(state.get(cid), dict) else None
            if stage == "ok":
                if rec:
                    if self.post("Credential `%s` is healthy again." % cid):
                        state.pop(cid, None)
                        changed = True
                continue
            renag = (rec and stage in RENAG_STAGES
                     and now - rec.get("alerted_at", 0) >= self.cfg["realert_days"] * 86400)
            if rec is None or rec.get("stage") != stage or renag:
                text = "Credential `%s`: %s - %s. Renew it in Jill's setup, then restart the container that holds it." % (
                    cid, stage.upper(), detail)
                if self.post(text):
                    state[cid] = {"stage": stage, "alerted_at": int(now)}
                    changed = True
        if changed:
            try:
                write_json_atomic(self.cred_state_file, state)
            except OSError as exc:
                log("WARN: could not save credential state: %s" % exc)


# --- configuration and boot ------------------------------------------------

def _int_env(env, name, default, minimum):
    try:
        return max(minimum, int(env.get(name, default)))
    except ValueError:
        return default


def parse_expires(raw):
    out = {}
    for item in re.split(r"[,\s]+", (raw or "").strip()):
        if "=" in item:
            k, _, v = item.partition("=")
            if re.fullmatch(r"[a-z0-9-]{1,40}", k.strip()):
                out[k.strip()] = v.strip()
    return out


def load_config(env=os.environ):
    """(cfg, problems). Fails closed: any problem leaves the switch unarmed."""
    problems = []
    token = env.get("MATRIX_CONTROL_TOKEN", "")
    if not token:
        problems.append("MATRIX_CONTROL_TOKEN is unset")
    principal = (env.get("MATRIX_PRINCIPAL") or "").strip()
    if not MXID_RE.match(principal):
        problems.append("MATRIX_PRINCIPAL must be the principal's full Matrix user id (@name:server)")
    room = (env.get("MATRIX_CONTROL_ROOM") or "").strip()
    if not room.startswith("!"):
        problems.append("MATRIX_CONTROL_ROOM must be a room id (!id:server), not an alias")
    alerts_room = (env.get("MATRIX_ALERTS_ROOM") or room).strip()
    if not alerts_room.startswith("!"):
        problems.append("MATRIX_ALERTS_ROOM must be a room id (!id:server)")
    cfg = {
        "homeserver": (env.get("MATRIX_HOMESERVER") or "http://host.docker.internal:8008").rstrip("/"),
        "token": token,
        "principal": principal,
        "control_room": room,
        "alerts_room": alerts_room,
        "control_dir": env.get("CONTROL_DIR", "/state/control"),
        "spool_dir": env.get("ALERT_SPOOL_DIR", "/state/alerts"),
        "cred_dir": env.get("CREDENTIAL_STATUS_DIR", "/state/credentials"),
        "cred_expect": [c for c in re.split(r"[,\s]+", env.get("CREDENTIAL_EXPECT", "venice")) if c],
        "cred_expires": parse_expires(env.get("CREDENTIAL_EXPIRES", "")),
        "probe_interval": _int_env(env, "CREDENTIAL_PROBE_SECONDS", 3600, 60),
        "warn_days": _int_env(env, "CREDENTIAL_WARN_DAYS", 7, 1),
        "urgent_days": _int_env(env, "CREDENTIAL_URGENT_DAYS", 1, 1),
        "realert_days": _int_env(env, "CREDENTIAL_REALERT_DAYS", 3, 1),
        "poll_seconds": _int_env(env, "CONTROL_POLL_SECONDS", 15, 5),
        "alerts_per_hour": _int_env(env, "ALERTS_PER_HOUR", 20, 1),
        "announce": env.get("CONTROL_ANNOUNCE_ON_BOOT", "1") == "1",
        "matrix_probe": None,
    }
    return cfg, problems


def boot(control):
    """Prove the switch can hear and the alert path can speak before arming.
    Returns a list of failures (empty = armed)."""
    cfg, m = control.cfg, control.matrix
    failures = []
    for d in (cfg["control_dir"], cfg["spool_dir"]):
        probe = os.path.join(d, ".boot-write-check")
        try:
            with open(probe, "w") as fh:
                fh.write("x")
            os.remove(probe)
        except OSError:
            failures.append("%s is not writable" % d)
    try:
        if not m.whoami():
            failures.append("whoami returned no user id")
    except MatrixError as exc:
        failures.append("the homeserver refused or could not be reached (%s)" % exc)
        return failures
    for label, room in (("control", cfg["control_room"]), ("alerts", cfg["alerts_room"])):
        try:
            m.joined(room)
        except MatrixError as exc:
            failures.append("the bot is not joined to the %s room (%s)" % (label, exc))
            continue
        try:
            if m.room_encrypted(room):
                failures.append("the %s room is end-to-end encrypted; this process holds no keys, so a `halt` "
                                "sent there would do nothing. Use an unencrypted room." % label)
        except MatrixError as exc:
            failures.append("could not read the %s room's encryption state (%s)" % (label, exc))
    if failures:
        return failures
    try:
        control.poll_room()
    except MatrixError as exc:
        failures.append("could not read the control room (%s)" % exc)
    return failures


def _loop(name, interval, fn):
    while True:
        try:
            fn()
        except Exception as exc:  # the switch must outlive any single failure
            log("ERROR: %s failed, continuing: %s" % (name, exc))
        time.sleep(interval)


def main():
    cfg, problems = load_config()
    if problems:
        log("ERROR: the Matrix kill switch is UNARMED. Jill cannot be stopped from Matrix.")
        for p in problems:
            log("ERROR:   %s" % p)
        log("ERROR: see docs/control.md. Staying up unhealthy; the dispatcher will not start without an armed switch.")
        while True:
            time.sleep(3600)
    control = Control(cfg, Matrix(cfg["homeserver"], cfg["token"]))
    failures = boot(control)
    if failures:
        log("ERROR: boot self-test failed; the kill switch is UNARMED:")
        for f in failures:
            log("ERROR:   %s" % f)
        return 1
    control._mark_armed()
    with open("/tmp/control-ready", "w") as fh:
        fh.write("armed\n")
    log("boot self-test passed: token valid, rooms joined and unencrypted, control room readable. ARMED.")
    if cfg["announce"]:
        control.post("Kill switch armed. Say `status`, `halt` or `resume` here.")
    threading.Thread(target=_loop, args=("spool", 10, control.drain_spool), daemon=True).start()

    def credentials():
        control.probe_matrix()
        control.check_credentials()

    threading.Thread(target=_loop, args=("credentials", min(cfg["probe_interval"], 3600), credentials),
                     daemon=True).start()
    _loop("listener", cfg["poll_seconds"], control.listen_once)


if __name__ == "__main__":
    sys.exit(main())
