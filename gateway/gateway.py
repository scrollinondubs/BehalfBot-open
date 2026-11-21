#!/usr/bin/env python3
"""Egress and control gateways for Jill. Stdlib only.

One process per route, each in its own container (docker-compose.yml):

  venice     POST /api/v1/chat/completions: model on the private-model
             allowlist, request fields and venice parameters on allowlists,
             no remote media (image_url must be a data: URL); GET /api/v1/models
  agentmail  READ her inbox (threads, messages, drafts, attachments);
             CREATE / EDIT / DELETE drafts to anyone (no scheduling fields);
             SEND a draft only with Sean's one-shot approval of that draft as
             it is now (gateway/approvals.py); every other send path refused
  siyuan     read-only endpoints; SQL a single SELECT; file reads only inside
             notebook folders (/data/<notebook-id>/...)
  mcp        an HTTP MCP server on a private network (Brave), /mcp only
  fetch      GET exactly one URL Sean approved, once, not following
             redirects, never to a private address; POST /request records
             a URL Jill would like Sean to approve
  api        the opencode serve API, for the bridge and dispatcher only:
             basic auth, a route allowlist (no MCP registration, no shell,
             no PTY, no config writes, no upgrade)

Every JSON body is parsed strictly (duplicate keys refused, including
case variants, at every depth), validated, and RE-SERIALISED: the upstream
receives the checked object, never the caller's bytes. Paths are
percent-decoded until stable, checked, and re-encoded by this process.
Repeated security-relevant headers are refused. Bodies and headers are
never logged.
"""
import base64
import hmac
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import approvals  # noqa: E402
import control_flags as flags  # noqa: E402

MAX_BODY = 20 * 1024 * 1024
VENICE_MAX_BODY = 4 * 1024 * 1024  # red-team R3-1: a refused body must not balloon memory
MAX_JSON_CONTAINERS = 50_000  # arrays + objects in one body; parsed only below this
MAX_FETCH = 10 * 1024 * 1024
DRAIN_SECONDS = 60
DRAIN_BYTES = 64 * 1024 * 1024
FWD_REQ_HEADERS = ("content-type", "accept", "mcp-session-id", "mcp-protocol-version", "last-event-id")
SINGLE_HEADERS = FWD_REQ_HEADERS + ("authorization", "content-length", "transfer-encoding", "host")
FWD_RESP_HEADERS = ("content-type", "cache-control", "mcp-session-id", "retry-after")
EMAIL = re.compile(r"^[^@\s<>,;]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class Deny(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class Forward:
    """What to send upstream after a policy approved the request."""

    def __init__(self, method, path, body=None, query=None, raw=None, after=None, release=None, tap=None,
                 no_caller_headers=False):
        self.method = method
        self.path = path
        self.body = body  # a validated Python object, re-serialised on send
        self.query = query or []
        self.raw = raw  # bytes, only for the trusted api route
        self.after = after  # called with (status, response bytes) before replying
        self.release = release  # called once the upstream exchange is over
        self.tap = tap  # sees the relayed response: feed(bytes), finish(status)
        self.no_caller_headers = no_caller_headers


class Local:
    """A response the gateway answers itself."""

    def __init__(self, status, obj):
        self.status = status
        self.obj = obj


# --- parsing ---------------------------------------------------------------

def canonical_path(raw):
    path = raw.split("?", 1)[0].split("#", 1)[0] or "/"
    for _ in range(5):
        nxt = unquote(path)
        if nxt == path:
            break
        path = nxt
    else:
        raise Deny(400, "path is encoded too many times")
    if not path.startswith("/") or "\\" in path or "//" in path or any(ord(c) < 0x21 for c in path):
        raise Deny(400, "malformed path")
    if any(seg in (".", "..") for seg in path.split("/")):
        raise Deny(400, "path traversal")
    return path


def _no_dupes(pairs):
    seen = set()
    for k, _ in pairs:
        low = k.lower()
        if low in seen:
            raise Deny(400, "duplicate or case-variant JSON key")
        seen.add(low)
    return dict(pairs)


def strict_json(body, allow_empty=False):
    if not body:
        if allow_empty:
            return {}
        raise Deny(400, "body required")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise Deny(400, "body must be UTF-8 JSON")
    if text.startswith("﻿"):
        raise Deny(400, "byte-order mark not accepted")
    # Counted before parsing: millions of tiny containers cost far more
    # memory to parse than their bytes (red-team R3-1, kill3).
    if text.count("[") + text.count("{") > MAX_JSON_CONTAINERS:
        raise Deny(413, "too many JSON arrays and objects in one body")
    try:
        data = json.loads(text, object_pairs_hook=_no_dupes)
    except Deny:
        raise
    except ValueError:
        raise Deny(400, "body is not JSON")
    if not isinstance(data, dict):
        raise Deny(400, "body must be a JSON object")
    return data


def only_keys(obj, allowed, what):
    if not isinstance(obj, dict):
        raise Deny(400, f"{what} must be an object")
    extra = sorted(k for k in obj if k not in allowed)
    if extra:
        raise Deny(403, f"{what} has fields this gateway does not allow: {', '.join(extra)}")


def query_pairs(raw, allowed):
    q = raw.split("?", 1)[1] if "?" in raw else ""
    pairs = parse_qsl(q, keep_blank_values=True)
    names = [k for k, _ in pairs]
    if len(set(names)) != len(names):
        raise Deny(400, "repeated query parameter")
    bad = [k for k in names if k not in allowed]
    if bad:
        raise Deny(403, "query parameter not allowed: " + ", ".join(sorted(bad)))
    return pairs


# --- venice ----------------------------------------------------------------

VENICE_TOP = {
    "model", "messages", "stream", "stream_options", "max_tokens", "max_completion_tokens", "temperature",
    "top_p", "tools", "tool_choice", "parallel_tool_calls", "stop", "seed", "frequency_penalty",
    "presence_penalty", "reasoning_effort", "response_format", "venice_parameters", "veniceParameters",
}
VENICE_PARAMS = {"disableThinking", "disable_thinking", "stripThinkingResponse", "strip_thinking_response",
                 "include_venice_system_prompt", "includeVeniceSystemPrompt"}
MESSAGE_KEYS = {"role", "content", "name", "tool_calls", "tool_call_id", "reasoning_content"}


# --- control gate and daily meter (venice; #49) ----------------------------
#
# All of Jill's spend goes through this gateway (chat and any heartbeat), so
# the kill switch and the spend ceiling bind HERE, where Jill cannot route
# around them, not only in the dispatcher.

def control_gate(ctx):
    """Refuse model calls while halted, or while the kill switch is not
    listening. The control-state volume is mounted read-only; if it is
    configured but missing, refuse (a switch nobody can see is not armed)."""
    d = ctx.get("control_dir")
    if not d:
        return
    if not os.path.isdir(d):
        raise Deny(503, "control state is not mounted; model calls refused")
    if flags.state(os.path.join(d, flags.HALT)) == "on":
        raise Deny(423, "Jill is halted by Sean; model calls are refused until he says resume")
    if ctx.get("require_armed"):
        armed, ok = flags.read(os.path.join(d, "armed.json"))
        at = armed.get("armed_at") if ok else None
        now = time.time()
        # NaN, Infinity and a time in the future are not a heartbeat (R3-5).
        if not isinstance(at, (int, float)) or isinstance(at, bool) or not math.isfinite(at) \
                or at > now + 60 or now - at > ctx["armed_max_age"]:
            raise Deny(503, "the kill switch is not listening; model calls are paused until it is")


def parse_prices(raw):
    """'model=in:out:cache_read,...' -> {model: (in, out, cache)}, USD per 1M tokens."""
    out = {}
    for item in (raw or "").split(","):
        name, _, nums = item.strip().partition("=")
        parts = nums.split(":")
        try:
            vals = [float(x) for x in parts]
        except ValueError:
            continue
        if name and len(vals) >= 2 and all(math.isfinite(v) and v >= 0 for v in vals):
            out[name] = (vals[0], vals[1], vals[2] if len(vals) > 2 else vals[0])
    return out


DEFAULT_PRICES = "zai-org-glm-5-2=1.40:4.40:0.26,z-ai-glm-5-3-flash=0.17:0.55:0.03"


def _count(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None




class Meter:
    """Per-day Venice spend and requests, persisted in the gateway's own
    volume (red-team round 2, N1-N3).

    reserve() HOLDS a pessimistic amount for the call: the model's whole
    context window (VENICE_MAX_PROMPT_TOKENS) as prompt tokens plus the
    output-token cap, at the model's prices. That bounds any bill Venice can
    issue for one call, whatever its usage says, so the ceiling holds even
    if a usage figure is wrong. A call
    is refused when settled + held + its hold would pass the ceiling, when
    VENICE_MAX_IN_FLIGHT calls are already open, past the per-minute rate,
    or past the daily request ceiling. settle() swaps the hold for the cost
    in the response's `usage`; with no usable usage (or an unknown outcome)
    the whole hold is charged. Settled spend therefore never passes the
    ceiling unless Venice bills past the model's context window. A
    meter file that cannot be read refuses everything.
    The principal's `reset meter` (control-state/meter-reset.json, written
    by jill-control) zeroes today's meter once."""

    def __init__(self, state_dir, max_usd, max_requests, prices, max_out=8192, max_in_flight=4,
                 per_minute=30, control_dir=None, clock=time.time, max_prompt=1048576):
        self.dir = state_dir
        self.max_usd = max_usd
        self.max_requests = max_requests
        self.prices = prices
        self.max_out = max_out
        self.max_prompt = max_prompt
        self.max_in_flight = max_in_flight
        self.per_minute = per_minute
        self.control_dir = control_dir
        self.clock = clock
        self.lock = threading.Lock()
        self.held = 0.0
        self.in_flight = 0
        self.recent = []

    def _path(self, day=None):
        return os.path.join(self.dir, "meter-%s.json" % (day or self._day()))

    def _day(self):
        return time.strftime("%Y-%m-%d", time.gmtime(self.clock()))

    def _load(self, day=None):
        p = self._path(day)
        if not os.path.lexists(p):
            return {"requests": 0, "usd": 0.0, "unmetered": 0}
        rec, ok = flags.read(p)
        req, usd = rec.get("requests"), rec.get("usd")
        if not ok or not isinstance(req, int) or isinstance(req, bool) or req < 0 \
                or not isinstance(usd, (int, float)) or isinstance(usd, bool) or not math.isfinite(usd) or usd < 0:
            raise Deny(503, "the Venice meter is unreadable; model calls are refused today")
        return rec

    def _save(self, rec, day=None):
        rec.update(date=day or self._day(), ceiling_usd=self.max_usd,
                   max_requests=self.max_requests, held_usd=round(self.held, 6), in_flight=self.in_flight)
        try:
            os.makedirs(self.dir, exist_ok=True)
            safe_write_json(self._path(day), rec)
        except OSError:
            raise Deny(503, "the Venice meter cannot be written; model calls are refused")

    def _apply_reset(self, rec):
        """`reset meter` clears the request count and the rate window;
        `reset meter spend` also clears the dollars. Applied once per
        request (keyed on its Matrix event time, so a replay is a no-op)."""
        if not self.control_dir:
            return
        req, ok = flags.read(os.path.join(self.control_dir, "meter-reset.json"))
        at = req.get("requested_at") if ok else None
        if isinstance(at, (int, float)) and not isinstance(at, bool) and math.isfinite(at) \
                and at > rec.get("reset_applied_at", 0) and at <= self.clock() + 60:
            rec.update(requests=0, reset_applied_at=at)
            self.recent = []
            if req.get("spend") is True:
                rec.update(usd=0.0, unmetered=0, over_hold=0)

    def recover(self):
        """After a restart the in-memory holds are gone but their calls may
        still be billed (red-team R3-1): fold the persisted held_usd into
        usd, and in_flight into unmetered, on the newest meter file."""
        try:
            names = sorted(n for n in os.listdir(self.dir) if re.fullmatch(r"meter-\d{4}-\d{2}-\d{2}\.json", n))
        except OSError:
            return None
        if not names:
            return None
        day = names[-1][len("meter-"):-len(".json")]
        with self.lock:
            rec = self._load(day)
            held, flying = rec.get("held_usd", 0), rec.get("in_flight", 0)
            held = held if isinstance(held, (int, float)) and not isinstance(held, bool) and math.isfinite(held) \
                and held > 0 else 0.0
            flying = flying if isinstance(flying, int) and not isinstance(flying, bool) and flying > 0 else 0
            if held or flying:
                rec["usd"] = round(rec["usd"] + held, 6)
                rec["unmetered"] = rec.get("unmetered", 0) + flying
                rec["recovered_holds"] = rec.get("recovered_holds", 0) + flying
            self._save(rec, day)
        return held, flying

    def price(self, model):
        if model in self.prices:
            return self.prices[model]
        return tuple(max(p[i] for p in self.prices.values()) for i in range(3))

    def hold_for(self, model, body_len=0, full=False):
        """Prompt bound: the request's bytes plus 4096 (a text prompt cannot
        have more tokens than bytes; 4096 covers what Venice adds), capped at
        the context window. full=True uses the whole context window: the
        fallback once a bill has passed its hold twice in a day."""
        p_in, p_out, _ = self.price(model)
        prompt = self.max_prompt if full else min(self.max_prompt, body_len + HOLD_PROMPT_SLACK)
        return (prompt * p_in + self.max_out * p_out) / 1e6

    def min_hold(self):
        """The smallest hold the dearest allowed model can take."""
        return max(self.hold_for(m, 0) for m in self.prices)

    def cost(self, model, usage):
        """USD for an OpenAI-style usage object, or None when it is unusable."""
        try:
            if not isinstance(usage, dict):
                return None
            prompt, completion = _count(usage.get("prompt_tokens")), _count(usage.get("completion_tokens"))
            if prompt is None or completion is None or prompt + completion == 0:
                return None  # no real call has zero tokens: charge the hold
            pd = usage.get("prompt_tokens_details") if isinstance(usage.get("prompt_tokens_details"), dict) else {}
            cd = usage.get("completion_tokens_details") if isinstance(usage.get("completion_tokens_details"), dict) else {}
            cached = min(_count(pd.get("cached_tokens")) or 0, prompt)
            reasoning = _count(cd.get("reasoning_tokens")) or 0
            # Reasoning is normally inside completion_tokens; if a model
            # reports more reasoning than completion, it was counted apart.
            out = completion + reasoning if reasoning > completion else completion
            p_in, p_out, p_cache = self.price(model)
            usd = ((prompt - cached) * p_in + cached * p_cache + out * p_out) / 1e6
        except (OverflowError, ValueError, TypeError):
            return None
        return usd if math.isfinite(usd) and usd >= 0 else None

    def _rate_check(self, rec):
        now = self.clock()
        self.recent = [t for t in self.recent if now - t < 60]
        if len(self.recent) >= self.per_minute:
            raise Deny(429, "more than %d Venice calls in a minute; slow down" % self.per_minute)
        if rec["requests"] >= self.max_requests:
            raise Deny(429, "the daily Venice request ceiling (%d) is reached" % self.max_requests)

    def count_request(self):
        """A call that costs nothing (GET /models, on a cache miss) still counts."""
        with self.lock:
            rec = self._load()
            self._apply_reset(rec)
            self._rate_check(rec)
            rec["requests"] += 1
            self.recent.append(self.clock())
            self._save(rec)

    def reserve(self, model, body_len):
        with self.lock:
            rec = self._load()
            self._apply_reset(rec)
            # Two bills over their hold today: the size-based bound is not
            # holding, so use the whole context window for the rest of the day.
            hold = self.hold_for(model, body_len, full=rec.get("over_hold", 0) >= 2)
            if self.in_flight >= self.max_in_flight:
                self._save(rec)
                raise Deny(429, "%d Venice calls are already in flight; try again shortly" % self.max_in_flight)
            if rec["usd"] + self.held >= self.max_usd or rec["usd"] + self.held + hold > self.max_usd:
                self._save(rec)
                raise Deny(429, "the daily Venice spend ceiling ($%.2f) is reached or held by calls in flight; "
                                "model calls resume tomorrow (UTC)" % self.max_usd)
            self._rate_check(rec)
            rec["requests"] += 1
            self.recent.append(self.clock())
            self.held += hold
            self.in_flight += 1
            try:
                self._save(rec)
            except Deny:
                self.held -= hold
                self.in_flight -= 1
                raise
        return hold, rec["date"]

    def settle(self, model, hold, status, usage, day=None):
        """status None means the outcome is unknown: the hold is charged.
        The cost lands on the day the call was reserved."""
        cost = self.cost(model, usage)
        unmetered = 0
        if cost is None:
            if status is None or 200 <= status < 300:
                cost, unmetered = hold, 1
            else:
                cost = 0.0
        with self.lock:
            self.held = max(0.0, self.held - hold)
            self.in_flight = max(0, self.in_flight - 1)
            try:
                rec = self._load(day)
            except Deny:
                return
            rec["usd"] = round(rec["usd"] + cost, 6)
            rec["unmetered"] = rec.get("unmetered", 0) + unmetered
            if cost > hold:
                rec["over_hold"] = rec.get("over_hold", 0) + 1
            try:
                self._save(rec, day)
            except Deny:
                pass


class UsageTap:
    """Sees a relayed response and settles the meter. SSE `data:` lines are
    parsed as they stream past, so a usage chunk at the end of a stream of
    any size is seen; a JSON body over LIMIT is searched from its tail
    (red-team N2)."""

    LIMIT = 4 * 1024 * 1024
    TAIL = 1024 * 1024
    LINE = 1024 * 1024

    def __init__(self, meter, model, hold, day=None):
        self.meter, self.model, self.hold, self.day = meter, model, hold, day
        self.head, self.tail, self.line = bytearray(), bytearray(), bytearray()
        self.total, self.sse_usage, self.done, self.complete = 0, None, False, False

    def feed(self, chunk):
        self.total += len(chunk)
        if len(self.head) < self.LIMIT:
            self.head += chunk[: self.LIMIT - len(self.head)]
        self.tail += chunk
        if len(self.tail) > self.TAIL:
            del self.tail[: len(self.tail) - self.TAIL]
        data = bytes(self.line) + chunk
        parts = data.split(b"\n")
        self.line = bytearray(parts.pop()[-self.LINE:])
        for raw in parts:
            self._line(raw)

    def _line(self, raw):
        line = raw.strip()
        if line.startswith(b"data:") and b'"usage"' in line:
            try:
                obj = json.loads(line[5:].strip())
            except ValueError:
                return
            if isinstance(obj, dict) and isinstance(obj.get("usage"), dict):
                self.sse_usage = obj["usage"]

    def usage(self):
        if self.line:
            self._line(bytes(self.line))
            self.line = bytearray()
        if self.sse_usage is not None:
            return self.sse_usage
        if self.total <= self.LIMIT:
            try:
                obj = json.loads(bytes(self.head))
                return obj.get("usage") if isinstance(obj, dict) else None
            except ValueError:
                return None
        text = bytes(self.tail).decode("utf-8", errors="replace")
        at = text.rfind('"usage"')
        if at < 0:
            return None
        brace = text.find("{", at)
        try:
            obj, _ = json.JSONDecoder().raw_decode(text[brace:])
        except (ValueError, IndexError):
            return None
        return obj if isinstance(obj, dict) else None

    def finish(self, status):
        if not self.done:
            self.done = True
            usage = self.usage() if self.complete else None
            self.meter.settle(self.model, self.hold, status if self.complete else None, usage, self.day)


def safe_write_json(path, obj):
    """Write via a random O_EXCL|O_NOFOLLOW temp name, then rename: a planted
    symlink or FIFO at a predictable temp path can neither redirect nor
    block the write."""
    d = os.path.dirname(path) or "."
    tmp = os.path.join(d, ".%s.%s.tmp" % (os.path.basename(path), os.urandom(8).hex()))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def venice_policy(ctx, method, path, body):
    if method == "GET" and path == "/api/v1/models":
        # Gated, served from a 10-minute cache, and on a miss counted like a
        # call with none of the caller's headers going upstream (N5, R3-4).
        control_gate(ctx)
        cache = ctx.get("models_cache")
        if cache is not None and cache.get("body") is not None and time.time() - cache["at"] < MODELS_CACHE_SECONDS:
            return Local(200, cache["body"])
        if ctx.get("meter") is not None:
            ctx["meter"].count_request()

        def remember(status, data):
            if cache is not None and status == 200:
                try:
                    cache.update(body=json.loads(data), at=time.time())
                except ValueError:
                    pass

        return Forward("GET", path, no_caller_headers=True, after=remember)
    if method != "POST" or path != "/api/v1/chat/completions":
        raise Deny(403, "only chat/completions (POST) and models (GET) are forwarded")
    control_gate(ctx)
    data = strict_json(body)
    only_keys(data, VENICE_TOP, "request")
    if data.get("model") not in ctx["models"]:
        raise Deny(403, "model is not on the private-model allowlist")
    for k in ("venice_parameters", "veniceParameters"):
        if k in data:
            only_keys(data[k], VENICE_PARAMS, k)
            if any(not isinstance(v, bool) for v in data[k].values()):
                raise Deny(400, f"{k} values must be booleans")
    msgs = data.get("messages")
    if not isinstance(msgs, list):
        raise Deny(400, "messages must be a list")
    for m in msgs:
        only_keys(m, MESSAGE_KEYS, "message")
        content = m.get("content")
        if isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    raise Deny(400, "content parts must be objects")
                kind = part.get("type")
                if kind == "text":
                    only_keys(part, {"type", "text", "cache_control"}, "text part")
                elif kind == "image_url":
                    only_keys(part, {"type", "image_url"}, "image part")
                    url = part["image_url"].get("url", "") if isinstance(part["image_url"], dict) else part["image_url"]
                    if not str(url).startswith("data:"):
                        raise Deny(403, "remote media is not forwarded; inline it as a data: URL")
                else:
                    raise Deny(403, f"content part type {kind!r} is not forwarded")
        elif content is not None and not isinstance(content, str):
            raise Deny(400, "message content must be text or parts")
    if data.get("stream"):
        # Venice only reports usage on a stream when asked; the meter needs it.
        data["stream_options"] = {"include_usage": True}
    meter = ctx.get("meter")
    if meter is None:
        return Forward("POST", path, body=data)
    # Bound the output so the hold bounds the call (red-team N1).
    # max_completion_tokens covers reasoning as well as visible output.
    for k in ("max_tokens", "max_completion_tokens"):
        v = data.get(k)
        if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 1):
            raise Deny(400, f"{k} must be a positive integer")
    asked = [data[k] for k in ("max_tokens", "max_completion_tokens") if data.get(k) is not None]
    cap = min(asked + [meter.max_out])
    data["max_completion_tokens"] = cap
    data["max_tokens"] = cap
    hold, day = meter.reserve(data["model"], len(json.dumps(data)))
    return Forward("POST", path, body=data, tap=UsageTap(meter, data["model"], hold, day))


MODELS_CACHE_SECONDS = 600
HOLD_PROMPT_SLACK = 4096
WRITE_TIMEOUT = 30  # a caller that does not read for this long is treated as gone (R3-2)
CALL_DEADLINE = 15 * 60  # whole call, first byte to last


# --- agentmail -------------------------------------------------------------

DRAFT_KEYS = {"to", "cc", "bcc", "reply_to", "subject", "text", "html", "labels", "attachments", "in_reply_to"}
ATTACHMENT_KEYS = {"filename", "content_type", "content", "content_disposition", "content_id"}
READ_QUERY = {"limit", "page_token", "labels", "before", "after", "ascending"}


# C0 controls and DEL. Bodies may carry newlines and tabs; nothing else may
# carry any control character (round-4 red-team N1: CR/LF in subject,
# labels, attachment names or in_reply_to could become extra MIME headers).
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
BODY_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MESSAGE_ID = re.compile(r"^<[^<>\s\x00-\x1f\x7f]{1,250}>$")


def _text(v, what, body=False):
    if not isinstance(v, str):
        raise Deny(400, f"{what} must be a string")
    if (BODY_CONTROL if body else CONTROL).search(v):
        raise Deny(400, f"{what} contains control characters")
    return v


def _addresses(v, what):
    """Plain addresses only; returned stripped, with the domain lower-cased."""
    items = v if isinstance(v, list) else [v]
    out = []
    for it in items:
        if not isinstance(it, str):
            raise Deny(400, f"{what} must be plain email addresses")
        a = it.strip(" ")
        if CONTROL.search(a) or not EMAIL.match(a):
            raise Deny(400, f"{what} must be plain email addresses")
        local, _, domain = a.rpartition("@")
        out.append(f"{local}@{domain.lower()}")
    return out if isinstance(v, list) else out[0]


def validate_draft(data):
    """Validate and NORMALISE a draft; the normalised form is what is
    forwarded, snapshotted, digested and sent."""
    only_keys(data, DRAFT_KEYS, "draft")
    out = {}
    for k in ("to", "cc", "bcc", "reply_to"):
        if k in data:
            out[k] = _addresses(data[k], k)
    if "subject" in data:
        out["subject"] = _text(data["subject"], "subject")
    for k in ("text", "html"):
        if k in data:
            out[k] = _text(data[k], k, body=True)
    if "in_reply_to" in data:
        v = _text(data["in_reply_to"], "in_reply_to")
        if not MESSAGE_ID.match(v):
            raise Deny(400, "in_reply_to must be a single message id like <id@host>")
        out["in_reply_to"] = v
    if "labels" in data:
        if not isinstance(data["labels"], list):
            raise Deny(400, "labels must be a list of strings")
        out["labels"] = [_text(x, "label") for x in data["labels"]]
    if "attachments" in data:
        atts = data["attachments"]
        if not isinstance(atts, list):
            raise Deny(400, "attachments must be a list")
        clean = []
        for a in atts:
            only_keys(a, ATTACHMENT_KEYS, "attachment")
            c = {}
            for k in ("filename", "content_type", "content_disposition", "content_id"):
                if k in a:
                    c[k] = _text(a[k], f"attachment {k}")
            if "content" in a:
                content = a["content"]
                if not isinstance(content, str) or not re.fullmatch(r"[A-Za-z0-9+/=\r\n]*", content):
                    raise Deny(400, "attachment content must be base64")
                c["content"] = content
            clean.append(c)
        out["attachments"] = clean
    return out


# Per-draft locks: a draft's edit, delete and send never overlap. A fixed
# set of striped locks keeps memory bounded whatever ids callers send.
_STRIPES = [threading.Lock() for _ in range(256)]


def draft_lock(draft_id):
    return _STRIPES[int(approvals.key_for("draft", draft_id)[:8], 16) % len(_STRIPES)]


SNAPSHOT_TTL = 30 * 24 * 3600
SNAPSHOT_QUOTA = 512 * 1024 * 1024


def _snapshot_path(ctx, draft_id):
    return os.path.join(ctx["state_dir"], "drafts", approvals.key_for("draft", draft_id) + ".json")


def load_snapshot(ctx, draft_id):
    try:
        with open(_snapshot_path(ctx, draft_id)) as f:
            rec = json.load(f)
    except (OSError, ValueError):
        return None
    return rec["content"] if rec.get("draft_id") == draft_id else None


def prune_snapshots(ctx, keep=None):
    """Drop snapshots older than SNAPSHOT_TTL, then oldest-first past the quota."""
    d = os.path.join(ctx["state_dir"], "drafts")
    try:
        entries = [(e.stat().st_mtime, e.stat().st_size, e.path) for e in os.scandir(d) if e.is_file()]
    except OSError:
        return
    now = time.time()
    total = 0
    for mtime, size, path_ in sorted(entries, reverse=True):
        total += size
        if path_ != keep and (now - mtime > SNAPSHOT_TTL or total > SNAPSHOT_QUOTA):
            try:
                os.remove(path_)
            except OSError:
                pass


def remove_snapshot(ctx, draft_id):
    try:
        os.remove(_snapshot_path(ctx, draft_id))
    except FileNotFoundError:
        pass


def save_snapshot(ctx, draft_id, content):
    p = _snapshot_path(ctx, draft_id)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"draft_id": draft_id, "content": approvals.sendable(content)}, f)
    os.replace(tmp, p)
    prune_snapshots(ctx, keep=p)


def send_body(content):
    """The approved snapshot as a messages/send request (AgentMail API)."""
    body = {k: v for k, v in content.items() if k != "in_reply_to"}
    if content.get("in_reply_to"):
        body["headers"] = {"In-Reply-To": content["in_reply_to"], "References": content["in_reply_to"]}
    return body


def agentmail_policy(ctx, method, path, body):
    """Drafts to anyone; a send delivers the gateway's own snapshot of the draft.

    Round-3 red-team C1: binding an approval to a digest of AgentMail's copy
    of the draft, then asking AgentMail to send "the draft", let a PATCH
    land between the check and the send. Now:
      - every draft written through this gateway is snapshotted here (the
        validated, normalised content, attachment bytes included); a draft
        made elsewhere becomes sendable only through a gateway PATCH, and
        then what goes out is that snapshot, never the outside draft;
        Sean approves the sha256 of that snapshot (GET /_jill/.../digest)
      - a send verifies the approval against the snapshot and then POSTs
        the snapshot itself to messages/send: AgentMail's draft is not what
        gets sent, so editing it cannot change what goes out
      - edits and deletes are refused while a live approval exists
      - edit, delete and send of one draft are serialised by a lock
      - any send attempt that reaches the approval burns it
    """
    base = "/v0/inboxes/" + ctx["inbox"]
    seg = r"[^/]+"
    if path.startswith("/_jill/drafts/") and path.endswith("/digest") and method == "GET":
        draft_id = path[len("/_jill/drafts/"):-len("/digest")]
        with draft_lock(draft_id):
            content = load_snapshot(ctx, draft_id)
        if content is None:
            raise Deny(404, "no snapshot of this draft: only drafts written through this gateway can be sent")
        return Local(200, {"draft_id": draft_id, "content": content, "sha256": approvals.draft_digest(content)})
    if not path.startswith(base + "/") and path != base:
        raise Deny(403, "only Jill's own inbox is reachable")
    rest = path[len(base):]
    if method == "GET" and re.fullmatch(
            rf"(/(threads|messages|drafts)(/{seg})?|/(threads|messages)/{seg}/attachments/{seg}|/threads/{seg}/messages)?", rest):
        return Forward("GET", path, query=query_pairs(ctx["raw_path"], READ_QUERY))

    if method == "POST" and rest == "/drafts":
        draft = validate_draft(strict_json(body))

        def remember(status, resp):
            if 200 <= status < 300:
                try:
                    draft_id = json.loads(resp)["draft_id"]
                except (ValueError, KeyError, TypeError):
                    return
                with draft_lock(draft_id):
                    if approvals.status("draft", draft_id, [ctx["consumed_dir"]], base=ctx["approvals_dir"]) == "live":
                        raise Deny(409, "AgentMail returned the id of a draft Sean has approved; its snapshot was not changed")
                    save_snapshot(ctx, draft_id, draft)

        return Forward("POST", path, body=draft, after=remember)

    m = re.fullmatch(rf"/drafts/({seg})", rest)
    if m and method in ("PATCH", "DELETE"):
        draft_id = m.group(1)
        patch = validate_draft(strict_json(body)) if method == "PATCH" else None
        lock = draft_lock(draft_id)
        lock.acquire()
        try:
            if approvals.status("draft", draft_id, [ctx["consumed_dir"]], base=ctx["approvals_dir"]) == "live":
                raise Deny(409, "Sean has approved this draft as it is; it cannot change until it is sent or the approval expires")
        except BaseException:
            lock.release()
            raise

        def update(status, resp):
            if not 200 <= status < 300:
                return
            if method == "DELETE":
                remove_snapshot(ctx, draft_id)
            else:
                merged = dict(load_snapshot(ctx, draft_id) or {})
                merged.update(patch)
                save_snapshot(ctx, draft_id, merged)

        return Forward(method, path, body=patch, after=update, release=lock.release)

    m = re.fullmatch(rf"/drafts/({seg})/send", rest)
    if m and method == "POST":
        if strict_json(body, allow_empty=True):
            raise Deny(400, "draft send takes no body")
        draft_id = m.group(1)
        lock = draft_lock(draft_id)
        lock.acquire()
        try:
            content = load_snapshot(ctx, draft_id)
            if content is None:
                raise Deny(404, "no snapshot of this draft: only drafts written through this gateway can be sent")
            digest = approvals.draft_digest(content)

            def same_draft(rec):
                if rec.get("sha256") != digest:
                    raise LookupError("the draft is not the one Sean approved; this approval is now used up")

            try:
                approvals.check_and_consume("draft", draft_id, ctx["consumed_dir"], base=ctx["approvals_dir"],
                                            verify=same_draft)
            except LookupError as e:
                raise Deny(403, f"not sent: {e}. Ask Sean to approve draft {draft_id}")
        except BaseException:
            lock.release()
            raise

        def cleanup(status, resp):
            # Sent: the draft and its snapshot are done (round-4 N6).
            if 200 <= status < 300:
                remove_snapshot(ctx, draft_id)
                try:
                    ctx["upstream_call"]("DELETE", f"{base}/drafts/{draft_id}")
                except Deny:
                    pass

        return Forward("POST", f"{base}/messages/send", body=send_body(content), after=cleanup, release=lock.release)

    raise Deny(403, "not allowed: Jill reads her inbox and writes drafts; sending needs Sean's approval of the draft")


# --- siyuan ----------------------------------------------------------------

SIYUAN_READ = {
    "/api/query/sql", "/api/attr/getBlockAttrs", "/api/block/getBlockKramdown", "/api/block/getChildBlocks",
    "/api/export/exportMdContent", "/api/file/getFile", "/api/file/readDir", "/api/filetree/getHPathByID",
    "/api/filetree/getHPathByPath", "/api/filetree/getIDsByHPath", "/api/filetree/getPathByID",
    "/api/notebook/getNotebookConf", "/api/notebook/lsNotebooks", "/api/system/bootProgress",
    "/api/system/currentTime", "/api/system/version",
}
NOTEBOOK_PATH = re.compile(r"^/data/\d{14}-[a-z0-9]{7}(/[^/]+)*/?$")


def siyuan_policy(ctx, method, path, body):
    if method != "POST" or path not in SIYUAN_READ:
        raise Deny(403, "only read-only SiYuan endpoints are forwarded")
    data = strict_json(body, allow_empty=True)
    if path == "/api/query/sql":
        stmt = str(data.get("stmt", "")).strip().rstrip(";").strip()
        if not re.match(r"(?is)^(select|with)\b", stmt) or ";" in stmt:
            raise Deny(403, "SQL must be a single SELECT")
        if re.search(r"(?i)\b(insert|update|delete|drop|alter|create|replace|attach|detach|pragma|vacuum)\b", stmt):
            raise Deny(403, "SQL must be read-only")
    if path in ("/api/file/getFile", "/api/file/readDir"):
        p = str(data.get("path", ""))
        if not NOTEBOOK_PATH.match(p) or ".." in p.split("/"):
            raise Deny(403, "file reads are limited to notebook folders (/data/<notebook-id>/...)")
    return Forward("POST", path, body=data)


# --- mcp -------------------------------------------------------------------

def mcp_policy(ctx, method, path, body):
    if path != "/mcp" or method not in ("GET", "POST", "DELETE"):
        raise Deny(403, "only /mcp is forwarded")
    if method == "POST":
        try:
            data = json.loads(body.decode("utf-8"), object_pairs_hook=_no_dupes)
        except Deny:
            raise
        except (UnicodeDecodeError, ValueError):
            raise Deny(400, "body is not JSON")
        return Forward("POST", path, body=data)
    return Forward(method, path)


# --- fetch -----------------------------------------------------------------

def public_address(host, port):
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        raise Deny(502, "host does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            raise Deny(403, "approved URL resolves to a private or local address")
    return infos[0][4][0]


def fetch_policy(ctx, method, path, body):
    if method == "POST" and path == "/request":
        data = strict_json(body)
        only_keys(data, {"url", "reason"}, "request")
        url = str(data.get("url", ""))
        if not re.match(r"^https?://", url) or len(url) > 2048:
            raise Deny(400, "url must be an absolute http(s) URL")
        line = json.dumps({"ts": time.time(), "url": url, "reason": str(data.get("reason", ""))[:500]})
        os.makedirs(ctx["state_dir"], exist_ok=True)
        with open(os.path.join(ctx["state_dir"], "requests.jsonl"), "a") as f:
            f.write(line + "\n")
        return Local(202, {"status": "requested", "note": "Sean has to approve this exact URL before you can fetch it"})
    if method != "POST" or path != "/fetch":
        raise Deny(403, "POST /fetch {url} or POST /request {url, reason}")
    data = strict_json(body)
    only_keys(data, {"url"}, "fetch")
    url = str(data.get("url", ""))
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise Deny(400, "url must be an absolute http(s) URL without credentials")
    try:
        approvals.check_and_consume("url", url, ctx["consumed_dir"], base=ctx["approvals_dir"])
    except LookupError as e:
        raise Deny(403, f"not fetched: {e}. POST /request {{url, reason}} and ask Sean to approve that exact URL")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    ip = public_address(parts.hostname, port)
    return Local("fetch", {"url": url, "ip": ip, "port": port, "parts": parts})


# --- api (opencode serve, bridge and dispatcher only) ----------------------

API_ROUTES = [
    ("GET", r"/global/health"),
    ("GET", r"/(global/)?event"),
    ("GET", r"/(config|config/providers|provider|agent|command|mcp|lsp|formatter|path|project/current|vcs|app|session/status|global/config)"),
    ("GET", r"/session(/[^/]+)?"),
    ("GET", r"/session/[^/]+/(message|message/[^/]+|children|todo|diff)"),
    ("POST", r"/session"),
    ("POST", r"/session/[^/]+/(message|prompt_async|abort|init|summarize)"),
    ("PATCH", r"/session/[^/]+"),
    ("DELETE", r"/session/[^/]+"),
    ("POST", r"/session/[^/]+/permissions/[^/]+"),
    ("POST", r"/permission/[^/]+/reply"),
    ("POST", r"/question/[^/]+/(reply|reject)"),
    ("GET", r"/(permission|question)"),
    ("POST", r"/log"),
]
API_DENY_NOTE = "not allowed through the API gateway (no MCP registration, shell, PTY, config writes or upgrades)"


def api_policy(ctx, method, path, body):
    for m, rx in API_ROUTES:
        if m == method and re.fullmatch(rx, path):
            q = ctx["raw_path"].split("?", 1)[1] if "?" in ctx["raw_path"] else ""
            return Forward(method, path, raw=body, query=parse_qsl(q, keep_blank_values=True))
    raise Deny(403, API_DENY_NOTE)


ROUTES = {
    "venice": {"policy": venice_policy, "upstream": "https://api.venice.ai", "auth": "Bearer {key}"},
    "agentmail": {"policy": agentmail_policy, "upstream": "https://api.agentmail.to", "auth": "Bearer {key}"},
    "siyuan": {"policy": siyuan_policy, "upstream": None, "auth": "token {key}"},
    "mcp": {"policy": mcp_policy, "upstream": None, "auth": None},
    "fetch": {"policy": fetch_policy, "upstream": "none://", "auth": None},
    "api": {"policy": api_policy, "upstream": None, "auth": None},
}


def load_config(env=os.environ):
    name = env.get("GATEWAY_ROUTE", "")
    if name not in ROUTES:
        raise SystemExit(f"GATEWAY_ROUTE must be one of {', '.join(ROUTES)}")
    route = ROUTES[name]
    upstream = env.get("UPSTREAM_URL") or route["upstream"]
    if not upstream:
        raise SystemExit(f"UPSTREAM_URL is required for route {name}")
    split = lambda v: [x.strip().lower() if "@" in x else x.strip() for x in (v or "").split(",") if x.strip()]
    if route["auth"] and not env.get("UPSTREAM_KEY"):
        raise SystemExit("UPSTREAM_KEY is required")
    cfg = {
        "name": name,
        "policy": route["policy"],
        "upstream": urlsplit(upstream),
        "auth": route["auth"].format(key=env["UPSTREAM_KEY"]) if route["auth"] else None,
        "basic_password": env.get("GATEWAY_BASIC_PASSWORD") or None,
        "models": set(split(env.get("VENICE_MODELS"))),
        "inbox": env.get("AGENTMAIL_INBOX", ""),
        "approvals_dir": env.get("APPROVALS_DIR", "/state/approvals"),
        "consumed_dir": os.path.join(env.get("GATEWAY_STATE_DIR", "/state/gateway"), "consumed"),
        "state_dir": env.get("GATEWAY_STATE_DIR", "/state/gateway"),
        "credential_dir": env.get("CREDENTIAL_STATUS_DIR") or None,
        "control_dir": env.get("CONTROL_DIR") or None,
        "require_armed": env.get("CONTROL_REQUIRE_ARMED", "0") == "1",
        "armed_max_age": int(env.get("CONTROL_ARMED_MAX_AGE_SECONDS", "90")),
        "meter": None,
    }
    if name == "venice":
        try:
            max_usd = float(env.get("VENICE_MAX_USD_PER_DAY", "5"))
            max_req = int(env.get("VENICE_MAX_REQUESTS_PER_DAY", "2000"))
            max_out = int(env.get("VENICE_MAX_OUTPUT_TOKENS", "8192"))
            max_prompt = int(env.get("VENICE_MAX_PROMPT_TOKENS", "1048576"))
            in_flight = int(env.get("VENICE_MAX_IN_FLIGHT", "4"))
            per_minute = int(env.get("VENICE_MAX_REQUESTS_PER_MINUTE", "30"))
        except ValueError:
            raise SystemExit("the VENICE_MAX_* limits must be numbers")
        if not math.isfinite(max_usd) or max_usd < 0 or max_req < 0 or min(max_out, in_flight, per_minute, max_prompt) < 1:
            raise SystemExit("the VENICE_MAX_* limits must be finite; the ceilings may be 0, the rest positive")
        prices = parse_prices(env.get("VENICE_PRICES") or DEFAULT_PRICES)
        unpriced = sorted(m for m in cfg["models"] if m not in prices)
        if unpriced:
            raise SystemExit("no price for allowed model(s) %s; add them to VENICE_PRICES or remove them "
                             "from VENICE_MODELS" % ", ".join(unpriced))
        cfg["meter"] = Meter(os.path.join(cfg["state_dir"], "meter"), max_usd, max_req, prices, max_out,
                             in_flight, per_minute, control_dir=cfg["control_dir"], max_prompt=max_prompt)
        cfg["meter"].prices = {m: prices[m] for m in cfg["models"]}
        if 0 < max_usd < cfg["meter"].min_hold():
            raise SystemExit("VENICE_MAX_USD_PER_DAY ($%.4f) is below one minimum hold ($%.4f), so no call could "
                             "ever run; raise it, lower VENICE_MAX_OUTPUT_TOKENS, or set 0 to refuse all calls"
                             % (max_usd, cfg["meter"].min_hold()))
        cfg["max_body"] = VENICE_MAX_BODY
        cfg["models_cache"] = {"body": None, "at": 0}
    if name == "venice" and not cfg["models"]:
        raise SystemExit("VENICE_MODELS is required")
    if name == "agentmail" and not cfg["inbox"]:
        raise SystemExit("AGENTMAIL_INBOX is required")
    if name == "api" and not cfg["basic_password"]:
        raise SystemExit("GATEWAY_BASIC_PASSWORD is required for the api route")
    return cfg


def connect(up, timeout=600):
    if up.scheme == "https":
        return http.client.HTTPSConnection(up.hostname, up.port or 443, timeout=timeout,
                                           context=ssl.create_default_context())
    return http.client.HTTPConnection(up.hostname, up.port or 80, timeout=timeout)


def make_handler(cfg):
    up = cfg["upstream"]

    def upstream_headers(extra=None):
        h = {"host": up.netloc}
        if cfg["auth"]:
            h["authorization"] = cfg["auth"]
        h.update(extra or {})
        return h

    def upstream_json(method, path):
        conn = connect(up, timeout=30)
        try:
            conn.request(method, (up.path.rstrip("/") + quote(path, safe="/@:")) or "/",
                         headers=upstream_headers({"accept": "application/json"}))
            resp = conn.getresponse()
            data = resp.read(MAX_BODY)
        except OSError:
            raise Deny(502, "upstream unreachable")
        finally:
            conn.close()
        if resp.status != 200:
            raise Deny(resp.status if resp.status in (403, 404) else 502, "upstream refused the lookup")
        try:
            return json.loads(data)
        except ValueError:
            raise Deny(502, "upstream returned non-JSON")

    def upstream_call(method, path):
        conn = connect(up, timeout=30)
        try:
            conn.request(method, (up.path.rstrip("/") + quote(path, safe="/@:")) or "/", headers=upstream_headers())
            resp = conn.getresponse()
            resp.read(MAX_BODY)
            return resp.status
        except OSError:
            raise Deny(502, "upstream unreachable")
        finally:
            conn.close()

    class Handler(BaseHTTPRequestHandler):
        server_version = "jill-gateway"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def _log(self, status, path, note=""):
            sys.stderr.write(f"[gateway:{cfg['name']}] {self.command} {path} -> {status} {note}\n")

        def _json(self, status, obj, path, note=""):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self._log(status, path, note)

        def _check_headers(self):
            for h in SINGLE_HEADERS:
                if len(self.headers.get_all(h) or []) > 1:
                    raise Deny(400, f"repeated {h} header")
            if cfg["basic_password"]:
                got = self.headers.get("authorization", "")
                want = "Basic " + base64.b64encode(f"opencode:{cfg['basic_password']}".encode()).decode()
                if not hmac.compare_digest(got.encode(), want.encode()):
                    raise Deny(401, "caller is not authorized")

        def _read_body(self):
            if self.command not in ("POST", "PUT", "PATCH"):
                return b""
            if self.headers.get("transfer-encoding"):
                raise Deny(411, "chunked request bodies are not accepted")
            raw_len = (self.headers.get("content-length") or "0").strip()
            if not re.fullmatch(r"[0-9]{1,9}", raw_len):
                raise Deny(400, "invalid content-length")
            n = int(raw_len)
            if n > cfg.get("max_body", MAX_BODY):
                raise Deny(413, "body too large")
            return self.rfile.read(n)

        def _handle(self):
            shown = "?"
            try:
                path = canonical_path(self.path)
                shown = path
                self._check_headers()
                body = self._read_body()
                ctx = dict(cfg, raw_path=self.path, upstream_json=upstream_json, upstream_call=upstream_call)
                decision = cfg["policy"](ctx, self.command, path, body)
            except Deny as d:
                return self._json(d.status, {"error": d.reason}, shown, d.reason)
            except (ValueError, OSError, TypeError, AttributeError, KeyError):
                return self._json(400, {"error": "bad request"}, shown)
            if isinstance(decision, Local):
                if decision.status == "fetch":
                    return self._fetch(decision.obj, shown)
                return self._json(decision.status, decision.obj, shown)

            try:
                headers = {} if decision.no_caller_headers else {
                    k: v for k, v in self.headers.items() if k.lower() in FWD_REQ_HEADERS}
                if decision.raw is not None:
                    payload = decision.raw
                elif decision.body is not None:
                    payload = json.dumps(decision.body).encode()
                    headers["content-type"] = "application/json"
                else:
                    payload = b""
                headers = upstream_headers(headers)
                if payload or decision.method in ("POST", "PUT", "PATCH"):
                    headers["content-length"] = str(len(payload))
                target = (up.path.rstrip("/") + quote(decision.path, safe="/@:")) or "/"
                if decision.query:
                    target += "?" + urlencode(decision.query)
                try:
                    conn = connect(up)
                    conn.request(decision.method, target, body=payload or None, headers=headers)
                    resp = conn.getresponse()
                except (OSError, http.client.HTTPException):
                    if decision.tap:
                        decision.tap.finish(None)  # may have reached Venice: charge the hold
                    return self._json(502, {"error": "upstream unreachable"}, shown)
                if decision.after:
                    data = resp.read(MAX_BODY)
                    conn.close()
                    try:
                        decision.after(resp.status, data)
                    except Deny as d:
                        return self._json(d.status, {"error": d.reason}, shown, d.reason)
                    self.send_response(resp.status)
                    for k, v in resp.getheaders():
                        if k.lower() in FWD_RESP_HEADERS:
                            self.send_header(k, v)
                    self.send_header("content-length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    self._log(resp.status, shown)
                    return
                self._relay(resp, conn, shown, cap=None, tap=decision.tap)
            finally:
                if decision.tap:
                    decision.tap.finish(None)
                if decision.release:
                    decision.release()

        def _relay(self, resp, conn, shown, cap, tap=None):
            """Relay the response. If the caller hangs up mid-stream and a
            meter tap is watching, keep reading upstream (bounded by
            DRAIN_SECONDS and DRAIN_BYTES) so the usage chunk is still seen;
            past the bounds the tap charges the hold (red-team N2)."""
            client = True
            call_deadline = time.time() + CALL_DEADLINE
            if tap:
                try:
                    self.connection.settimeout(WRITE_TIMEOUT)
                except OSError:
                    pass
            try:
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() in FWD_RESP_HEADERS or k.lower().startswith("x-ratelimit"):
                        self.send_header(k, v)
                self.send_header("connection", "close")
                self.end_headers()
            except OSError:
                client = False
            sent, drained, deadline = 0, 0, None
            try:
                while True:
                    if tap and time.time() >= call_deadline:
                        break  # the whole call ran past CALL_DEADLINE: charge the hold
                    if not client:
                        if not tap:
                            break
                        if deadline is None:
                            deadline = time.time() + DRAIN_SECONDS
                        remaining = min(deadline, call_deadline) - time.time()
                        if remaining <= 0 or drained > DRAIN_BYTES:
                            break
                        if conn.sock:
                            conn.sock.settimeout(remaining)
                    elif tap and conn.sock:
                        conn.sock.settimeout(max(0.1, min(600, call_deadline - time.time())))
                    chunk = resp.read1(65536)
                    if not chunk:
                        if tap:
                            tap.complete = True
                        break
                    if tap:
                        tap.feed(chunk)
                    if not client:
                        drained += len(chunk)
                        continue
                    if cap is not None and sent + len(chunk) > cap:
                        self.wfile.write(chunk[: cap - sent])
                        break
                    try:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    except OSError:
                        client = False
                        continue
                    sent += len(chunk)
            except (OSError, http.client.HTTPException):
                pass
            finally:
                conn.close()
                if tap:
                    tap.finish(resp.status)
            self._log(resp.status, shown)

        def _fetch(self, f, shown):
            parts = f["parts"]
            target = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
            try:
                # Connect to the address that was vetted as public (no second DNS
                # lookup to rebind), and verify TLS against the hostname.
                conn = http.client.HTTPConnection(parts.hostname, f["port"], timeout=20)
                sock = socket.create_connection((f["ip"], f["port"]), timeout=20)
                if parts.scheme == "https":
                    sock = ssl.create_default_context().wrap_socket(sock, server_hostname=parts.hostname)
                conn.sock = sock
                conn.request("GET", target, headers={"host": parts.netloc.split("@")[-1],
                                                      "user-agent": "jill-fetch/1", "accept": "*/*"})
                resp = conn.getresponse()
            except (OSError, ssl.SSLError):
                return self._json(502, {"error": "fetch failed"}, shown)
            # Redirects are returned, not followed: a new URL needs its own approval.
            self._relay(resp, conn, shown, cap=MAX_FETCH)

        do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = do_HEAD = do_OPTIONS = _handle

    return Handler


# --- credential probe (Jill v2 C, #49) -------------------------------------
#
# The keys live only in the gateways, so only a gateway can tell whether its
# key still works. With CREDENTIAL_STATUS_DIR set, a key-holding gateway makes
# one cheap authenticated call upstream every CREDENTIAL_PROBE_SECONDS and
# writes a status-only record to <dir>/<route>.json: result, HTTP status and
# timestamps, never the key or any response body. jill-control reads those
# records (read-only) and alerts. Nothing Jill sends can trigger a probe.

PROBES = {
    "venice": ("GET", "/api/v1/api_keys/rate_limits", None),
    "agentmail": ("GET", "/v0/inboxes/{inbox}", None),
    "siyuan": ("POST", "/api/notebook/lsNotebooks", {}),
}


def probe_once(cfg, call):
    """call(method, path, body) -> (HTTP status, body bytes), raising Deny
    when unreachable. 402 and an explicit accessPermitted: false (Venice) are
    'exhausted'; 429 is 'rate_limited'."""
    method, path, body = PROBES[cfg["name"]]
    try:
        status, data = call(method, path.format(inbox=cfg["inbox"]), body)
    except Deny:
        return "error", 0
    if status == 402:
        return "exhausted", status
    if status == 429:
        return "rate_limited", status
    if status in (401, 403):
        return "rejected", status
    if 200 <= status < 300:
        if cfg["name"] == "venice":
            try:
                info = json.loads(data).get("data", {})
            except (ValueError, AttributeError):
                info = {}
            if isinstance(info, dict) and info.get("accessPermitted") is False:
                return "exhausted", status
        return "ok", status
    return "error", status


def write_probe(cfg, result, status, now=None):
    now = int(now if now is not None else time.time())
    path = os.path.join(cfg["credential_dir"], cfg["name"] + ".json")
    try:
        with open(path) as f:
            prev = json.load(f)
        last_ok = prev.get("last_ok_at") if isinstance(prev, dict) else None
    except (OSError, ValueError):
        last_ok = None
    rec = {"route": cfg["name"], "result": result, "http_status": status, "checked_at": now,
           "last_ok_at": now if result == "ok" else last_ok}
    safe_write_json(path, rec)
    return rec


def probe_loop(cfg, call, interval):
    while True:
        result, status = probe_once(cfg, call)
        try:
            write_probe(cfg, result, status)
        except OSError as e:
            sys.stderr.write(f"[gateway:{cfg['name']}] credential probe could not write its status: {e}\n")
        sys.stderr.write(f"[gateway:{cfg['name']}] credential probe: {result} {status}\n")
        time.sleep(interval)


def main():
    cfg = load_config()
    if cfg.get("meter") is not None:
        got = cfg["meter"].recover()
        if got and (got[0] or got[1]):
            sys.stderr.write("[gateway:venice] restart: folded $%.4f of holds from %d call(s) in flight into "
                             "today's spend\n" % got)
    host, _, port = os.environ.get("GATEWAY_LISTEN", "0.0.0.0:8080").rpartition(":")
    server = ThreadingHTTPServer((host or "0.0.0.0", int(port)), make_handler(cfg))
    server.daemon_threads = True
    if cfg["credential_dir"] and cfg["name"] in PROBES:
        up = cfg["upstream"]

        def call(method, path, body):
            conn = connect(up, timeout=30)
            try:
                payload = json.dumps(body).encode() if body is not None else None
                headers = {"host": up.netloc, "authorization": cfg["auth"], "accept": "application/json"}
                if payload is not None:
                    headers["content-type"] = "application/json"
                    headers["content-length"] = str(len(payload))
                conn.request(method, (up.path.rstrip("/") + quote(path, safe="/@:")) or "/", body=payload,
                             headers=headers)
                resp = conn.getresponse()
                return resp.status, resp.read(1024 * 1024)
            except OSError:
                raise Deny(502, "upstream unreachable")
            finally:
                conn.close()

        interval = max(60, int(os.environ.get("CREDENTIAL_PROBE_SECONDS", "3600")))
        threading.Thread(target=probe_loop, args=(cfg, call, interval), daemon=True).start()
    sys.stderr.write(f"[gateway:{cfg['name']}] listening on {host}:{port}, upstream {cfg['upstream'].netloc}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
