"""Halt and conservation flags: one schema, one reader. Stdlib only.

Ported from the chassis (scripts/_control-flags.sh and
discord-control-listener.py, behalfbot 47a13d6). Both flags are JSON files
with the same five keys:

    {"enabled": bool, "enabled_at": ts, "enabled_by": str,
     "auto_lift_after": ts, "reason": str}

Timestamps are "%Y-%m-%dT%H:%M:%SZ" (UTC).

Only the jill-control sidecar writes them (into the control-state volume).
Every other reader mounts that volume read-only, so reading never rewrites:
an expired auto-lift reads as "off" and the sidecar clears the file on its
own loop. The failure direction is fixed: a file that exists but cannot be
read or parsed, or carries an auto-lift time that cannot be parsed, reads as
ON. A halt that quietly lifts itself because a date string was malformed is
the outage this exists to end.
"""
import json
import os
import re
import stat
from datetime import datetime, timezone

HALT = "halt.json"
CONSERVATION = "conservation-mode.json"


def utcnow_iso(now=None):
    now = now or datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def parse_iso(ts):
    """Epoch seconds, or None unless ts is exactly YYYY-MM-DDTHH:MM:SSZ."""
    if not isinstance(ts, str) or not ISO_UTC.match(ts):
        return None
    raw = ts.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


MAX_BYTES = 64 * 1024


def read(path):
    """(data, ok). ok is False when the file exists but is unreadable or
    larger than any flag, cursor or probe record has reason to be."""
    # O_NOFOLLOW + O_NONBLOCK, then fstat: a symlink is refused, and a FIFO
    # planted where a file should be can neither block this thread nor be
    # read as data.
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return {}, True
    except OSError:
        return {}, False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
            return {}, False
        with os.fdopen(fd, "rb") as fh:
            fd = None
            data = json.loads(fh.read(MAX_BYTES + 1).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return {}, False
    finally:
        if fd is not None:
            os.close(fd)
    if not isinstance(data, dict):
        return {}, False
    return data, True


def state(path, now=None):
    """'on', 'off' or 'expired' (on, but past its auto-lift). Never writes."""
    data, ok = read(path)
    if not ok:
        return "on"
    enabled = data.get("enabled", False)
    if not isinstance(enabled, bool):
        return "on"  # "true", 1, null: not a boolean, so invalid, so on
    if enabled is not True:
        return "off"
    lift = data.get("auto_lift_after")
    if lift is None:
        return "on"
    epoch = parse_iso(lift)
    if epoch is None:
        return "on"
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    return "expired" if now >= epoch else "on"


def is_on(path, now=None):
    return state(path, now) == "on"


def write(path, enabled, by=None, auto_lift=None, reason=None):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    payload = {
        "enabled": bool(enabled),
        "enabled_at": utcnow_iso() if enabled else None,
        "enabled_by": by if enabled else None,
        "auto_lift_after": auto_lift if enabled else None,
        "reason": reason if enabled else None,
    }
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def lift_expired(path, now=None):
    """Writer side: clear a flag whose auto-lift has passed. True if cleared."""
    if state(path, now) == "expired":
        write(path, False)
        return True
    return False
