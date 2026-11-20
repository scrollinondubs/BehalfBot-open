#!/usr/bin/env python3
"""Sean's one-shot approvals for things Jill may not do on her own. Stdlib only.

Two kinds, same store:

  draft   send ONE specific draft, exactly as it was when Sean saw it (bound
          to a sha256 of the whole sendable object, attachment bytes
          included), once, before it expires
  url     fetch ONE exact URL through the fetch gateway, once, before it
          expires

Who can do what (docker-compose.yml):

  approvals dir   written ONLY by the bridge and the dispatcher (where Sean's
                  "approve draft <id>" / "approve url <url>" from Matrix will
                  land, package D) and by this CLI run inside them; mounted
                  read-only into agentmail-proxy and fetch-gateway; not
                  mounted into opencode-serve at all
  consumed dir    each gateway's own state volume; a consumption marker is
                  created with O_EXCL BEFORE the request goes upstream, so one
                  approval is one use, and a crash fails closed

CLI (testing, and the manual path until the Matrix bridge lands):

  approvals.py approve-draft <draft_id> --sha256 <digest> [--ttl 900]
  CONSUMED_DIRS=/state/agentmail-consumed:/state/fetch-consumed approvals.py list
  approvals.py approve-url <url> [--ttl 600]
  approvals.py list
  approvals.py revoke <kind> <key>

The digest for a draft: `approvals.py digest <draft_id>` in the bridge or
dispatcher, reading agentmail-proxy's snapshot from a read-only mount (the
exact content a send will deliver, and its sha256). The gateway also serves
it at GET /_jill/drafts/<draft_id>/digest. A send delivers that stored content, not
  whatever AgentMail's copy of the draft holds at the time.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import time

APPROVALS_DIR = os.environ.get("APPROVALS_DIR", "/state/approvals")
MAX_TTL = 3600
DRAFT_ID = re.compile(r"^[A-Za-z0-9._:@<>+=-]{1,200}$")


def key_for(kind, value):
    return hashlib.sha256(f"{kind}\0{value}".encode()).hexdigest()


# Everything a send delivers. The digest is over the canonical JSON of the
# whole sendable object: recipients, subject, bodies, labels, threading and
# every attachment's bytes (round-3 red-team H1).
SENDABLE = ("to", "cc", "bcc", "reply_to", "subject", "text", "html", "labels", "attachments", "in_reply_to")


def sendable(draft):
    return {k: draft[k] for k in SENDABLE if k in draft and draft[k] is not None}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def draft_digest(draft):
    return hashlib.sha256(canonical(sendable(draft)).encode()).hexdigest()


def _path(base, kind, value):
    return os.path.join(base, kind, key_for(kind, value) + ".json")


def write_approval(kind, value, ttl, extra=None, base=APPROVALS_DIR):
    ttl = max(1, min(int(ttl), MAX_TTL))
    os.makedirs(os.path.join(base, kind), exist_ok=True)
    rec = {"kind": kind, "value": value, "created_at": time.time(), "expires_at": time.time() + ttl,
           "nonce": secrets.token_hex(16)}
    rec.update(extra or {})
    p = _path(base, kind, value)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f)
    os.replace(tmp, p)
    return rec


def _load(kind, value, base):
    try:
        with open(_path(base, kind, value)) as f:
            rec = json.load(f)
    except (OSError, ValueError):
        return None
    if rec.get("kind") != kind or rec.get("value") != value:
        return None
    if not re.fullmatch(r"[0-9a-f]{32}", str(rec.get("nonce", ""))):
        return None
    return rec


def _marker(consumed_dir, kind, value, rec):
    return os.path.join(consumed_dir, f"{kind}-{key_for(kind, value)}-{rec['nonce']}")


def status(kind, value, consumed_dirs, base=APPROVALS_DIR, now=None):
    """'none', 'live', 'used' or 'expired' for the current approval of this thing."""
    now = time.time() if now is None else now
    rec = _load(kind, value, base)
    if rec is None:
        return "none"
    if any(os.path.exists(_marker(d, kind, value, rec)) for d in consumed_dirs):
        return "used"
    if now > float(rec.get("expires_at", 0)):
        return "expired"
    return "live"


def check_and_consume(kind, value, consumed_dir, base=APPROVALS_DIR, now=None, verify=None):
    """Consume Sean's approval, then verify it; return the record or raise LookupError.

    The approval is BURNED by any attempt that reaches here, before verify
    runs: a refused attempt (say, a draft whose content no longer matches
    what Sean approved) cannot be retried against the same approval.
    (Round-3 red-team C1: a free retry made a lost race costless.)
    """
    now = time.time() if now is None else now
    rec = _load(kind, value, base)
    if rec is None:
        raise LookupError("no approval from Sean for this")
    if now > float(rec.get("expires_at", 0)):
        raise LookupError("Sean's approval has expired")
    os.makedirs(consumed_dir, exist_ok=True)
    try:
        fd = os.open(_marker(consumed_dir, kind, value, rec), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise LookupError("this approval was already used")
    os.close(fd)
    if verify:
        verify(rec)
    return rec


def main(argv=None):
    ap = argparse.ArgumentParser(description="Sean's one-shot approvals for Jill")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("approve-draft")
    d.add_argument("draft_id")
    d.add_argument("--sha256", required=True, help="digest from agentmail-proxy /_jill/drafts/<id>/digest")
    d.add_argument("--ttl", type=int, default=900)
    u = sub.add_parser("approve-url")
    u.add_argument("url")
    u.add_argument("--ttl", type=int, default=600)
    dg = sub.add_parser("digest", help="show a draft's snapshot and sha256 (what a send would deliver)")
    dg.add_argument("draft_id")
    sub.add_parser("list")
    r = sub.add_parser("revoke")
    r.add_argument("kind", choices=["draft", "url"])
    r.add_argument("value")
    a = ap.parse_args(argv)

    if a.cmd == "digest":
        snap_dir = os.environ.get("SNAPSHOT_DIR", "/state/agentmail-gw/drafts")
        try:
            with open(os.path.join(snap_dir, key_for("draft", a.draft_id) + ".json")) as f:
                rec = json.load(f)
        except (OSError, ValueError):
            sys.exit("no snapshot for that draft (only drafts written through agentmail-proxy can be sent)")
        if rec.get("draft_id") != a.draft_id:
            sys.exit("snapshot does not match that draft id")
        content = sendable(rec["content"])
        print(json.dumps({"draft_id": a.draft_id, "content": content, "sha256": draft_digest(content)}, indent=2))
        return
    if a.cmd == "approve-draft":
        if not DRAFT_ID.match(a.draft_id) or not re.fullmatch(r"[0-9a-f]{64}", a.sha256):
            sys.exit("draft id or sha256 is malformed")
        rec = write_approval("draft", a.draft_id, a.ttl, {"sha256": a.sha256})
    elif a.cmd == "approve-url":
        if not re.match(r"^https?://", a.url) or any(c.isspace() for c in a.url):
            sys.exit("url must be an absolute http(s) URL")
        rec = write_approval("url", a.url, a.ttl)
    elif a.cmd == "revoke":
        try:
            os.remove(_path(APPROVALS_DIR, a.kind, a.value))
        except FileNotFoundError:
            pass
        print("revoked")
        return
    else:
        # CONSUMED_DIRS: the gateways' consumed-marker dirs, mounted read-only
        # here, so a used approval shows as used (round-3 red-team M2).
        consumed = [d for d in os.environ.get("CONSUMED_DIRS", "").split(":") if d]
        for kind in ("draft", "url"):
            d_ = os.path.join(APPROVALS_DIR, kind)
            for name in sorted(os.listdir(d_)) if os.path.isdir(d_) else []:
                with open(os.path.join(d_, name)) as f:
                    rec = json.load(f)
                st = status(kind, rec["value"], consumed)
                left = int(rec["expires_at"] - time.time())
                shown = f"live, {left}s left" if st == "live" else st
                if not consumed and st == "live":
                    shown += " (use state unknown: CONSUMED_DIRS not set)"
                print(f"{kind}\t{rec['value']}\t{shown}")
        return
    print(f"approved {rec['kind']} {rec['value']} for {int(rec['expires_at'] - rec['created_at'])}s")


if __name__ == "__main__":
    main()
