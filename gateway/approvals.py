#!/usr/bin/env python3
"""Sean's one-shot approvals for things Jill may not do on her own. Stdlib only.

Two kinds, same store:

  draft   send ONE specific AgentMail draft, exactly as it was when Sean saw
          it (bound to a sha256 of its recipients, subject, body and
          attachments), once, before it expires
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
  approvals.py approve-url <url> [--ttl 600]
  approvals.py list
  approvals.py revoke <kind> <key>

The digest for a draft comes from agentmail-proxy:
  GET /_jill/drafts/<draft_id>/digest   (recipients, subject and sha256)
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


def draft_digest(draft):
    """sha256 over what a send would actually deliver."""
    keep = {k: draft.get(k) for k in ("to", "cc", "bcc", "reply_to", "subject", "text", "html")}
    keep["attachments"] = sorted(
        str(a.get("attachment_id") or a.get("id") or a.get("filename") or a) if isinstance(a, dict) else str(a)
        for a in (draft.get("attachments") or [])
    )
    return hashlib.sha256(json.dumps(keep, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


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


def check_and_consume(kind, value, consumed_dir, base=APPROVALS_DIR, now=None, verify=None):
    """Return the approval record and mark it used, or raise LookupError(reason).

    verify(rec) runs BEFORE the record is consumed, so a mismatch (say, a
    draft edited after Sean approved it) refuses without burning the approval.
    """
    now = time.time() if now is None else now
    p = _path(base, kind, value)
    try:
        with open(p) as f:
            rec = json.load(f)
    except (OSError, ValueError):
        raise LookupError("no approval from Sean for this")
    if rec.get("kind") != kind or rec.get("value") != value:
        raise LookupError("approval record does not match")
    if now > float(rec.get("expires_at", 0)):
        raise LookupError("Sean's approval has expired")
    if verify:
        verify(rec)
    os.makedirs(consumed_dir, exist_ok=True)
    nonce = str(rec.get("nonce", ""))
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise LookupError("approval record is malformed")
    marker = os.path.join(consumed_dir, f"{kind}-{key_for(kind, value)}-{nonce}")
    try:
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise LookupError("this approval was already used")
    os.close(fd)
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
    sub.add_parser("list")
    r = sub.add_parser("revoke")
    r.add_argument("kind", choices=["draft", "url"])
    r.add_argument("value")
    a = ap.parse_args(argv)

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
        for kind in ("draft", "url"):
            d_ = os.path.join(APPROVALS_DIR, kind)
            for name in sorted(os.listdir(d_)) if os.path.isdir(d_) else []:
                with open(os.path.join(d_, name)) as f:
                    rec = json.load(f)
                left = int(rec["expires_at"] - time.time())
                print(f"{kind}\t{rec['value']}\t{'expired' if left <= 0 else f'{left}s left'}")
        return
    print(f"approved {rec['kind']} {rec['value']} for {int(rec['expires_at'] - rec['created_at'])}s")


if __name__ == "__main__":
    main()
