#!/usr/bin/env python3
"""Scripted OpenAI-compatible model for the guard self-test. Stdlib only.

It plays the model in a real `opencode run`: the parent session calls a list
of tools that the guards must deny (plus one harmless positive control), then
launches a subagent through the `task` tool, and the child session does the
same. OpenCode executes every call through its real tool path, so the guard
plugin either fires or it does not.

The mock is also the observer. Each tool result comes back to it in the next
request, and it records ONLY two booleans per case: did the result carry the
guard's "[guardrails]" tag, and did it carry the positive-control marker. It
never stores or logs result text, because if a guard failed that text could
be a secret.

  python3 mock_llm.py <port> <results.json> [bind-address, default 127.0.0.1]

Cases are read from cases.json next to this file.
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = json.load(open(os.path.join(HERE, "cases.json")))
RESULTS_PATH = sys.argv[2]
RESULTS = {}
LOCK = threading.Lock()


def text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in content)
    return ""


def record(messages):
    # A document block the Matrix bridge would put in Sean's message must
    # reach the model quarantined (red-team round 7 R2-12).
    first_user = next((text_of(m.get("content")) for m in messages if m.get("role") == "user"), "")
    if "BEGIN UNTRUSTED DOCUMENT" in first_user:
        with LOCK:
            RESULTS["_user_doc"] = {"flagged": "[injection-scan] WARNING" in first_user, "denied": False, "ok": False}
    for m in messages:
        if m.get("role") != "tool":
            continue
        cid = str(m.get("tool_call_id", ""))
        if not cid.startswith("call_"):
            continue
        body = text_of(m.get("content"))
        with LOCK:
            RESULTS[cid[5:]] = {
                "denied": "[guardrails]" in body,
                "ok": "selftest-ok" in body,
                "canary": "[canary-loaded]" in body,
                "escaped": "selftest-escaped" in body,
                # The injection scanner's quarantine banner (#51).
                "flagged": "[injection-scan] WARNING" in body,
                # Names only: a server-run file tool that followed a planted
                # symlink into the server's environment would return these.
                "leak": "OPENCODE_SERVER_PASSWORD" in body or "CALLER_TOKEN" in body,
            }
    with LOCK:
        tmp = RESULTS_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(RESULTS, f)
        os.replace(tmp, RESULTS_PATH)


def log_shape(req):
    """Names only: which request fields and content-part types the client sends."""
    if not os.environ.get("MOCK_LOG_SHAPE"):
        return
    parts = sorted({p.get("type", "?") for m in req.get("messages", []) if isinstance(m.get("content"), list)
                    for p in m["content"] if isinstance(p, dict)})
    vp = sorted((req.get("venice_parameters") or {}).keys())
    sys.stderr.write(f"[mock] keys={sorted(req.keys())} venice_parameters={vp} part_types={parts}\n")


def next_action(req):
    log_shape(req)
    messages = req.get("messages", [])
    record(messages)
    if not req.get("tools"):
        return None
    first_user = next((text_of(m.get("content")) for m in messages if m.get("role") == "user"), "")
    if "SELFTEST-CHILD" in first_user:
        script = CASES["child"]
    elif "SELFTEST-PARENT" in first_user:
        script = CASES["parent"]
    else:
        return None
    done = sum(len(m.get("tool_calls") or []) for m in messages if m.get("role") == "assistant")
    if done >= len(script):
        return None
    case = script[done]
    return {"id": "call_" + case["id"], "name": case["tool"], "arguments": json.dumps(case["args"])}


def chunk(delta, finish=None):
    return {
        "id": "selftest",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "mock",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"object": "list", "data": [{"id": "mock", "object": "model"}]}).encode())

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0") or 0))
        try:
            req = json.loads(body or b"{}")
        except ValueError:
            req = {}
        action = next_action(req)
        usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        if action:
            events = [
                chunk({"role": "assistant", "tool_calls": [{"index": 0, "id": action["id"], "type": "function",
                                                              "function": {"name": action["name"], "arguments": action["arguments"]}}]}),
                dict(chunk({}, "tool_calls"), usage=usage),
            ]
            message = {"role": "assistant", "content": None, "tool_calls": [
                {"id": action["id"], "type": "function", "function": {"name": action["name"], "arguments": action["arguments"]}}]}
            finish = "tool_calls"
        else:
            events = [chunk({"role": "assistant", "content": "selftest done"}), dict(chunk({}, "stop"), usage=usage)]
            message = {"role": "assistant", "content": "selftest done"}
            finish = "stop"
        if req.get("stream"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("cache-control", "no-cache")
            self.end_headers()
            for e in events:
                self.wfile.write(("data: " + json.dumps(e) + "\n\n").encode())
            self.wfile.write(b"data: [DONE]\n\n")
        else:
            out = {"id": "selftest", "object": "chat.completion", "created": 0, "model": "mock",
                   "choices": [{"index": 0, "message": message, "finish_reason": finish}], "usage": usage}
            data = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)


if __name__ == "__main__":
    with open(RESULTS_PATH, "w") as f:
        json.dump({}, f)
    bind = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
    ThreadingHTTPServer((bind, int(sys.argv[1])), Handler).serve_forever()
