"""mitmproxy addon used by the android-api-dynamic workflow.

Writes one JSON line per completed HTTP flow / websocket message / TLS failure
to $FLOWS_OUT (default flows.jsonl), for later summarizing by summarize_flows.py.
Bodies are truncated to BODY_LIMIT bytes.
"""
import json
import os
import base64
from mitmproxy import http

OUT = os.environ.get("FLOWS_OUT", "flows.jsonl")
LIM = int(os.environ.get("BODY_LIMIT", "4096"))
f = open(OUT, "a", buffering=1)


def body(m):
    c = m.raw_content or b""
    try:
        return {"text": c[:LIM].decode("utf-8"), "len": len(c)}
    except UnicodeDecodeError:
        return {"b64": base64.b64encode(c[:512]).decode(), "len": len(c)}


def response(flow: http.HTTPFlow):
    r = flow.request
    s = flow.response
    f.write(json.dumps({
        "t": "http", "ts": r.timestamp_start, "method": r.method, "scheme": r.scheme,
        "host": r.host, "port": r.port, "path": r.path, "http": r.http_version,
        "req_headers": dict(r.headers), "req": body(r),
        "status": s.status_code if s else None,
        "resp_headers": dict(s.headers) if s else {},
        "resp": body(s) if s else None,
    }) + "\n")


def tls_failed_client(data):
    f.write(json.dumps({
        "t": "tls_fail", "sni": getattr(data.conn, "sni", None),
        "error": str(getattr(data.conn, "error", "")),
    }) + "\n")


def websocket_message(flow: http.HTTPFlow):
    m = flow.websocket.messages[-1]
    f.write(json.dumps({
        "t": "ws", "host": flow.request.host, "path": flow.request.path,
        "from_client": m.from_client, "text": (m.text[:LIM] if m.is_text else None),
        "len": len(m.content),
    }) + "\n")
