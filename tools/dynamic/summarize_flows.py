#!/usr/bin/env python3
"""Collapse flows.jsonl (+ optional java_events.jsonl) into an endpoint table.

usage: summarize_flows.py flows.jsonl [java_events.jsonl]
"""
import sys
import json
import re
import collections


def norm(path):
    """collapse ids in a path so repeated hits on /users/123 and /users/456 count as one endpoint"""
    p = path.split("?")[0]
    p = re.sub(r"/[0-9a-f]{8}-[0-9a-f-]{27}", "/{uuid}", p)
    p = re.sub(r"/\d{2,}", "/{n}", p)
    return re.sub(r"/[A-Za-z0-9_\-]{24,}", "/{token}", p)


def shape(v, depth=0):
    if isinstance(v, dict):
        return {k: shape(x, depth + 1) for k, x in list(v.items())[:25]} if depth < 3 else "{...}"
    if isinstance(v, list):
        return [shape(v[0], depth + 1)] if v else []
    return type(v).__name__


def jshape(body):
    try:
        return shape(json.loads(body["text"]))
    except Exception:
        return None


SENSITIVE_HEADER = re.compile(r"auth|token|cookie|api[-_]?key", re.I)
SKIP_HEADER = {"host", "user-agent", "accept-encoding", "content-length", "connection", "accept", "content-type"}


def main():
    flows_path = sys.argv[1]
    rows = collections.OrderedDict()
    tls_fail = collections.Counter()
    ws = collections.Counter()

    for line in open(flows_path):
        e = json.loads(line)
        if e["t"] == "tls_fail":
            tls_fail[e.get("sni") or "?"] += 1
        elif e["t"] == "ws":
            ws[e["host"] + e["path"].split("?")[0]] += 1
        elif e["t"] == "http":
            key = (e["method"], e["host"], norm(e["path"]))
            r = rows.setdefault(key, {
                "n": 0, "status": collections.Counter(), "query_keys": set(), "headers": set(),
                "auth_headers": set(), "req_shape": None, "resp_shape": None, "content_types": set(),
            })
            r["n"] += 1
            r["status"][e["status"]] += 1
            if "?" in e["path"]:
                r["query_keys"] |= {kv.split("=")[0] for kv in e["path"].split("?", 1)[1].split("&")}
            for h, v in e["req_headers"].items():
                if SENSITIVE_HEADER.search(h):
                    r["auth_headers"].add(h + ": " + v.split(" ")[0][:12] + "...")
                elif h.lower() not in SKIP_HEADER:
                    r["headers"].add(h)
            ct = e["resp_headers"].get("content-type", e["resp_headers"].get("Content-Type", ""))
            r["content_types"].add(ct.split(";")[0])
            if r["req_shape"] is None and e.get("req", {}).get("text"):
                r["req_shape"] = jshape(e["req"])
            if r["resp_shape"] is None and e.get("resp", {}).get("text"):
                r["resp_shape"] = jshape(e["resp"])

    print("# dynamic endpoints (%d)" % len(rows))
    for (method, host, path), r in rows.items():
        print("- `%s https://%s%s` x%d status=%s content-type=%s" % (
            method, host, path, r["n"], dict(r["status"]), ",".join(sorted(x for x in r["content_types"] if x))))
        if r["query_keys"]:
            print("    query:", ", ".join(sorted(r["query_keys"])))
        if r["auth_headers"]:
            print("    auth headers:", ", ".join(sorted(r["auth_headers"])))
        if r["headers"]:
            print("    other headers:", ", ".join(sorted(r["headers"])))
        if r["req_shape"]:
            print("    request body shape:", json.dumps(r["req_shape"]))
        if r["resp_shape"]:
            print("    response body shape:", json.dumps(r["resp_shape"]))

    if ws:
        print("\n# websocket endpoints")
        for k, n in ws.items():
            print("- %s x%d" % (k, n))

    if tls_fail:
        print("\n# TLS handshakes that never completed through the proxy")
        print("# (certificate pinning, a non-system CA store, or a stack that ignores the HTTP(S) proxy)")
        for sni, n in tls_fail.items():
            print("- %s x%d" % (sni, n))

    if len(sys.argv) > 2:
        counts = collections.Counter()
        hook_failures = []
        for line in open(sys.argv[2]):
            e = json.loads(line)
            if e.get("t") == "java":
                counts[(e["k"], e["v"])] += 1
            elif e.get("t") == "hook" and "fail" in e:
                hook_failures.append(e["fail"])
        if hook_failures:
            print("\n# java hooks that failed to attach (class/method not present at this API level / build)")
            for h in hook_failures:
                print("-", h)
        print("\n# java-layer URLs / hostnames observed (supplements the proxy capture; "
              "useful when native code or a non-HTTP client bypasses the proxy)")
        for (kind, value), n in counts.most_common(300):
            print("- [%s] %s x%d" % (kind, value, n))


if __name__ == "__main__":
    main()
