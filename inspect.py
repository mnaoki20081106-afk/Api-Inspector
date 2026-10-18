#!/usr/bin/env python3
"""api-inspector host: spawn/attach with Frida, stream calls to JSONL, print ranked report on exit."""
import argparse, json, signal, sys, time
from pathlib import Path

import frida

AGENT = Path(__file__).parent / "agent" / "inspector.js"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    t = ap.add_mutually_exclusive_group(required=True)
    t.add_argument("-n", "--attach", help="process name or pid to attach to")
    t.add_argument("-f", "--spawn", help="executable / package to spawn")
    ap.add_argument("-U", "--usb", action="store_true", help="use USB device (Android/iOS)")
    ap.add_argument("-H", "--host", help="remote frida-server host:port")
    ap.add_argument("-m", "--module", action="append", default=[], help="module glob to watch (repeatable); default main module")
    ap.add_argument("-i", "--include", action="append", default=[], help="function glob to include")
    ap.add_argument("-x", "--exclude", action="append", default=[], help="function glob to exclude")
    ap.add_argument("--max-hooks", type=int, default=400)
    ap.add_argument("--hot", type=int, default=200, help="calls/sec before auto-mute")
    ap.add_argument("--no-imports", action="store_true")
    ap.add_argument("--bt", action="store_true", help="capture backtraces")
    ap.add_argument("-o", "--out", default="calls.jsonl")
    ap.add_argument("-r", "--report", default="report.json")
    ap.add_argument("-d", "--duration", type=float, default=0, help="seconds; 0 = until Ctrl+C")
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args()

    dev = (frida.get_device_manager().add_remote_device(a.host) if a.host
           else frida.get_usb_device() if a.usb else frida.get_local_device())
    pid = dev.spawn([a.spawn]) if a.spawn else None
    target = pid if pid is not None else (int(a.attach) if a.attach.isdigit() else a.attach)
    sess = dev.attach(target)
    script = sess.create_script(AGENT.read_text())
    out = open(a.out, "w", buffering=1)

    def on_msg(msg, _data):
        if msg["type"] == "error":
            print("[agent error]", msg.get("description"), file=sys.stderr)
            return
        p = msg["payload"]
        out.write(json.dumps(p) + "\n")
        if a.quiet:
            return
        if p["t"] == "call":
            args = ", ".join(str(x["v"]) if x["k"] != "cstr" and x["k"] != "wstr" else json.dumps(x["v"]) for x in p["args"][:4])
            print(f"[{p['cat']:6}] {p['fn']}({args}) -> {p.get('ret', {}).get('v')}")
        elif p["t"] in ("ready", "muted", "warn"):
            print(f"[{p['t']}]", {k: v for k, v in p.items() if k != "t"})

    script.on("message", on_msg)
    script.load()
    api = script.exports_sync
    api.configure({
        "modules": a.module, "include": a.include or ["*"], "exclude": a.exclude,
        "maxHooks": a.max_hooks, "hotLimit": a.hot, "includeImports": not a.no_imports, "backtrace": a.bt,
    })
    n = api.start()
    if pid is not None:
        dev.resume(pid)
    print(f"hooked {n} functions; Ctrl+C to stop and write {a.report}")

    stop = {"v": False}
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__("v", True))
    t0 = time.time()
    while not stop["v"] and (not a.duration or time.time() - t0 < a.duration):
        time.sleep(0.2)

    rep = api.report()
    Path(a.report).write_text(json.dumps(rep, indent=2))
    print(f"\n{'score':>5} {'calls':>7}  {'cat':6} function")
    for r in rep[:25]:
        print(f"{r['score']:>5} {r['calls']:>7}  {r['cat']:6} {r['fn']}" + (f"   e.g. {r['strs'][0]!r}" if r["strs"] else ""))
    api.stop()
    sess.detach()


if __name__ == "__main__":
    main()
