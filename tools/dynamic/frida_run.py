#!/usr/bin/env python3
"""Spawn a package on the attached adb device under Frida, load frida_observe.js
(passive URL/DNS/OkHttp/WebView logging only - no TLS trust changes), run for N
seconds, write every message to an output JSONL file.

usage: frida_run.py PKG SECONDS OUT.jsonl
"""
import sys
import json
import time
import pathlib
import frida


def main():
    pkg, secs, out_path = sys.argv[1], float(sys.argv[2]), sys.argv[3]
    device = frida.get_usb_device(timeout=30)
    pid = device.spawn([pkg])
    session = device.attach(pid)
    out = open(out_path, "w", buffering=1)

    def on_message(message, _data):
        if message["type"] == "send":
            out.write(json.dumps(message["payload"]) + "\n")
        elif message["type"] == "error":
            out.write(json.dumps({"t": "agent_error", "d": message.get("description")}) + "\n")

    script_path = pathlib.Path(__file__).parent / "frida_observe.js"
    script = session.create_script(script_path.read_text())
    script.on("message", on_message)
    script.load()
    device.resume(pid)

    time.sleep(secs)
    try:
        session.detach()
    except Exception:
        pass


if __name__ == "__main__":
    main()
