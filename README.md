# api-inspector

Frida-based tool that hooks a target's exports/imports, classifies arguments (ints, pointers, C/UTF-16 strings),
tags functions by category (net/file/memory/crypto/proc/time/input/gfx), auto-mutes hot functions,
and ranks everything by how interesting it looks.

    pip install -r requirements.txt
    python inspect.py -n target.exe -m '*' -x 'Rtl*' -d 30          # attach, all modules, 30s
    python inspect.py -f ./app -m libgame.so -i 'send*' -i 'recv*'  # spawn, narrow filter
    python inspect.py -U -f com.example.app --bt                    # Android via USB, backtraces

Outputs `calls.jsonl` (one event per call) and `report.json` (ranked summary with per-argument type histograms).
Hook budget defaults to 400 (`--max-hooks`); raise it carefully, wide hooking on a hot process will stall it.
