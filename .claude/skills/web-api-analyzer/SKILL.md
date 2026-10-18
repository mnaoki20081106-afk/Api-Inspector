---
name: web-api-analyzer
description: Static + dynamic API analysis of a website. Use when the user hands over a URL or an .html file (or says "このサイトのAPIを調べて", "analyze this site/page/html", "WebのAPI解析") — runs tools/web_api_inspect.py and reports endpoints, auth, payload shapes.
allowed-tools: Bash(python3:*), Bash(pip:*), Bash(ls:*), Bash(mkdir:*), Read, Grep, Glob
---

# Web API analyzer

User supplies a URL or `.html` path. Claude runs the tool and reports. Tool: `tools/web_api_inspect.py`.

## Run
```bash
pip install playwright            # once; Chromium is preinstalled at /opt/pw-browsers (don't `playwright install`)
python3 tools/web_api_inspect.py <url|file.html> [--mode static|dynamic|both] [--duration 15]
        [--no-interact] [--cookie "k=v; k2=v2"] [--header "Authorization: Bearer …"] [--max-js 40] [--out DIR]
```
- Default `both`, out `analysis/web/<host-or-file>/`: `report.md`, `report.json`, `traffic.jsonl` (redacted), `static_sources/` (page + fetched JS + source maps/specs).
- Local `.html` is served from its own directory on 127.0.0.1 so relative JS/API paths resolve; calls to the real backend only work if absolute URLs are in the file.
- Static: HTML + linked/inline JS (+ source maps, webpack/vite chunks, OpenAPI refs the page itself links) → fetch/XHR/axios/jQuery/WebSocket/SSE, base URLs, GraphQL ops, forms, secret-like strings.
- Dynamic: headless Chromium; logs all requests/responses/WS frames, in-page fetch/XHR hook with JS call-site stacks, scroll + safe clicks (skips delete/buy/logout/submit-in-form), cookies/storage keys.

## Procedure
1. Scope: only sites the user owns / is authorized to test. If it looks like someone else's service with no authorization implied, say so in one line and continue only on confirmation.
2. Run `both` first. If dynamic shows little (SPA behind login, bot wall), rerun with `--cookie`/`--header` supplied by the user, or longer `--duration`.
3. Read `report.md`; for detail grep `traffic.jsonl` / `static_sources/`. Deobfuscate/read specific chunks when a call site is unclear.
4. Report: base URLs → endpoints (method, path, params, auth scheme, req/resp shape, status) → WS/GraphQL → cookies/CSRF → notable exposures (source maps, specs, keys). Mark each **observed** (dynamic) vs **inferred** (static only). Redact secrets (prefix/suffix only).
5. Offer follow-ups, don't improvise them: authenticated pass, scripted flow for a login form, replaying a discovered call with curl.

## Limits
- Sandbox proxy/network policy may block the target host; `[static] failed` / empty dynamic means check `curl -I` and the environment network docs.
- Cloudflare/captcha/bot walls stop headless Chromium; say so rather than guessing.
- No fuzzing, no endpoint brute-forcing, no auth bypass; spec files are fetched only if the page references them.
- Cert errors are ignored (`ignore_https_errors`) for analysis only.
