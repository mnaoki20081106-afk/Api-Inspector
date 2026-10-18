#!/usr/bin/env python3
"""web_api_inspect — static + dynamic API discovery for a web page.

Input : a URL or a local .html file.
Output: <out>/report.md, <out>/report.json, <out>/traffic.jsonl, <out>/static_sources/*

  python3 tools/web_api_inspect.py <url|file.html> [--mode static|dynamic|both]
         [--out analysis/web/<name>] [--duration 15] [--no-interact]
         [--cookie "k=v; k2=v2"] [--header "Name: value"] [--max-js 40]

Static : HTML + linked/inline JS (+ source maps) parsed for URLs, fetch/XHR/axios/$.ajax/
         WebSocket/EventSource calls, GraphQL ops, forms, OpenAPI/Swagger refs, secrets-looking keys.
Dynamic: headless Chromium (Playwright). Records every request/response/WebSocket frame,
         scrolls + clicks safe elements, then groups XHR/fetch by host/path with JSON shapes.
Secrets in headers/bodies are redacted in the report (traffic.jsonl keeps redacted too).
Only point this at sites you own or are authorized to test. No fuzzing / no auth bypass here.
"""
import argparse, collections, hashlib, html, http.server, json, os, re, socketserver
import sys, threading, urllib.parse, urllib.request
from pathlib import Path

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
THIRD_PARTY = re.compile(
    r"(google-analytics|googletagmanager|doubleclick|googlesyndication|gstatic|googleapis\.com/css|"
    r"facebook\.(net|com)|fbcdn|sentry|segment\.(io|com)|hotjar|clarity\.ms|newrelic|datadog|"
    r"cloudflareinsights|cdn\.jsdelivr|cdnjs|unpkg|fonts\.g|adobedtm|amplitude|mixpanel|intercom|"
    r"hubspot|twitter\.com|t\.co|linkedin|tiktok|bing\.com|optimizely|onesignal|stripe\.com/v)", re.I)
SENSITIVE_H = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "proxy-authorization",
               "x-csrf-token", "x-xsrf-token", "api-key"}
SENSITIVE_K = re.compile(r"(pass(word)?|token|secret|api[_-]?key|auth|session|jwt|csrf|otp|pin|ssn|card)", re.I)

# ---------- helpers ----------
def redact(v, keep=4):
    v = str(v)
    return v if len(v) <= 2 * keep + 2 else f"{v[:keep]}…{v[-keep:]}({len(v)})"

def redact_headers(h):
    return {k: (redact(v) if k.lower() in SENSITIVE_H else v) for k, v in (h or {}).items()}

def shape(o, depth=0):
    """JSON → type skeleton, values dropped."""
    if depth > 5: return "…"
    if isinstance(o, dict): return {k: shape(v, depth + 1) for k, v in list(o.items())[:40]}
    if isinstance(o, list): return [shape(o[0], depth + 1)] if o else []
    if isinstance(o, bool): return "bool"
    if isinstance(o, (int, float)): return "num"
    if o is None: return "null"
    return "str"

def redact_json(o):
    if isinstance(o, dict):
        return {k: (redact(v) if SENSITIVE_K.search(k) and isinstance(v, (str, int)) else redact_json(v)) for k, v in o.items()}
    if isinstance(o, list): return [redact_json(x) for x in o[:3]]
    return o

def body_summary(text, ctype=""):
    if not text: return None
    t = text.strip()
    if t[:1] in "{[":
        try: return {"json_shape": shape(json.loads(t)), "sample": redact_json(json.loads(t))}
        except Exception: pass
    if "x-www-form-urlencoded" in ctype or re.fullmatch(r"[\w.%\-\[\]]+=[^&]*(&[\w.%\-\[\]]+=[^&]*)*", t[:2000] or "x"):
        q = urllib.parse.parse_qs(t, keep_blank_values=True)
        return {"form": {k: (redact(v[0]) if SENSITIVE_K.search(k) else v[0][:60]) for k, v in q.items()}}
    return {"text": t[:300]}

def http_get(url, headers, timeout=20, max_bytes=8_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(max_bytes), r.headers.get("Content-Type", ""), r.geturl()

# ---------- static ----------
RX = {
    "fetch":     re.compile(r"""\bfetch\(\s*([`'"])((?:(?!\1).)+)\1(?:\s*,\s*\{([^}]{0,400}))?""", re.S),
    "xhr_open":  re.compile(r"""\.open\(\s*(['"])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1\s*,\s*([`'"])((?:(?!\3).)+)\3""", re.I),
    "axios":     re.compile(r"""\b(?:axios|http|api|client|request|\$http|this\.\$http|instance)\.(get|post|put|patch|delete|head)\(\s*([`'"])((?:(?!\2).)+)\2"""),
    "axios_cfg": re.compile(r"""\burl\s*:\s*([`'"])((?:(?!\1)[^\n]){2,200})\1\s*,\s*(?:[^{}]{0,80}?)method\s*:\s*['"](\w+)['"]|\bmethod\s*:\s*['"](\w+)['"]\s*,\s*url\s*:\s*([`'"])((?:(?!\5)[^\n]){2,200})\5""", re.I),
    "jquery":    re.compile(r"""\$\.(get|post|getJSON|ajax)\(\s*([`'"])((?:(?!\2).)+)\2"""),
    "ws":        re.compile(r"""new\s+(WebSocket|EventSource)\(\s*([`'"])((?:(?!\2).)+)\2"""),
    "baseurl":   re.compile(r"""(?:baseURL|base_url|BASE_URL|API_URL|apiUrl|API_BASE|apiBase|endpoint|serverUrl|backendUrl)\s*[:=]\s*([`'"])((?:(?!\1)[^\n]){3,200})\1""", re.I),
    "abs_url":   re.compile(r"""(?:https?|wss?)://[^\s'"`<>\\)(\]\[{},]{4,300}"""),
    "api_path":  re.compile(r"""['"`](/(?:api|v\d+|graphql|gql|rest|rpc|trpc|ajax|json|_next/data|wp-json|services?|backend|internal|auth|oauth|socket\.io|ws)(?:/[\w\-./:{}$%?=&@~+,]*)?)['"`]"""),
    "graphql":   re.compile(r"""\b(query|mutation|subscription)\s+(\w+)?\s*(?:\([^)]*\))?\s*\{""", re.S),
    "openapi":   re.compile(r"""['"`]([^'"`\s]*(?:openapi|swagger|api-docs)[^'"`\s]*\.(?:json|ya?ml)|/(?:swagger|api-docs|redoc|docs)(?:/[\w.\-]*)?)['"`]""", re.I),
    "sourcemap": re.compile(r"""//[#@]\s*sourceMappingURL=(\S+)"""),
    "secret":    re.compile(r"""(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}|sk_live_[0-9a-zA-Z]{16,}|xox[baprs]-[0-9A-Za-z\-]{10,}|ghp_[0-9A-Za-z]{30,}|(?:api[_-]?key|client[_-]?secret|access[_-]?token)['"]?\s*[:=]\s*['"][A-Za-z0-9_\-./+]{16,}['"])""", re.I),
}
JUNK_URL = re.compile(r"(w3\.org|schema\.org|xmlns|example\.(com|org)|localhost:\d+/?$|\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|mp4|webp)(\?|$))", re.I)

def scan_text(text, src, base):
    f = collections.defaultdict(list)
    def add(kind, method, url, extra=""):
        url = url.strip()
        if url and not JUNK_URL.search(url): f[kind].append({"method": method, "url": absolutize(url, base), "raw": url, "src": src, "extra": extra})
    for m in RX["fetch"].finditer(text):
        opts = m.group(3) or ""
        mm = re.search(r"method\s*:\s*['\"](\w+)", opts)
        add("fetch", (mm.group(1).upper() if mm else "GET"), m.group(2), re.sub(r"\s+", " ", opts)[:200])
    for m in RX["xhr_open"].finditer(text): add("xhr", m.group(2).upper(), m.group(4))
    for m in RX["axios"].finditer(text): add("http_client", m.group(1).upper(), m.group(3))
    for m in RX["axios_cfg"].finditer(text):
        add("http_client", (m.group(3) or m.group(4) or "?").upper(), m.group(2) or m.group(6))
    for m in RX["jquery"].finditer(text): add("jquery", {"getjson": "GET"}.get(m.group(1).lower(), m.group(1).upper()), m.group(3))
    for m in RX["ws"].finditer(text): add("websocket" if m.group(1) == "WebSocket" else "sse", "WS" if m.group(1) == "WebSocket" else "GET", m.group(3))
    for m in RX["baseurl"].finditer(text): add("base_url", "-", m.group(2))
    for m in RX["abs_url"].finditer(text): add("abs_url", "-", m.group(0).rstrip(".;:"))
    for m in RX["api_path"].finditer(text): add("api_path", "-", m.group(1))
    for m in RX["graphql"].finditer(text):
        snippet = text[m.start():m.start() + 160].replace("\n", " ")
        f["graphql_ops"].append({"op": m.group(1), "name": m.group(2) or "", "snippet": snippet, "src": src})
    for m in RX["openapi"].finditer(text): add("openapi_ref", "GET", m.group(1))
    for m in RX["sourcemap"].finditer(text): f["sourcemap"].append({"url": absolutize(m.group(1), base), "src": src})
    for m in RX["secret"].finditer(text):
        f["secret_like"].append({"value": redact(m.group(0), 6), "src": src})
    return f

def absolutize(u, base):
    if u.startswith(("http://", "https://", "ws://", "wss://", "data:")): return u
    if "${" in u or "{" in u and not u.startswith("/"): return u  # template literal, keep raw
    return urllib.parse.urljoin(base, u) if base else u

def static_analyze(target, headers, out, max_js):
    res = {"pages": [], "scripts": [], "forms": [], "findings": collections.defaultdict(list), "fetched": [], "errors": []}
    sdir = out / "static_sources"; sdir.mkdir(parents=True, exist_ok=True)
    if True:
        raw, ctype, final = http_get(target, headers); base = final
    else:
        raw, base = Path(target).read_bytes(), ""
    page = raw.decode("utf-8", "replace")
    (sdir / "page.html").write_text(page)
    res["pages"].append(base or target)
    def merge(f):
        for k, v in f.items(): res["findings"][k].extend(v)
    merge(scan_text(page, "page.html", base))
    # forms
    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", page, re.S | re.I):
        a = fm.group(1)
        act = re.search(r"action=['\"]([^'\"]*)", a); meth = re.search(r"method=['\"](\w+)", a)
        names = re.findall(r"<(?:input|select|textarea)\b[^>]*name=['\"]([^'\"]+)", fm.group(2), re.I)
        res["forms"].append({"action": absolutize(act.group(1), base) if act else base, "method": (meth.group(1).upper() if meth else "GET"), "fields": names})
    # scripts
    srcs = re.findall(r"<script\b[^>]*\bsrc=['\"]([^'\"]+)", page, re.I)
    srcs += re.findall(r"<link\b[^>]*rel=['\"](?:modulepreload|preload)['\"][^>]*href=['\"]([^'\"]+\.m?js[^'\"]*)", page, re.I)
    for i, s in enumerate(re.findall(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", page, re.S | re.I)):
        if s.strip(): merge(scan_text(s, f"inline#{i}", base))
    seen, queue = set(), list(dict.fromkeys(absolutize(s, base) for s in srcs))
    own_host = urllib.parse.urlparse(base).netloc if base else ""
    while queue and len(seen) < max_js:
        u = queue.pop(0)
        if u in seen or not u.startswith("http") or u.startswith("data:"): continue
        seen.add(u)
        if THIRD_PARTY.search(u) and urllib.parse.urlparse(u).netloc != own_host: continue
        try:
            b, ct, fin = http_get(u, headers)
        except Exception as e:
            res["errors"].append(f"{u}: {e}"); continue
        t = b.decode("utf-8", "replace")
        name = hashlib.sha1(u.encode()).hexdigest()[:8] + "_" + re.sub(r"[^\w.\-]", "_", os.path.basename(urllib.parse.urlparse(u).path) or "index")[:60]
        (sdir / name).write_text(t)
        res["scripts"].append({"url": u, "bytes": len(b), "file": name})
        f = scan_text(t, u, fin); merge(f)
        # webpack/vite lazy chunks: sibling chunk names
        for cm in re.finditer(r"""['"`]((?:\./|/)?(?:assets|static|_next|chunks?|js)/[\w\-./]+\.m?js)['"`]""", t):
            queue.append(absolutize(cm.group(1), fin))
        for sm in f.get("sourcemap", []):
            if sm["url"].startswith("http") and len(seen) < max_js:
                try:
                    mb, _, _ = http_get(sm["url"], headers, max_bytes=20_000_000)
                    mj = json.loads(mb); res["findings"]["sourcemap_sources"] += [{"src": u, "sources": [s for s in mj.get("sources", []) if "node_modules" not in s][:60]}]
                    for sname, sc in zip(mj.get("sources", []), mj.get("sourcesContent") or []):
                        if sc and "node_modules" not in sname: merge(scan_text(sc, f"map:{sname}", fin))
                except Exception as e:
                    res["errors"].append(f"sourcemap {sm['url']}: {e}")
    # well-known spec refs: only fetch what the page itself references
    for r in list(res["findings"].get("openapi_ref", []))[:6]:
        if r["url"].startswith("http"):
            try:
                b, ct, _ = http_get(r["url"], headers)
                if b.lstrip()[:1] in (b"{", b"o", b"s") and (b"openapi" in b[:2000] or b"swagger" in b[:2000]):
                    p = sdir / ("spec_" + hashlib.sha1(r["url"].encode()).hexdigest()[:6] + ".json"); p.write_bytes(b)
                    res["fetched"].append({"openapi_spec": r["url"], "file": p.name})
            except Exception: pass
    res["findings"] = dict(res["findings"])
    return res

# ---------- dynamic ----------
def serve_local(path):
    root = str(Path(path).resolve().parent); name = Path(path).name
    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(s, *a, **k): super().__init__(*a, directory=root, **k)
        def log_message(s, *a): pass
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H); srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/{urllib.parse.quote(name)}"

SAFE_CLICK = r"(more|next|load|show|expand|tab|menu|search|filter|sort|detail|view|read|older|次|もっと|表示|検索|詳細|メニュー)"
DANGER_CLICK = r"(delete|remove|logout|log out|sign ?out|buy|purchase|pay|checkout|submit|confirm|cancel|unsubscribe|削除|購入|支払|ログアウト|解除|送信)"

SECRETS = []  # literal credential values; scrubbed from every written artifact

def scrub(t):
    for v in SECRETS:
        t = t.replace(v, "‹redacted›")
    return t

def do_login(ctx, login):
    """Fill + submit a login form with creds from env. Never prints values. Returns status string."""
    pg = ctx.new_page()
    try:
        pg.goto(login["url"], wait_until="networkidle", timeout=45000)
        pw = pg.query_selector("input[type=password]:visible")
        if not pw:  # two-step login: username first
            u = pg.query_selector("input[type=email]:visible, input[name*=user i]:visible, input[name*=mail i]:visible, input[name*=login i]:visible, input[type=text]:visible")
            if u: u.fill(login["user"]); u.press("Enter"); pg.wait_for_timeout(1500)
            pw = pg.query_selector("input[type=password]:visible")
        if not pw: return "no password field found (SSO/JS-rendered/bot wall?)"
        u = pg.query_selector("input[type=email]:visible, input[name*=user i]:visible, input[name*=mail i]:visible, input[name*=login i]:visible, input[type=text]:visible")
        if u and not u.input_value(): u.fill(login["user"])
        pw.fill(login["pass"]); pw.press("Enter")
        try: pg.wait_for_load_state("networkidle", timeout=15000)
        except Exception: pass
        pg.wait_for_timeout(1500)
        body = (pg.inner_text("body") or "").lower()
        if pg.query_selector("input[autocomplete=one-time-code], input[name*=otp i], input[name*=code i]:visible") or re.search(r"verification code|two-factor|2fa|認証コード|二段階", body):
            return "2FA/OTP required — stopped (supply --storage-state from a session you logged in yourself)"
        if pg.query_selector("iframe[src*=captcha], iframe[src*=recaptcha], .g-recaptcha, .h-captcha, [data-sitekey]"):
            return "captcha present — stopped"
        if pg.query_selector("input[type=password]:visible"):
            return "still on a password form — login probably failed"
        return "ok"
    finally:
        pg.close()

def dynamic_analyze(url, headers, cookie, out, duration, interact, login=None, state_in=None, state_out=None):
    from playwright.sync_api import sync_playwright
    traffic, ws_frames = [], []
    exe = None
    for c in sorted(Path("/opt/pw-browsers").glob("chromium-*/chrome-linux*/chrome")) if Path("/opt/pw-browsers").exists() else []:
        exe = str(c)
    with sync_playwright() as p:
        try:
            br = p.chromium.launch(headless=True, **({"executable_path": exe} if exe else {}), args=["--no-sandbox"])
        except Exception:
            br = p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = br.new_context(user_agent=UA, extra_http_headers=headers, ignore_https_errors=True, viewport={"width": 1366, "height": 900},
                             **({"storage_state": state_in} if state_in and Path(state_in).is_file() else {}))
        login_status = None
        if login:
            login_status = do_login(ctx, login); print(f"[login] {login_status}", file=sys.stderr)
            if state_out and login_status == "ok":
                Path(state_out).parent.mkdir(parents=True, exist_ok=True); ctx.storage_state(path=state_out); os.chmod(state_out, 0o600)
        if cookie:
            host = urllib.parse.urlparse(url).hostname
            ctx.add_cookies([{"name": k.strip(), "value": v, "domain": host, "path": "/"} for k, _, v in (c.partition("=") for c in cookie.split(";") if "=" in c)])
        # hook fetch/XHR/WebSocket in-page to catch things CDP resource types blur (e.g. beacons, sw)
        ctx.add_init_script("""(()=>{window.__ai=[];const L=(o)=>{try{window.__ai.push(o)}catch(e){}};
          const f=window.fetch;window.fetch=function(i,o){try{L({t:'fetch',u:String(i&&i.url||i),m:(o&&o.method)||(i&&i.method)||'GET',b:o&&typeof o.body==='string'?o.body.slice(0,2000):null,s:(new Error()).stack.split('\\n').slice(2,5).join(' | ')})}catch(e){};return f.apply(this,arguments)};
          const oo=XMLHttpRequest.prototype.open,os=XMLHttpRequest.prototype.send;
          XMLHttpRequest.prototype.open=function(m,u){this.__m=m;this.__u=u;return oo.apply(this,arguments)};
          XMLHttpRequest.prototype.send=function(b){try{L({t:'xhr',u:String(this.__u),m:this.__m,b:typeof b==='string'?b.slice(0,2000):null,s:(new Error()).stack.split('\\n').slice(2,5).join(' | ')})}catch(e){};return os.apply(this,arguments)};
        })()""")
        page = ctx.new_page()
        pending = {}
        def on_req(r):
            pending[r] = {"method": r.method, "url": r.url, "type": r.resource_type, "req_headers": redact_headers(r.headers),
                          "post": body_summary(r.post_data, r.headers.get("content-type", "")) if r.post_data else None,
                          "initiator_frame": r.frame.url if r.frame else None}
        def on_resp(r):
            d = pending.get(r.request)
            if not d: return
            d["status"] = r.status; d["resp_headers"] = redact_headers(r.headers)
            ct = r.headers.get("content-type", ""); d["content_type"] = ct
            if d["type"] in ("xhr", "fetch", "document") and ("json" in ct or "graphql" in ct or "text/plain" in ct or "xml" in ct):
                try: d["resp"] = body_summary(r.text()[:200_000], ct)
                except Exception: pass
        def on_fail(r):
            d = pending.get(r)
            if d: d["failed"] = r.failure
        page.on("request", on_req); page.on("response", on_resp); page.on("requestfailed", on_fail)
        def on_ws(ws):
            e = {"ws": ws.url, "frames": []}; ws_frames.append(e)
            ws.on("framesent", lambda d: e["frames"].append(("send", str(d)[:300])) if len(e["frames"]) < 20 else None)
            ws.on("framereceived", lambda d: e["frames"].append(("recv", str(d)[:300])) if len(e["frames"]) < 20 else None)
        page.on("websocket", on_ws)
        try: page.goto(url, wait_until="networkidle", timeout=45000)
        except Exception as e: print(f"[dyn] goto: {e}", file=sys.stderr)
        deadline = duration * 1000
        if interact:
            try:
                for _ in range(6):
                    page.mouse.wheel(0, 1200); page.wait_for_timeout(600)
                page.evaluate("window.scrollTo(0,0)")
                clicked = 0
                for el in page.query_selector_all("a[href^='#'], button, [role=tab], [role=button], summary, input[type=search], select")[:60]:
                    if clicked >= 12: break
                    try:
                        txt = (el.inner_text() or el.get_attribute("aria-label") or "").strip()[:40]
                        tag = el.evaluate("e=>e.tagName+'|'+(e.type||'')+'|'+(e.closest('form')?'form':'')")
                        if re.search(DANGER_CLICK, txt, re.I) or tag.endswith("|form") and "submit" in tag.lower(): continue
                        if tag.startswith(("SELECT", "INPUT")) or re.search(SAFE_CLICK, txt, re.I) or "tab" in (el.get_attribute("role") or ""):
                            if tag.startswith("INPUT"): el.fill("test", timeout=500); el.press("Enter", timeout=500)
                            elif tag.startswith("SELECT"): el.select_option(index=1, timeout=500)
                            else: el.click(timeout=800, no_wait_after=True)
                            clicked += 1; page.wait_for_timeout(700)
                    except Exception as e: print(f"[dyn] el: {type(e).__name__}: {str(e)[:100]}", file=sys.stderr)
            except Exception as e: print(f"[dyn] interact: {e}", file=sys.stderr)
        page.wait_for_timeout(max(1000, deadline - 8000))
        hooked = []
        try: hooked = page.evaluate("window.__ai||[]")
        except Exception: pass
        cookies = [{"name": c["name"], "domain": c["domain"], "httpOnly": c["httpOnly"], "secure": c["secure"], "sameSite": c.get("sameSite"), "value": redact(c["value"])} for c in ctx.cookies()]
        try:
            ls = page.evaluate("Object.keys(localStorage).concat(Object.keys(sessionStorage))")
        except Exception: ls = []
        title = page.title()
        br.close()
    return {"login": login_status, "requests": list(pending.values()), "ws": ws_frames, "hooked": hooked, "cookies": cookies, "storage_keys": ls, "title": title}

# ---------- report ----------
def norm_path(u):
    p = urllib.parse.urlparse(u)
    segs = []
    for s in p.path.split("/"):
        if re.fullmatch(r"\d+|[0-9a-f]{8,}|[0-9a-f\-]{32,}", s, re.I): s = "{id}"
        segs.append(s)
    return p.netloc, "/".join(segs), sorted(urllib.parse.parse_qs(p.query).keys())

def group_api(reqs, own_host):
    g = collections.OrderedDict()
    for r in reqs:
        if r["type"] not in ("xhr", "fetch", "websocket", "eventsource", "ping", "other") and not (r["type"] == "document" and "json" in r.get("content_type", "")):
            continue
        host, path, qk = norm_path(r["url"])
        key = (r["method"], host, path)
        e = g.setdefault(key, {"method": r["method"], "host": host, "path": path, "query_keys": set(), "statuses": set(), "count": 0,
                               "third_party": bool(THIRD_PARTY.search(r["url"])) and host != own_host, "req_headers": {}, "post": None, "resp": None, "ct": ""})
        e["count"] += 1; e["query_keys"].update(qk)
        if "status" in r: e["statuses"].add(r["status"])
        if not e["post"] and r.get("post"): e["post"] = r["post"]
        if not e["resp"] and r.get("resp"): e["resp"] = r["resp"]; e["ct"] = r.get("content_type", "")
        for h, v in r["req_headers"].items():
            if h.lower() in ("authorization", "x-api-key", "content-type", "x-csrf-token", "x-xsrf-token", "x-requested-with", "origin", "x-auth-token") or h.lower().startswith("x-"):
                e["req_headers"][h] = v
    return list(g.values())

def md_report(target, st, dyn, out):
    L = [f"# API analysis: {target}", ""]
    own = urllib.parse.urlparse(dyn["requests"][0]["url"]).netloc if dyn and dyn["requests"] else ""
    if dyn:
        apis = group_api(dyn["requests"], own)
        first = [a for a in apis if not a["third_party"]]; third = [a for a in apis if a["third_party"]]
        L += [f"## Dynamic — observed API calls ({len(first)} first-party, {len(third)} third-party)", "", f"login: {dyn.get('login') or 'n/a'} · page title: `{dyn['title']}` · total requests: {len(dyn['requests'])}", ""]
        for a in first:
            L.append(f"### `{a['method']} {a['host']}{a['path']}`  ×{a['count']}  status {sorted(a['statuses'])}")
            if a["query_keys"]: L.append(f"- query: {', '.join(sorted(a['query_keys']))}")
            if a["req_headers"]: L.append(f"- headers: `{json.dumps(a['req_headers'], ensure_ascii=False)}`")
            if a["post"]: L.append(f"- request body: `{json.dumps(a['post'], ensure_ascii=False)[:600]}`")
            if a["resp"]: L.append(f"- response ({a['ct']}): `{json.dumps(a['resp'].get('json_shape', a['resp']), ensure_ascii=False)[:600]}`")
            L.append("")
        if third: L += ["### third-party (not analysed)", ""] + [f"- `{a['method']} {a['host']}{a['path']}` ×{a['count']}" for a in third] + [""]
        if dyn["ws"]:
            L += ["## WebSockets", ""]
            for w in dyn["ws"]: L += [f"- `{w['ws']}`"] + [f"  - {d} `{m}`" for d, m in w["frames"][:8]]
            L.append("")
        stack = [h for h in dyn["hooked"] if h.get("s")][:15]
        if stack: L += ["## Call sites (in-page hook)", ""] + [f"- `{h['m']} {h['u'][:120]}` ← {h['s'][:160]}" for h in stack] + [""]
        L += ["## Cookies / storage", ""] + [f"- cookie `{c['name']}` @ {c['domain']} httpOnly={c['httpOnly']} secure={c['secure']} sameSite={c['sameSite']} = `{c['value']}`" for c in dyn["cookies"]]
        if dyn["storage_keys"]: L.append(f"- storage keys: {', '.join(dyn['storage_keys'][:30])}")
        L.append("")
    if st:
        F = st["findings"]
        L += [f"## Static — {len(st['scripts'])} scripts scanned, {len(st['forms'])} forms", ""]
        def uniq(kind, n=60):
            seen, o = set(), []
            for x in F.get(kind, []):
                k = (x.get("method"), x.get("url"))
                if k not in seen: seen.add(k); o.append(x)
            return o[:n]
        for kind, title in [("base_url", "Base URLs / config"), ("fetch", "fetch()"), ("xhr", "XMLHttpRequest"), ("http_client", "axios-like clients"),
                            ("jquery", "jQuery ajax"), ("websocket", "WebSocket"), ("sse", "EventSource"), ("api_path", "API-looking paths"), ("openapi_ref", "OpenAPI/Swagger refs")]:
            xs = uniq(kind)
            if xs: L += [f"### {title}", ""] + [f"- `{(x['method'] + ' ') if x['method'] != '-' else ''}{x['url']}`  ← {os.path.basename(x['src'])[:40]}" + (f"  opts: `{x['extra'][:100]}`" if x.get("extra") else "") for x in xs] + [""]
        hosts = collections.Counter(urllib.parse.urlparse(x["url"]).netloc for x in F.get("abs_url", []) if x["url"].startswith("http"))
        if hosts: L += ["### Hosts referenced (absolute URLs)", ""] + [f"- {h} ×{c}" + ("  (third-party)" if THIRD_PARTY.search(h) else "") for h, c in hosts.most_common(40)] + [""]
        if F.get("graphql_ops"): L += ["### GraphQL operations", ""] + [f"- {x['op']} {x['name']}: `{x['snippet'][:120]}`" for x in F["graphql_ops"][:30]] + [""]
        if st["forms"]: L += ["### Forms", ""] + [f"- `{f['method']} {f['action']}` fields: {', '.join(f['fields'])}" for f in st["forms"]] + [""]
        if F.get("secret_like"): L += ["### Secret-like strings (redacted)", ""] + [f"- `{x['value']}` in {os.path.basename(x['src'])[:40]}" for x in F["secret_like"][:20]] + [""]
        if F.get("sourcemap_sources"): L += ["### Source maps exposed", ""] + [f"- {x['src']}: {len(x['sources'])} sources" for x in F["sourcemap_sources"]] + [""]
        if st["fetched"]: L += ["### OpenAPI specs fetched", ""] + [f"- {x['openapi_spec']} → static_sources/{x['file']}" for x in st["fetched"]] + [""]
        if st["errors"]: L += ["### Fetch errors", ""] + [f"- {e[:200]}" for e in st["errors"][:15]] + [""]
    L += ["---", "Confidence: *Dynamic* = observed on the wire. *Static* = present in code, may be dead/conditional.",
          "Auth-gated endpoints are only seen if `--cookie`/`--header` were supplied."]
    return "\n".join(L)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target"); ap.add_argument("--mode", default="both", choices=["static", "dynamic", "both"])
    ap.add_argument("--out"); ap.add_argument("--duration", type=int, default=15)
    ap.add_argument("--no-interact", action="store_true"); ap.add_argument("--cookie", default="")
    ap.add_argument("--header", action="append", default=[]); ap.add_argument("--max-js", type=int, default=40)
    ap.add_argument("--login-url", help="login page URL; creds come from env, never argv")
    ap.add_argument("--user-env", default="WEB_USER"); ap.add_argument("--pass-env", default="WEB_PASS")
    ap.add_argument("--secrets-file", help="KEY=VALUE file (chmod 600) providing the env vars; deleted after read with --shred")
    ap.add_argument("--shred", action="store_true")
    ap.add_argument("--storage-state", help="Playwright storage_state JSON: loaded if exists, written after successful login (default .secrets/<name>.state.json)")
    a = ap.parse_args()
    hdrs = dict(h.split(":", 1) for h in a.header); hdrs = {k.strip(): v.strip() for k, v in hdrs.items()}
    if a.secrets_file:
        for ln in Path(a.secrets_file).read_text().splitlines():
            if "=" in ln and not ln.lstrip().startswith("#"): k, _, v = ln.partition("="); os.environ.setdefault(k.strip(), v.strip().strip("'\""))
        if a.shred: Path(a.secrets_file).write_bytes(b"\0" * Path(a.secrets_file).stat().st_size); Path(a.secrets_file).unlink()
    login = None
    if a.login_url:
        u, w = os.environ.get(a.user_env), os.environ.get(a.pass_env)
        if not (u and w): sys.exit(f"login requested but env {a.user_env}/{a.pass_env} not set (add them in the environment's secrets, or --secrets-file)")
        login = {"url": a.login_url, "user": u, "pass": w}; SECRETS[:] = [x for x in (u, w) if len(x) >= 4]
    for h in a.header + ([a.cookie] if a.cookie else []):
        SECRETS.extend(x for x in re.split(r"[\s;:]+", h.split(":", 1)[-1])[-1:] if len(x) >= 8)
    is_url = bool(re.match(r"https?://", a.target))
    if not is_url and not Path(a.target).is_file(): sys.exit(f"not a URL or file: {a.target}")
    name = re.sub(r"[^\w.\-]+", "_", (urllib.parse.urlparse(a.target).netloc if is_url else Path(a.target).stem))
    out = Path(a.out or f"analysis/web/{name}"); out.mkdir(parents=True, exist_ok=True)
    st = dyn = None
    state_path = a.storage_state or (f".secrets/{name}.state.json" if login else None)
    srv = None; url = a.target
    if not is_url: srv, url = serve_local(a.target)  # local .html: serve its dir so relative JS/API paths resolve
    def run_dyn():
        nonlocal dyn
        try: dyn = dynamic_analyze(url, hdrs, a.cookie, out, a.duration, not a.no_interact, login, state_path, state_path if login else None)
        except Exception as e: print(f"[dynamic] failed: {type(e).__name__}: {e}", file=sys.stderr)
    authed = bool(login or (state_path and Path(state_path).is_file()))
    if authed and a.mode in ("dynamic", "both"): run_dyn()
    if authed and state_path and Path(state_path).is_file():  # reuse the logged-in session for static fetches
        try:
            host = urllib.parse.urlparse(url).hostname or ""
            ck = "; ".join(f"{c['name']}={c['value']}" for c in json.loads(Path(state_path).read_text()).get("cookies", []) if host.endswith(c["domain"].lstrip(".")))
            if ck: hdrs.setdefault("Cookie", ck); SECRETS.extend(c.split("=", 1)[1] for c in ck.split("; ") if len(c.split("=", 1)[1]) >= 8)
        except Exception: pass
    if a.mode in ("static", "both"):
        try: st = static_analyze(url, hdrs, out, a.max_js)
        except Exception as e: print(f"[static] failed: {e}", file=sys.stderr)
    if not authed and a.mode in ("dynamic", "both"): run_dyn()
    if srv: srv.shutdown()
    if dyn:
        with open(out / "traffic.jsonl", "w") as f:
            for r in dyn["requests"]: f.write(scrub(json.dumps(r, ensure_ascii=False)) + "\n")
    (out / "report.json").write_text(scrub(json.dumps({"target": a.target, "static": st, "dynamic": dyn}, ensure_ascii=False, indent=1, default=list)))
    rep = scrub(md_report(a.target, st, dyn, out)); (out / "report.md").write_text(rep)
    for fp in (out / "static_sources").glob("*"):
        try: fp.write_text(scrub(fp.read_text()))
        except Exception: pass
    print(rep); print(f"\n[saved] {out}/report.md  report.json  traffic.jsonl  static_sources/", file=sys.stderr)

if __name__ == "__main__":
    main()
