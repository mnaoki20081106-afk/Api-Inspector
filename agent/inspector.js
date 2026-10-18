'use strict';

// api-inspector agent: enumerates a target's exports/imports, hooks them, classifies args,
// ranks functions by call volume / arg diversity. Host config arrives via rpc.exports.configure.

const cfg = {
  modules: [],            // module name globs; empty = main module only
  include: ['*'],         // function name globs
  exclude: [],            // function name globs
  maxHooks: 400,
  argCount: 6,
  backtrace: false,
  hotLimit: 200,          // calls/sec before a function is auto-muted from the live log
  includeImports: true,   // hook imported functions resolved in watched modules too
};

const stats = new Map();   // key -> {mod, name, addr, calls, muted, args:[Set], strs:Set, rets:Set, win:{t,n}}
const hooks = new Map();   // key -> InvocationListener

const CATEGORIES = [
  ['net',    /^(send|recv|sendto|recvfrom|connect|accept|bind|listen|WSA\w+|socket|getaddrinfo|gethostbyname|SSL_\w+|curl_\w+|Internet\w+|Http\w+|WinHttp\w+)$/i],
  ['file',   /^(open|openat|read|write|close|fopen|fread|fwrite|stat|unlink|CreateFile\w*|ReadFile|WriteFile|DeleteFile\w*|FindFirstFile\w*|NtCreateFile|NtReadFile|NtWriteFile)$/i],
  ['memory', /^(mmap|munmap|mprotect|malloc|free|VirtualAlloc\w*|VirtualProtect\w*|VirtualQuery\w*|ReadProcessMemory|WriteProcessMemory|NtProtectVirtualMemory|NtAllocateVirtualMemory)$/i],
  ['crypto', /^(EVP_\w+|AES_\w+|SHA\w*_\w+|MD5\w*|HMAC\w*|RSA_\w+|BCrypt\w+|Crypt\w+|NCrypt\w+|mbedtls_\w+)$/i],
  ['proc',   /^(fork|exec\w*|system|popen|dlopen|dlsym|LoadLibrary\w*|GetProcAddress|CreateProcess\w*|CreateThread|NtCreateThreadEx|ptrace)$/i],
  ['time',   /^(time|gettimeofday|clock_gettime|GetTickCount\w*|QueryPerformanceCounter|timeGetTime)$/i],
  ['input',  /^(GetAsyncKeyState|GetKeyState|GetCursorPos|SetCursorPos|SendInput|mouse_event|keybd_event|GetRawInputData)$/i],
  ['gfx',    /^(Present|D3D\w+|IDXGI\w+|eglSwapBuffers|glDraw\w+|vk\w+|SwapBuffers|BitBlt)$/i],
];

function globToRe(g) {
  return new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
}
const matchAny = (list, s) => list.some(r => r.test(s));

function categorize(name) {
  for (const [c, re] of CATEGORIES) if (re.test(name)) return c;
  return 'other';
}

function isReadable(p) {
  try { return !p.isNull() && Process.findRangeByAddress(p) !== null; } catch (_) { return false; }
}

function tryCString(p) {
  try {
    const s = p.readCString(128);
    if (s && s.length >= 3 && /^[\x20-\x7e\t\r\n]+$/.test(s)) return s;
  } catch (_) {}
  return null;
}

function tryWString(p) {
  try {
    const s = p.readUtf16String(128);
    if (s && s.length >= 3 && /^[\x20-\x7e\t\r\n]+$/.test(s)) return s;
  } catch (_) {}
  return null;
}

// classify one argument value: {k: kind, v: display}
function classify(v) {
  if (v.isNull()) return { k: 'null', v: '0x0' };
  const n = v.toUInt32 ? v.toUInt32() : 0;
  const asNum = v.compare(ptr(0x10000)) < 0;
  if (asNum) return { k: 'int', v: v.toInt32() };
  if (isReadable(v)) {
    const s = tryCString(v);
    if (s !== null) return { k: 'cstr', v: s };
    const w = tryWString(v);
    if (w !== null) return { k: 'wstr', v: w };
    const range = Process.findRangeByAddress(v);
    return { k: 'ptr', v: v.toString(), prot: range ? range.protection : '?' };
  }
  return { k: 'val', v: v.toString() };
}

function hookTarget(mod, name, addr, source) {
  const key = mod + '!' + name;
  if (hooks.has(key) || hooks.size >= cfg.maxHooks) return false;
  const st = {
    mod, name, addr: addr.toString(), cat: categorize(name), source,
    calls: 0, muted: false, argKinds: [], strs: new Set(), rets: new Set(),
    winT: 0, winN: 0,
  };
  for (let i = 0; i < cfg.argCount; i++) st.argKinds.push({});
  stats.set(key, st);
  try {
    hooks.set(key, Interceptor.attach(addr, {
      onEnter(args) {
        st.calls++;
        const now = Date.now();
        if (now - st.winT > 1000) { st.winT = now; st.winN = 0; }
        st.winN++;
        if (!st.muted && st.winN > cfg.hotLimit) {
          st.muted = true;
          send({ t: 'muted', fn: key, reason: 'hot (>' + cfg.hotLimit + '/s)' });
        }
        const cl = [];
        for (let i = 0; i < cfg.argCount; i++) {
          let c;
          try { c = classify(args[i]); } catch (_) { c = { k: 'err', v: '?' }; }
          st.argKinds[i][c.k] = (st.argKinds[i][c.k] || 0) + 1;
          if ((c.k === 'cstr' || c.k === 'wstr') && st.strs.size < 64) st.strs.add(c.v);
          cl.push(c);
        }
        this._args = cl;
        if (st.muted) return;
        const ev = { t: 'call', fn: key, cat: st.cat, tid: this.threadId, args: cl };
        if (cfg.backtrace) {
          ev.bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .slice(0, 8).map(DebugSymbol.fromAddress).map(String);
        }
        this._ev = ev;
      },
      onLeave(ret) {
        let r;
        try { r = classify(ret); } catch (_) { r = { k: 'err', v: '?' }; }
        if (st.rets.size < 32) st.rets.add(String(r.v));
        if (this._ev) { this._ev.ret = r; send(this._ev); }
      },
    }));
    return true;
  } catch (e) {
    stats.delete(key);
    send({ t: 'warn', msg: 'attach failed ' + key + ': ' + e.message });
    return false;
  }
}

function targetModules() {
  const mods = Process.enumerateModules();
  if (!cfg.modules.length) return [mods[0]];
  const res = cfg.modules.map(globToRe);
  return mods.filter(m => matchAny(res, m.name));
}

function attachAll() {
  const inc = cfg.include.map(globToRe), exc = cfg.exclude.map(globToRe);
  const wanted = n => matchAny(inc, n) && !matchAny(exc, n);
  let n = 0;
  for (const m of targetModules()) {
    for (const e of m.enumerateExports()) {
      if (e.type === 'function' && wanted(e.name) && hookTarget(m.name, e.name, e.address, 'export')) n++;
    }
    if (cfg.includeImports) {
      for (const i of m.enumerateImports()) {
        if (i.type === 'function' && i.address && wanted(i.name) &&
            hookTarget(i.module || '?', i.name, i.address, 'import')) n++;
      }
    }
  }
  return n;
}

function score(s) {
  // interesting = called, takes strings, varied args/returns; hot spam gets a penalty
  const kinds = s.argKinds.reduce((a, o) => a + Object.keys(o).length, 0);
  return Math.round(Math.log2(s.calls + 1) * 10 + s.strs.size * 2 + kinds + s.rets.size - (s.muted ? 15 : 0));
}

function report() {
  return Array.from(stats.entries())
    .filter(([, s]) => s.calls > 0)
    .map(([k, s]) => ({
      fn: k, cat: s.cat, source: s.source, addr: s.addr, calls: s.calls, muted: s.muted,
      score: score(s), argKinds: s.argKinds, strs: Array.from(s.strs).slice(0, 12),
      rets: Array.from(s.rets).slice(0, 8),
    }))
    .sort((a, b) => b.score - a.score);
}

rpc.exports = {
  configure(c) { Object.assign(cfg, c); return cfg; },
  start() { const n = attachAll(); send({ t: 'ready', hooked: n, platform: Process.platform, arch: Process.arch }); return n; },
  modules() { return Process.enumerateModules().map(m => ({ name: m.name, base: m.base.toString(), size: m.size, path: m.path })); },
  exports(mod) { return Process.getModuleByName(mod).enumerateExports().map(e => ({ name: e.name, type: e.type, addr: e.address.toString() })); },
  report,
  unmute(fn) { const s = stats.get(fn); if (s) { s.muted = false; s.winN = 0; } return !!s; },
  stop() { hooks.forEach(h => h.detach()); hooks.clear(); return true; },
};
