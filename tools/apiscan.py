#!/usr/bin/env python3
"""apiscan - static API discovery for Android APK / XAPK / APKS. Zero dependencies (stdlib only).

    python3 tools/apiscan.py app.apk -o out/            # writes out/apiscan.json + out/apiscan.md, prints md
    python3 tools/apiscan.py app.apk --json             # JSON to stdout

Finds: base URLs / hosts / WebSocket endpoints, Retrofit endpoint definitions (method, path, params, response type)
straight from the DEX annotations, HTTP libraries, cert pins, cleartext / network-security-config, deep links,
manifest meta-data keys, secrets (redacted), cross-platform frameworks (Flutter / RN / Unity / Cordova) and
where their strings live. Output is meant to be read by an agent: stable JSON + compact markdown.
"""
import argparse, io, json, os, re, struct, sys, zipfile
from collections import Counter, defaultdict

MAX_FILE = 96 * 1024 * 1024
SKIP_EXT = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp3', '.mp4', '.ogg', '.wav', '.ttf', '.otf', '.woff', '.woff2',
            '.webm', '.mov', '.ico', '.bmp', '.svg', '.pfb', '.aac', '.m4a', '.flac', '.mkv', '.avi', '.kotlin_module'}

# ---------------------------------------------------------------- noise / classification
NOISE_HOSTS = re.compile(
    r'(^|\.)(schemas\.android\.com|schemas\.microsoft\.com|w3\.org|xmlpull\.org|ns\.adobe\.com|apache\.org|'
    r'example\.(com|org|net)|localhost|xmlsoap\.org|purl\.org|openxmlformats\.org|json-schema\.org|'
    r'iana\.org|ietf\.org|mozilla\.org|android\.com|developer\.android\.com|source\.android\.com|'
    r'sun\.com|java\.com|oracle\.com|eclipse\.org|slf4j\.org|jetbrains\.com|kotlinlang\.org|'
    r'xml\.org|relaxng\.org|sax\.sourceforge\.net|rfc-editor\.org|openid\.net|googleapis\.dev|'
    r'creativecommons\.org|gnu\.org|unicode\.org|ogp\.me|schema\.org|facebook\.com/2008)$', re.I)
THIRD_PARTY = re.compile(
    r'(firebase|firebaseio|google|gstatic|googleapis|googleusercontent|gvt\d|doubleclick|admob|crashlytics|app-measurement|'
    r'facebook|fbcdn|fb\.com|instagram|sentry|bugsnag|adjust|appsflyer|branch\.io|app\.link|onesignal|amplitude|mixpanel|'
    r'segment|braze|appboy|unity3d|unityads|applovin|ironsrc|vungle|chartboost|inmobi|mopub|smaato|pubmatic|criteo|'
    r'twitter|twimg|tiktok|snapchat|youtube|ytimg|paypal|stripe|braintree|datadog|newrelic|instabug|hockeyapp|'
    r'play\.google|cloudfront\.net|akamai|fastly|jsdelivr|cloudflare|github|gitlab|bitbucket|mapbox|here\.com|'
    r'kakao|naver|line\.me|line-scdn|baidu|qq\.com|weixin|wechat|alipay|umeng|jpush|getui|huawei|hicloud|xiaomi|'
    r'samsung|vk\.com|yandex|mail\.ru|appcenter|microsoft|live\.com|azure|windows\.net|aws|amazon)', re.I)

LIB_PREFIXES = [
    ('okhttp3/', 'OkHttp'), ('com/squareup/okhttp/', 'OkHttp2'), ('retrofit2/', 'Retrofit'), ('retrofit/', 'Retrofit1'),
    ('com/android/volley/', 'Volley'), ('io/grpc/', 'gRPC'), ('com/apollographql/', 'Apollo GraphQL'),
    ('io/ktor/', 'Ktor'), ('org/chromium/net/', 'Cronet'), ('io/socket/', 'Socket.IO'), ('com/loopj/android/http/', 'AsyncHttpClient'),
    ('org/apache/http/', 'Apache HttpClient'), ('com/koushikdutta/', 'Ion/AndroidAsync'), ('com/androidnetworking/', 'FastAndroidNetworking'),
    ('com/github/kittinunf/fuel/', 'Fuel'), ('com/google/gson/', 'Gson'), ('com/squareup/moshi/', 'Moshi'),
    ('com/fasterxml/jackson/', 'Jackson'), ('kotlinx/serialization/', 'kotlinx.serialization'), ('com/google/protobuf/', 'protobuf'),
    ('org/java_websocket/', 'Java-WebSocket'), ('okhttp3/internal/ws/', 'OkHttp WebSocket'), ('com/neovisionaries/ws/', 'nv-websocket'),
    ('com/google/firebase/', 'Firebase'), ('com/facebook/', 'Facebook SDK'), ('com/adjust/sdk/', 'Adjust'),
    ('com/appsflyer/', 'AppsFlyer'), ('io/sentry/', 'Sentry'), ('com/onesignal/', 'OneSignal'), ('com/amplitude/', 'Amplitude'),
    ('com/mixpanel/', 'Mixpanel'), ('com/unity3d/', 'Unity'), ('io/flutter/', 'Flutter'), ('com/facebook/react/', 'React Native'),
    ('org/apache/cordova/', 'Cordova'), ('com/getcapacitor/', 'Capacitor'), ('mono/android/', 'Xamarin'),
    ('com/google/android/gms/', 'Play Services'), ('com/auth0/', 'Auth0'), ('net/openid/appauth/', 'AppAuth'),
    ('com/stripe/', 'Stripe'), ('com/braintreepayments/', 'Braintree'), ('com/bumptech/glide/', 'Glide'),
    ('com/squareup/picasso/', 'Picasso'), ('coil/', 'Coil'), ('androidx/work/', 'WorkManager'),
    ('com/tencent/', 'Tencent SDK'), ('com/baidu/', 'Baidu SDK'), ('com/alibaba/', 'Alibaba SDK'),
    ('com/securepreferences/', 'SecurePrefs'), ('com/scottyab/rootbeer/', 'RootBeer'), ('com/guardsquare/', 'DexGuard'),
    ('com/google/android/play/core/integrity/', 'Play Integrity'), ('com/google/android/gms/safetynet/', 'SafetyNet'),
]

SECRET_PATTERNS = [
    ('google_api_key', re.compile(r'AIza[0-9A-Za-z_\-]{35}')),
    ('aws_access_key', re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b')),
    ('stripe_key', re.compile(r'\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b')),
    ('slack_token', re.compile(r'\bxox[abprs]-[0-9A-Za-z\-]{10,}\b')),
    ('github_token', re.compile(r'\bgh[pousr]_[0-9A-Za-z]{30,}\b')),
    ('jwt', re.compile(r'\beyJ[0-9A-Za-z_\-]{8,}\.eyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\b')),
    ('private_key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ('firebase_db', re.compile(r'https://[a-z0-9\-]+(?:-default-rtdb)?\.firebaseio\.com')),
    ('sentry_dsn', re.compile(r'https://[0-9a-f]{16,}@[a-z0-9.\-]+/\d+')),
    ('basic_auth_url', re.compile(r'https?://[^/\s:@]+:[^/\s:@]+@[^\s/]+')),
]
GENERIC_SECRET = re.compile(
    r'(?i)\b(api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|app[_-]?secret|auth[_-]?token|access[_-]?token|'
    r'x-api-key|authorization)\b["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-./+=]{12,})["\']')

URL_RE = re.compile(rb'(?:https?|wss?)://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%{}]{4,}')
URL_RE16 = re.compile('(?:https?|wss?)://[A-Za-z0-9\\-._~:/?#\\[\\]@!$&\'()*+,;=%{}]{4,}')
PIN_RE = re.compile(r'sha(?:1|256)/[A-Za-z0-9+/]{27,43}=?')
PATH_RE = re.compile(r'^/?(?:[A-Za-z0-9_\-.~{}:]+/){1,}[A-Za-z0-9_\-.~{}:?=&%,]*$')
PATH_HINT = re.compile(r'(?i)(api|v\d+|rest|graphql|gql|auth|oauth|login|logout|signin|signup|register|token|user|users|account|'
                       r'session|search|feed|post|posts|list|config|settings|profile|device|push|notif|payment|order|cart|'
                       r'product|item|upload|download|sync|event|track|log|report|verify|refresh|me\b|ws|socket)')
NOT_PATH = re.compile(r'(\[*L[A-Za-z0-9_/$]+;?$)|(?i:\.(png|jpe?g|gif|webp|xml|java|kt|class|so|dll|json|txt|html?|js|css|ttf|otf|ogg|mp\d|9\.png|pb)$|'
                      r'^/?(res|assets|lib|META-INF|android|androidx|kotlin|java|javax|org|com|dalvik|sun|libcore)/|'
                      r'^/(proc|sys|dev|data|system|vendor|etc|storage|sdcard|mnt|tmp|cache|apex|product)(/|$))')
HOST_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|jp|cn|app|dev|ai|me|tv|xyz|info|biz|us|uk|de|fr|ru|'
                     r'kr|in|br|tech|cloud|online|site|live|gg|so|to|sh|ly|fm|cc|ws|eu|ca|au|nl|it|es|se|ch|pl|tw|hk|sg|id|vn|th|ph)$', re.I)

# ---------------------------------------------------------------- DEX
def uleb(b, p):
    r = s = 0
    while True:
        x = b[p]; p += 1
        r |= (x & 0x7f) << s
        if not x & 0x80: return r, p
        s += 7

def mutf8(b, p):
    _, p = uleb(b, p)
    e = b.index(0, p)
    raw = b[p:e]
    try: return raw.decode('utf-8')
    except UnicodeDecodeError:
        return raw.decode('utf-8', 'replace')  # surrogate pairs / modified NUL, close enough for regex work

RETROFIT_HTTP = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}
PARAM_ANN = {'Query', 'QueryMap', 'QueryName', 'Path', 'Body', 'Field', 'FieldMap', 'Part', 'PartMap', 'Header', 'HeaderMap', 'Url', 'Tag'}

class Dex:
    def __init__(self, data, name):
        self.b = data; self.name = name
        b = data
        if b[:4] != b'dex\n': raise ValueError('not dex')
        (self.nstr, self.stroff, self.ntype, self.typeoff, self.nproto, self.protooff,
         self.nfield, self.fieldoff, self.nmeth, self.methoff, self.nclass, self.classoff) = struct.unpack_from('<12I', b, 0x38)
        self._s = {}
        self.strings = None

    def strs(self):
        if self.strings is None:
            b = self.b
            offs = struct.unpack_from('<%dI' % self.nstr, b, self.stroff)
            self.strings = [mutf8(b, o) for o in offs]
        return self.strings

    def string(self, i): return self.strs()[i]
    def type_name(self, i):
        return self.string(struct.unpack_from('<I', self.b, self.typeoff + 4 * i)[0])
    def proto(self, i):
        shorty, ret, params = struct.unpack_from('<3I', self.b, self.protooff + 12 * i)
        ps = []
        if params:
            n, = struct.unpack_from('<I', self.b, params)
            ps = [self.type_name(t) for t in struct.unpack_from('<%dH' % n, self.b, params + 4)]
        return self.type_name(ret), ps
    def method(self, i):
        c, p, n = struct.unpack_from('<HHI', self.b, self.methoff + 8 * i)
        ret, ps = self.proto(p)
        return self.type_name(c), self.string(n), ret, ps

    def class_names(self):
        return [self.type_name(i) for i in range(self.ntype)]

    # -- encoded values
    def value(self, p):
        b = self.b
        h = b[p]; p += 1
        t, a = h & 0x1f, h >> 5
        if t == 0x1f: return bool(a), p
        if t == 0x1e: return None, p
        if t == 0x1c:
            n, p = uleb(b, p); out = []
            for _ in range(n):
                v, p = self.value(p); out.append(v)
            return out, p
        if t == 0x1d:
            return self.annotation(p)
        sz = a + 1
        raw = int.from_bytes(b[p:p + sz], 'little'); p += sz
        if t == 0x17: return self.string(raw), p
        if t == 0x18: return self.type_name(raw), p
        if t == 0x1b:
            c, n, _, _ = self.field(raw); return n, p
        if t in (0x04, 0x02, 0x00, 0x06):
            bits = sz * 8
            if raw >> (bits - 1): raw -= 1 << bits
            return raw, p
        return raw, p
    def field(self, i):
        c, t, n = struct.unpack_from('<HHI', self.b, self.fieldoff + 8 * i)
        return self.type_name(c), self.string(n), self.type_name(t), None
    def annotation(self, p):
        b = self.b
        ti, p = uleb(b, p); n, p = uleb(b, p)
        el = {}
        for _ in range(n):
            ni, p = uleb(b, p); v, p = self.value(p)
            el[self.string(ni)] = v
        return (self.type_name(ti), el), p
    def annotation_item(self, off):
        a, _ = self.annotation(off + 1)
        return a
    def annotation_set(self, off):
        if not off: return []
        n, = struct.unpack_from('<I', self.b, off)
        return [self.annotation_item(o) for o in struct.unpack_from('<%dI' % n, self.b, off + 4)]

    def endpoints(self):
        """Retrofit-style endpoints from method annotations. Yields dicts."""
        b = self.b
        out = []
        for ci in range(self.nclass):
            cls, acc, sup, ifs, src, ann_off, data_off, sv = struct.unpack_from('<8I', b, self.classoff + 32 * ci)
            if not ann_off: continue
            cname = self.type_name(cls)
            cls_ann, nf, nm, npar = struct.unpack_from('<4I', b, ann_off)
            base = ann_off + 16 + 8 * nf
            pars = {}
            pbase = base + 8 * nm
            for k in range(npar):
                mi, lo = struct.unpack_from('<2I', b, pbase + 8 * k)
                if not lo: continue
                cnt, = struct.unpack_from('<I', b, lo)
                lst = []
                for so in struct.unpack_from('<%dI' % cnt, b, lo + 4):
                    lst.append(self.annotation_set(so))
                pars[mi] = lst
            for k in range(nm):
                mi, ao = struct.unpack_from('<2I', b, base + 8 * k)
                anns = self.annotation_set(ao)
                http = None; headers = []; flags = []; sig = None
                for (t, el) in anns:
                    short = t.rsplit('/', 1)[-1].rstrip(';')
                    if t.startswith('Lretrofit2/http/') or t.startswith('Lretrofit/http/'):
                        if short in RETROFIT_HTTP:
                            http = (short, el.get('value', ''))
                        elif short == 'HTTP':
                            http = (el.get('method', '?'), el.get('path', ''))
                        elif short == 'Headers':
                            v = el.get('value', []); headers += v if isinstance(v, list) else [v]
                        elif short in ('FormUrlEncoded', 'Multipart', 'Streaming'):
                            flags.append(short)
                    elif t == 'Ldalvik/annotation/Signature;':
                        v = el.get('value', [])
                        sig = ''.join(v) if isinstance(v, list) else str(v)
                if not http: continue
                cn, mn, ret, ps = self.method(mi)
                params = []
                plist = pars.get(mi, [])
                for idx, ptype in enumerate(ps):
                    kind = None; name = None
                    for (t, el) in (plist[idx] if idx < len(plist) else []):
                        if t.startswith('Lretrofit2/http/') or t.startswith('Lretrofit/http/'):
                            s = t.rsplit('/', 1)[-1].rstrip(';')
                            if s in PARAM_ANN: kind = s; name = el.get('value')
                    params.append({'in': kind or '?', 'name': name, 'type': pretty_type(ptype)})
                out.append({'class': pretty_type(cn), 'method': mn, 'http': http[0], 'path': http[1],
                            'headers': headers, 'flags': flags, 'params': params,
                            'returns': pretty_sig(sig) if sig else pretty_type(ret), 'dex': self.name})
        return out

def pretty_type(d):
    arr = 0
    while d.startswith('['): arr += 1; d = d[1:]
    prim = {'I': 'int', 'J': 'long', 'Z': 'boolean', 'B': 'byte', 'S': 'short', 'C': 'char', 'F': 'float', 'D': 'double', 'V': 'void'}
    r = prim.get(d) or (d[1:-1].replace('/', '.') if d.startswith('L') and d.endswith(';') else d)
    return r + '[]' * arr

def pretty_sig(s):
    # "(params)Lretrofit2/Call<Lcom/x/User;>;" -> "retrofit2.Call<com.x.User>"
    if s.startswith('(') and ')' in s: s = s[s.index(')') + 1:]
    s = re.sub(r'L([A-Za-z0-9_/$]+)', lambda m: m.group(1).replace('/', '.'), s)
    return s.replace(';', '').replace('+', '? extends ')

# ---------------------------------------------------------------- binary XML
def parse_axml(b):
    """Returns list of (path:list[str], tag, attrs:dict). Namespaces dropped; refs shown as @0xID."""
    if len(b) < 8 or struct.unpack_from('<H', b, 0)[0] != 0x0003: raise ValueError('not axml')
    pool = []
    p = 8
    out = []; stack = []
    n = len(b)
    while p + 8 <= n:
        t, hs, sz = struct.unpack_from('<HHI', b, p)
        if sz == 0: break
        if t == 0x0001:
            cnt, sc, flags, sstart, _ = struct.unpack_from('<5I', b, p + 8)
            offs = struct.unpack_from('<%dI' % cnt, b, p + hs)
            utf8 = bool(flags & 0x100)
            for o in offs:
                q = p + sstart + o
                if utf8:
                    l = b[q]; q += 1 + (1 if l & 0x80 else 0)
                    bl = b[q]; q += 1
                    if bl & 0x80: bl = ((bl & 0x7f) << 8) | b[q]; q += 1
                    pool.append(b[q:q + bl].decode('utf-8', 'replace'))
                else:
                    l, = struct.unpack_from('<H', b, q); q += 2
                    if l & 0x8000: l = ((l & 0x7fff) << 16) | struct.unpack_from('<H', b, q)[0]; q += 2
                    pool.append(b[q:q + 2 * l].decode('utf-16le', 'replace'))
        elif t == 0x0102:
            ns, name, astart, asize, acount = struct.unpack_from('<2i3H', b, p + 16)
            attrs = {}
            for i in range(acount):
                a = p + 16 + astart + i * 20
                ans, aname, raw, vsz, _, dt, data = struct.unpack_from('<3iHBBI', b, a)
                nm = pool[aname] if 0 <= aname < len(pool) else str(aname)
                if raw >= 0 and raw < len(pool): v = pool[raw]
                elif dt == 3: v = pool[data] if data < len(pool) else str(data)
                elif dt == 0x12: v = data != 0
                elif dt == 0x10: v = struct.unpack('<i', struct.pack('<I', data))[0]
                elif dt == 0x11: v = hex(data)
                elif dt == 1: v = '@0x%08x' % data
                elif dt == 2: v = '?0x%08x' % data
                else: v = data
                attrs[nm] = v
            tag = pool[name] if 0 <= name < len(pool) else str(name)
            stack.append(tag)
            out.append((list(stack), tag, attrs))
        elif t == 0x0104:
            idx, = struct.unpack_from('<i', b, p + 16)
            if 0 <= idx < len(pool): out.append((stack + ['#text'], '#text', {'text': pool[idx]}))
        elif t == 0x0103:
            if stack: stack.pop()
        p += sz
    return out

def scan_manifest(data):
    info = {'package': None, 'versionName': None, 'versionCode': None, 'minSdk': None, 'targetSdk': None, 'permissions': [],
            'application': {}, 'components': [], 'deeplinks': [], 'meta_data': [], 'queries': [], 'parse_error': None}
    try: els = parse_axml(data)
    except Exception as e:
        info['parse_error'] = repr(e); return info
    comp = None; ifl = None
    for path, tag, a in els:
        if tag == 'manifest':
            info['package'] = a.get('package'); info['versionName'] = a.get('versionName'); info['versionCode'] = a.get('versionCode')
        elif tag == 'uses-sdk':
            info['minSdk'] = a.get('minSdkVersion'); info['targetSdk'] = a.get('targetSdkVersion')
        elif tag == 'uses-permission' or tag == 'uses-permission-sdk-23':
            info['permissions'].append(a.get('name'))
        elif tag == 'application':
            info['application'] = {k: a[k] for k in ('usesCleartextTraffic', 'networkSecurityConfig', 'debuggable', 'allowBackup', 'name', 'extractNativeLibs') if k in a}
        elif tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
            comp = {'type': tag, 'name': a.get('name'), 'exported': a.get('exported'), 'filters': []}
            info['components'].append(comp)
        elif tag == 'intent-filter':
            ifl = {'actions': [], 'categories': [], 'data': []}
            if comp is not None: comp['filters'].append(ifl)
        elif tag == 'action' and ifl is not None: ifl['actions'].append(a.get('name'))
        elif tag == 'category' and ifl is not None: ifl['categories'].append(a.get('name'))
        elif tag == 'data' and ifl is not None:
            d = {k: a[k] for k in ('scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'mimeType') if k in a}
            ifl['data'].append(d)
        elif tag == 'meta-data':
            info['meta_data'].append({'name': a.get('name'), 'value': a.get('value', a.get('resource'))})
    for c in info['components']:
        for f in c['filters']:
            sch = [d for d in f['data'] if 'scheme' in d]
            if sch and any(x in f['actions'] for x in ('android.intent.action.VIEW',)):
                for d in sch:
                    info['deeplinks'].append({'component': c['name'], **d, 'autoVerify': None})
    info['components'] = [{k: v for k, v in c.items() if k != 'filters'} | ({'has_deeplink': True} if any(
        d.get('scheme') for f in c['filters'] for d in f['data']) else {}) for c in info['components']]
    return info

def scan_nsc(data):
    """network_security_config from binary xml"""
    try: els = parse_axml(data)
    except Exception: return None
    if not els or els[0][1] != 'network-security-config': return None
    res = {'cleartext_base': None, 'domains': [], 'pins': [], 'trust_user_certs': False, 'debug_overrides': False}
    cur = None
    for path, tag, a in els:
        if tag == 'base-config' and 'cleartextTrafficPermitted' in a: res['cleartext_base'] = a['cleartextTrafficPermitted']
        elif tag == 'domain-config':
            cur = {'domains': [], 'cleartext': a.get('cleartextTrafficPermitted'), 'pins': []}; res['domains'].append(cur)
        elif tag == '#text' and cur is not None and path[-2:-1] == ['domain']:
            cur['domains'].append(a['text'])
        elif tag == 'pin' and cur is not None:
            cur['pins'].append(a.get('digest', ''))
        elif tag == 'certificates' and a.get('src') == 'user': res['trust_user_certs'] = True
        elif tag == 'debug-overrides': res['debug_overrides'] = True
    return res

# ---------------------------------------------------------------- string harvesting
def host_of(url):
    m = re.match(r'(?:https?|wss?)://(?:[^/@]*@)?([^/:?#]+)(?::(\d+))?', url, re.I)
    return (m.group(1).lower(), m.group(2)) if m else (None, None)

def clean_url(u):
    return u.rstrip('.,;:)\'"]}>').rstrip('\\')

class Harvest:
    def __init__(self):
        self.urls = defaultdict(set)      # url -> sources
        self.paths = defaultdict(set)
        self.hosts = defaultdict(set)
        self.secrets = defaultdict(set)   # (kind, redacted) -> sources
        self.pins = defaultdict(set)
        self.gql = set()

    def text(self, s, src, strict_strings=False):
        """s: a decoded string (dex string / short text). strict_strings=True means s is one whole string literal."""
        if '://' in s:
            for m in URL_RE16.finditer(s):
                u = clean_url(m.group(0))
                if len(u) > 10: self.urls[u].add(src)
        if strict_strings:
            if 4 <= len(s) <= 200 and '/' in s and ' ' not in s and PATH_RE.match(s) and not NOT_PATH.search(s) and PATH_HINT.search(s):
                self.paths[s].add(src)
            elif 4 <= len(s) <= 80 and HOST_RE.match(s) and not NOISE_HOSTS.search(s):
                self.hosts[s.lower()].add(src)
            if ('query ' in s or 'mutation ' in s or 'subscription ' in s) and '{' in s and len(s) < 4000 and re.match(r'\s*(query|mutation|subscription|fragment)\b', s):
                self.gql.add(s.strip()[:300])
        if len(s) >= 8:
            self.sec(s, src)
        for m in PIN_RE.finditer(s): self.pins[m.group(0)].add(src)

    def sec(self, s, src):
        for kind, rx in SECRET_PATTERNS:
            for m in rx.finditer(s):
                self.secrets[(kind, redact(m.group(0)))].add(src)
        for m in GENERIC_SECRET.finditer(s):
            self.secrets[('generic:' + m.group(1).lower(), redact(m.group(2)))].add(src)

    def blob(self, data, src):
        """raw bytes from non-dex files: native libs, assets, js bundles, arsc"""
        for m in URL_RE.finditer(data):
            u = clean_url(m.group(0).decode('latin-1'))
            if len(u) > 10: self.urls[u].add(src)
        if len(data) < 24 * 1024 * 1024 or src.endswith(('.js', '.json', '.xml', '.html', '.txt', '.properties', '.bundle', '.hbc')):
            try: t = data.decode('utf-8', 'ignore')
            except Exception: t = ''
            self.sec(t, src)
            for m in PIN_RE.finditer(t): self.pins[m.group(0)].add(src)
            for m in re.finditer(r'(?:["\'`])(/(?:api|v\d)[A-Za-z0-9_\-./{}:]*)["\'`]', t):
                if len(m.group(1)) < 120: self.paths[m.group(1)].add(src)
        # UTF-16 strings (arsc, .NET, Unity)
        if b'h\x00t\x00t\x00p\x00' in data:
            for m in re.finditer(rb'(?:h\x00t\x00t\x00p\x00s?\x00?:\x00/\x00/\x00)(?:[\x20-\x7e]\x00){4,}', data):
                u = clean_url(m.group(0).decode('utf-16le', 'ignore'))
                if len(u) > 10: self.urls[u].add(src)

def redact(v):
    return v if len(v) <= 8 else v[:4] + '…' + v[-4:] + '(%d)' % len(v)

# ---------------------------------------------------------------- container walk
def iter_apks(path):
    """yield (label, zipfile.ZipFile) for the APK itself or each apk inside an xapk/apks bundle."""
    z = zipfile.ZipFile(path)
    names = z.namelist()
    if 'AndroidManifest.xml' in names:
        yield os.path.basename(path), z; return
    for n in names:
        if n.lower().endswith('.apk'):
            try: yield n, zipfile.ZipFile(io.BytesIO(z.read(n)))
            except zipfile.BadZipFile: pass

FRAMEWORK_MARKERS = [
    ('Flutter', ('lib/', 'libflutter.so')), ('Flutter (AOT code)', ('lib/', 'libapp.so')),
    ('React Native', ('assets/', 'index.android.bundle')), ('Hermes bytecode', ('assets/', '.hbc')),
    ('Unity IL2CPP', ('lib/', 'libil2cpp.so')), ('Unity Mono', ('assets/bin/Data/Managed', 'Assembly-CSharp.dll')),
    ('Xamarin/.NET', ('assemblies/', '.dll')), ('Cordova/Capacitor', ('assets/www/', 'index.html')),
    ('Cocos2d', ('lib/', 'libcocos2d')), ('Godot', ('lib/', 'libgodot')), ('Unreal', ('lib/', 'libUE4.so')),
]

def scan(path):
    H = Harvest()
    res = {'file': os.path.basename(path), 'apks': [], 'manifest': None, 'nsc': None, 'libraries': {}, 'frameworks': [],
           'native_libs': [], 'endpoints': [], 'dex_classes': 0, 'obfuscated': None, 'warnings': []}
    libs = Counter(); allclasses = 0; short_names = 0
    for label, z in iter_apks(path):
        res['apks'].append(label)
        names = z.namelist()
        for n in names:
            low = n.lower()
            for fw, (pre, sub) in FRAMEWORK_MARKERS:
                if n.startswith(pre) and sub in n and fw not in res['frameworks']: res['frameworks'].append(fw)
            if n.endswith('.so'): res['native_libs'].append(n)
        for n in names:
            info = z.getinfo(n)
            if info.is_dir() or info.file_size > MAX_FILE: continue
            low = n.lower()
            ext = os.path.splitext(low)[1]
            if ext in SKIP_EXT: continue
            try: data = z.read(n)
            except Exception: continue
            if n == 'AndroidManifest.xml':
                m = scan_manifest(data)
                if res['manifest'] is None or (m['package'] and not res['manifest']['package']) or label == res['apks'][0] and m['package']:
                    res['manifest'] = m
                for md in m['meta_data']:
                    if isinstance(md['value'], str): H.text(md['value'], 'manifest:meta-data')
                continue
            if re.match(r'classes\d*\.dex$', n) or (n.endswith('.dex') and data[:4] == b'dex\n'):
                try: d = Dex(data, label + ':' + n)
                except Exception as e:
                    res['warnings'].append('dex %s: %r' % (n, e)); continue
                try:
                    tn = d.class_names()
                    allclasses += len(tn)
                    for t in tn:
                        t2 = t[1:]
                        for pre, name in LIB_PREFIXES:
                            if t2.startswith(pre): libs[name] += 1; break
                        base = t2.rsplit('/', 1)[-1]
                        if len(base) <= 2: short_names += 1
                    for s in d.strs(): H.text(s, n, True)
                    res['endpoints'] += d.endpoints()
                except Exception as e:
                    res['warnings'].append('dex parse %s: %r' % (n, e))
                continue
            if low.startswith('res/xml') and ext == '.xml' and data[:2] == b'\x03\x00':
                nsc = scan_nsc(data)
                if nsc: res['nsc'] = nsc
                continue
            H.blob(data, n)
    res['dex_classes'] = allclasses
    res['obfuscated'] = bool(allclasses and short_names / allclasses > 0.35)
    res['libraries'] = dict(libs.most_common())
    res['native_libs'] = sorted(set(res['native_libs']))[:80]
    return res, H

def build_report(res, H):
    # hosts: from urls and bare strings
    hosts = defaultdict(lambda: {'urls': set(), 'sources': set(), 'port': set()})
    for u, src in H.urls.items():
        h, port = host_of(u)
        if not h or NOISE_HOSTS.search(h) or '.' not in h and h != 'localhost' or h.startswith('%') or '{' in h and '}' not in h: continue
        hosts[h]['urls'].add(u); hosts[h]['sources'] |= src
        if port: hosts[h]['port'].add(port)
    for h, src in H.hosts.items():
        hosts[h]['sources'] |= src
    ep_paths = {e['path'] for e in res['endpoints']}
    rows = []
    for h, v in hosts.items():
        third = bool(THIRD_PARTY.search(h))
        rows.append({'host': h, 'third_party': third, 'n_urls': len(v['urls']), 'ports': sorted(v['port']),
                     'schemes': sorted({u.split(':', 1)[0] for u in v['urls']}) or ['?'],
                     'sample_urls': sorted(v['urls'], key=len)[:12], 'sources': sorted(v['sources'])[:5]})
    rows.sort(key=lambda r: (r['third_party'], -r['n_urls'], r['host']))
    # base URL candidates: app-owned URLs ending in "/" or shallow path, prefer ones with api/v\d
    base = []
    for r in rows:
        if r['third_party']: continue
        for u in r['sample_urls']:
            if re.match(r'^(https?|wss?)://[^/]+(/[A-Za-z0-9_\-.]+){0,3}/?$', u): base.append(u)
    base = sorted(set(base), key=lambda u: (0 if re.search(r'api|v\d|rest|gql|graphql', u, re.I) else 1, len(u)))[:20]
    # endpoint group by class
    by_class = defaultdict(list)
    for e in res['endpoints']: by_class[e['class']].append(e)
    paths = sorted(p for p in H.paths if p not in ep_paths and p.lstrip('/') not in {x.lstrip('/') for x in ep_paths})
    sec = [{'kind': k, 'value': v, 'sources': sorted(s)[:3]} for (k, v), s in sorted(H.secrets.items())]
    rep = {
        'file': res['file'], 'apks': res['apks'], 'manifest': res['manifest'], 'network_security_config': res['nsc'],
        'frameworks': res['frameworks'], 'libraries': res['libraries'], 'obfuscated': res['obfuscated'],
        'dex_classes': res['dex_classes'], 'hosts': rows, 'base_url_candidates': base,
        'endpoints': res['endpoints'], 'other_path_strings': paths[:300], 'graphql_documents': sorted(H.gql)[:50],
        'cert_pins': sorted(H.pins)[:50], 'secrets_redacted': sec, 'native_libs': res['native_libs'], 'warnings': res['warnings'],
    }
    rep['verdict'] = verdict(rep)
    return rep

def verdict(r):
    v = []
    n_ep = len(r['endpoints'])
    own = [h for h in r['hosts'] if not h['third_party']]
    if n_ep: v.append('Retrofit endpoints recovered statically (%d) - high confidence for path/method/params' % n_ep)
    if own: v.append('%d app-owned hosts found in strings (confidence: string present, runtime use not proven)' % len(own))
    fw = r['frameworks']
    if 'Flutter (AOT code)' in fw or 'Flutter' in fw:
        v.append('Flutter: Dart code is in libapp.so (AOT) - Java-level hooks and system-CA MITM do NOT see its traffic; URLs above come from raw strings only')
    if 'React Native' in fw: v.append('React Native: endpoints live in assets/index.android.bundle - see other_path_strings / hosts sourced from it')
    if any(f.startswith('Unity') for f in fw): v.append('Unity: API logic is in C# (il2cpp metadata / Assembly-CSharp.dll); run dynamic capture, or dump with Il2CppDumper')
    if r['obfuscated']: v.append('Class names are obfuscated; Retrofit annotations survive R8 but service class names are mangled')
    if r['cert_pins']: v.append('Certificate pins present (%d) - dynamic MITM needs unpinning (frida script included)' % len(r['cert_pins']))
    nsc = r['network_security_config']; m = r['manifest'] or {}
    if m.get('application', {}).get('usesCleartextTraffic') is True: v.append('usesCleartextTraffic=true')
    if not n_ep and not own: v.append('Little static signal: run dynamic capture (android_api_dynamic.yml)')
    return v

def to_md(r):
    L = []
    m = r['manifest'] or {}
    L.append('# apiscan: %s' % r['file'])
    L.append('package=%s version=%s (%s) minSdk=%s targetSdk=%s apks=%s' % (m.get('package'), m.get('versionName'), m.get('versionCode'), m.get('minSdk'), m.get('targetSdk'), len(r['apks'])))
    if r['frameworks']: L.append('frameworks: ' + ', '.join(r['frameworks']))
    if r['libraries']: L.append('libraries: ' + ', '.join('%s(%d)' % kv for kv in list(r['libraries'].items())[:25]))
    L.append('obfuscated: %s, classes: %d' % (r['obfuscated'], r['dex_classes']))
    L.append('\n## verdict'); L += ['- ' + x for x in r['verdict']]
    if r['base_url_candidates']:
        L.append('\n## base URL candidates'); L += ['- ' + u for u in r['base_url_candidates']]
    own = [h for h in r['hosts'] if not h['third_party']]; third = [h for h in r['hosts'] if h['third_party']]
    L.append('\n## app hosts (%d)' % len(own))
    for h in own[:60]:
        L.append('- %s  [%s] n=%d  %s' % (h['host'], ','.join(h['schemes']), h['n_urls'], ' | '.join(h['sample_urls'][:3])))
    L.append('\n## third-party hosts (%d): ' % len(third) + ', '.join(h['host'] for h in third[:60]))
    if r['endpoints']:
        L.append('\n## endpoints (%d)' % len(r['endpoints']))
        cur = None
        for e in sorted(r['endpoints'], key=lambda e: (e['class'], e['path'])):
            if e['class'] != cur: cur = e['class']; L.append('\n### ' + cur)
            ps = ', '.join('%s%s:%s' % (p['in'] if p['in'] != '?' else '', '(%s)' % p['name'] if p['name'] else '', p['type']) for p in e['params'])
            extra = (' H=' + ';'.join(e['headers'])) if e['headers'] else ''
            extra += (' ' + ','.join(e['flags'])) if e['flags'] else ''
            L.append('- `%s %s`  %s(%s) -> %s%s' % (e['http'], e['path'], e['method'], ps, e['returns'], extra))
    if r['other_path_strings']:
        L.append('\n## other path-like strings (%d, first 80)' % len(r['other_path_strings']))
        L += ['- ' + p for p in r['other_path_strings'][:80]]
    if r['graphql_documents']:
        L.append('\n## graphql documents'); L += ['- `%s`' % g.replace('\n', ' ')[:200] for g in r['graphql_documents'][:20]]
    if r['cert_pins']: L.append('\n## cert pins\n' + '\n'.join('- ' + p for p in r['cert_pins'][:20]))
    nsc = r['network_security_config']
    if nsc: L.append('\n## network_security_config\n```json\n%s\n```' % json.dumps(nsc, indent=1))
    if m.get('deeplinks'):
        L.append('\n## deep links'); L += ['- %s://%s%s%s (%s)' % (d.get('scheme'), d.get('host', '*'), d.get('pathPrefix', d.get('path', '')), d.get('pathPattern', ''), d['component']) for d in m['deeplinks'][:30]]
    md = [x for x in m.get('meta_data', []) if x.get('value') is not None and re.search(r'(?i)key|id|token|secret|url|api|dsn|client', x.get('name') or '')]
    if md: L.append('\n## manifest meta-data (key-ish)'); L += ['- %s = %s' % (x['name'], redact(str(x['value'])) if re.search(r'(?i)key|secret|token', x['name']) else x['value']) for x in md[:30]]
    if r['secrets_redacted']:
        L.append('\n## secrets (redacted)'); L += ['- %s: %s  (%s)' % (s['kind'], s['value'], ', '.join(s['sources'])) for s in r['secrets_redacted'][:40]]
    perms = [p for p in m.get('permissions', []) if p]
    if perms: L.append('\n## permissions\n' + ', '.join(p.replace('android.permission.', '') for p in perms))
    if r['warnings']: L.append('\n## warnings\n' + '\n'.join('- ' + w for w in r['warnings']))
    return '\n'.join(L) + '\n'

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('apk'); ap.add_argument('-o', '--out', help='output dir for apiscan.json / apiscan.md')
    ap.add_argument('--json', action='store_true', help='print JSON instead of markdown')
    a = ap.parse_args()
    res, H = scan(a.apk)
    rep = build_report(res, H)
    md = to_md(rep)
    if a.out:
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, 'apiscan.json'), 'w') as f: json.dump(rep, f, indent=1, default=list)
        with open(os.path.join(a.out, 'apiscan.md'), 'w') as f: f.write(md)
    sys.stdout.write(json.dumps(rep, indent=1, default=list) if a.json else md)

if __name__ == '__main__':
    main()
