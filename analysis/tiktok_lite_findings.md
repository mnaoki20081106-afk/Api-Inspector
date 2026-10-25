# TikTok Lite (com.zhiliaoapp.musically.go) — Dynamic Analysis Findings

**APK SHA256:** `ac29ea53fe725ec9837bbccf6d7782d82d97bb75f864eecba69f50c4e94ea1d1`  
**Method:** Frida 16.5.9, spawn mode, x86_64 Android 29 emulator (GitHub Actions)  
**Runs completed:** 22  
**Date:** 2026-10-25

---

## Captured HTTP Endpoints

| Host | Path | Notes |
|------|------|-------|
| `api16.tiktokv.com` | `/lite/v2/decompression/report/` | Boot telemetry |
| `mon-boot.tiktokv.com` | `/monitor/appmonitor/v3/settings?update_version_code=4020130&...` | App monitor settings |
| `dv9cjr-cdn-settings.appsflyersdk.com` | `/android/v1/<hash>/settings` | AppsFlyer SDK config |
| `dv9cjr-dlsdk.appsflyersdk.com` | `/v1.0/android/com.zhiliaoapp.musically.go?af_sig=<sig>` | AppsFlyer deep link SDK |
| `dv9cjr-conversions.appsflyersdk.com` | `/api/v6.14/androidevent?app_id=com.zhiliaoapp.musically.go` | AppsFlyer conversion events |
| `dv9cjr-gcdsdk.appsflyersdk.com` | `/install_data/v5.0/com.zhiliaoapp.musically.go?device_id=<id>` | AppsFlyer install data |
| `tnc16-normal-useast5.tiktokv.us` | `/get_domains/v5/` | Domain config fetch |
| `firebaseinstallations.googleapis.com` | `/v1/projects/musically-lite-go/installations` | Firebase install registration |

**Not captured (target data):** `u_code`, `share_page_data` Map keys, coin/reward API endpoints  
Reason: app crashes during boot init before reaching invite/attribution code paths.

---

## Native Crash Chain (x86_64 emulator, ARM libs stripped)

Each run progressed further as crashes were fixed. Fixes applied in order:

| Fix # | Class | Method | Strategy |
|-------|-------|--------|----------|
| 1 | `com.ss.android.ugc.aweme.sec.SecApiImpl` | `initSec()` | Neuter call site (avoids `ms.bd.o.k.a` obfuscated native) |
| 2 | `com.tiktok.ttm.TTMCore$JNIHelper` | `init()` | Targeted no-op |
| 3 | `com.ss.android.ugc.aweme.creativetool.nativeab.NativeABManager` | `nativeInit()` | Targeted no-op |
| 4 | `X.8mf` (obfuscated) | `onLoadNativeLibs()` | Neuter VESDK native load entry point |
| 5-10 | `com.ss.android.vesdklite.log.LELogcat` | all native methods | Batch reflection stub |
| 5-10 | `com.ss.android.vesdklite.moniter.ApplogUtilsInvoker` | all native methods | Batch reflection stub |
| 5-10 | `com.ss.android.vesdklite.utils.VEUtilsLite` | all native methods | Batch reflection stub |
| 5-10 | `com.ss.android.vesdklite.log.LELog2ClientInvoker` | all native methods | Batch reflection stub |

**Current blocker (Run 22):** Still encountering new VESDK/native class crashes during boot.

---

## Key Technical Findings

### Network Stack
- TikTok Lite uses **Cronet/QUIC**, not OkHttp3
- All OkHttp3 hooks (`RealInterceptorChain`, `RealCall`) fail with `ClassNotFoundException`
- `java.net.URL.openConnection` is the working capture path for boot-phase requests

### Attribution SDK
- AppsFlyer SDK present and making network calls to 4 distinct AF subdomains
- `ShareInviteHelper.logInvite` hook armed but never fired (app doesn't reach invite screens)
- `AFb1gSDK.onAttributionDataReceived` hook armed but never fired
- AF conversion event endpoint confirmed: `dv9cjr-conversions.appsflyersdk.com/api/v6.14/androidevent`

### Security / Anti-tamper
- `com.ss.android.ugc.aweme.sec.SecApiImpl.initSec()` → ByteDance security SDK init
- Leads to obfuscated class `ms.bd.o.k.a` which has ARM-only native impl
- Must be neutered before any meaningful app execution on x86_64

### VESDK (Video Edit SDK)
- `com.ss.android.vesdklite.*` has extensive native method surface across multiple classes
- All require ARM native libs; batch-stubbing via reflection is the only scalable approach
- Classes discovered crashing (in order): `LELogcat`, `ApplogUtilsInvoker`, `VEUtilsLite`, `LELog2ClientInvoker`

---

## Frida Script

See [`frida_scripts/android_http.js`](../frida_scripts/android_http.js)

**Hook architecture:**
```
-1. Universal native-method stub (reflection-based, per-class batch)
 0. Runtime.load0 / loadLibrary0  (suppress UnsatisfiedLinkError)
 1. ClassLoader.loadClass          (event-driven native stub trigger)
 2. Targeted fixes #1-4           (specific crasher classes)
 3. VESDK batch stubs #5-10       (com.ss.android.vesdklite.*)
 4. java.net.URL.openConnection   (Cronet/legacy HTTP capture)
 5. ShareInviteHelper.logInvite   (invite params / u_code)
 6. AppsFlyer logEvent            (attribution events)
 7. AFb1gSDK.onAttributionDataReceived (u_code from attribution callback)
```

---

## Static Analysis Findings (prior session, ~92% complete)

### Referral/Invite Flow
- `com.appsflyer.share.ShareInviteHelper.logInvite(Context, String channel, Map<String,String> params)` — the primary invite logging call
- Map keys expected to include: `u_code` (referral code), `share_page_data` (page context)
- Confirmed via static analysis; dynamic confirmation blocked by boot crash loop

### Coin/Reward API
- Reward-related endpoints likely under `api16.tiktokv.com` or `api-normal-useast5.tiktokv.us`
- Specific paths not yet dynamically confirmed
- Static analysis suggested paths under `/aweme/v1/` namespace

---

## Analysis Limitations

1. **ARM-only natives on x86_64 emulator** — the fundamental blocker. Stripping ARM64 libs to install on x86_64 creates a cascade of missing native implementations. Each fix uncovers the next crasher.

2. **No UI automation** — even if the boot crash loop is resolved, invite/referral screens require user interaction (navigating to profile → invite friends) that hasn't been automated.

3. **Cronet/QUIC** — standard OkHttp hooks don't work. URL.openConnection captures pre-connection URLs but not full request/response bodies for QUIC traffic.

---

## Recommended Next Steps

**Option A (continue current approach):** Keep adding VESDK class names to the batch stub list until boot completes. Risk: more classes may appear; no known ceiling.

**Option B (ARM64 emulator):** Use an `arm64-v8a` emulator image (e.g. `reactivecircus/android-emulator-runner` with `arch: arm64`). Native libs run natively, eliminating the entire crash chain. Slower emulation but far fewer hooks needed.

**Option C (rooted physical device / ADB):** Run on a real ARM64 device with Frida server. Fastest path to the actual invite flow with real AF callbacks.

**Option D (network proxy only):** Use mitmproxy/Burp with certificate pinning bypass instead of Frida. Captures HTTP(S) traffic without needing to survive the boot init chain.
