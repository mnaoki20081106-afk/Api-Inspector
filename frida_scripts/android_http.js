'use strict';
/**
 * android_http.js -- TikTok Lite API interceptor
 *
 * Hooks (in priority order):
 * -1. Universal native-method stub (prevents crash after ARM libs stripped)
 *  0. Runtime.load0 / loadLibrary0  (suppress JNI errors -> pure-Java mode)
 *  1. okhttp3.internal.http.RealInterceptorChain.proceed  (all OkHttp3 calls)
 *  2. okhttp3.RealCall / okhttp3.internal.connection.RealCall (sync calls)
 *  3. okhttp3.OkHttpClient.newCall  (URL logger fallback)
 *  4. java.net.URL.openConnection   (Cronet / legacy)
 *  5. com.appsflyer.share.ShareInviteHelper (invite link params)
 *  6. AppsFlyer logEvent            (attribution events)
 *  7. AFb1gSDK.onAttributionDataReceived (u_code from attribution)
 *
 * Output format: [HTTP] >> METHOD URL | [HTTP] << CODE URL | [AF] event
 */

Java.perform(function () {
  var TAG = '[HTTP]';

  // -- -1. Universal native-method stub ---------------------------------------
  // ARM libs are stripped from the APK so the x86_64 emulator has no native
  // implementations. Once loadLibrary errors are suppressed (step 0), the VM
  // still throws "No implementation found for native method" the first time
  // any native-modifier Java method is actually invoked, which kills the app
  // mid-init before it reaches any network/attribution code. Fix: walk every
  // loaded class, find native methods via real Java reflection, and replace
  // each with a stub that returns a default value for its declared type.
  var stubbedNative = {};
  function stubNativeMethods(className) {
    if (stubbedNative[className]) return;
    stubbedNative[className] = true;
    try {
      var JClass = Java.use(className).class;
      var methods = JClass.getDeclaredMethods();
      for (var i = 0; i < methods.length; i++) {
        var m = methods[i];
        var mods = m.getModifiers();
        // java.lang.reflect.Modifier.NATIVE == 0x100
        if ((mods & 0x100) === 0) continue;
        var mname = m.getName();
        var retType = m.getReturnType().getName();
        try {
          var W = Java.use(className);
          var overloads = W[mname].overloads;
          overloads.forEach(function (ol) {
            ol.implementation = function () {
              switch (retType) {
                case 'void': return undefined;
                case 'boolean': return false;
                case 'byte': case 'short': case 'int': case 'char': return 0;
                case 'long': return 0;
                case 'float': case 'double': return 0.0;
                default: return null; // Object / String / array
              }
            };
          });
          console.log('[STUB] native ' + className + '.' + mname +
            ' -> default ' + retType);
        } catch (e3) {
          // overload resolution failed for this one method; skip it
        }
      }
    } catch (e) {
      // class not Java.use-able (e.g. interface, primitive) - ignore
    }
  }

  // Exclude ART/system/framework packages: they have real native impls
  // already resident in the VM, and stubbing them would break the runtime
  // itself. Everything else (app code, vendor SDKs, obfuscated packages
  // like ms.bd.*, X.*, etc.) is a candidate - TikTok's crashing native
  // method lives in ms.bd.o.k, which no fixed prefix list would predict.
  var SYSTEM_PREFIXES = [
    'android.', 'androidx.', 'java.', 'javax.', 'dalvik.', 'sun.',
    'libcore.', 'kotlin.', 'kotlinx.', 'com.android.', 'org.apache.',
    'org.json.', 'okio.', 'org.xml.', 'org.w3c.', 'junit.', 'org.chromium.'
  ];
  function isSystemClass(cn) {
    for (var i = 0; i < SYSTEM_PREFIXES.length; i++) {
      if (cn.indexOf(SYSTEM_PREFIXES[i]) === 0) return true;
    }
    return false;
  }

  function scanLoadedClassesForNatives() {
    try {
      Java.enumerateLoadedClassesSync().forEach(function (cn) {
        if (!isSystemClass(cn)) {
          stubNativeMethods(cn);
        }
      });
    } catch (e) {
      console.log('[STUB] scan failed: ' + e);
    }
  }

  // Event-driven catch attempt: hook ClassLoader.loadClass so every class
  // load is stubbed the instant it resolves. NOTE: confirmed in Run 8 this
  // does NOT catch ms.bd.o.k - ART's ClassLinker resolves most implicit
  // class references directly from the dex without ever calling the public
  // loadClass() method, so this hook only helps for explicit Class.forName
  // style lookups. Kept as a best-effort layer; see the targeted fixes below
  // for the actual crashers found so far.
  try {
    var CL = Java.use('java.lang.ClassLoader');
    CL.loadClass.overloads.forEach(function (ol) {
      ol.implementation = function () {
        var cls = ol.apply(this, arguments);
        try {
          var name = arguments[0];
          if (typeof name === 'string' && !isSystemClass(name)) {
            stubNativeMethods(name);
          }
        } catch (eL) {}
        return cls;
      };
    });
    console.log('[Frida] ClassLoader.loadClass hooked (event-driven native stub)');
  } catch (eCL) {
    console.log('[Frida] ClassLoader.loadClass hook failed: ' + eCL);
  }

  // Targeted fix for the confirmed crasher: ms.bd.o.k.a is reached only via
  // com.ss.android.ugc.aweme.sec.SecApiImpl.initSec(). Rather than chase the
  // obfuscated native class (ART resolves it before any Java-level hook can
  // intervene), neuter initSec itself so the call chain never reaches the
  // native method at all. This is ByteDance's security/anti-tamper SDK init,
  // not anything needed for the invite/attribution flow we're after.
  try {
    var SecApi = Java.use('com.ss.android.ugc.aweme.sec.SecApiImpl');
    SecApi.initSec.overloads.forEach(function (ol) {
      ol.implementation = function () {
        console.log('[STUB] skipped SecApiImpl.initSec (avoids ms.bd.o.k.a native crash)');
        return undefined;
      };
    });
    console.log('[Frida] SecApiImpl.initSec neutered');
  } catch (eSec) {
    console.log('[Frida] SecApiImpl.initSec hook failed: ' + eSec);
  }

  // Run 9: SecApiImpl.initSec bypass worked - app progressed further, then
  // crashed on a different native init: com.tiktok.ttm.TTMCore$JNIHelper.init,
  // called from PumbaaTask (a Lego background task) during TTM (template
  // manager) setup. Unlike ms.bd.o.k this is a plain, non-obfuscated nested
  // class name, so hook it directly by name instead of relying on the
  // generic scanner (which may still lose the race on background threads).
  try {
    var TTMHelper = Java.use('com.tiktok.ttm.TTMCore$JNIHelper');
    TTMHelper.init.overloads.forEach(function (ol) {
      ol.implementation = function () {
        console.log('[STUB] skipped TTMCore$JNIHelper.init (native TTM init)');
        return undefined;
      };
    });
    console.log('[Frida] TTMCore$JNIHelper.init neutered');
  } catch (eTTM) {
    console.log('[Frida] TTMCore$JNIHelper.init hook failed: ' + eTTM);
  }

  // Run 11: app progressed well past the previous two crashers (JNI ref
  // overflow fixed), reached DFServiceInitTask (dynamic feature module init)
  // and crashed on com.ss.android.ugc.aweme.creativetool.nativeab
  // .NativeABManager.nativeInit - creative-tool A/B flag native init,
  // unrelated to invite/attribution. Same pattern: neuter the one Java
  // call site directly.
  try {
    var NativeAB = Java.use('com.ss.android.ugc.aweme.creativetool.nativeab.NativeABManager');
    NativeAB.nativeInit.overloads.forEach(function (ol) {
      ol.implementation = function () {
        console.log('[STUB] skipped NativeABManager.nativeInit');
        return undefined;
      };
    });
    console.log('[Frida] NativeABManager.nativeInit neutered');
  } catch (eNAB) {
    console.log('[Frida] NativeABManager.nativeInit hook failed: ' + eNAB);
  }

  // Run 12: NativeABManager fix worked, but the very same DFServiceInitTask
  // chain (CreativeToolImpl's native video-editing SDK init) hit yet another
  // native method: com.ss.android.vesdklite.log.LELogcat.nativeLog - just a
  // native logger call. This whole dynamic-feature module (video creative
  // tools/camera/editor) is unrelated to the invite/attribution/coin flow
  // we're tracing and is clearly riddled with native inits. Rather than
  // whack-a-mole each one, neuter the task that starts the whole chain:
  // DFServiceInitTask.run(). Skips CreativeToolImpl init (and everything
  // under it: NativeABManager, LELogcat, etc.) in one hook.
  try {
    var DFTask = Java.use('com.ss.android.ugc.aweme.aab.modules.DFServiceInitTask');
    DFTask.run.overloads.forEach(function (ol) {
      ol.implementation = function () {
        console.log('[STUB] skipped DFServiceInitTask.run (video-editing SDK init, unrelated to invite flow)');
        return undefined;
      };
    });
    console.log('[Frida] DFServiceInitTask.run neutered');
  } catch (eDF) {
    console.log('[Frida] DFServiceInitTask.run hook failed: ' + eDF);
  }

  // Run 10: the broad scanner above crashed the app a different way -
  // JNI ERROR (app bug): global reference table overflow (max=51200).
  // Java.use() on every non-system class, re-run every 200ms for 120s,
  // accumulates global refs faster than the table can hold alongside the
  // app's own normal classloading. Both real native crashes (ms.bd.o.k,
  // TTMCore$JNIHelper) are now handled by targeted named hooks above, which
  // cost one Java.use() each instead of thousands, so disable the broad
  // scan entirely rather than tune its rate - any further crasher gets
  // diagnosed from the log and added above by name, the same way.
  // scanLoadedClassesForNatives(); -- disabled, see note above
  // var scanTimer = setInterval(scanLoadedClassesForNatives, 200); -- disabled

  // -- helpers ----------------------------------------------------------------
  function logReq(method, url, req) {
    console.log(TAG + ' >> ' + method + ' ' + url);
    var HDRS = [
      'X-Gorgon', 'X-Argus', 'X-Ladon', 'X-Khronos', 'X-Tython',
      'X-SS-Req-Ticket', 'X-Vc-Bdturing-Sdk-Version',
      'Content-Type', 'User-Agent', 'Authorization',
      'tt-ticket-guard-public-key', 'tt-ticket-guard-version'
    ];
    HDRS.forEach(function (h) {
      try {
        var v = req.header(h);
        if (v) console.log(TAG + '    ' + h + ': ' + String(v).slice(0, 120));
      } catch (_) {}
    });
  }

  function logResp(code, url, resp) {
    console.log(TAG + ' << ' + code + ' ' + url);
    try {
      var ct = resp.header('Content-Type') || '';
      if (ct.indexOf('json') >= 0) {
        var body = resp.peekBody(4096).string();
        console.log(TAG + '    body: ' + String(body).slice(0, 500));
      }
    } catch (_) {}
  }

  // -- 0. Suppress JNI load errors -------------------------------------------
  // ARM libs stripped from APK -> UnsatisfiedLinkError on every loadLibrary call.
  // Catch and swallow so Java bytecode keeps executing on x86_64 emulator.
  try {
    var Runtime = Java.use('java.lang.Runtime');
    ['load0', 'loadLibrary0'].forEach(function (meth) {
      try {
        Runtime[meth].overloads.forEach(function (ol) {
          ol.implementation = function () {
            var name = arguments[arguments.length - 1];
            try {
              return ol.apply(this, arguments);
            } catch (e) {
              console.log('[LOAD] suppressed ' + name + ': ' + e.message);
            }
          };
        });
      } catch (e2) {}
    });
    console.log('[Frida] Runtime.load* hooks armed (JNI suppression active)');
  } catch (e) {
    console.log('[Frida] Runtime.load* failed: ' + e);
  }

  // -- 1. RealInterceptorChain.proceed ----------------------------------------
  var ric_hooked = false;
  try {
    var RIC = Java.use('okhttp3.internal.http.RealInterceptorChain');
    RIC.proceed.overloads.forEach(function (ol) {
      ol.implementation = function () {
        var req = arguments[0];
        var url = req.url().toString();
        logReq(req.method(), url, req);
        var resp = ol.apply(this, arguments);
        logResp(resp.code(), url, resp);
        return resp;
      };
    });
    ric_hooked = true;
    console.log('[Frida] RealInterceptorChain hooked (' +
      RIC.proceed.overloads.length + ' overloads)');
  } catch (e) {
    console.log('[Frida] RIC failed: ' + e);
  }

  // -- 2a. okhttp3.RealCall (OkHttp3 < 4.x) -----------------------------------
  if (!ric_hooked) {
    try {
      var RC3 = Java.use('okhttp3.RealCall');
      RC3.execute.implementation = function () {
        var req = this.originalRequest.value;
        var url = req.url().toString();
        logReq(req.method(), url, req);
        var resp = this.execute();
        logResp(resp.code(), url, resp);
        return resp;
      };
      console.log('[Frida] RealCall3.execute hooked');
    } catch (e) {
      console.log('[Frida] RealCall3 failed: ' + e);
    }

    // -- 2b. okhttp3.internal.connection.RealCall (OkHttp3 4.x) ---------------
    try {
      var RC4 = Java.use('okhttp3.internal.connection.RealCall');
      RC4.execute.implementation = function () {
        var req;
        try { req = this.request$.value; } catch (_) {
          try { req = this.originalRequest.value; } catch (__) { req = null; }
        }
        var url = req ? req.url().toString() : '(unknown)';
        if (req) logReq(req.method(), url, req);
        var resp = this.execute();
        logResp(resp.code(), url, resp);
        return resp;
      };
      console.log('[Frida] RealCall4.execute hooked');
    } catch (e) {
      console.log('[Frida] RealCall4 failed: ' + e);
    }
  }

  // -- 3. OkHttpClient.newCall (URL catch-all) --------------------------------
  try {
    var OHC = Java.use('okhttp3.OkHttpClient');
    OHC.newCall.implementation = function (req) {
      console.log(TAG + ' newCall ' + req.url().toString());
      return this.newCall(req);
    };
    console.log('[Frida] OkHttpClient.newCall hooked');
  } catch (e) {
    console.log('[Frida] OkHttpClient.newCall failed: ' + e);
  }

  // -- 4. java.net.URL.openConnection (legacy / Cronet) ----------------------
  try {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function () {
      var s = this.toString();
      if (s.indexOf('http') === 0) console.log(TAG + ' URLConn ' + s);
      return this.openConnection();
    };
    console.log('[Frida] URL.openConnection hooked');
  } catch (e) {
    console.log('[Frida] URL.openConnection failed: ' + e);
  }

  // -- 5. ShareInviteHelper (invite link params -> u_code etc.) --------------
  try {
    var SIH = Java.use('com.appsflyer.share.ShareInviteHelper');
    SIH.logInvite.implementation = function (ctx, channel, map) {
      console.log('[AF] logInvite channel=' + channel);
      try {
        var iter = map.entrySet().iterator();
        while (iter.hasNext()) {
          var entry = iter.next();
          console.log('[AF]   ' + entry.getKey() + ' = ' + entry.getValue());
        }
      } catch (e2) {
        console.log('[AF]   map: ' + map.toString());
      }
      return this.logInvite(ctx, channel, map);
    };
    console.log('[Frida] ShareInviteHelper.logInvite hooked');
  } catch (e) {
    console.log('[Frida] ShareInviteHelper failed: ' + e);
  }

  // -- 6. AppsFlyer logEvent (attribution + invite events) ------------------
  var afClasses = [
    'com.appsflyer.internal.AFb1vSDK',
    'com.appsflyer.AppsFlyerLib'
  ];
  afClasses.forEach(function (cls) {
    try {
      var AF = Java.use(cls);
      AF.logEvent.overloads.forEach(function (ol) {
        ol.implementation = function () {
          try {
            var parts = [];
            for (var i = 0; i < arguments.length; i++) {
              parts.push(String(arguments[i]).slice(0, 200));
            }
            console.log('[AF] logEvent: ' + parts.join(' | '));
          } catch (_) {}
          return ol.apply(this, arguments);
        };
      });
      console.log('[Frida] ' + cls + '.logEvent hooked');
    } catch (e) {
      console.log('[Frida] ' + cls + ' logEvent failed: ' + e);
    }
  });

  // -- 7. AppsFlyer onAttributionDataReceived (u_code from attribution) -----
  try {
    var AFb = Java.use('com.appsflyer.internal.AFb1gSDK');
    AFb.onAttributionDataReceived.overloads.forEach(function (ol) {
      ol.implementation = function () {
        try {
          var parts = [];
          for (var i = 0; i < arguments.length; i++) {
            parts.push(String(arguments[i]).slice(0, 300));
          }
          console.log('[AF] onAttributionDataReceived: ' + parts.join(' | '));
        } catch (_) {}
        return ol.apply(this, arguments);
      };
    });
    console.log('[Frida] AFb1gSDK.onAttributionDataReceived hooked');
  } catch (e) {
    console.log('[Frida] AFb1gSDK hook failed: ' + e);
  }

  console.log('[Frida] All hooks armed. Waiting for traffic...');
});
