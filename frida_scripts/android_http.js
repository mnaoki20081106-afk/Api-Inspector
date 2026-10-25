'use strict';
/**
 * android_http.js -- TikTok Lite API interceptor
 *
 * Hooks (in priority order):
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
