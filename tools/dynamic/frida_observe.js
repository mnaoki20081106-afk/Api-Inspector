'use strict';
/*
 * Passive, read-only logging of network-shaped calls at the Java layer.
 * Hooks nothing that affects TLS trust or certificate validation - it only observes
 * arguments to URL/OkHttp/WebView/DNS entry points and reports them to the host.
 * Useful to catch traffic a system/user-CA-aware proxy capture misses (e.g. native
 * sockets, or to confirm which library actually issued a given request).
 */
function log(o) { send(o); }

Java.perform(function () {
  function tryHook(name, fn) {
    try { fn(); log({ t: 'hook', ok: name }); }
    catch (e) { log({ t: 'hook', fail: name, err: String(e) }); }
  }

  tryHook('java.net.URL.openConnection', function () {
    var URL = Java.use('java.net.URL');
    var open = URL.openConnection.overload();
    open.implementation = function () {
      log({ t: 'java', k: 'url', v: this.toString() });
      return open.call(this);
    };
  });

  tryHook('java.net.InetAddress.getAllByName', function () {
    var InetAddress = Java.use('java.net.InetAddress');
    var resolve = InetAddress.getAllByName.overload('java.lang.String');
    resolve.implementation = function (host) {
      log({ t: 'java', k: 'dns', v: host });
      return resolve.call(this, host);
    };
  });

  tryHook('okhttp3.Request$Builder.build', function () {
    var Builder = Java.use('okhttp3.Request$Builder');
    var build = Builder.build.overload();
    build.implementation = function () {
      var req = build.call(this);
      try { log({ t: 'java', k: 'okhttp', v: req.method() + ' ' + req.url().toString() }); } catch (_) {}
      return req;
    };
  });

  tryHook('android.webkit.WebView.loadUrl', function () {
    var WebView = Java.use('android.webkit.WebView');
    var load = WebView.loadUrl.overload('java.lang.String');
    load.implementation = function (url) {
      log({ t: 'java', k: 'webview', v: url });
      return load.call(this, url);
    };
  });

  tryHook('android.webkit.WebView.postUrl', function () {
    var WebView = Java.use('android.webkit.WebView');
    var post = WebView.postUrl.overload('java.lang.String', '[B');
    post.implementation = function (url, data) {
      log({ t: 'java', k: 'webview_post', v: url });
      return post.call(this, url, data);
    };
  });

  log({ t: 'ready' });
});
