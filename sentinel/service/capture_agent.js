// Native HTTP capture agent for Sentinel's "Capture to Requests (no proxy)" mode.
//
// Loaded by the frida CLI (which bundles a working Java bridge — the in-process
// python binding cannot, on frida 17). It hooks the app's own HTTP layer and
// prints one line per request as:
//     @@REQ@@ {"method":"GET","url":"https://...","via":"tigon"}
// frida_svc reads those lines and feeds them to reqmon, so decrypted requests
// show up in the Requests tab with no proxy, no CA, and the app untouched.
//
// Covers Meta/Instagram/Facebook (Tigon) and the common OkHttp stack; both are
// best-effort and wrapped, so a missing class never stops the others.
'use strict';

function emit(obj) { try { console.log('@@REQ@@ ' + JSON.stringify(obj)); } catch (e) {} }
function info(m) { try { console.log('@@INFO@@ ' + m); } catch (e) {} }

function hookTigon() {
  var any = false;
  ['com.facebook.tigon.TigonXplatService', 'com.facebook.tigon.javaservice.JavaBackedTigonService']
    .forEach(function (cn) {
      var C;
      try { C = Java.use(cn); } catch (e) { return; }
      var methods;
      try { methods = C.class.getDeclaredMethods(); } catch (e) { return; }
      methods.forEach(function (m) {
        var ps = m.getParameterTypes();
        if (!(ps.length && ps[0].getName().indexOf('TigonRequest') >= 0)) return;
        var name = m.getName();
        try {
          C[name].overloads.forEach(function (ov) {
            ov.implementation = function () {
              try {
                var req = arguments[0];
                if (req && req.url) {
                  emit({ method: '' + req.method(), url: '' + req.url(), via: 'tigon' });
                }
              } catch (e) {}
              return ov.apply(this, arguments);
            };
          });
          any = true;
        } catch (e) {}
      });
    });
  if (any) info('hooked Tigon');
  return any;
}

function hookOkHttp() {
  // okhttp3.Request carries method()+url(); RealCall.execute/enqueue runs one.
  var ok = false;
  try {
    var RealCall = Java.use('okhttp3.RealCall');
    var grab = function (call) {
      try {
        var r = call.request();
        emit({ method: '' + r.method(), url: '' + r.url().toString(), via: 'okhttp' });
      } catch (e) {}
    };
    try { RealCall.execute.implementation = function () { grab(this); return this.execute(); }; ok = true; } catch (e) {}
    try {
      RealCall.enqueue.implementation = function (cb) { grab(this); return this.enqueue(cb); };
      ok = true;
    } catch (e) {}
  } catch (e) {}
  if (ok) info('hooked OkHttp');
  return ok;
}

function hookUrlConn() {
  // java.net HttpURLConnection (and the android.com.squareup shade) — getInputStream fires the request.
  var ok = false;
  ['com.android.okhttp.internal.huc.HttpURLConnectionImpl',
   'com.android.okhttp.internal.huc.DelegatingHttpsURLConnection'].forEach(function (cn) {
    try {
      var C = Java.use(cn);
      C.getInputStream.implementation = function () {
        try { emit({ method: '' + this.getRequestMethod(), url: '' + this.getURL().toString(), via: 'huc' }); } catch (e) {}
        return this.getInputStream();
      };
      ok = true;
    } catch (e) {}
  });
  if (ok) info('hooked HttpURLConnection');
  return ok;
}

var _tigon = false, _rest = false;
function runTigon() {
  if (_tigon) return;
  Java.perform(function () { if (hookTigon()) { _tigon = true; info('capture active'); } });
}
function runRest() {
  // OkHttp / HttpURLConnection installed separately and later, so if hooking one
  // of them is unhappy on a given app it cannot take the Tigon hook down with it.
  if (_rest) return;
  Java.perform(function () {
    var b = hookOkHttp(), c = hookUrlConn();
    if (b || c) { _rest = true; if (!_tigon) info('capture active'); }
  });
}
// Tigon first (the Meta path, proven stable); give ART time to settle on attach.
setTimeout(runTigon, 1500);
setTimeout(runTigon, 4000);
setTimeout(runRest, 6000);
setTimeout(runRest, 10000);
