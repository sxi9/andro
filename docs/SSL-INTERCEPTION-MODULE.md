# SSL Interception & Unpinning — module plan

> **Authorized use only.** This module exists to intercept the HTTPS traffic
> of an app you are allowed to test (a bug-bounty program's in-scope app, a
> client engagement, or your own app) on a device you own. It is gated behind
> an open **Engagement** (see `PENTEST-PLATFORM-PLAN.md`, Phase 0): the target
> package must be in scope, and every step is written to the audit log. As the
> Bugcrowd note says, the bypass itself is usually a P5/informational finding —
> its value is unlocking the API for real testing.

Target device for reference: Xiaomi M2101K6P, **Android 14 (SDK 34)**, rooted
(Magisk/KernelSU/APatch). Android 14 is the important case: the system trust
store is served from the Conscrypt **APEX** (`/apex/com.android.conscrypt/
cacerts`), so a certificate copied into `/system/etc/security/cacerts` is
*not* trusted until the APEX view is overlaid. The module handles that.

There are two independent problems; the module does both and reports which an
app needs:

1. **Trust** — make the proxy's CA trusted by the app (defeats apps that use
   the system trust store and don't pin).
2. **Pinning** — defeat an app that pins to a specific cert/key regardless of
   the trust store (needs runtime instrumentation).

---

## Part A — Device trust & proxy (reuses the root/su + ADB planes)

### A1. Proxy wiring
Pick per target; expose all three in the UI:
- **Global proxy**: `settings put global http_proxy <host>:<port>` (clears with
  `:0`). Simplest; many apps honor it. WiFi-proxy equivalent as a fallback.
- **Per-app transparent redirect** (for apps that ignore the global proxy,
  **including Flutter** apps, which use BoringSSL and ignore the system proxy):
  `iptables`/`nat OUTPUT -m owner --uid-owner <uid> -p tcp --dport 443/80 -j
  DNAT --to <host>:<mitmport>` with mitmproxy in **transparent** mode. Scoped
  to the one target uid, reverted on stop. Reuses the uid resolution and the
  iptables helper already written for the firewall action.
- **Reachability check**: confirm the device can reach `<host>:<port>` and that
  the proxy is up before declaring success.

### A2. CA install (version-aware)
Operator supplies the proxy CA (upload the Burp/mitmproxy PEM, or Sentinel
fetches mitmproxy's `~/.mitmproxy/mitmproxy-ca-cert.cer`).
- Compute the legacy subject hash (`openssl x509 -subject_hash_old -in ca.pem`)
  → target filename `<hash>.0`, PEM + `openssl x509 -text -fingerprint`
  trailer, mode 644.
- **Android ≤ 13**: install as a **system** CA via a systemless mount so it
  survives and apps trust it:
  - Preferred: generate a **Magisk module** (or use the KernelSU/APatch
    equivalent) that places the cert under `/system/etc/security/cacerts` via
    the module overlay — clean, reversible by disabling the module.
  - Fallback (no module): `mount -o rw,remount /`, copy, `chmod 644`,
    `mount -o ro,remount /` — or a `tmpfs` bind-mount of the cacerts dir when
    `/system` is not writable.
- **Android 14 (this device)**: the trust store is the Conscrypt APEX. Copy the
  current apex cacerts to a tmpfs, add `<hash>.0`, then **bind-mount** the
  tmpfs over `/apex/com.android.conscrypt/cacerts` (and over
  `/system/etc/security/cacerts` for apps reading the legacy path), restoring
  SELinux context (`chcon u:object_r:system_security_cacerts_file:s0`). This is
  what the community "Conscrypt trust" / "cert-fixer" Magisk modules do;
  Sentinel can drive the bind-mount directly or install such a module. The
  overlay is torn down on stop / revert.
- Verify: `settings`/`keystore` reflection is unreliable; instead launch the
  proxy and confirm an in-scope request lands in the flow view.

### A3. Revert
One button restores everything: clear the proxy setting, delete the iptables
rules, unmount the bind mounts / disable the module, remove the cert. The
audit log records install and revert.

---

## Part B — Pinning bypass (Frida / objection, per in-scope app)

For an app that still rejects the proxy after A, the app pins. Runtime
instrumentation on the one in-scope target:

- **frida-server lifecycle** (Phase 2): detect device arch, push the matching
  `frida-server`, start/stop it, show status (uses the root plane).
- **Unpinning presets** — a vetted script library the operator runs against
  the selected in-scope app, covering the common stacks:
  - Java/AOSP: `TrustManagerImpl.verifyChain`, `X509TrustManagerExtensions`,
    `OkHttp CertificatePinner`, `TrustManager`/`SSLContext` custom managers,
    Conscrypt, WebViewClient `onReceivedSslError`.
  - **Flutter** (BoringSSL): hook `ssl_crypto_x509_session_verify_cert_chain`
    / `session_verify_cert_chain` in `libflutter.so` by pattern, since Flutter
    neither uses the system trust store nor the system proxy — pair this with
    the A1 transparent redirect.
  - Xamarin, Cordova/Capacitor WebView, and native pinning as additional
    presets.
  - `objection` wrapper: `android sslpinning disable` as a one-click
    alternative to the raw Frida script.
- **Spawn vs attach**: offer spawn (`-f <pkg>`, catches pinning set up at
  startup) and attach to a running pid; both scoped to the in-scope package.
- **Result**: the module reports which preset worked and whether traffic now
  flows into the proxy; saved to the engagement.

---

## Part C — Dashboard wiring

A new **Intercept** tab (or a section inside the App Manager detail for the
selected app):
1. Pick an in-scope target app (gated by the engagement scope matcher).
2. **Trust & proxy**: upload/choose CA → install (version-aware) → set proxy
   mode (global / per-app transparent) → reachability check.
3. **Start interception**: launches/points at mitmproxy; flows stream into the
   Traffic view (Phase 3).
4. If traffic fails: **Bypass pinning** → pick a preset or objection →
   spawn/attach → re-check.
5. **Stop / revert**: tears down proxy, iptables, mounts, frida-server; logs it.

Status chips throughout: root ok, frida-server up, CA installed (system/apex),
proxy set, app pinning detected/bypassed.

---

## Part D — Per-app request log, filter & watcher

Once traffic is intercepted (or even without a proxy, from the existing
tcpdump/DNS/SNI capture + `/proc/net`→uid attribution), give each app its own
request stream, not one global firehose.

- **Per-app attribution**: every flow/connection carries the owning package
  (uid→pkg map already exists). The request log is scoped to the selected app;
  "All apps" is a view, per-app is the default.
- **Request log** (one row per request): timestamp, method, host, path, status,
  size, duration, scheme/port, and for intercepted HTTPS the full
  request/response (headers + body) on expand. Rows stream live over the
  existing WebSocket.
- **Filter bar**: by host/domain (incl. wildcard), path substring/regex,
  method, status class (2xx/3xx/4xx/5xx), scheme (http vs https), content-type,
  has-auth-header, and "new host not seen before this session". Filters compose
  and persist per app (localStorage), matching the dashboard's existing
  sortable/searchable table conventions.
- **Watcher / rules**: save a filter as a named watch on an app, e.g.
  "any cleartext (http) request", "requests to a host outside the app's usual
  set", "Authorization/Cookie/token in a URL", "request to `*.facebook.com` /
  a tracker host", "a 401/403 burst". A match raises an alert (the existing
  severity-chip + toast + alerts store + optional desktop notification) and is
  written to the engagement. This reuses the per-device RulesEngine pattern,
  scoped per app.
- **Endpoint map**: fold the per-app requests into a deduped host+path
  inventory (method set, first/last seen, count) — the API surface of that one
  app, which is what drives the actual bug-bounty testing.
- **Export**: the per-app log / endpoint map to CSV/JSON/HAR, saved to the
  engagement as evidence.

Deliverables: a per-app "Requests" view in the Intercept/Traffic tab and in the
App Manager detail for the selected app, backed by the flow store filtered by
package, with saved watches feeding the alerts pipeline.

## Build order & deps
1. CA install (version-aware, Android 14 apex bind-mount) + proxy wiring +
   revert — the highest-value, no-extra-dep part (needs only root + openssl,
   both present).
2. mitmproxy bridge + flow view (Phase 3).
3. frida-server lifecycle + the unpinning preset library + objection wrapper.

Optional host deps (degrade gracefully, UI says what to install, same pattern
as `pyaxmlparser`): `mitmproxy`, `frida-tools`, `objection`. Each step ships
demo-mode fixtures + tests + an adversarial review, and every active step
checks the engagement scope and writes the audit log.
