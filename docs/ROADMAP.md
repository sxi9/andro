# Android Sentinel — roadmap & status checklist

All work is on branch `claude/youthful-goldberg-01npzu`. This file is the
single place that tracks every plan we made and what is built vs pending.
`[x]` = shipped and tested on the branch · `[~]` = partially done · `[ ]` = planned.

---

## A. Monitoring platform (the original dashboard) — DONE

- [x] Core: config, event bus, SQLite (WAL) store, per-device rules engine, alerts
- [x] ADB layer (USB + wireless), `su -c` wrapping, device-state parsing
- [x] Logcat stream (pid→package), live over WebSocket
- [x] Network: tcpdump capture → DNS answers + TLS SNI; per-connection (/proc/net → uid → app) + transport; cellular/radio
- [x] Netstats (WiFi vs mobile), GeoIP enrichment, tracker/hostname attribution
- [x] Mic/camera access (appops sensors, camera service)
- [x] Apps & permissions inventory; threats (accessibility, device admin, CAs, proxy/private-DNS, stalkerware IOC)
- [x] FastAPI server + REST + WebSocket; demo mode; pytest suite
- [x] Multi-device manager (no cap, USB + wireless) + Devices & ADB tab (restart/kill/pair/connect)
- [x] Files & Storage: per-app storage, APK+data extraction, file browser, backups, evidence export
- [x] Product UX: global search, sortable tables, drill-downs, draggable/collapsible layout, tooltips, toasts
- [x] One-command installers (`install.sh` / `install.ps1`) + `run.cmd` / `run.sh` launchers with dependency checks
- [x] Several adversarial-review passes with findings fixed

## B. App Manager (muntashirakon/AppManager parity, host-side) — DONE

- [x] Full package inventory: all / user / system / disabled / **uninstalled (debloated)**, per Android user/profile
- [x] Real app names (built-in map + APK label extraction; WebAPK name/URL/host browser)
- [x] "Find anywhere" — prove whether an app exists on any user / on disk; default handlers (browser/launcher/sms/dialer)
- [x] Detail tabs: Overview, Permissions, App ops, Components, Scanner, Manifest, Signatures, Storage, Prefs & DBs, Backups, History
- [x] Components: exported/permission/intent-filters; launch/start/send; enable/disable; **IFW block/unblock**; block all trackers
- [x] Scanner: 146 tracker + 50 library code signatures matched against `classes*.dex` (ranged reads); manifest decode; v1/v2/v3 certs
- [x] Actions (27): freeze (disable/suspend/hide)/unfreeze, uninstall(-k)/reinstall, uninstall-updates, appops set/reset/deny-dangerous, grant/revoke, prevent-background, battery, netpolicy, sensors, Magisk denylist, app-links, firewall, compile, save-apk, kill, prefs-set/delete, launch/open-settings
- [x] Controls: battery exemption, restrict background data, sensors, DenyList, open-links, firewall; every action validated + audit-logged
- [x] Batch ops over selected apps, 1-click ops, CSV/JSON/Markdown export
- [x] Install APK/APKS/XAPK/APKM + restore of host backups; shared_prefs editor + read-only SQLite viewer
- [x] Root/su controls (`rootctl`): detect Magisk/KernelSU/APatch, request su, use-root toggle, adb root/unroot
- [x] Android 13+ multi-user package-listing fix (multi-uid lines)
- [x] Phase-2 review: 43 confirmed findings fixed; regression review fixed

## C. SSL interception & unpinning (`docs/SSL-INTERCEPTION-MODULE.md`)

- [x] **Step 1 — CA trust + proxy** (DONE, reviewed)
  - [x] `inspect_ca` (subject/issuer, sha256/sha1, validity, is_ca, OpenSSL `<hash>.0` name)
  - [x] Version-aware install: Android 14 Conscrypt **APEX** tmpfs+bind overlay; pre-14 `/system` remount/bind; SELinux label
  - [x] Store-aware **revert** (removes a system-written cert, not just unmount)
  - [x] Proxy toggle: global (`settings http_proxy`) + **per-app transparent redirect** (SENTINEL_PROXY nat chain, iptables + ip6tables)
  - [x] No stale per-app redirect on target/mode switch (tracks all hooked uids)
  - [x] Intercept tab: authorization banner, status chips, CA inspect/install/revert, proxy host/port/mode + per-app picker
- [ ] **Step 2 — per-app request monitor** (NEXT, recommended)
  - [ ] Per-app request stream (method/host/path/status/size/duration; full headers+body for intercepted HTTPS)
  - [ ] Composable filter bar (host/path regex, method, status class, scheme, has-auth-header, new-host)
  - [ ] Saved **watches** → alerts (cleartext, token-in-URL, tracker host, 4xx burst) via the rules/alerts pipeline
  - [ ] Per-app endpoint map + HAR/CSV/JSON export
  - [ ] "Did it work?" indicator (traffic flowing = CA+proxy worked; nothing = app pins)
- [ ] **Step 3 — Frida unpinning** (for apps that pin after step 1)
  - [ ] `frida-server` lifecycle (arch-matched push, start/stop, status)
  - [ ] Unpin presets: OkHttp `CertificatePinner`, `TrustManagerImpl`, Conscrypt, WebView, **Flutter/BoringSSL**; `objection` one-click
  - [ ] Spawn/attach per in-scope app; custom-script slot; reports bypass result
- [ ] **Step 3.5 — mitmproxy bridge** (full flow view feeding step 2)
- [ ] **Step 1.5 — Magisk cert module export** (CA survives reboot / reaches running apps without restart)
- [ ] iOS support — NOT planned (Sentinel is Android/ADB-only; iOS would be a separate device plane: libimobiledevice, jailbreak, iOS-specific unpinning)

## D. Pentest platform roadmap (`docs/PENTEST-PLATFORM-PLAN.md`) — PLANNED

Authorized mobile-application security testing (MAST) workbench. Build order below.

- [ ] **Phase 0 — Engagement / scope / authorization gate** (build first)
  - [ ] Engagement records (client, dates, authorization reference)
  - [ ] Scope: in-scope packages / hosts / CIDRs + out-of-scope deny list; `observe` vs `active` mode
  - [ ] Append-only audit log every active module checks; `engagement.allows(...)` guard
  - [ ] *Note:* the intercept module already confirms + audit-logs every active call as an interim gate
- [ ] **Phase 1 — Static analysis (APK SAST), deepened** — *scanner/manifest base already built (B)*
  - [ ] Attack-surface ranking, secrets/entropy scan, TLS-pinning/cleartext detection, library→CVE lookup
  - [ ] Findings model `{id, title, severity, cwe, evidence, remediation}`
- [ ] **Phase 3 — Traffic interception & analysis** — *partially: step 1 proxy done; step 2/3.5 are this*
- [ ] **Phase 2 — Dynamic instrumentation (Frida/objection)** — *= SSL step 3, plus crypto/WebView tracing, intent fuzzing*
- [ ] **Phase 5 — Reporting & evidence** — findings + audit log + evidence → Markdown/PDF/HTML, OWASP MASVS/MASTG mapping
- [ ] **Phase 4 — Network & service recon** — scope-guarded nmap/service checks for lab/in-scope only

## E. Earlier staged ideas (from the original monitoring roadmap)

- [x] Static APK tracker scan (done via the App Manager Scanner)
- [x] Raw/decoded manifest view (done via the Manifest tab)
- [x] Per-app firewall (done via the firewall action)
- [x] Per-user / profile scanning (done across App Manager)
- [ ] Screen-off exfiltration detector
- [ ] QUIC/HTTP3 SNI capture
- [ ] Device-node watcher (/dev camera/mic open detection)
- [ ] Desktop/OS notifications for alerts
- [ ] Root-module (Magisk) audit
- [ ] Automated remediation suggestions

---

### Suggested next step
**C/Step 2 — per-app request monitor.** It closes the interception loop (install CA → set proxy → watch the app's requests land, with a clear "did it work?" signal) and is lower-risk than Frida. After that, **C/Step 3 — Frida unpinning** for apps that still pin.
