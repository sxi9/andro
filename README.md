# Android Sentinel

A local dashboard for **your own rooted Android device** — defensive monitoring
**and** authorized mobile-app security testing.

Sentinel runs on your PC, talks to the phone over ADB (USB or wireless
debugging), and gives you, in one place:

- **Monitoring** — live system logs, every network connection and where it
  lands, microphone / camera / location / clipboard access, app and permission
  changes, the cellular radio layer, and an alert engine tuned to spyware /
  stalkerware patterns.
- **App Manager** — full inventory (per-user, incl. debloated/hidden), real app
  names, components with IFW blocking, a tracker/library scanner, manifest and
  signatures, app-ops, permissions, a shared-prefs editor and SQLite viewer,
  batch and 1-click operations, install/restore, freeze/suspend/hide, net
  policy, firewall, and more — host-side parity with AppManager.
- **SSL interception (Reqable-style, self-contained)** — Sentinel generates and
  installs **its own CA** (Android-14 APEX-aware), runs its own proxy
  (mitmproxy) or works with Burp, points the device at it (one click), and shows
  per-app HTTP requests with filters, saved watches, a **Repeater** and HAR/CSV/
  JSON export. **Frida pinning-bypass** (live-streaming, all stacks) for apps
  that pin. A reboot-persistent **Magisk CA module**. An **Engagement** scope
  gate and a read-only **Activity Console**.

**All data stays on your machine.** No cloud, no telemetry; the web UI binds to
`127.0.0.1`. Active actions confirm and are audit-logged.

> **Scope**: for a device you own and apps you are authorized to test
> (bug-bounty in-scope / your own). Pointed at someone else's device or app it
> is abuse. Don't.

See **[docs/SETUP-AND-USAGE.md](docs/SETUP-AND-USAGE.md)** for the full phone +
PC setup and the interception workflow, **[CLAUDE.md](CLAUDE.md)** for
architecture and conventions, and **[docs/ROADMAP.md](docs/ROADMAP.md)** for
status.

---

## Quick start

```bash
# Windows: powershell -ExecutionPolicy Bypass -File install.ps1   (then run.cmd)
# Linux/macOS: ./install.sh                                         (then ./run.sh)
# The run.* launchers use the installer's venv and install anything a
# `git pull` added to requirements.txt before starting. By hand:
pip install -r requirements.txt

# try it with a simulated device first (no phone needed):
python -m sentinel --demo

# real device over USB:
#   1. Settings → Developer options → USB debugging ON, plug in, accept the prompt
python -m sentinel

# real device over wireless debugging (Android 11+):
#   1. Developer options → Wireless debugging → Pair device with pairing code
#   2. adb pair <phone-ip>:<pair-port>   (enter the code)
#   3. adb connect <phone-ip>:<port>
python -m sentinel --serial <phone-ip>:<port>
```

Open **http://127.0.0.1:8765**.

### What needs root, what doesn't

| Capability | Needs root? |
|---|---|
| App inventory, permissions, installer provenance | no (adb shell) |
| Mic / camera / location / clipboard access (appops) | no |
| Logcat (all apps' logs — adb holds READ_LOGS) | no |
| God-mode audit (accessibility, device admin, notification access) | no |
| Per-app data usage, WiFi vs cellular (`dumpsys netstats`) | no |
| Telephony state, serving cell, radio log | no |
| Live socket table with owning UID (`/proc/net/*`) | **yes** (su) |
| Hostname capture — DNS + TLS SNI via on-device tcpdump | **yes** + tcpdump binary |
| User CA store listing | **yes** |

Without root Sentinel still runs; the network tab just shows less. If the
device lacks a `tcpdump` binary, push a static arm64 build to
`/data/local/tmp/tcpdump`, `chmod +x` it, and pass
`--tcpdump /data/local/tmp/tcpdump` (flag name: config `tcpdump_path`).

### Optional enrichment

- **GeoIP**: download the free GeoLite2 City and ASN `.mmdb` files from
  MaxMind, `pip install geoip2`, then
  `python -m sentinel --geoip-db GeoLite2-City.mmdb --asn-db GeoLite2-ASN.mmdb`.
  Lookups are offline; nothing is sent anywhere.
- **Tracker list**: built-in list of ~45 mobile ad/analytics endpoints;
  extend with one domain per line in `~/.android-sentinel/trackers.txt`.
- **Stalkerware indicators**: put known stalkerware package names, one per
  line, in `~/.android-sentinel/stalkerware-pkgs.txt`. The
  [AssoEchap/stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)
  project maintains the reference list. Installed matches raise a critical alert.

---

## The dashboard

- **Live Activity** — one merged timeline: sensor access, connections,
  app changes, threats, alerts. Plus "right now": who holds the camera,
  which apps hold god-mode access.
- **Network & Data** — live connections with owning app, hostname (from DNS
  answers and TLS ClientHello SNI — **no decryption, no MITM**), org,
  country and tracker match; a live destination map; per-app egress split
  **WiFi vs cellular**; transport filter.
- **Mic · Cam · Location** — every appops access with
  **foreground/background** attribution; background mic or camera is
  flagged immediately. Live camera clients from the camera service.
- **Apps & Permissions** — third-party inventory with installer provenance
  (Play vs sideloaded), dangerous grants, god-mode badges, versions and
  signing-cert tracking. Diffed every poll: installs, removals, updates,
  silently-added permissions all become events.
- **Logcat** — streaming system log (main/system/crash/events) attributed
  to the owning app, filterable.
- **Cellular & Radio** — network type, operator, call state, serving cell
  (CI/TAC), mobile-data by app, and the radio log buffer.
- **Alerts & Rules** — what tripped, with acknowledge/mute, and toggles for
  every detection.

## Detections

| Rule | Why it matters |
|---|---|
| Background mic / camera use | the core spying signal |
| Background recording → upload within 2 min | recording that leaves the device |
| New user CA certificate | someone preparing to decrypt your HTTPS |
| CA + proxy / private-DNS combo | conclusive interception pattern |
| New god-mode grant (a11y / admin / notif) | the top three abuse surfaces |
| Sideloaded app holding god-mode | the classic stalkerware shape |
| Stalkerware indicator match | known-bad package names |
| New destination country per app | exfiltration to somewhere new |
| Cleartext egress (port 80/21/23) | unencrypted data leaving |
| Known tracker endpoint | ad/analytics telemetry |
| APK signer changed on update | repackaged / hijacked app |
| Dangerous permission silently granted | privilege creep |
| SMS + internet on non-messaging app | OTP theft shape |
| High egress rate | bulk exfiltration |
| Cellular downgrade to 2G | IMSI-catcher tell |
| Wireless debugging left on | the risk this tool itself adds |

## Architecture

```
Android (rooted)  --ADB (USB / wireless)-->  collectors  -->  event bus  -->  rules engine
  logcat, dumpsys appops/netstats/package,   (parsers are                 \->  SQLite store
  /proc/net, tcpdump -w -, telephony          pure + unit                  \->  WebSocket -> dashboard
                                              tested)
```

Every signal becomes one `Event` on one bus; the store, the rules engine and
every dashboard client are just subscribers. Parsers are pure functions with
fixtures for the Android 10–15 format variants (`tests/`).

## Honest limitations

- **No payload contents.** Without MITM you learn who, where, how much, and
  when — never *what*. That is deliberate: user CAs are ignored by apps since
  Android 7 and pinning breaks the rest, so decryption buys little and risks a lot.
- **Polling, not push.** Sensor liveness is polled (~1.5s); sub-second mic
  touches can slip between polls. Short-lived sockets can be missed by the
  table poll — the DNS/SNI capture usually still names the destination.
- **appops sees framework access only.** On a rooted phone, native code
  reading `/dev/snd*` directly bypasses it. (Device-node watching is on the
  roadmap.)
- **DoH/QUIC blind spot.** Apps with their own encrypted DNS bypass the DNS
  capture; QUIC (HTTP/3) carries SNI differently and isn't parsed yet.
- **dumpsys is not a stable API.** Parsers are tolerant and tested against
  known variants, but OEM skins (Samsung/MIUI/etc.) can need parser fixes.
- **Attribution edge cases.** Shared UIDs collapse packages together, and
  Play Services proxies other apps' traffic under its own UID.
- **Wireless ADB is fragile under load** and is itself an attack surface —
  Sentinel warns when it is left on. Prefer USB for long captures.

## Roadmap

Cross-tab UID correlation scoring, screen-off exfiltration windows,
QUIC Initial SNI parsing, device-node (native) sensor watcher, trigger-based
deep capture (strace/perfetto) on flagged PIDs, per-app firewall via
`iptables -m owner`, evidence export, signing-cert IOC matching.

## Development

```bash
pip install -e .[dev]
pytest            # parser + rules + store suites, no device needed
python -m sentinel --demo   # full pipeline against a simulated device
```

## Files, storage and backup (own-device)

The **Files & Storage** tab adds device-management capabilities on top of monitoring:

- **Per-app storage** — data, cache and APK size for every app (from `dumpsys diskstats`, no slow `du` sweep), sorted by footprint.
- **App storage inspector** — for any app, where it keeps everything: its `/data/data/<pkg>` layout, the `files`/`cache`/`databases`/`shared_prefs` subdirs with sizes, the external dir, and a scan for log-like files it writes.
- **Extract / backup** — pull an app exactly as stored: its APK (base + splits) and its private data directory tarred as-is, plus an optional external dir, written under `~/.android-sentinel/backups/<pkg>_<timestamp>/` with a manifest. Same operation as Titanium/Neo Backup. Needs root.
- **File browser** — read-only `ls` navigation of the device filesystem (root), starting at `/sdcard`.
- **Evidence export** — a signed, timestamped JSON + text report of alerts and key events for a chosen window, saved locally, for your records or to document stalkerware.

Everything stays on this computer. These features need root for app data dirs; the APK and `/sdcard` work without it.

## Per-app risk score

Each app gets a 0-100 risk score blending god-mode access, dangerous permissions, sideload status, cellular egress and the SMS+internet combo. The Apps and Files tabs sort by it, so the apps worth reviewing float to the top.

## Multiple devices, USB and wireless

Sentinel monitors every connected device at once, USB and wireless together,
with no cap. It polls `adb devices` and gives each ready device its own
collectors, rules engine and hostname cache; events are tagged with the device
serial and the dashboard scopes every tab to the device you pick in the header
dropdown.

### "waiting for device" when `adb devices` shows it

That almost always means adb reports the device in a state that is not ready,
and the old UI hid the reason. The **Devices & ADB** tab now shows every
device adb sees with its exact state and what to do:

- **unauthorized** — unlock the phone and tap Allow on the "Allow USB
  debugging?" prompt (tick "Always allow"). No prompt? Toggle USB debugging
  off and on, or revoke authorizations in Developer options.
- **offline** — the connection is stale. Replug, press Reconnect, or
  Restart ADB.
- **no permissions** (Linux) — add an Android udev rule or run adb as a user
  in the `plugdev` group, then Restart ADB.

### ADB controls (in the Devices & ADB tab)

- **Restart ADB** — the kill switch for the local adb server (kill + start).
  Fixes most "offline"/"stuck" states without touching the phone.
- **Reconnect offline**, plus per-device Reconnect / Disconnect.
- **Wireless debugging** — Pair with the pairing `ip:port` and 6-digit code
  (Android 11+), then Connect with the main `ip:port`. All inputs are
  validated to `host:port`, so nothing shell-like is ever passed to adb.

The dashboard is local-only: Host validation blocks DNS rebinding, the
WebSocket checks Origin, and every state-changing request (ADB controls,
backups, exports) is refused if it carries a cross-site Origin.

## App Manager

The **App Manager** tab (inspired by [App Manager](https://github.com/muntashirakon/AppManager))
lists **every** package, system and user, not just third-party ones. Chrome,
Google Photos, Samsung and Google system apps all appear here. Filter by
user/system/disabled, search by name or package, and click an app for:

- identity: version, target/min SDK, ABI, installer, install and update
  times, data directory, signing certificate, enabled state
- declared vs granted permissions, each with grant/revoke
- app-ops activity, component override state, god-mode access
- owner actions: enable/disable, force-stop, clear cache, clear data,
  uninstall, set an app op, enable/disable a component. Destructive ones
  ask for confirmation. Every argument is validated and shell-quoted.

### Real app names

Package names are shown with a readable name from a built-in map of ~180
common apps, or a guess from the package name (hash-like segments and
`_v2` suffixes are skipped). For the real label of every app Sentinel reads
each APK's `AndroidManifest.xml` and `resources.arsc` by byte range over adb
(a few hundred KB per app, never the whole APK) and decodes them with
`pyaxmlparser`, which the installers now set up from `requirements.txt`.
This runs automatically the first time the App Manager opens on a device;
**Resolve names** re-runs it for anything still guessed.

WebAPKs ("Web app" shortcuts a Chromium browser creates for a PWA, packages
like `org.chromium.webapk.<hash>`) get their real PWA name plus the start URL,
scope and host browser from their manifest. Names are cached per device.
