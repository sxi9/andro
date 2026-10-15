# Android Sentinel

A local, defensive monitoring dashboard for **your own rooted Android device**.

Sentinel runs on your PC, talks to the phone over ADB (USB or wireless
debugging), and shows everything the device is doing in one place: live
system logs, every network connection and where it lands, microphone /
camera / location / clipboard access, app and permission changes, the
cellular radio layer, and an alert engine tuned to the patterns real
spyware and stalkerware leave behind.

**All data stays on your machine.** There is no cloud, no telemetry, and the
web UI binds to `127.0.0.1` by default.

> **Scope**: this is a tool for monitoring a device you own and control.
> Pointed at someone else's device it is stalkerware. Don't.

---

## Quick start

```bash
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
