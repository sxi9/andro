# CLAUDE.md — project context for Android Sentinel

Context for anyone (human or AI) working on this repo. Read this first.

## What this is

A **host-side** dashboard that drives the owner's **own rooted Android phone**
over the owner's **own adb** (USB or wireless), for **authorized** monitoring
and **authorized mobile-application security testing** (bug-bounty in-scope /
own apps). Everything runs locally; the web UI binds to `127.0.0.1`. There is
no cloud, no telemetry. Reference device during development: Xiaomi **M2101K6P,
Android 14 (SDK 34)**, rooted (Magisk/KernelSU/APatch).

Branch for all work: `claude/youthful-goldberg-01npzu`.

## Hard rules (do not break these)

These are load-bearing security guardrails, not style preferences:

1. **No free-form shell endpoint.** The browser can never send an arbitrary
   command to the device. Every device action is a specific, named operation
   with its own validated route. (The Activity Console is read-only; it shows
   what Sentinel ran, it does not take shell input.)
2. **Validate + quote every device-/request-derived string** before it reaches
   a shell: a strict `re.fullmatch` / `\Z`-anchored regex (never a bare `$`,
   which also matches before a trailing newline) **and** `shlex.quote`. Fixed
   paths/flags are constants, not interpolated input.
3. **Active (device-changing) actions require `confirm=true`** and emit an
   audit event (`app.action` / `intercept.action` / `frida.log`).
4. **GETs never change device state.** Reads are GET; mutations are POST.
5. **CSRF/Origin guard** on every non-GET; the Origin must match the request's
   own Host (a cross-site page cannot forge Host). TrustedHost confines Host to
   loopback names.
6. **Engagement scope gate**: when an engagement is active, active modules call
   `engagement.require_scope(hub, pkg=…, host=…)`, which raises `ScopeError`
   (-> 403) for out-of-scope targets and `observe` mode. No engagement active =
   own-device default, unrestricted.
7. **Own-device framing stays explicit** in UI copy and docs. This is not built
   to hide from the device owner or to target anything at scale.

## Architecture

- `sentinel/__main__.py` — entrypoint; checks required deps (fastapi, uvicorn)
  and warns on optional ones (pyaxmlparser, python-multipart, frida, mitmproxy).
- `sentinel/config.py` — CLI args / `Config`.
- `sentinel/adb/client.py` — `AdbClient`: `shell_sync(cmd, su=False)`,
  `exec_out_bytes`, `push_file`, `pull_*`, `install`, `root/unroot`, device
  listing/state parsing. `su -c` wrapping gated on `use_su`.
- `sentinel/adb/device.py` — `device_info`, uid→package map (handles Android
  13+ multi-uid `uid:10146,1010146` lines).
- `sentinel/context.py` — `DeviceContext` (per device: `adb`, `device{}`,
  `state{}`, `store`, `emit_threadsafe`, `tasks`) and `Hub` (shared: `cfg`,
  `devices`, `store`, `bus`, `backup`, `resolve`, `default_serial`).
- `sentinel/core/` — `events.py` (`Event`, `SEV_*`), `bus.py` (pub/sub),
  `store.py` (SQLite WAL; events + per-key snapshots), `rules.py` (RulesEngine).
- `sentinel/collectors/` — logcat, net sockets/pcap (DNS+SNI), appops sensors,
  camera, netstats, packages, threats, radio, storage, capture.
- `sentinel/enrich/` — `labels.py` (app names; rejects `@7F..`-style resource
  refs), `manifest.py`+`signatures.py` (ranged APK read: components, certs, dex
  tracker/lib scan), geoip/hostnames/trackers.
- `sentinel/service/` — the action layer (see map below).
- `sentinel/server/app.py` — `create_app(cfg)`: all routes + WebSocket `/ws` +
  demo data. Helpers: `_dev`, `_refuse`, `_bad`, `_demo_refuse`, `_csrf_guard`,
  `_origin_ok`.
- `sentinel/server/static/` — `index.html`, `app.js` (one vanilla-JS IIFE, no
  build step), `style.css`.

### service/ module map

| module | purpose |
|---|---|
| `appmanager.py` | full app inventory, per-user, find-anywhere, detail, 27 owner actions, batch, 1-click, controls, export, history. `_PKG`/`_vpkg`, `DESTRUCTIVE`, `_emit_action`. |
| `appdata.py` | per-app storage, shared_prefs read/write (symlink-safe), read-only sqlite viewer, processes, `package_uid`. |
| `installer.py` | APK/bundle install, restore of host backups. |
| `backup.py` | APK+data extraction jobs. |
| `rootctl.py` | root manager detect, request su, use-su toggle, adb root/unroot. |
| `intercept.py` | CA `inspect_ca`/`install_ca` (Android-14 APEX overlay)/`revert_ca`; `set_proxy` (global / per-app `SENTINEL_PROXY` nat chain, tracks all hooked uids). |
| `ca.py` | **built-in** Sentinel CA (generate/persist RSA CA, key 0600; `mitm_confdir` for mitmproxy to mint leaf certs). |
| `certmodule.py` | build a flashable Magisk module that trusts the CA on every boot. |
| `mitm.py` | mitmproxy bridge (optional); streams flows into `reqmon`; `host_ip()`. |
| `reqmon.py` | per-device HTTP flow ring, per-app filter, watches→alerts, endpoint map, HAR/CSV/JSON export, `replay` (Repeater). |
| `frida_svc.py` | frida-server lifecycle + **live-streaming** unpinning (session kept alive, each hook → `frida.log` event). Presets incl. "all". |
| `engagement.py` | engagement records + scope matcher + `require_scope`. |

## Conventions

- Python: `from __future__ import annotations`, type hints, short why-comments
  matching surrounding density. Blocking adb/host work in routes via
  `await asyncio.to_thread(...)`. Lazy `from ..service import X` inside handlers.
- Demo mode = `dctx is None or dctx.adb is None`: GETs return realistic data
  with `"demo": true`; active POSTs return `_demo_refuse()` (400).
- Frontend: one IIFE; `$`/`$$`/`esc`/`dq`/`DEV`/`toast`/`shortApp`/`getJSON`/
  `postJSON`/`amGet`; escape every interpolated value with `esc()`; tab dispatch
  via `currentTab` + `go(tab)` + per-tab `loadX()`.
- Optional deps degrade gracefully and the UI says what to `pip install`.

## Build / test / run

```bash
python3 -m pytest tests/ -q            # 290 tests; keep green
node --check sentinel/server/static/app.js
python3 -m sentinel --demo --demo-devices 1 --port 88xx   # demo server for smoke tests
```

Launchers `run.cmd` / `run.sh` use the installer's venv and `pip install -r
requirements.txt` when it changed. Required deps: fastapi, uvicorn, cryptography,
pyaxmlparser, python-multipart. Optional: frida-tools, mitmproxy, geoip2.

## Working method (how this repo has been built)

- Multi-agent **Workflow** builds on disjoint files (one owner per shared file:
  `app.py`, `static/*`), each with a precise HTTP contract, then integrate +
  run the suite + demo smoke + an **adversarial review workflow** (finders →
  refutation-voted verifiers) before pushing. Note: the Workflow tool may be
  blocked by the auto-mode classifier for large/sensitive batches — then build
  directly with Edit/Write/Bash.
- Every change: run the full suite, `node --check`, a demo smoke test, then
  commit with the attribution footer and push to the working branch.
- Commit messages state the real test count (don't overstate).

## Status & roadmap

See `docs/ROADMAP.md` (checklist), `docs/SSL-INTERCEPTION-MODULE.md`,
`docs/PENTEST-PLATFORM-PLAN.md`, and `docs/SETUP-AND-USAGE.md`. Done: monitoring
platform, App Manager parity, SSL interception steps 1–3.5 (built-in CA +
one-click + proxy + request monitor + Frida unpinning + mitm bridge + Magisk
module), engagement gate, Activity Console. Open: MAST track (SAST findings
engine, reporting, network recon) and staged ideas (screen-off exfil, QUIC SNI,
device-node watcher, desktop notifications, root-module audit).

Not done / caveats: no real-device verification of Frida/mitm from the build
environment; the wave-2 adversarial review hasn't run (Workflow was blocked).
