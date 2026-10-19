# Setup & usage

Authorized own-device use only. The dashboard runs on your **PC** and drives
your **own rooted phone** over your own adb.

## 1. Install & run (PC)

**Windows**
```
powershell -ExecutionPolicy Bypass -File install.ps1   # once
run.cmd                                                 # phone on USB
run.cmd --demo                                          # simulated device, no phone
run.cmd -s <ip>:<port>                                  # wireless
```
**Linux/macOS**: `./install.sh` then `./run.sh` (same flags).

`run.*` uses the installer's venv and installs anything new in
`requirements.txt` before starting. Dashboard: **http://127.0.0.1:8765**.

Optional features need extra packages **in that venv**:
```
<venv>/python -m pip install mitmproxy frida-tools
# Windows venv path: C:\Users\<you>\AppData\Local\android-sentinel\.venv\Scripts\python.exe
```

## 2. Phone setup (one-time)

- **Developer options → USB debugging** ON; plug in; accept the authorization
  prompt. Confirm with `adb devices` (state `device`).
- **MIUI / Xiaomi** (e.g. M2101K6P): sign in to a Mi account, and in Developer
  options turn ON **"Install via USB"** and **"USB debugging (Security
  settings)"**. If root/debug actions misbehave, also **"Turn off MIUI
  optimization"**.
- **Root**: in the dashboard **Devices & ADB → Root → Request su**, then tap
  **Grant** on the phone (Magisk/KernelSU/APatch). Turn on **Use root for
  actions**.
- **Wi-Fi**: phone and PC on the same network (the proxy host is the PC's LAN
  IP). USB is only for adb; proxy traffic goes over Wi-Fi.

## 3. HTTPS interception (like Reqable, self-contained)

In **SSL Intercept**:

1. **CA** — one of:
   - **Create & install Sentinel CA (root)** (Proxy CA card) — generates
     Sentinel's own CA and installs it over su, or
   - **Set up interception** (One-click card) — CA + install + start proxy +
     point the device, all at once, or
   - paste a **Burp/mitmproxy** PEM and Install (optional external CA).
2. **A proxy must actually be listening** at the proxy host:port, or the phone
   loses internet:
   - **mitmproxy** (built-in): `pip install mitmproxy`, then mitmproxy card →
     **Start** (uses Sentinel's CA; flows appear in the **Requests** tab), or
   - **Burp**: add a listener on `0.0.0.0:8080`, install Burp's CA instead.
   - Allow inbound on that port through the PC firewall (Windows Defender
     prompt).
3. **Proxy** — the dashboard sets a **global** system proxy
   (`settings put global http_proxy <ip>:<port>`); you do **not** need to set a
   Wi-Fi proxy by hand. (Manual fallback: Settings → Wi-Fi → network → Proxy →
   Manual.) For apps that ignore the system proxy (Flutter, some custom
   networking), use proxy mode **"This app only"** (per-app transparent
   redirect).
4. **Restart the target app** after installing the CA (Android 14 serves the
   trust store from the Conscrypt APEX; already-running apps keep the old view).
5. Drive the app → watch **Requests** (filter, save a watch, Repeater resend,
   export HAR/CSV/JSON) and the **Console** (live command output).
6. **Turn proxy off** when done so the phone gets normal internet back.

### Reboot-persistent CA
**Magisk module…** in the Proxy CA card downloads a flashable module that
re-installs the CA on every boot (Android-14 APEX + /system bind-mount) and
reaches already-running apps — flash it in Magisk.

## 4. Bypassing certificate pinning (Frida)

For an app that still refuses the proxy after the CA is trusted:

1. **On the PC**: `pip install frida-tools` in the venv (the Frida card shows
   "frida on host" when present).
2. **On the phone**: put the **frida-server** binary matching your device arch
   (arm64) **and** the PC frida-tools version at `/data/local/tmp/frida-server`:
   download `frida-server-<ver>-android-arm64.xz` from
   github.com/frida/frida/releases, decompress, then
   `adb push … /data/local/tmp/frida-server` and
   `adb shell su -c "chmod 755 /data/local/tmp/frida-server"`.
   (frida-tools and frida-server versions must match.)
3. In the Frida card: **Start server** → target app → preset **All stacks** →
   **Spawn** → **Unpin app**.
4. **Open Console** and **use the app** — each hook/bypass streams live. The app's
   traffic then appears in Requests/your proxy. **Stop unpinning** when done.

Errors: `unable to connect` → frida-tools/server version mismatch;
`ProcessNotFound` → use Spawn mode.

## 5. Tabs

Live Activity · Network & Data · Mic·Cam·Location · Apps & Permissions · App
Manager (full owner controls, components, scanner, manifest, signatures,
prefs/DB, backups) · Logcat · Cellular & Radio · Files & Storage · Alerts &
Rules · **SSL Intercept** (CA, proxy, Frida, mitm, engagement) · **Requests**
(per-app flows, filters, watches, Repeater, export) · **Console** (live
read-only feed of everything Sentinel runs) · Devices & ADB (root, states,
connection controls).

## 6. Safety

Own-device / in-scope only. All data local; UI binds to loopback. Active
actions confirm and are audit-logged; an **Engagement** (SSL Intercept tab) can
restrict actions to in-scope packages/hosts and an observe-only mode. There is
no free-form shell from the browser by design.
