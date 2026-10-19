"""Build a flashable Magisk/KernelSU module that installs the operator's proxy
CA into the system trust store on every boot.

Step 1's `install_ca` overlays the store live but in the global mount namespace,
so already-running apps keep the old view until restart and the overlay is gone
after a reboot. A module makes the CA persist and reach every app after a
reboot. The operator flashes the returned zip in Magisk. Building it needs no
device.
"""
from __future__ import annotations

import io
import zipfile

from .intercept import inspect_ca

_MODULE_PROP = """\
id=sentinel_proxy_ca
name=Sentinel Proxy CA
version=v1
versionCode=1
author=Android Sentinel
description=Installs an operator-supplied HTTPS proxy CA into the system trust store (authorized testing; remove when done).
"""

# runs late enough that /apex is mounted; overlays both the legacy store and the
# Android 14 Conscrypt APEX so every app trusts the CA after a reboot.
_SERVICE_SH = """\
#!/system/bin/sh
MODDIR=${0%/*}
SYS=/system/etc/security/cacerts
APEX=/apex/com.android.conscrypt/cacerts
CERT="$MODDIR/system/etc/security/cacerts/@@HASH@@"
[ -f "$CERT" ] || exit 0

# wait for the apex to be available (bounded)
i=0
while [ ! -d "$APEX" ] && [ $i -lt 60 ]; do sleep 1; i=$((i+1)); done

TMP=/dev/sentinel-cacerts
rm -rf "$TMP"; mkdir -p "$TMP"
cp -f "$APEX"/* "$TMP"/ 2>/dev/null
cp -f "$SYS"/* "$TMP"/ 2>/dev/null
cp -f "$CERT" "$TMP"/
chown 0:0 "$TMP"/*; chmod 644 "$TMP"/*
chcon u:object_r:system_security_cacerts_file:s0 "$TMP"/* 2>/dev/null

mount -t tmpfs tmpfs "$SYS" 2>/dev/null
cp -f "$TMP"/* "$SYS"/ 2>/dev/null
chcon u:object_r:system_security_cacerts_file:s0 "$SYS"/* 2>/dev/null
[ -d "$APEX" ] && mount -o bind "$TMP" "$APEX" 2>/dev/null
"""

_CUSTOMIZE_SH = """\
#!/system/bin/sh
ui_print "- Sentinel Proxy CA (@@SUBJ@@)"
ui_print "- Installs into the system trust store on every boot."
ui_print "- Remove this module when your testing is done."
set_perm_recursive "$MODPATH" 0 0 0755 0644
"""


def build_module(pem_bytes: bytes) -> tuple[str, bytes]:
    """Return (filename, zip_bytes) for a flashable module that trusts the CA.
    Raises ValueError on a PEM that is not a certificate."""
    info = inspect_ca(pem_bytes)          # validates; raises ValueError otherwise
    hash_name = info["hash_name"]
    subj = (info.get("subject") or "proxy CA")[:60]
    pem = pem_bytes if isinstance(pem_bytes, bytes) else str(pem_bytes).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("module.prop", _MODULE_PROP)
        z.writestr("service.sh", _SERVICE_SH.replace("@@HASH@@", hash_name))
        z.writestr("customize.sh", _CUSTOMIZE_SH.replace("@@SUBJ@@", subj))
        # the cert the module ships and installs
        z.writestr(f"system/etc/security/cacerts/{hash_name}", pem)
        # META-INF installer so Magisk recognises the zip
        z.writestr("META-INF/com/google/android/update-binary",
                   "#MAGISK\n")
        z.writestr("META-INF/com/google/android/updater-script",
                   "#MAGISK\n")
    return "sentinel-ca-module.zip", buf.getvalue()
