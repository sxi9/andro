"""`python -m sentinel` — start the dashboard."""
from __future__ import annotations

import logging
import sys


_REQUIRED = {           # import name -> pip name (requirements.txt)
    "fastapi": "fastapi",
    "uvicorn": "uvicorn[standard]",
}
_OPTIONAL = {           # import name -> (pip name, dashboard feature it enables)
    "multipart": ("python-multipart", "Install APK"),
    "pyaxmlparser": ("pyaxmlparser", "Resolve names"),
}


def _missing_deps(mods: dict) -> list[str]:
    """Import names from `mods` that are not installed."""
    import importlib.util
    out = []
    for mod in mods:
        if importlib.util.find_spec(mod) is None:
            if mod == "multipart" and importlib.util.find_spec("python_multipart") is not None:
                continue   # newer releases also ship under this name
            out.append(mod)
    return out


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    from .config import parse_args
    cfg = parse_args(argv)

    # a `git pull` can add requirements; say exactly what to run with the
    # same interpreter that is running us (pip is rarely on PATH on Windows)
    how = f"  \"{sys.executable}\" -m pip install -r requirements.txt\n(or run install.ps1 / install.sh again)"
    missing = _missing_deps(_REQUIRED)
    if missing:
        print(f"Missing Python packages: {', '.join(_REQUIRED[m] for m in missing)}\n"
              f"Install them with:\n{how}", file=sys.stderr)
        return 2
    optional = _missing_deps(_OPTIONAL)
    if optional:
        # the dashboard degrades on its own (the Install button / Resolve
        # names say what to install); warn up front but start anyway
        off = ", ".join(f"{_OPTIONAL[m][0]} ({_OPTIONAL[m][1]} is off)" for m in optional)
        print(f"Optional Python packages missing: {off}\n"
              f"Install them with:\n{how}", file=sys.stderr)

    if not cfg.demo:
        from .adb.client import AdbClient
        probe = AdbClient(adb_path=cfg.adb_path, serial=cfg.serial)
        try:
            devs = probe.devices()
        except Exception as e:
            print(f"adb not usable ({e}). Install platform-tools or run with --demo.",
                  file=sys.stderr)
            return 2
        live = [d for d in devs if d["state"] == "device"]
        if not live:
            print("No device attached. Enable USB debugging and plug in, or "
                  "`adb pair` + `adb connect host:port` for wireless, or run with --demo.",
                  file=sys.stderr)
            print("Continuing anyway — collectors will attach when a device appears.",
                  file=sys.stderr)

    import uvicorn
    from .server.app import create_app
    app = create_app(cfg)
    print(f"\n  Android Sentinel → http://{cfg.host}:{cfg.port}\n"
          f"  {'DEMO MODE (simulated device)' if cfg.demo else 'Own-device monitoring; data stays local.'}\n")
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
