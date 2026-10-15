"""`python -m sentinel` — start the dashboard."""
from __future__ import annotations

import logging
import sys


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    from .config import parse_args
    cfg = parse_args(argv)

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
