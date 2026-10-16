"""One app's data, read (and in two narrow cases written) over root adb.

Storage layout and sizes, shared_prefs XML files, sqlite databases (copied to
this host and opened read-only - never queried on the device) and the process
list. Writes exist only for a single preference key and go through a pushed
temp file + `cp` as root into a staged name next to the target, chown/chmod/
restorecon on that stage, then a rename into place (an app-planted symlink is
never followed). Every path component that reaches a shell is validated
against a strict pattern and shell-quoted.
"""
from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
import sqlite3
import tempfile
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from ..adb.client import AdbError
from ..parsers.packagedump import parse_pm_list
from ..parsers.storage import parse_du_k, parse_ls_la

_PKG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]{1,254}$")
PREF_FILE = re.compile(r"^[A-Za-z0-9_.\-]{1,128}\.xml$")
PREF_KEY = re.compile(r"^[A-Za-z0-9_.:\-]{1,200}$")
DB_FILE = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")
TABLE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
PREF_TYPES = ("string", "int", "long", "float", "boolean", "set")
_MAX_VALUE = 4000
_COUNT_CAP = 1_000_000
# where apps commonly keep logs, relative to /data/data/<pkg>
LOG_HINTS = ("*.log", "*.txt", "*log*", "*.trace", "*.out")
_PS_COLS = "PID,PPID,UID,RSS,STAT,TIME,NAME"


def _vpkg(pkg: str) -> str:
    if not _PKG.match(pkg or ""):
        raise AdbError("invalid package name")
    return pkg


def _vfile(name: str, pattern: re.Pattern, what: str) -> str:
    if not pattern.match(name or "") or ".." in name:
        raise AdbError(f"invalid {what} name")
    return name


def _vuser(user) -> int:
    try:
        u = int(user)
    except (TypeError, ValueError):
        raise AdbError("invalid user id") from None
    if not 0 <= u <= 999:
        raise AdbError("invalid user id")
    return u


def package_uid(dctx, pkg: str, user: int = 0) -> int | None:
    """The app's uid for one user: `pm list packages -U` (exact match), then
    the cached uid map, then the package dump kept by the collectors."""
    adb = dctx.adb
    q = shlex.quote(pkg)
    for scope in (f"--user {int(user)} ", ""):
        try:
            rows = parse_pm_list(adb.shell_sync(f"pm list packages {scope}-U {q}", timeout=20))
        except AdbError:
            continue
        uid = (rows.get(pkg) or {}).get("uid")
        if uid is not None:
            return int(uid)
    maps = getattr(dctx, "maps", None)
    if maps is not None:
        for uid, p in maps.all_packages().items():
            if p == pkg:
                return int(uid) + int(user) * 100000
    inv = (getattr(dctx, "state", None) or {}).get("apps") or {}
    uid = (inv.get(pkg) or {}).get("uid")
    return int(uid) if uid is not None else None


# ---------------- device file writes ----------------

def write_device_file(dctx, remote: str, data: bytes, *, mode: str = "644",
                      owner: str | None = None, restorecon: bool = True,
                      mkdir: bool = False) -> str:
    """Write bytes to a root-owned path: push to /data/local/tmp (the only
    place adb may write), `cp` to a staged name beside the target as root, fix
    its mode/owner/SELinux label, then rename it over the target. mkdir creates
    the parent (root-owned, so only for system dirs). Returns the shell output;
    raises AdbError on failure."""
    if not remote.startswith("/") or ".." in remote or not re.fullmatch(r"[A-Za-z0-9_./\-]+", remote):
        raise AdbError("invalid remote path")
    if owner is not None and not re.fullmatch(r"\d{1,7}:\d{1,7}", owner):
        raise AdbError("invalid owner")
    if not re.fullmatch(r"[0-7]{3,4}", mode):
        raise AdbError("invalid mode")
    adb = dctx.adb
    tmp_remote = f"/data/local/tmp/sentinel-{uuid.uuid4().hex}"
    fd, local = tempfile.mkstemp(prefix="sentinel-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        if not adb.push_file(local, tmp_remote):
            raise AdbError("adb push to /data/local/tmp failed")
    finally:
        try:
            os.unlink(local)
        except OSError:
            pass
    parent = posixpath.dirname(remote)
    # cp and a plain chown both follow a symlink at the target, so the file is
    # staged under a random name next to it and renamed into place: rename(2)
    # replaces a link instead of writing through it
    stage = f"{parent}/.sentinel-{uuid.uuid4().hex}.tmp"
    q_t, q_r, q_p, q_s = (shlex.quote(tmp_remote), shlex.quote(remote),
                          shlex.quote(parent), shlex.quote(stage))
    if mkdir:
        steps = [f"mkdir -p {q_p}"]
    else:
        # the parent may be a dir the app owns (shared_prefs): it must be a real one
        steps = [f"test -d {q_p} && test ! -L {q_p}"]
    steps += [f"cp {q_t} {q_s}", f"chmod {mode} {q_s}"]
    if owner:
        steps.append(f"chown {owner} {q_s}")
    if restorecon:
        steps.append(f"restorecon {q_s}")
    # the target: absent or a regular file, never a link, directory or device
    steps += [f"test ! -L {q_r} && ( test ! -e {q_r} || test -f {q_r} )", f"mv -f {q_s} {q_r}"]
    cmd = "(" + " && ".join(steps) + f" && echo WROTE); rm -f {q_t} {q_s}"
    out = adb.shell_sync(cmd, su=True, timeout=30)
    if "WROTE" not in out:
        raise AdbError(f"write failed: {out.strip()[:200] or 'target is not a regular file in a real directory, or permission denied (root?)'}")
    return out


def _cat(dctx, path: str, *, timeout: float = 60.0) -> bytes:
    return dctx.adb.exec_out_bytes(f"cat {shlex.quote(path)}", su=True, timeout=timeout)


# ---------------- storage ----------------

def storage(dctx, pkg: str) -> dict:
    """Where one app keeps its data, with sizes, log-like files, APKs and the
    backups of it on this host. Root, on demand."""
    _vpkg(pkg)
    adb = dctx.adb
    data_dir = f"/data/data/{pkg}"
    ext_dir = f"/sdcard/Android/data/{pkg}"
    obb_dir = f"/sdcard/Android/obb/{pkg}"
    media_dir = f"/sdcard/Android/media/{pkg}"
    de_dir = f"/data/user_de/0/{pkg}"
    try:
        sizes = parse_du_k(adb.du_sizes([data_dir, ext_dir, obb_dir, media_dir, de_dir,
                                         f"{data_dir}/cache", f"{data_dir}/code_cache",
                                         f"{data_dir}/databases", f"{data_dir}/shared_prefs",
                                         f"{data_dir}/files"]))
    except AdbError:
        sizes = {}
    try:
        listing = [e.to_dict() for e in parse_ls_la(adb.list_dir(data_dir))]
    except AdbError:
        listing = []
    try:
        log_out = adb.find_files(data_dir, list(LOG_HINTS), limit=100)
        logs = [ln.strip() for ln in log_out.splitlines() if ln.strip()]
    except AdbError:
        logs = []
    try:
        apk_paths = adb.apk_paths(pkg)
    except AdbError:
        apk_paths = []
    apk_sizes: dict[str, int] = {}
    if apk_paths:
        try:
            apk_sizes = parse_du_k(adb.du_sizes(apk_paths, su=False, timeout=30))
        except AdbError:
            apk_sizes = {}
    st = ((dctx.state.get("storage") or {}).get("apps") or {}).get(pkg, {})
    app_bytes = sum(apk_sizes.values()) or st.get("app", 0) or 0
    backups = []
    svc = getattr(getattr(dctx, "hub", None), "backup", None)
    if svc is not None:
        try:
            backups = [{"name": b["name"], "path": b["path"], "bytes": b["bytes"],
                        "captured": b["captured"], "components": b["components"]}
                       for b in svc.list_backups(serial=dctx.serial) if b.get("package") == pkg]
        except Exception:  # noqa: BLE001 - a broken backup dir must not hide the rest
            backups = []
    return {
        "package": pkg, "data_dir": data_dir, "external_dir": ext_dir,
        "obb_dir": obb_dir, "media_dir": media_dir, "de_dir": de_dir,
        "sizes": sizes, "entries": listing, "log_files": logs,
        "subdirs": {
            "files": f"{data_dir}/files", "cache": f"{data_dir}/cache",
            "databases": f"{data_dir}/databases", "shared_prefs": f"{data_dir}/shared_prefs",
            "code_cache": f"{data_dir}/code_cache", "external": ext_dir,
        },
        "cache_bytes": (sizes.get(f"{data_dir}/cache", 0) + sizes.get(f"{data_dir}/code_cache", 0))
        or st.get("cache", 0) or 0,
        "data_bytes": sizes.get(data_dir, 0) or st.get("data", 0) or 0,
        "app_bytes": app_bytes,
        "apk_paths": apk_paths,
        "splits": [{"path": p, "size": apk_sizes.get(p, 0)} for p in apk_paths],
        "backups": backups,
    }


# ---------------- shared_prefs ----------------

def _prefs_dir(pkg: str, user: int = 0) -> str:
    # /data/data is user 0's CE dir (/data/user/0 links to it); a work profile
    # or secondary user keeps its own copy under /data/user/<N>
    u = _vuser(user)
    base = f"/data/data/{_vpkg(pkg)}" if u == 0 else f"/data/user/{u}/{_vpkg(pkg)}"
    return f"{base}/shared_prefs"


def _parse_prefs(raw: bytes) -> list[dict]:
    if not raw.strip():
        return []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise AdbError(f"not a shared_prefs XML file: {e}") from None
    out = []
    for el in root:
        key = el.get("name")
        if key is None or el.tag not in PREF_TYPES:
            continue
        if el.tag == "string":
            val = el.text or ""
        elif el.tag == "set":
            val = [c.text or "" for c in el if c.tag == "string"]
        else:
            val = el.get("value", "")
            if el.tag in ("int", "long"):
                try:
                    val = int(val)
                except ValueError:
                    pass
            elif el.tag == "float":
                try:
                    val = float(val)
                except ValueError:
                    pass
            elif el.tag == "boolean":
                val = val == "true"
        out.append({"key": key, "type": el.tag, "value": val})
    return out


def prefs_list(dctx, pkg: str, user: int = 0) -> dict:
    d = _prefs_dir(pkg, user)
    try:
        entries = parse_ls_la(dctx.adb.list_dir(d))
    except AdbError as e:
        return {"files": [], "error": str(e)}
    files = []
    for e in entries:
        if e.kind != "file" or not PREF_FILE.match(e.name):
            continue
        n = 0
        if len(files) < 60:          # count keys for a reasonable number of files
            try:
                n = len(_parse_prefs(_cat(dctx, f"{d}/{e.name}", timeout=20)))
            except AdbError:
                n = 0
        files.append({"name": e.name, "size": e.size, "entries": n})
    return {"files": files}


def prefs_read(dctx, pkg: str, file: str, user: int = 0) -> dict:
    _vfile(file, PREF_FILE, "prefs file")
    raw = _cat(dctx, f"{_prefs_dir(pkg, user)}/{file}")
    if not raw.strip():
        raise AdbError("file is empty or unreadable (root?)")
    return {"file": file, "entries": _parse_prefs(raw)}


def _coerce(ptype: str, value) -> object:
    """A request value into the XML attribute/text for its type."""
    if ptype in ("int", "long"):
        try:
            return str(int(value))
        except (TypeError, ValueError):
            raise AdbError(f"value is not an {ptype}") from None
    if ptype == "float":
        try:
            return repr(float(value))
        except (TypeError, ValueError):
            raise AdbError("value is not a float") from None
    if ptype == "boolean":
        if isinstance(value, str):
            return "true" if value.strip().lower() in ("true", "1", "yes", "on") else "false"
        return "true" if value else "false"
    if ptype == "set":
        if isinstance(value, str):
            v = value.strip()
            if v.startswith("["):
                try:
                    value = json.loads(v)
                except ValueError:
                    raise AdbError("set value must be a JSON list or one item per line") from None
            else:
                value = [ln for ln in v.splitlines() if ln.strip()]
        if not isinstance(value, list):
            raise AdbError("set value must be a list")
        return [str(x) for x in value]
    return "" if value is None else str(value)


def _render_prefs(root: ET.Element) -> bytes:
    # Android's own layout: single quotes in the declaration, <map> root
    body = ET.tostring(root, encoding="unicode")
    return ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n" + body + "\n").encode()


_PROBE_MARK = re.compile(r"\b(ABSENT|EMPTY)\b")


def _rewrite_prefs(dctx, pkg: str, file: str, mutate, user: int = 0) -> str:
    user = _vuser(user)
    path = f"{_prefs_dir(pkg, user)}/{file}"
    raw = _cat(dctx, path)
    if raw.strip():
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            raise AdbError(f"not a shared_prefs XML file: {e}") from None
    else:
        # exec-out hides cat's exit status, so no output is ambiguous: only a
        # file confirmed absent (or truly empty) starts as a fresh <map>; a
        # failed read must never replace the app's real preferences
        q = shlex.quote(path)
        probe = dctx.adb.shell_sync(
            f"if test -e {q}; then test -s {q} && echo NONEMPTY || echo EMPTY; else echo ABSENT; fi",
            su=True, timeout=20)
        if not _PROBE_MARK.search(probe):
            raise AdbError("could not read the prefs file (root?); it was left untouched")
        root = ET.Element("map")
    mutate(root)
    uid = package_uid(dctx, pkg, user)
    if uid is None:
        raise AdbError("could not resolve the app's uid (is it installed for this user?)")
    uid = uid % 100000 + user * 100000    # this user's instance, whichever lookup answered
    write_device_file(dctx, path, _render_prefs(root), mode="660", owner=f"{uid}:{uid}")
    return "set"


def prefs_set(dctx, pkg: str, file: str, key: str, ptype: str, value, user: int = 0) -> str:
    _vfile(file, PREF_FILE, "prefs file")
    if not PREF_KEY.match(key or ""):
        raise AdbError("invalid key")
    if ptype not in PREF_TYPES:
        raise AdbError("invalid type")
    if len(str(value if not isinstance(value, list) else json.dumps(value))) > _MAX_VALUE:
        raise AdbError("value too long")
    rendered = _coerce(ptype, value)

    def mutate(root: ET.Element) -> None:
        for el in list(root):
            if el.get("name") == key:
                root.remove(el)
        el = ET.SubElement(root, ptype, {"name": key})
        if ptype == "string":
            el.text = rendered
        elif ptype == "set":
            for item in rendered:
                ET.SubElement(el, "string").text = item
        else:
            el.set("value", rendered)
    return _rewrite_prefs(dctx, pkg, file, mutate, user)


def prefs_delete(dctx, pkg: str, file: str, key: str, user: int = 0) -> str:
    _vfile(file, PREF_FILE, "prefs file")
    if not PREF_KEY.match(key or ""):
        raise AdbError("invalid key")
    found = False

    def mutate(root: ET.Element) -> None:
        nonlocal found
        for el in list(root):
            if el.get("name") == key:
                root.remove(el)
                found = True
        if not found:
            raise AdbError("key not found")
    _rewrite_prefs(dctx, pkg, file, mutate, user)
    return "deleted"


# ---------------- sqlite databases ----------------

def _db_dir(pkg: str) -> str:
    return f"/data/data/{_vpkg(pkg)}/databases"


def db_list(dctx, pkg: str) -> dict:
    d = _db_dir(pkg)
    try:
        entries = parse_ls_la(dctx.adb.list_dir(d))
    except AdbError as e:
        return {"files": [], "error": str(e)}
    files = []
    for e in entries:
        if e.kind != "file" or not DB_FILE.match(e.name):
            continue
        base, ext = os.path.splitext(e.name)
        if e.name.endswith(("-journal", "-wal", "-shm")):
            continue
        if ext.lower() in (".db", ".sqlite", ".sqlite3") or ext == "":
            files.append({"name": e.name, "size": e.size})
    return {"files": files}


def _json_cell(v):
    if isinstance(v, bytes):
        return f"<blob {len(v)} B>"
    if isinstance(v, float) and v != v:   # NaN is not JSON
        return None
    return v


def db_read(dctx, pkg: str, file: str, table: str | None = None, limit: int = 200) -> dict:
    """Copy the database (plus -wal/-shm) to a temp dir on this host and open
    that copy read-only; nothing is ever executed against the live file."""
    _vfile(file, DB_FILE, "database")
    if table is not None and table != "" and not TABLE.match(table):
        raise AdbError("invalid table name")
    table = table or None
    limit = max(1, min(int(limit), 1000))
    remote = f"{_db_dir(pkg)}/{file}"
    tmp = tempfile.mkdtemp(prefix="sentinel-db-")
    local = os.path.join(tmp, "db.sqlite")
    try:
        main = _cat(dctx, remote, timeout=300)
        if not main.startswith(b"SQLite format 3"):
            raise AdbError("not a SQLite database (or unreadable without root)")
        Path(local).write_bytes(main)
        for suffix in ("-wal", "-shm"):
            side = _cat(dctx, remote + suffix, timeout=300)
            if side:
                Path(local + suffix).write_bytes(side)
        con = sqlite3.connect(f"file:{local}?mode=ro", uri=True)
        try:
            names = [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            tables = []
            for n in names:
                qn = '"' + n.replace('"', '""') + '"'
                try:
                    cnt = con.execute(f"SELECT COUNT(*) FROM (SELECT 1 FROM {qn} LIMIT {_COUNT_CAP + 1})"
                                      ).fetchone()[0]
                    cnt = -1 if cnt > _COUNT_CAP else cnt
                except sqlite3.Error:
                    cnt = -1
                tables.append({"name": n, "rows": cnt})
            columns: list[str] = []
            rows: list[list] = []
            truncated = False
            if table is not None:
                if table not in names:
                    raise AdbError("no such table")
                cur = con.execute(f'SELECT * FROM "{table}" LIMIT {limit + 1}')
                columns = [c[0] for c in cur.description or []]
                fetched = cur.fetchall()
                truncated = len(fetched) > limit
                rows = [[_json_cell(v) for v in r] for r in fetched[:limit]]
        finally:
            con.close()
    except sqlite3.Error as e:
        raise AdbError(f"sqlite: {e}") from None
    finally:
        for f in Path(tmp).glob("*"):
            try:
                f.unlink()
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass
    return {"file": file, "tables": tables, "table": table, "columns": columns,
            "rows": rows, "truncated": truncated}


# ---------------- processes ----------------

def parse_ps(text: str) -> list[dict]:
    """`ps -A -o PID,PPID,UID,RSS,STAT,TIME,NAME` -> rows. NAME is last and may
    hold spaces, so only the fixed leading columns are split."""
    out = []
    lines = text.splitlines()
    for line in lines[1:] if lines and "PID" in lines[0] else lines:
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        try:
            out.append({"pid": int(parts[0]), "ppid": int(parts[1]), "uid": int(parts[2]),
                        "rss_kb": int(parts[3]), "state": parts[4], "cputime": parts[5],
                        "name": parts[6].strip()})
        except ValueError:
            continue
    return out


def parse_meminfo(text: str) -> dict:
    want = {"MemTotal": "total_kb", "MemAvailable": "avail_kb",
            "SwapTotal": "swap_total_kb", "SwapFree": "swap_free_kb"}
    mem = {v: 0 for v in want.values()}
    for line in text.splitlines():
        k, _, rest = line.partition(":")
        if k in want:
            m = re.search(r"\d+", rest)
            if m:
                mem[want[k]] = int(m.group())
    return mem


def processes(dctx) -> dict:
    adb = dctx.adb
    try:
        procs = parse_ps(adb.shell_sync(f"ps -A -o {_PS_COLS}", timeout=20))
    except AdbError:
        procs = []
    try:
        mem = parse_meminfo(adb.shell_sync("cat /proc/meminfo", timeout=10))
    except AdbError:
        mem = parse_meminfo("")
    maps = getattr(dctx, "maps", None)
    if maps is not None and hasattr(maps, "ensure_uid_map"):
        try:
            maps.ensure_uid_map()          # blocking refresh; we are in a thread
        except Exception:  # noqa: BLE001
            pass
    uid2pkg = maps.all_packages() if maps is not None else {}
    for p in procs:
        uid = p["uid"]
        # app uids start at 10000; secondary users add 100000 per user
        p["package"] = (uid2pkg.get(uid) or uid2pkg.get(uid % 100000)) if uid >= 10000 else None
    procs.sort(key=lambda p: -p["rss_kb"])
    return {"processes": procs, "mem": mem}
