"""Parse `logcat -v threadtime` lines."""
from __future__ import annotations

import re
from dataclasses import dataclass

# 10-15 18:46:01.123  1234  1300 I ActivityManager: Start proc 4711:com.foo/u0a155
_LINE = re.compile(
    r"^(?P<date>\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF])\s+"
    r"(?P<tag>.*?)\s*:\s(?P<msg>.*)$"
)


@dataclass
class LogLine:
    pid: int
    tid: int
    level: str
    tag: str
    msg: str
    date: str
    time: str


def parse_line(line: str) -> LogLine | None:
    m = _LINE.match(line.rstrip("\n"))
    if not m:
        return None
    return LogLine(
        pid=int(m["pid"]), tid=int(m["tid"]), level=m["level"],
        tag=m["tag"], msg=m["msg"], date=m["date"], time=m["time"],
    )
