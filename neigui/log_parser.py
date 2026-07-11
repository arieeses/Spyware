"""解析 Nginx `neigui` 日志格式。

log_format neigui '$time_iso8601|$http_x_forwarded_for|$remote_addr|'
                  '$status|$request_time|$http_user_agent|'
                  '$arg_token|$request_uri';

真实 IP: 优先取 X-Forwarded-For 的第一段(最靠近客户端), 否则 remote_addr。
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, Optional

FIELDS = 8


@dataclass
class PullRecord:
    ts: datetime
    ip: str
    status: int
    request_time: float
    ua: str
    token: str
    uri: str


def _real_ip(xff: str, remote: str) -> str:
    xff = (xff or "").strip()
    if xff and xff != "-":
        return xff.split(",")[0].strip()
    return (remote or "").strip()


def _parse_ts(s: str) -> Optional[datetime]:
    s = s.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def parse_line(line: str) -> Optional[PullRecord]:
    line = line.rstrip("\n")
    if not line:
        return None
    parts = line.split("|")
    if len(parts) < FIELDS:
        return None
    ts = _parse_ts(parts[0])
    if ts is None:
        return None
    ip = _real_ip(parts[1], parts[2])
    try:
        status = int(parts[3])
    except ValueError:
        status = 0
    try:
        rt = float(parts[4])
    except ValueError:
        rt = 0.0
    token = parts[6].strip()
    if not token or token == "-":
        return None
    return PullRecord(ts=ts, ip=ip, status=status, request_time=rt,
                      ua=parts[5], token=token, uri=parts[7])


def parse_file(path: str) -> Iterator[PullRecord]:
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            rec = parse_line(line)
            if rec is not None:
                yield rec
