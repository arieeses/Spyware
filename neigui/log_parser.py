"""解析订阅拉取日志。支持两种格式, 自动识别:

1) 本系统自定义的 `neigui` 管道格式(最精确, XFF 真实 IP + request_time):
   log_format neigui '$time_iso8601|$http_x_forwarded_for|$remote_addr|'
                     '$status|$request_time|$http_user_agent|'
                     '$arg_token|$request_uri';

2) 标准 Nginx access.log(combined/common)—— 直接对着面板现成日志即可, 免改 nginx。
   token 从请求 URI 的 ?token= 里取; 只保留带 token 的订阅请求。

真实 IP: 管道格式优先取 X-Forwarded-For 第一段, 否则 remote_addr。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, Optional
from urllib.parse import urlsplit, parse_qs

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
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S",
                "%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _token_from_uri(uri: str) -> str:
    """从 URI 查询串取 token(v2board 订阅是 ?token=xxx)。"""
    try:
        qs = parse_qs(urlsplit(uri).query)
    except (ValueError, TypeError):
        return ""
    return (qs.get("token", [""])[0] or "").strip()


# 标准 combined/common 日志: IP - user [time] "METHOD URI PROTO" status bytes "ref" "ua"
_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+\S+'
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)


def _parse_combined(line: str) -> Optional[PullRecord]:
    m = _COMBINED.match(line)
    if not m:
        return None
    ts = _parse_ts(m.group("ts"))
    if ts is None:
        return None
    req = m.group("req") or ""
    rp = req.split(" ")
    uri = rp[1] if len(rp) >= 2 else req
    token = _token_from_uri(uri)
    if not token:  # 只关心带 token 的订阅拉取, 其余访问忽略
        return None
    try:
        status = int(m.group("status"))
    except (ValueError, TypeError):
        status = 0
    return PullRecord(ts=ts, ip=m.group("ip"), status=status, request_time=0.0,
                      ua=(m.group("ua") or "").strip(), token=token, uri=uri)


def _parse_pipe(line: str) -> Optional[PullRecord]:
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


def parse_line(line: str) -> Optional[PullRecord]:
    line = line.rstrip("\n")
    if not line:
        return None
    # 自定义管道格式优先(字段最全); 否则回退标准 access.log
    if "|" in line:
        rec = _parse_pipe(line)
        if rec is not None:
            return rec
    return _parse_combined(line)


def parse_file(path: str) -> Iterator[PullRecord]:
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            rec = parse_line(line)
            if rec is not None:
                yield rec
