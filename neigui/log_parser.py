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

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterator, List, Optional
from urllib.parse import urlsplit, parse_qs

FIELDS = 8


def _ip_in_nets(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _pick_real_ip(remote: str, forwarded: str, proxy_nets=None) -> str:
    """从「转发字段 + remote」里挑真实客户端 IP。

    上层反代会把真实 IP 放在末段转发字段(可能是 'client' 或 'client, p1, p2'),
    remote 则是最近一跳的反代。候选链靠前=更接近真实客户端。
    - 有反代名单: 取链中第一个「不在反代名单」的 IP;
    - 无名单: 取转发字段的第一个(即真实客户端), 否则 remote。
    """
    chain: List[str] = []
    for part in (forwarded or "").split(","):
        p = part.strip()
        if p and p != "-":
            chain.append(p)
    r = (remote or "").strip()
    if r and r != "-":
        chain.append(r)
    if not chain:
        return ""
    if proxy_nets:
        for c in chain:
            if not _ip_in_nets(c, proxy_nets):
                return c
    return chain[0]


@dataclass
class PullRecord:
    ts: datetime
    ip: str
    status: int
    request_time: float
    ua: str
    token: str
    uri: str




_MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
           "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
# CLF: 14/Jul/2026:08:08:44 +0800  (月份名手动映射, 不依赖系统 locale)
_CLF_TS = re.compile(
    r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?")


def _parse_ts(s: str) -> Optional[datetime]:
    s = s.strip()
    # ISO8601(自定义管道格式用)
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # CLF/combined 的 dd/Mon/yyyy —— 手动解析, 避开 %b 的 locale 依赖
    m = _CLF_TS.match(s)
    if m:
        mon = _MONTHS.get(m.group(2).lower())
        if mon:
            tz = timezone.utc
            if m.group(7):
                sign = 1 if m.group(7)[0] == "+" else -1
                tz = timezone(sign * timedelta(
                    hours=int(m.group(7)[1:3]), minutes=int(m.group(7)[3:5])))
            try:
                return datetime(int(m.group(3)), mon, int(m.group(1)),
                                int(m.group(4)), int(m.group(5)), int(m.group(6)), tzinfo=tz)
            except ValueError:
                return None
    return None


def _token_from_uri(uri: str) -> str:
    """从 URI 查询串取 token(v2board 订阅是 ?token=xxx)。"""
    try:
        qs = parse_qs(urlsplit(uri).query)
    except (ValueError, TypeError):
        return ""
    return (qs.get("token", [""])[0] or "").strip()


# 标准 combined/common 日志: IP - user [time] "METHOD URI PROTO" status bytes "ref" "ua" ["真实IP/XFF"]
# 末段可选的引号字段 = 上层反代传下来的真实客户端 IP(如宝塔/1Panel 反代常见)
_COMBINED = re.compile(
    r'^(?P<remote>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+\S+'
    r'(?:\s+"(?P<ref>[^"]*)")?'
    r'(?:\s+"(?P<ua>[^"]*)")?'
    r'(?:\s+"(?P<xff>[^"]*)")?'
)


def _parse_combined(line: str, proxy_nets=None) -> Optional[PullRecord]:
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
    ip = _pick_real_ip(m.group("remote"), m.group("xff"), proxy_nets)
    return PullRecord(ts=ts, ip=ip, status=status, request_time=0.0,
                      ua=(m.group("ua") or "").strip(), token=token, uri=uri)


def _parse_pipe(line: str, proxy_nets=None) -> Optional[PullRecord]:
    parts = line.split("|")
    if len(parts) < FIELDS:
        return None
    ts = _parse_ts(parts[0])
    if ts is None:
        return None
    ip = _pick_real_ip(parts[2], parts[1], proxy_nets)  # 管道格式: [1]=XFF, [2]=remote
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


def parse_line(line: str, proxy_nets=None) -> Optional[PullRecord]:
    line = line.rstrip("\n")
    if not line:
        return None
    # 自定义管道格式优先(字段最全); 否则回退标准 access.log
    if "|" in line:
        rec = _parse_pipe(line, proxy_nets)
        if rec is not None:
            return rec
    return _parse_combined(line, proxy_nets)


def load_proxy_nets():
    """读取反代IP名单(CIDR/IP), 用于从转发链里剔除反代、取真实客户端IP。"""
    from .config import CONFIG
    nets = []
    try:
        with open(CONFIG.proxy_ips_file, encoding="utf-8") as f:
            for ln in f:
                ln = ln.split("#", 1)[0].strip()
                if not ln:
                    continue
                try:
                    nets.append(ipaddress.ip_network(ln, strict=False))
                except ValueError:
                    continue
    except (FileNotFoundError, AttributeError):
        pass
    return nets


def parse_file(path: str, proxy_nets=None) -> Iterator[PullRecord]:
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            rec = parse_line(line, proxy_nets)
            if rec is not None:
                yield rec
