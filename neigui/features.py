"""按 token 聚合拉取记录 + v2board 用户画像, 产出特征向量。"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from .enrich import Blacklist, IpClassifier, UaClassifier


@dataclass
class TokenFeatures:
    token: str
    pull_count: int = 0
    distinct_ips: int = 0
    asn_type_counts: Dict[str, int] = field(default_factory=dict)
    hosting_ratio: float = 0.0
    self_ratio: float = 0.0
    tool_ua_ratio: float = 0.0
    has_client_ua: bool = False
    spoof: bool = False                       # 客户端UA + 机房ASN
    interval_cv: Optional[float] = None       # 拉取间隔变异系数(越低越像机器)
    blacklist_hit: bool = False               # 命中 IP/UA/ASN 黑名单
    blacklist_reason: str = ""
    first_pull: Optional[datetime] = None
    last_pull: Optional[datetime] = None
    # 来自 v2board
    email: Optional[str] = None
    user_id: Optional[int] = None
    group_id: Optional[int] = None
    panel: Optional[str] = None
    traffic_bytes: int = 0
    created_at: Optional[datetime] = None
    expired_at: Optional[datetime] = None
    account_age_days: Optional[float] = None
    reg_to_first_pull_secs: Optional[float] = None


def _parse_dt(s) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def build_features(token: str, pull_rows: List, user_row,
                   ipc: IpClassifier, uac: UaClassifier, bl: Blacklist = None) -> TokenFeatures:
    f = TokenFeatures(token=token)
    f.pull_count = len(pull_rows)

    ips = set()
    type_counts: Dict[str, int] = {}
    tool = client = 0
    times: List[datetime] = []

    for r in pull_rows:
        ip = r["ip"]
        ips.add(ip)
        t = ipc.classify(ip)
        type_counts[t] = type_counts.get(t, 0) + 1
        ui = uac.classify(r["ua"])
        if ui.is_tool:
            tool += 1
        if ui.is_client:
            client += 1
            if t == "hosting":
                f.spoof = True
        if bl is not None and not f.blacklist_hit:
            if bl.ip_hit(ip):
                f.blacklist_hit = True
                f.blacklist_reason = f"IP/ASN 黑名单命中: {ip}"
            elif bl.ua_hit(r["ua"]):
                f.blacklist_hit = True
                f.blacklist_reason = f"UA 黑名单命中: {(r['ua'] or '')[:40]}"
        dt = _parse_dt(r["ts"])
        if dt:
            times.append(dt)

    n = max(f.pull_count, 1)
    f.distinct_ips = len(ips)
    f.asn_type_counts = type_counts
    f.hosting_ratio = type_counts.get("hosting", 0) / n
    f.self_ratio = type_counts.get("self", 0) / n
    f.tool_ua_ratio = tool / n
    f.has_client_ua = client > 0

    times.sort()
    if times:
        f.first_pull, f.last_pull = times[0], times[-1]
    if len(times) >= 3:
        intervals = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
        intervals = [x for x in intervals if x > 0]
        if len(intervals) >= 2:
            mean = statistics.mean(intervals)
            if mean > 0:
                f.interval_cv = statistics.pstdev(intervals) / mean

    if user_row is not None:
        f.email = user_row["email"]
        f.user_id = user_row["user_id"]
        f.group_id = user_row["group_id"]
        f.panel = user_row["panel"] if "panel" in user_row.keys() else None
        f.traffic_bytes = user_row["traffic_bytes"] or 0
        f.created_at = _parse_dt(user_row["created_at"])
        f.expired_at = _parse_dt(user_row["expired_at"] if "expired_at" in user_row.keys() else None)
        if f.created_at and times:
            f.account_age_days = (f.last_pull - f.created_at).total_seconds() / 86400.0
            f.reg_to_first_pull_secs = (f.first_pull - f.created_at).total_seconds()

    return f
