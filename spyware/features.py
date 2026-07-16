"""按 token 聚合拉取记录 + v2board 用户画像, 产出特征向量。"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from .enrich import Blacklist, IpClassifier, UaClassifier

_BEIJING = timezone(timedelta(hours=8))


@dataclass
class TokenFeatures:
    token: str
    pull_count: int = 0
    distinct_ips: int = 0
    distinct_uas: int = 0         # 用过多少个不同 UA(共享/轮换嫌疑)
    burst_uas: int = 0            # 任一短时窗口内出现的最大不同 UA 数(秒级轮换=自动化)
    night_pulls: int = 0          # 北京时间深夜时段(默认2-6点)的拉取次数
    online_ips: int = 0           # 近期活跃窗口内的不同 IP 数(在线IP)
    ip_shared_users: int = 0      # 该 token 的IP中, 被最多账号共用的那个的账号数
    cross_panel_ips: int = 0      # 该 token 的IP横跨的不同面板数(≥2=一机打多机场)
    email_panels: int = 0         # 该邮箱在多少个不同面板注册过
    time_concentration: float = 0.0  # 拉取时刻在一天内的聚集度(0~1, 越大越像定时)
    time_days: int = 0            # 拉取覆盖的不同天数
    up30: int = 0                 # 近30天上行字节
    down30: int = 0               # 近30天下行字节
    active_days90: int = 0        # 近90天有流量的天数(每天都在用)
    maxup_day: int = 0            # 近90天单日上行峰值
    maxdown_day: int = 0          # 近90天单日下行峰值
    feature_hit: bool = False     # 命中特征库(手工)
    feature_reason: str = ""
    # 内鬼库分维度命中
    ins_ip: bool = False          # 与内鬼同一IP(精确)
    ins_subnet: bool = False      # 与内鬼同一网段
    ins_asn: bool = False         # 与内鬼同一ASN
    ins_ua: bool = False          # 与内鬼同一UA
    ins_prefix: bool = False      # 邮箱前缀与内鬼相同
    ins_tag_sets: object = None   # 内鬼行为标签集(供 score_token 算行为相似)
    main_ip: Optional[str] = None  # 代表 IP(最近一次拉取), 供「同IP」下钻
    asn_type_counts: Dict[str, int] = field(default_factory=dict)
    clouds: List[str] = field(default_factory=list)   # 命中的云厂商(阿里云/AWS/腾讯云/UCloud等)
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
    plan: Optional[str] = None
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
                   ipc: IpClassifier, uac: UaClassifier, bl: Blacklist = None,
                   ip_users: dict = None, window_hours: int = 24,
                   now: datetime = None, ip_panels: dict = None,
                   email_panels: dict = None, featlib=None,
                   burst_window: int = 120,
                   night_start: int = 2, night_end: int = 6, insmatch=None) -> TokenFeatures:
    f = TokenFeatures(token=token)
    f.pull_count = len(pull_rows)

    ips = set()
    uas = set()
    recent_ips = set()
    type_counts: Dict[str, int] = {}
    tool = client = 0
    times: List[datetime] = []
    tua: List = []            # (时间, UA) 对, 供短时多UA轮换判定
    _latest = None            # (dt, ip) 最近一次拉取, 取代表 IP
    if now is None:
        now = datetime.now(timezone.utc)
    win_start = now - timedelta(hours=max(1, window_hours))

    self_count = 0
    for r in pull_rows:
        ip = r["ip"]
        # 自有设备(自有IP/反代IP/自有UA)不参与评分: 只计入 self_ratio, 其余信号全跳过
        if ipc.is_self_ip(ip) or uac.is_self(r["ua"]):
            self_count += 1
            continue
        ips.add(ip)
        if r["ua"]:
            uas.add(r["ua"])
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
            if r["ua"]:
                tua.append((dt, r["ua"]))
            if dt >= win_start and ip:
                recent_ips.add(ip)
            if ip and (_latest is None or dt >= _latest[0]):
                _latest = (dt, ip)
            d8 = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            bh = d8.astimezone(_BEIJING).hour   # 北京时间小时
            if night_start <= bh < night_end:
                f.night_pulls += 1

    n = max(f.pull_count, 1)
    f.distinct_ips = len(ips)
    f.distinct_uas = len(uas)
    f.online_ips = len(recent_ips)
    # 短时多UA轮换: 任一 burst_window 秒滑动窗口内的最大不同 UA 数
    if len(tua) >= 2:
        tua.sort(key=lambda x: x[0])
        cnt: Dict[str, int] = {}
        j = 0
        for i in range(len(tua)):
            cnt[tua[i][1]] = cnt.get(tua[i][1], 0) + 1
            while (tua[i][0] - tua[j][0]).total_seconds() > burst_window:
                cnt[tua[j][1]] -= 1
                if cnt[tua[j][1]] == 0:
                    del cnt[tua[j][1]]
                j += 1
            if len(cnt) > f.burst_uas:
                f.burst_uas = len(cnt)
    # 该 token 近期在线 IP 中, 被最多其他账号共用的那个的账号数
    if ip_users and recent_ips:
        f.ip_shared_users = max((ip_users.get(ip, 1) for ip in recent_ips), default=0)
    # 跨面板同IP: 该 token 的所有 IP 横跨的不同面板数
    if ip_panels and ips:
        spanned = set()
        for ip in ips:
            spanned |= ip_panels.get(ip, set())
        f.cross_panel_ips = len(spanned)
    # 固定时段拉取: 拉取时刻在一天内的圆周聚集度(向量长度 R, 越接近1越集中)
    if len(times) >= 2:
        f.time_days = len({t.date() for t in times})
        angs = [2 * math.pi * (t.hour * 60 + t.minute) / 1440.0 for t in times]
        c = sum(math.cos(a) for a in angs) / len(angs)
        s = sum(math.sin(a) for a in angs) / len(angs)
        f.time_concentration = math.hypot(c, s)
    real = max(f.pull_count - self_count, 1)   # 非自有拉取数(其余比率的分母)
    # 跨云机房: 该账号(非自有)IP 命中了哪些云厂商
    from .asn import cloud_of
    cl = set()
    for ip in ips:
        c = cloud_of(ipc.asn_info(ip)[1])
        if c:
            cl.add(c)
    f.clouds = sorted(cl)
    f.asn_type_counts = type_counts
    f.hosting_ratio = type_counts.get("hosting", 0) / real
    f.self_ratio = self_count / n               # 自有设备占比(供排除层)
    f.tool_ua_ratio = tool / real
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
        keys = user_row.keys()
        f.email = user_row["email"]
        f.user_id = user_row["user_id"]
        f.group_id = user_row["group_id"]
        f.panel = user_row["panel"] if "panel" in keys else None
        f.plan = user_row["plan"] if "plan" in keys else None
        f.traffic_bytes = user_row["traffic_bytes"] or 0
        f.up30 = (user_row["up30"] or 0) if "up30" in keys else 0
        f.down30 = (user_row["down30"] or 0) if "down30" in keys else 0
        f.active_days90 = (user_row["active_days90"] or 0) if "active_days90" in keys else 0
        f.maxup_day = (user_row["maxup_day"] or 0) if "maxup_day" in keys else 0
        f.maxdown_day = (user_row["maxdown_day"] or 0) if "maxdown_day" in keys else 0
        f.created_at = _parse_dt(user_row["created_at"])
        f.expired_at = _parse_dt(user_row["expired_at"] if "expired_at" in keys else None)
        if f.created_at and times:
            f.account_age_days = (f.last_pull - f.created_at).total_seconds() / 86400.0
            f.reg_to_first_pull_secs = (f.first_pull - f.created_at).total_seconds()
        if email_panels and f.email:
            f.email_panels = len(email_panels.get(f.email, set()))

    if _latest:
        f.main_ip = _latest[1]
    asndb = getattr(ipc, "asndb", None)
    # 特征库匹配(手工登记的 IP/UA/ASN/邮箱); 无拉取时也能靠邮箱命中
    if featlib is not None and not featlib.empty:
        reason = featlib.match(ips, uas, f.email, asndb)
        if reason:
            f.feature_hit = True
            f.feature_reason = reason
    # 内鬼库分维度匹配(精确IP/网段/ASN/UA/邮箱前缀; 行为相似留给 score_token)
    if insmatch is not None and not insmatch.empty:
        f.ins_ip = insmatch.hit_ip(ips)
        f.ins_subnet = insmatch.hit_subnet(ips)
        f.ins_asn = insmatch.hit_asn(ips, asndb)
        f.ins_ua = insmatch.hit_ua(uas)
        f.ins_prefix = insmatch.hit_prefix(f.email)
        f.ins_tag_sets = insmatch  # 传匹配器, score_token 用累计标签算行为相似

    return f
