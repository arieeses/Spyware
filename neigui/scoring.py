"""排除层 + 多维加权评分。每个信号输出贡献值、理由与分类标签(可解释)。"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from .config import CONFIG, Config
from .features import TokenFeatures


@dataclass
class Signal:
    name: str
    points: float
    detail: str
    tag: str = ""          # 短分类标签(用于管理表展示)


@dataclass
class RiskResult:
    token: str
    score: float
    level: str
    excluded: bool
    signals: List[Signal] = field(default_factory=list)
    note: str = ""
    # —— 展示字段 ——
    email: Optional[str] = None
    user_id: Optional[int] = None
    panel: Optional[str] = None
    plan: Optional[str] = None
    distinct_ips: int = 0
    distinct_uas: int = 0
    online_ips: int = 0
    ip_shared_users: int = 0
    pull_count: int = 0
    last_pull: Optional[datetime] = None
    traffic_bytes: int = 0
    created_at: Optional[datetime] = None
    expired_at: Optional[datetime] = None

    @property
    def tags(self) -> List[str]:
        return [s.tag for s in self.signals if s.tag]


def _level(score: float, th) -> str:
    if score >= th.level_high:
        return "高"
    if score >= th.level_mid:
        return "中"
    if score >= th.level_low:
        return "低"
    return "正常"


def _display(f: TokenFeatures) -> dict:
    return dict(email=f.email, user_id=f.user_id, panel=f.panel, plan=f.plan,
                distinct_ips=f.distinct_ips, distinct_uas=f.distinct_uas,
                online_ips=f.online_ips, ip_shared_users=f.ip_shared_users,
                pull_count=f.pull_count, last_pull=f.last_pull,
                traffic_bytes=f.traffic_bytes, created_at=f.created_at, expired_at=f.expired_at)


def score_token(f: TokenFeatures, cfg: Config = CONFIG, disabled=None) -> RiskResult:
    """disabled: 被关闭的信号/参数 key 集合(来自风险规则页开关)。"""
    w, th = cfg.weights, cfg.thresholds
    off = disabled or set()
    signals: List[Signal] = []

    def on(key):
        return key not in off

    # —— 排除层: 自有基础设施(黑名单优先, 不被排除; 开关 self_exclude_ratio 可关) ——
    if (on("self_exclude_ratio") and not f.blacklist_hit
            and f.pull_count > 0 and f.self_ratio >= th.self_exclude_ratio):
        return RiskResult(f.token, 0.0, "正常", excluded=True,
                          note="自有基础设施IP拉取(subconverter/监控/节点), 已排除",
                          **_display(f))

    # 0. 命中黑名单(强, 直接判高危)
    bl = f.blacklist_hit and on("blacklist_hit")
    if bl:
        signals.append(Signal("命中黑名单", w.blacklist_hit, f.blacklist_reason or "命中黑名单",
                              tag="黑名单"))

    # 1. 机房ASN拉订阅
    if on("hosting_asn") and f.hosting_ratio > 0:
        signals.append(Signal("机房ASN拉订阅", round(f.hosting_ratio * w.hosting_asn, 1),
            f"{f.hosting_ratio * 100:.0f}% 拉取来自机房/IDC(真人应为住宅/移动)", tag="机房IP"))

    # 2. 工具/空 UA
    if on("ua_tool") and f.tool_ua_ratio > 0:
        signals.append(Signal("工具类UA", round(f.tool_ua_ratio * w.ua_tool, 1),
            f"{f.tool_ua_ratio * 100:.0f}% 拉取为工具/空UA(curl/python/Go 等)", tag="可疑客户端"))

    # 3. UA伪造(客户端UA + 机房ASN)
    if on("ua_spoof") and f.spoof:
        signals.append(Signal("UA伪造嫌疑", w.ua_spoof,
            "声称客户端UA却来自机房ASN, 高度疑似伪造(建议上TLS指纹核验)", tag="UA伪造"))

    # 4. 机器般规整拉取
    if (on("pull_regularity") and f.interval_cv is not None
            and f.pull_count >= th.regular_min_pulls and f.interval_cv <= th.regular_cv):
        signals.append(Signal("机器规整拉取", w.pull_regularity,
            f"拉取间隔变异系数 {f.interval_cv:.2f} 偏低, 呈自动化定时特征", tag="自动化"))

    # 5. 流量背离(拉取活跃却零流量, 抗伪装)
    if (on("traffic_divergence") and f.pull_count >= th.divergence_min_pulls
            and f.traffic_bytes <= th.divergence_max_bytes):
        signals.append(Signal("流量背离", w.traffic_divergence,
            f"拉取 {f.pull_count} 次却仅用 {f.traffic_bytes / 1048576:.1f}MB 流量, 只拿节点不使用",
            tag="流量背离"))

    # 6. 注册→拉取轨迹(新号侦察)
    if (on("reg_trajectory") and f.reg_to_first_pull_secs is not None
            and 0 <= f.reg_to_first_pull_secs <= th.reg_immediate_secs
            and f.account_age_days is not None and f.account_age_days <= th.new_account_days
            and f.traffic_bytes <= th.divergence_max_bytes):
        signals.append(Signal("注册即侦察", w.reg_trajectory,
            f"注册后 {f.reg_to_first_pull_secs / 60:.0f} 分钟内即拉取且几乎无流量, "
            "疑似注册就为拿节点清单", tag="注册侦察"))

    # 7. 多UA(一个 token 用了多个不同客户端, 共享/轮换嫌疑)
    if on("multi_ua") and f.distinct_uas >= th.multi_ua_min:
        signals.append(Signal("多客户端UA", w.multi_ua,
            f"该 token 用过 {f.distinct_uas} 个不同 UA, 疑似多人共享或工具轮换", tag="多UA"))

    # 8. 多IP在线(近期活跃窗口内在多个 IP 出现, 分发/扫描)
    if on("online_ips") and f.online_ips >= th.online_ips_min:
        signals.append(Signal("多IP在线", w.online_ips,
            f"近 {th.online_window_hours}h 在 {f.online_ips} 个不同 IP 活跃, 疑似分发或分布式扫描",
            tag="多IP在线"))

    # 9. IP共用账号(该 token 的 IP 被多个账号共用, 聚合点/攻击机)
    if on("ip_shared") and f.ip_shared_users >= th.ip_shared_min:
        signals.append(Signal("IP共用账号", w.ip_shared,
            f"该 token 的某个 IP 同时被 {f.ip_shared_users} 个账号使用, 疑似聚合点/攻击机",
            tag="IP共用"))

    # 11. 跨面板同IP: 该 token 的拉取 IP 横跨多个前端面板(一台机器打多个机场)
    if on("cross_panel_ip") and f.cross_panel_ips >= th.cross_panel_ip_min:
        signals.append(Signal("跨面板同IP", w.cross_panel_ip,
            f"拉取 IP 横跨 {f.cross_panel_ips} 个前端面板, 疑似一机打多机场", tag="跨面板同IP"))

    # 12. 同邮箱多面板: 同一邮箱在多个面板注册(批量身份)
    if on("email_multi_panel") and f.email_panels >= th.email_panel_min:
        signals.append(Signal("同邮箱多面板", w.email_multi_panel,
            f"该邮箱在 {f.email_panels} 个面板注册, 疑似批量身份", tag="同邮箱多面板"))

    # 13. 固定时段拉取: 拉取时刻聚集在一天内某窄时段, 跨多天(cron/自动化)
    if (on("fixed_schedule") and f.pull_count >= th.fixed_min_pulls
            and f.time_days >= th.fixed_min_days
            and f.time_concentration >= th.fixed_concentration):
        signals.append(Signal("固定时段拉取", w.fixed_schedule,
            f"跨 {f.time_days} 天但拉取时刻高度集中(聚集度 {f.time_concentration:.2f}), 呈定时自动化",
            tag="固定时段"))

    # 14. 流量对称: 近30天上下行接近对称(中转/攻击, 真人应下行远大于上行)
    if on("traffic_symmetry"):
        hi, lo = max(f.up30, f.down30), min(f.up30, f.down30)
        if lo > 0 and (f.up30 + f.down30) >= th.symmetry_min_bytes and lo / hi >= th.symmetry_ratio:
            signals.append(Signal("流量上下行对称", w.traffic_symmetry,
                f"近30天上行 {f.up30 / 1048576:.0f}MB / 下行 {f.down30 / 1048576:.0f}MB 接近对称, "
                "非真人下载型, 疑似中转/攻击", tag="流量对称"))

    # 10. 重点排查: 新号(reg_year_from 年后注册)+ 订阅有效期内 + 流量<阈值(付费却几乎不用)
    if on("active_lowtraffic") and f.created_at and f.expired_at:
        exp = f.expired_at if f.expired_at.tzinfo else f.expired_at.replace(tzinfo=timezone.utc)
        if (f.created_at.year >= th.reg_year_from and exp > datetime.now(timezone.utc)
                and f.traffic_bytes < th.active_lowtraffic_max_bytes):
            mb = th.active_lowtraffic_max_bytes / 1048576
            signals.append(Signal("有效期内零流量新号", w.active_lowtraffic,
                f"{th.reg_year_from}年后注册, 订阅在有效期内却仅用 "
                f"{f.traffic_bytes / 1048576:.2f}MB(<{mb:.0f}MB), 疑似只拉节点不使用",
                tag="重点排查"))

    # —— 节点侧信号(ip_silence / scan_pattern / tls_mismatch)需节点日志, 增量5接入 ——

    score = min(100.0, round(sum(s.points for s in signals), 1))
    if bl:
        score = max(score, th.level_high)  # 黑名单强制判高危
    return RiskResult(f.token, score, _level(score, th), excluded=False,
                      signals=signals, **_display(f))
