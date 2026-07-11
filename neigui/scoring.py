"""排除层 + 多维加权评分。每个信号输出贡献值、理由与分类标签(可解释)。"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
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
    distinct_ips: int = 0
    pull_count: int = 0
    last_pull: Optional[datetime] = None
    traffic_bytes: int = 0

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
    return dict(email=f.email, user_id=f.user_id, panel=f.panel, distinct_ips=f.distinct_ips,
                pull_count=f.pull_count, last_pull=f.last_pull, traffic_bytes=f.traffic_bytes)


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

    # —— 节点侧信号(ip_silence / scan_pattern / tls_mismatch)需节点日志, 增量5接入 ——

    score = min(100.0, round(sum(s.points for s in signals), 1))
    if bl:
        score = max(score, th.level_high)  # 黑名单强制判高危
    return RiskResult(f.token, score, _level(score, th), excluded=False,
                      signals=signals, **_display(f))
