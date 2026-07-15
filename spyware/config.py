"""权重、阈值与路径配置。

所有判定参数集中在此,便于按真实数据校准。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


def _default_db_path() -> str:
    """DB 路径优先级: 环境变量 SPYWARE_DB > config.json 的 db_path > 默认。便于迁移。"""
    env = os.environ.get("SPYWARE_DB")
    if env:
        return env
    cfg = os.path.join(BASE_DIR, "config.json")
    if os.path.exists(cfg):
        try:
            import json
            with open(cfg, encoding="utf-8") as f:
                p = json.load(f).get("db_path")
            if p:
                return p
        except Exception:  # noqa: BLE001
            pass
    return os.path.join(BASE_DIR, "spyware.db")


@dataclass
class Weights:
    """各信号满分贡献值。命中程度 × 权重 = 实际得分。"""
    hosting_asn: float = 25.0        # 机房ASN拉订阅
    ua_tool: float = 15.0            # 工具/空 UA
    ua_spoof: float = 20.0           # 客户端UA + 机房ASN(伪造)
    pull_regularity: float = 10.0    # 机器般规整拉取
    traffic_divergence: float = 30.0 # 拉取活跃却零流量(抗伪装)
    reg_trajectory: float = 15.0     # 注册即拉取且无流量(新号侦察)
    multi_ua: float = 12.0           # 单 token 用多个不同客户端UA(共享/轮换)
    ua_burst: float = 25.0           # 短时窗口内秒级轮换多个UA(自动化探测, 比总数更硬)
    online_ips: float = 18.0         # 单 token 近期在多个IP在线(分发/扫描)
    ip_shared: float = 22.0          # 该 token 的IP被多个账号共用(聚合点/攻击机)
    active_lowtraffic: float = 30.0  # 2025+注册 + 有效期内 + 流量<5MB(付费却几乎不用)
    cross_panel_ip: float = 25.0     # 同一拉取IP横跨多个前端面板(一机打多机场)
    email_multi_panel: float = 20.0  # 同一邮箱在多个面板注册(批量身份)
    fixed_schedule: float = 12.0     # 拉取时刻固定在一天内某窄时段(cron/自动化)
    traffic_symmetry: float = 18.0   # 近30天上下行接近对称(中转/攻击, 非真人下载型)
    feature_lib: float = 50.0        # 命中手工登记的特征库(IP/UA/ASN/邮箱)
    # —— 内鬼库分维度匹配(每个独立开关) ——
    insider_ip: float = 55.0         # 与内鬼同一个 IP(精确)
    insider_subnet: float = 30.0     # 与内鬼同一网段(默认/24)
    insider_asn: float = 22.0        # 与内鬼同一 ASN
    insider_ua: float = 35.0         # 与内鬼用同一客户端/UA(整串)
    insider_pattern: float = 25.0    # 行为模式与内鬼相似(命中相同的一组信号)
    insider_prefix: float = 30.0     # 邮箱前缀与内鬼相同(如 bintest_vpn@任意域名)
    night_pull: float = 12.0         # 北京时间深夜(默认2-6点)仍在拉订阅(真人多在睡觉)
    blacklist_hit: float = 60.0      # 命中黑名单(IP/UA/ASN, 强, 直接判高危)
    # —— 节点侧信号(需节点日志, 增量5接入, 暂占位) ——
    ip_silence: float = 25.0
    scan_pattern: float = 15.0
    tls_mismatch: float = 25.0


@dataclass
class Thresholds:
    # 风险分档
    level_high: float = 75.0
    level_mid: float = 50.0
    level_low: float = 30.0
    # 流量背离: 近三个月「每天都在用」但每天上/下行都极小(只探节点不真用)
    divergence_active_days: int = 60                   # 近90天里至少这么多天有流量(≈每天都在用)
    divergence_day_up_bytes: int = 5 * 1024 * 1024     # 每日上行峰值上限 5MB
    divergence_day_down_bytes: int = 5 * 1024 * 1024   # 每日下行峰值上限 5MB
    divergence_max_bytes: int = 50 * 1024 * 1024       # 50MB(累计流量上限, 供「注册即侦察」复用)
    # 拉取规整: 间隔变异系数(CV)低于此判为机器
    regular_cv: float = 0.35
    regular_min_pulls: int = 6
    # 注册→拉取: 注册后多少秒内首拉算"立即"; 账龄多少天内算新号
    reg_immediate_secs: int = 600
    new_account_days: int = 7
    # 排除层: 自有IP占比达此比例即排除
    self_exclude_ratio: float = 0.99
    # 在线/近期活跃窗口(小时)——「在线IP」「IP共用账号」按此窗口统计
    online_window_hours: int = 24
    # 重点排查: 注册年份下限(含) + 有效期内流量上限(字节, 默认 5MB)
    reg_year_from: int = 2025
    active_lowtraffic_max_bytes: int = 5 * 1024 * 1024
    # 跨面板同IP: 该 token 的IP横跨的不同面板数达此值即判
    cross_panel_ip_min: int = 2
    # 同邮箱多面板: 邮箱出现在这么多不同面板即判
    email_panel_min: int = 2
    # 固定时段拉取: 需最少拉取次数 + 跨天数; 时刻聚集度(0~1, 越接近1越集中)达阈值即判
    fixed_min_pulls: int = 6
    fixed_min_days: int = 2
    fixed_concentration: float = 0.85
    # 流量对称: 近30天 min(u,d)/max(u,d) 达此值(越接近1越对称)+ 总量下限(字节)
    symmetry_ratio: float = 0.5
    symmetry_min_bytes: int = 10 * 1024 * 1024
    # 多UA: 一个 token 用过的不同 UA 数达此值即判「多UA」
    multi_ua_min: int = 4
    # 短时多UA: burst_window 秒窗口内不同 UA 数达此值即判「短时多UA」
    burst_ua_min: int = 4
    burst_ua_window: int = 120
    # 深夜拉取: 北京时间 [night_start, night_end) 点内拉取次数达此值即判
    night_start_hour: int = 2
    night_end_hour: int = 6
    night_min_pulls: int = 3
    # 内鬼库匹配: 同网段的网段长度(24=/24); 行为相似需与某内鬼共享的信号数下限
    insider_subnet_prefix: int = 24
    insider_pattern_min: int = 3
    # 在线IP: 一个 token 近期活跃 IP 数达此值即判「多IP在线」
    online_ips_min: int = 6
    # IP共用: 该 token 的某个IP被这么多不同账号共用即判「IP共用」
    ip_shared_min: int = 3


@dataclass
class Config:
    weights: Weights = field(default_factory=Weights)
    thresholds: Thresholds = field(default_factory=Thresholds)
    self_ips_file: str = os.path.join(DATA_DIR, "self_ips.txt")
    hosting_cidrs_file: str = os.path.join(DATA_DIR, "hosting_cidrs.txt")
    ua_clients_file: str = os.path.join(DATA_DIR, "ua_clients.txt")
    ip_blacklist_file: str = os.path.join(DATA_DIR, "ip_blacklist.txt")
    ua_blacklist_file: str = os.path.join(DATA_DIR, "ua_blacklist.txt")
    asn_blacklist_file: str = os.path.join(DATA_DIR, "asn_blacklist.txt")
    proxy_ips_file: str = os.path.join(DATA_DIR, "proxy_ips.txt")
    asn_mmdb_file: str = os.path.join(DATA_DIR, "GeoLite2-ASN.mmdb")      # MaxMind GeoLite2-ASN(优先)
    asn_db_file: str = os.path.join(DATA_DIR, "ip2asn-v4.tsv")           # iptoasn.com 数据(备选)
    asn_hosting_kw_file: str = os.path.join(DATA_DIR, "asn_hosting_keywords.txt")
    db_path: str = field(default_factory=_default_db_path)


CONFIG = Config()
