"""权重、阈值与路径配置。

所有判定参数集中在此,便于按真实数据校准。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


def _default_db_path() -> str:
    """DB 路径优先级: 环境变量 NEIGUI_DB > config.json 的 db_path > 默认。便于迁移。"""
    env = os.environ.get("NEIGUI_DB")
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
    return os.path.join(BASE_DIR, "neigui.db")


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
    online_ips: float = 18.0         # 单 token 近期在多个IP在线(分发/扫描)
    ip_shared: float = 22.0          # 该 token 的IP被多个账号共用(聚合点/攻击机)
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
    # 流量背离: 拉取够活跃 且 流量低于下限
    divergence_min_pulls: int = 10
    divergence_max_bytes: int = 50 * 1024 * 1024  # 50MB
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
    # 多UA: 一个 token 用过的不同 UA 数达此值即判「多UA」
    multi_ua_min: int = 4
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
    db_path: str = field(default_factory=_default_db_path)


CONFIG = Config()
