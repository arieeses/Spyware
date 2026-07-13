"""全流程编排: 逐 token 聚合特征 → 评分 → 按分数排序。"""
from __future__ import annotations

from typing import List

from .config import CONFIG, Config
from .enrich import Blacklist, IpClassifier, UaClassifier
from .features import build_features
from .scoring import RiskResult, score_token
from .store import Store


def _disabled_signals(store) -> set:
    import json
    raw = store.get_kv("signals_off", "")
    try:
        return set(json.loads(raw)) if raw else set()
    except (ValueError, TypeError):
        return set()


def analyze(store: Store, cfg: Config = CONFIG) -> List[RiskResult]:
    ipc = IpClassifier()
    uac = UaClassifier()
    bl = Blacklist()
    off = _disabled_signals(store)
    results: List[RiskResult] = []
    pull_tokens = set(store.tokens())
    # 有拉取行为的用户: 正常评分
    for token in pull_tokens:
        feats = build_features(token, store.pulls_for(token), store.user(token), ipc, uac, bl)
        results.append(score_token(feats, cfg, off))
    # 同步来但暂无拉取日志的用户: 显示为"正常/待评估"(拉取0), 便于查看/搜索
    for u in store.all_users():
        if u["token"] in pull_tokens:
            continue
        results.append(RiskResult(
            u["token"], 0.0, "正常", excluded=False,
            email=(u["email"] if "email" in u.keys() else None),
            user_id=(u["user_id"] if "user_id" in u.keys() else None),
            panel=(u["panel"] if "panel" in u.keys() else None),
            traffic_bytes=(u["traffic_bytes"] or 0) if "traffic_bytes" in u.keys() else 0,
        ))
    results.sort(key=lambda r: r.score, reverse=True)
    return results


def decide(store: Store, token: str, cfg: Config = CONFIG) -> dict:
    """给订阅网关用: 返回某 token 的处置池。
    pool: normal(真实节点) / limited(限速节点) / isolated(隔离/特定IP节点)。
    """
    pulls = store.pulls_for(token)
    user = store.user(token)
    feats = build_features(token, pulls, user, IpClassifier(), UaClassifier(), Blacklist())
    r = score_token(feats, cfg, _disabled_signals(store))
    # 分级 → (处置池, 入口域名 key, 等级名)
    if feats.blacklist_hit:
        pool, dkey, tier = "isolated", "insider", "内鬼专用"
    elif r.level == "高":
        pool, dkey, tier = "isolated", "high", "高风险"
    elif r.level == "中":
        pool, dkey, tier = "limited", "mid", "中风险"
    elif r.level == "低":
        pool, dkey, tier = "normal", "low", "低风险"
    else:
        pool, dkey, tier = "normal", "normal", "正常用户"
    # 用户归属面板 → 该面板+等级下每个协议的入口域名
    import json as _json
    panel = user["panel"] if user is not None and "panel" in user.keys() else None
    dm = {}
    try:
        dm = _json.loads(store.get_kv("domains_map", "") or "{}")
    except (ValueError, TypeError):
        dm = {}
    domains = dm.get(panel, {}).get(dkey, {}) if panel else {}
    # 下发范围: relay=只改写中转节点(parent_id 非空), 直连节点忽略; all=全部
    scope = store.get_kv("rewrite_scope", "relay") or "relay"
    return {"token": token, "level": r.level, "score": r.score,
            "blacklist": feats.blacklist_hit, "tier": tier, "tier_key": dkey,
            "pool": pool, "panel": panel, "scope": scope, "domains": domains}
