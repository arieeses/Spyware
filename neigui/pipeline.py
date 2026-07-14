"""全流程编排: 逐 token 聚合特征 → 评分 → 按分数排序。"""
from __future__ import annotations

from typing import List

from .config import CONFIG, Config
from .enrich import Blacklist, IpClassifier, UaClassifier
from .features import build_features
from .scoring import RiskResult, score_token
from .store import Store


def _pdt(s):
    from datetime import datetime
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _disabled_signals(store) -> set:
    import json
    raw = store.get_kv("signals_off", "")
    try:
        return set(json.loads(raw)) if raw else set()
    except (ValueError, TypeError):
        return set()


import threading
import time as _time

_ANALYZE_CACHE = {"key": None, "val": None}
_ANALYZE_LOCK = threading.Lock()


def analyze(store: Store, cfg: Config = CONFIG) -> List[RiskResult]:
    """带缓存: 数据未变(data_version 不变)且在 5 分钟窗口内, 直接复用上次结果。
    翻页/筛选/搜索都走缓存, 不再对全部用户重算。"""
    key = (store.data_version(), store.get_kv("signals_off", ""),
           store.get_kv("rewrite_scope", ""), int(_time.time() // 300))
    with _ANALYZE_LOCK:
        if _ANALYZE_CACHE["key"] == key and _ANALYZE_CACHE["val"] is not None:
            return _ANALYZE_CACHE["val"]
    val = _analyze(store, cfg)
    with _ANALYZE_LOCK:
        _ANALYZE_CACHE["key"] = key
        _ANALYZE_CACHE["val"] = val
    return val


def _analyze(store: Store, cfg: Config = CONFIG) -> List[RiskResult]:
    from datetime import datetime, timedelta, timezone
    ipc = IpClassifier()
    uac = UaClassifier()
    bl = Blacklist()
    off = _disabled_signals(store)
    win_h = cfg.thresholds.online_window_hours
    now = datetime.now(timezone.utc)
    since_iso = (now - timedelta(hours=max(1, win_h))).isoformat()
    ip_users = store.ip_user_counts(since_iso)   # 窗口内 IP→不同账号数
    results: List[RiskResult] = []
    pull_tokens = set(store.tokens())
    # 有拉取行为的用户: 正常评分
    for token in pull_tokens:
        feats = build_features(token, store.pulls_for(token), store.user(token), ipc, uac, bl,
                               ip_users=ip_users, window_hours=win_h, now=now)
        results.append(score_token(feats, cfg, off))
    # 同步来但暂无拉取日志的用户: 显示为"正常/待评估"(拉取0), 便于查看/搜索
    for u in store.all_users():
        if u["token"] in pull_tokens:
            continue
        cols = u.keys()
        results.append(RiskResult(
            u["token"], 0.0, "正常", excluded=False,
            email=(u["email"] if "email" in cols else None),
            user_id=(u["user_id"] if "user_id" in cols else None),
            panel=(u["panel"] if "panel" in cols else None),
            plan=(u["plan"] if "plan" in cols else None),
            traffic_bytes=(u["traffic_bytes"] or 0) if "traffic_bytes" in cols else 0,
            created_at=_pdt(u["created_at"]) if "created_at" in cols else None,
            expired_at=_pdt(u["expired_at"]) if "expired_at" in cols else None,
        ))
    results.sort(key=lambda r: r.score, reverse=True)
    return results


def decide(store: Store, token: str, cfg: Config = CONFIG) -> dict:
    """给订阅网关用: 返回某 token 的处置池。
    pool: normal(真实节点) / limited(限速节点) / isolated(隔离/特定IP节点)。
    """
    from datetime import datetime, timedelta, timezone
    pulls = store.pulls_for(token)
    user = store.user(token)
    win_h = cfg.thresholds.online_window_hours
    now = datetime.now(timezone.utc)
    since_iso = (now - timedelta(hours=max(1, win_h))).isoformat()
    feats = build_features(token, pulls, user, IpClassifier(), UaClassifier(), Blacklist(),
                           ip_users=store.ip_user_counts(since_iso), window_hours=win_h, now=now)
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
