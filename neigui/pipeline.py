"""全流程编排: 逐 token 聚合特征 → 评分 → 按分数排序。"""
from __future__ import annotations

import json
from dataclasses import asdict, replace
from typing import List

from .config import CONFIG, Config, Thresholds, Weights
from .enrich import Blacklist, IpClassifier, UaClassifier
from .features import build_features
from .scoring import RiskResult, score_token
from .store import Store


def load_config(store, base: Config = CONFIG) -> Config:
    """把面板里改过的权重/阈值(kv risk_overrides)覆盖到默认 config 上, 得到生效配置。"""
    raw = store.get_kv("risk_overrides", "")
    if not raw:
        return base
    try:
        ov = json.loads(raw)
    except (ValueError, TypeError):
        return base
    w = asdict(base.weights)
    th = asdict(base.thresholds)
    for k, v in (ov.get("weights") or {}).items():
        if k in w:
            try:
                w[k] = float(v)
            except (ValueError, TypeError):
                pass
    for k, v in (ov.get("thresholds") or {}).items():
        if k in th:
            try:
                th[k] = type(th[k])(float(v))   # 保持 int/float 原类型
            except (ValueError, TypeError):
                pass
    return replace(base, weights=Weights(**w), thresholds=Thresholds(**th))


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

_RECOMPUTE_LOCK = threading.Lock()


def scores_fingerprint(store: Store) -> str:
    """评分依赖的指纹: 数据版本 + 信号开关 + 权重阈值覆盖。任一变化就该重算。"""
    return (f"{store.data_version()}|{store.get_kv('signals_off', '')}"
            f"|{store.get_kv('risk_overrides', '')}")


def scores_stale(store: Store, max_age: int = 300) -> bool:
    """指纹变了, 或距上次重算超过 max_age 秒(让在线IP等时间相关信号保持新鲜)。"""
    if store.get_kv("scores_version", "") != scores_fingerprint(store):
        return True
    try:
        return (_time.time() - float(store.get_kv("scores_ts", "0") or 0)) > max_age
    except (ValueError, TypeError):
        return True


def recompute_scores(store: Store, cfg: Config = None) -> int:
    """全量评分并物化进 scores 表。后台(调度线程)调用, 不阻塞页面请求。"""
    with _RECOMPUTE_LOCK:
        cfg = cfg or load_config(store)
        fp = scores_fingerprint(store)          # 先取指纹, 期间若又变化下轮再算
        results = _analyze(store, cfg)
        store.replace_scores([_score_row(r) for r in results])
        store.set_kv("scores_version", fp)
        store.set_kv("scores_ts", str(_time.time()))
        return len(results)


def _score_row(r: RiskResult):
    sigs = [{"name": s.name, "points": s.points, "detail": s.detail, "tag": s.tag}
            for s in r.signals]
    return (r.token, r.score, r.level, 1 if r.excluded else 0,
            ",".join(r.tags), json.dumps(sigs, ensure_ascii=False),
            r.email, r.user_id, r.panel, r.plan,
            r.distinct_ips, r.online_ips, r.distinct_uas, r.ip_shared_users,
            r.pull_count, r.traffic_bytes,
            r.created_at.isoformat() if r.created_at else None,
            r.expired_at.isoformat() if r.expired_at else None,
            r.last_pull.isoformat() if r.last_pull else None)


def analyze(store: Store, cfg: Config = None) -> List[RiskResult]:
    """全量评分列表(内部/兜底用)。热路径(风险名单/仪表盘)改读 scores 表, 不再走这里。"""
    return _analyze(store, cfg or load_config(store))


def _analyze(store: Store, cfg: Config = CONFIG) -> List[RiskResult]:
    from datetime import datetime, timedelta, timezone
    ipc = IpClassifier()
    uac = UaClassifier()
    bl = Blacklist()
    off = _disabled_signals(store)
    win_h = cfg.thresholds.online_window_hours
    now = datetime.now(timezone.utc)
    since_iso = (now - timedelta(hours=max(1, win_h))).isoformat()
    from .enrich import FeatureLib
    featlib = FeatureLib(store)                   # 内鬼特征库(手工登记)
    ip_users = store.ip_user_counts(since_iso)   # 窗口内 IP→不同账号数
    ip_panels = store.ip_panel_map()             # IP→面板集合(跨面板同IP)
    email_panels = store.email_panel_map()       # 邮箱→面板集合(同邮箱多面板)
    results: List[RiskResult] = []
    pull_tokens = set(store.tokens())
    # 有拉取行为的用户: 正常评分
    for token in pull_tokens:
        feats = build_features(token, store.pulls_for(token), store.user(token), ipc, uac, bl,
                               ip_users=ip_users, window_hours=win_h, now=now,
                               ip_panels=ip_panels, email_panels=email_panels, featlib=featlib)
        results.append(score_token(feats, cfg, off))
    # 同步来但暂无拉取日志的用户: 仍按"画像信号"评分(如「有效期内零流量新号」重点排查),
    # 无拉取所以 IP/UA/ASN 等日志类信号不触发。空拉取的 build_features 很轻。
    for u in store.all_users():
        if u["token"] in pull_tokens:
            continue
        feats = build_features(u["token"], [], u, ipc, uac, bl,
                               ip_users=ip_users, window_hours=win_h, now=now,
                               email_panels=email_panels, featlib=featlib)
        results.append(score_token(feats, cfg, off))
    results.sort(key=lambda r: r.score, reverse=True)
    return results


def decide(store: Store, token: str, cfg: Config = None) -> dict:
    """给订阅网关用: 返回某 token 的处置池。
    pool: normal(真实节点) / limited(限速节点) / isolated(隔离/特定IP节点)。
    """
    from datetime import datetime, timedelta, timezone
    cfg = cfg or load_config(store)
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
