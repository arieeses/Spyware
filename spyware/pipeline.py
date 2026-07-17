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


def apply_auto_insider_rules(store: Store, results) -> set:
    """按「自动入库规则」把命中特征库的账号移入内鬼库, 并刷新命中直方图(供预览)。
    规则=一组必须同时命中的特征类型(AND), 规则之间 OR。返回本轮被移入的 token 集合。
    同时把"每种命中类型组合的账号数"写入 kv feat_kind_hist, 供 UI 预览任意规则命中量。"""
    rules = store.get_auto_insider_rules()
    enabled = [set(r["conds"]) for r in rules if r.get("on") and r.get("conds")]
    insiders = store.insider_tokens()
    hist: dict = {}
    promoted: set = set()
    for r in results:
        if r.token in insiders or r.excluded:
            continue
        ks = r.feature_kinds or set()
        if not ks:
            continue
        key = ",".join(sorted(ks))               # 命中类型组合 → 计数(预览用)
        hist[key] = hist.get(key, 0) + 1
        if any(conds <= ks for conds in enabled):
            promoted.add(r.token)
    if promoted:
        from .asn import get_asndb
        asndb = get_asndb()
        by_token = {r.token: r for r in results}
        for tok in promoted:
            r = by_token.get(tok)
            pulls = list(store.pulls_for(tok))
            ips = sorted({p["ip"] for p in pulls if p["ip"]})
            uas = sorted({p["ua"] for p in pulls if p["ua"]})
            asns = sorted({asndb.lookup(ip)[0] for ip in ips
                           if asndb and asndb.lookup(ip)[0]}) if asndb else []
            store.add_insider(tok, email=(r.email if r else None), panel=(r.panel if r else None),
                              ips=ips, uas=uas, asns=list(asns), tags=store.score_tags(tok))
        try:
            store.add_runlog("auto", "自动入库", True, f"命中规则自动移入内鬼库 {len(promoted)} 个")
        except Exception:  # noqa: BLE001
            pass
    store.set_kv("feat_kind_hist", json.dumps(hist, ensure_ascii=False))
    return promoted


def recompute_scores(store: Store, cfg: Config = None) -> int:
    """全量评分并物化进 scores 表。后台(调度线程)调用, 不阻塞页面请求。"""
    with _RECOMPUTE_LOCK:
        cfg = cfg or load_config(store)
        results = _analyze(store, cfg)
        promoted = apply_auto_insider_rules(store, results)   # 命中规则的账号移入内鬼库
        fp = scores_fingerprint(store)          # 取指纹(含入库导致的版本变化), 期间若又变化下轮再算
        store.replace_scores([_score_row(r) for r in results if r.token not in promoted])
        store.set_kv("scores_version", fp)
        store.set_kv("scores_ts", str(_time.time()))
        return len(results)


def recompute_one(store: Store, token: str, cfg: Config = None) -> None:
    """只重算并写回单个 token 的评分(移出内鬼库后立即让它回名单, 不等后台全量)。"""
    from datetime import datetime, timedelta, timezone
    from .enrich import Blacklist, IpClassifier, UaClassifier, FeatureLib, InsiderMatcher
    cfg = cfg or load_config(store)
    if token in store.insider_tokens():
        return
    off = _disabled_signals(store)
    win_h = cfg.thresholds.online_window_hours
    now = datetime.now(timezone.utc)
    since_iso = (now - timedelta(hours=max(1, win_h))).isoformat()
    feats = build_features(
        token, store.pulls_for(token), store.user(token),
        IpClassifier(), UaClassifier(), Blacklist(),
        ip_users=store.ip_user_counts_for_token(token, since_iso),
        window_hours=win_h, now=now,
        ip_panels=store.ip_panel_map(), email_panels=store.email_panel_map(),
        featlib=FeatureLib(store), insmatch=InsiderMatcher(store, cfg.thresholds.insider_subnet_prefix),
        burst_window=cfg.thresholds.burst_ua_window,
        night_start=cfg.thresholds.night_start_hour, night_end=cfg.thresholds.night_end_hour)
    store.upsert_score(_score_row(score_token(feats, cfg, off)))


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
            r.last_pull.isoformat() if r.last_pull else None,
            r.main_ip)


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
    from .enrich import FeatureLib, InsiderMatcher
    featlib = FeatureLib(store)                       # 特征库(手工登记)
    insmatch = InsiderMatcher(store, cfg.thresholds.insider_subnet_prefix)  # 内鬼库分维度匹配
    insiders = store.insider_tokens()                 # 已移入内鬼库的账号: 不再评分/进名单
    ip_users = store.ip_user_counts(since_iso)   # 窗口内 IP→不同账号数
    ip_panels = store.ip_panel_map()             # IP→面板集合(跨面板同IP)
    email_panels = store.email_panel_map()       # 邮箱→面板集合(同邮箱多面板)
    results: List[RiskResult] = []
    pull_tokens = set(store.tokens())
    # 有拉取行为的用户: 正常评分
    bw = cfg.thresholds.burst_ua_window
    ns, ne = cfg.thresholds.night_start_hour, cfg.thresholds.night_end_hour
    for token in pull_tokens:
        if token in insiders:
            continue
        feats = build_features(token, store.pulls_for(token), store.user(token), ipc, uac, bl,
                               ip_users=ip_users, window_hours=win_h, now=now,
                               ip_panels=ip_panels, email_panels=email_panels, featlib=featlib,
                               burst_window=bw, night_start=ns, night_end=ne, insmatch=insmatch)
        results.append(score_token(feats, cfg, off))
    # 同步来但暂无拉取日志的用户: 仍按"画像信号"评分(如「有效期内零流量新号」重点排查),
    # 无拉取所以 IP/UA/ASN 等日志类信号不触发。空拉取的 build_features 很轻。
    for u in store.all_users():
        if u["token"] in pull_tokens or u["token"] in insiders:
            continue
        feats = build_features(u["token"], [], u, ipc, uac, bl,
                               ip_users=ip_users, window_hours=win_h, now=now,
                               email_panels=email_panels, featlib=featlib, insmatch=insmatch)
        results.append(score_token(feats, cfg, off))
    results.sort(key=lambda r: r.score, reverse=True)
    return results
