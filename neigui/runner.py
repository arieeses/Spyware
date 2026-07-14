"""运行器: 把"数据源"跑成实际动作(导入日志 / 同步 v2board)。CLI 与 Web 共用。"""
from __future__ import annotations

import glob
import json
import os
import time
from datetime import datetime
from typing import Tuple

from .log_parser import load_proxy_nets, parse_line
from .store import Store


def _parse_spec(spec: str):
    """每行 '路径' 或 '路径 | 归属标签'。返回 [(路径, 标签), ...]。"""
    out = []
    for line in (spec or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        label = ""
        if "|" in line:
            p, _, lb = line.partition("|")
            line, label = p.strip(), lb.strip()
        if line:
            out.append((line, label))
    return out


def _expand_one(pathspec: str):
    """单条路径: 目录→目录下 *.log; 通配→展开; 文件→自身。"""
    if os.path.isdir(pathspec):
        files = glob.glob(os.path.join(pathspec, "*.log"))
    elif any(ch in pathspec for ch in "*?["):
        files = glob.glob(pathspec)
    elif os.path.isfile(pathspec):
        files = [pathspec]
    else:
        files = []
    return sorted(set(os.path.abspath(f) for f in files))


def _expand_paths(spec: str):
    """展开所有行(忽略标签), 返回实际文件列表。"""
    files = []
    for pathspec, _ in _parse_spec(spec):
        files.extend(_expand_one(pathspec))
    return sorted(set(files))


def _ingest_one(store: Store, path: str, reset: bool, src: str = None, proxy_nets=None) -> int:
    st = os.stat(path)
    start = 0
    state = None if reset else store.get_ingest_state(path)
    if state and state["inode"] == st.st_ino and state["offset"] <= st.st_size:
        start = state["offset"]
    recs = []
    with open(path, encoding="utf-8", errors="replace") as f:
        f.seek(start)
        while True:
            line = f.readline()
            if not line:
                break
            rec = parse_line(line, proxy_nets)
            if rec is not None:
                recs.append(rec)
        end = f.tell()
    n = store.add_pulls(recs, src=src)
    store.set_ingest_state(path, end, st.st_ino)
    return n


def ingest_logfile(store: Store, path_spec: str, reset: bool = False,
                   src: str = None) -> Tuple[int, int, int]:
    """增量导入日志。path_spec 支持多行/通配(按日期滚动的日志用 *sub.log 匹配)。
    返回 (新增条数, 匹配文件数, 0)。每个文件各自记录 offset。"""
    proxy_nets = load_proxy_nets()
    total = nfiles = 0
    for pathspec, label in _parse_spec(path_spec):
        for f in _expand_one(pathspec):
            total += _ingest_one(store, f, reset, label or src, proxy_nets)
            nfiles += 1
    return total, nfiles, 0


def sync_v2board(store: Store, cfg: dict, panel: str = None):
    """返回 (用户数, 协议列表, 节点数, 中转数)。节点/协议探测失败不影响用户同步。"""
    from .connectors.v2board import V2BoardConnector
    paid_only = store.get_kv("sync_paid_only", "0") == "1"
    conn = V2BoardConnector(cfg)
    n = conn.sync_users(store, panel, paid_only=paid_only)
    if paid_only:
        store.purge_unpaid_users(panel)   # 顺带清掉本地已同步的"从未购买"用户
    try:
        conn.sync_traffic_daily(store, panel)   # 每日流量入本地(供详情页+流量对称); 失败不影响
    except Exception:  # noqa: BLE001
        pass
    try:
        protos, total, relay = conn.detect_nodes(store, panel)
    except Exception:  # noqa: BLE001
        protos, total, relay = [], 0, 0
    return n, protos, total, relay


def run_source(store: Store, src) -> Tuple[bool, str]:
    """执行一个数据源并记入运行日志。返回 (是否成功, 消息)。"""
    ok, msg = _run_source(store, src)
    try:
        store.add_runlog(src["type"], src["name"], ok, msg)
        store.set_kv(f"src_ok::{src['id']}", "1" if ok else "0")
        store.set_kv(f"src_seen::{src['id']}", str(time.time()))
    except Exception:  # noqa: BLE001
        pass
    return ok, msg


def _run_source(store: Store, src) -> Tuple[bool, str]:
    cfg = json.loads(src["config"] or "{}")
    try:
        if src["type"] == "logfile":
            if cfg.get("mode") == "push":
                return True, "推送源: 由远程服务器推送, 无需手动导入"
            if cfg.get("mode") == "syslog":
                return True, "syslog 直发: 由 Nginx 直接发送, 无需手动导入"
            if cfg.get("mode") == "agent":
                store.set_kv(f"agent_force::{cfg.get('key', '')}", "1")
                return True, "已通知探针立即上报(约数秒内刷新查看)"
            n, nf, _ = ingest_logfile(store, cfg["path"], src=(cfg.get("panel") or src["name"]))
            return True, f"导入 {n} 条新记录(匹配 {nf} 个文件)"
        if src["type"] == "v2board":
            n, protos, total, relay = sync_v2board(store, cfg, panel=src["name"])
            if total:
                return True, f"同步 {n} 用户, {total} 节点({len(protos)} 协议, {relay} 中转)"
            return True, f"同步 {n} 个用户"
        return False, f"未知类型: {src['type']}"
    except FileNotFoundError:
        return False, f"文件不存在: {cfg.get('path')}"
    except SystemExit as e:  # 缺 pymysql 等
        return False, str(e)
    except Exception as e:  # noqa: BLE001 - 面板要展示任何错误而非崩溃
        return False, f"错误: {e}"


def run_all(store: Store) -> str:
    msgs = []
    for src in store.list_sources():
        if not src["enabled"]:
            continue
        ok, msg = run_source(store, src)
        flag = "✓" if ok else "✗"
        msgs.append(f"{flag} [{src['name']}] {msg}")
    summary = " · ".join(msgs) if msgs else "无启用的数据源"
    store.set_kv("last_run_summary", summary)
    store.set_kv("last_run_ts", datetime.now().isoformat(timespec="seconds"))
    return summary
