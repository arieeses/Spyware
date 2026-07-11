"""运行器: 把"数据源"跑成实际动作(导入日志 / 同步 v2board)。CLI 与 Web 共用。"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Tuple

from .log_parser import parse_line
from .store import Store


def ingest_logfile(store: Store, path: str, reset: bool = False) -> Tuple[int, int, int]:
    """增量导入单个日志文件。返回 (新增条数, 起始offset, 结束offset)。"""
    path = os.path.abspath(path)
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
            rec = parse_line(line)
            if rec is not None:
                recs.append(rec)
        end = f.tell()
    n = store.add_pulls(recs)
    store.set_ingest_state(path, end, st.st_ino)
    return n, start, end


def sync_v2board(store: Store, cfg: dict, panel: str = None):
    """返回 (用户数, 协议列表, 节点数, 中转数)。节点/协议探测失败不影响用户同步。"""
    from .connectors.v2board import V2BoardConnector
    conn = V2BoardConnector(cfg)
    n = conn.sync_users(store, panel)
    try:
        protos, total, relay = conn.detect_nodes(store, panel)
    except Exception:  # noqa: BLE001
        protos, total, relay = [], 0, 0
    return n, protos, total, relay


def run_source(store: Store, src) -> Tuple[bool, str]:
    """执行一个数据源, 返回 (是否成功, 消息)。异常不抛出, 转成消息。"""
    cfg = json.loads(src["config"] or "{}")
    try:
        if src["type"] == "logfile":
            if cfg.get("mode") == "push":
                return True, "推送源: 由远程服务器推送, 无需手动导入"
            if cfg.get("mode") == "syslog":
                return True, "syslog 直发: 由 Nginx 直接发送, 无需手动导入"
            if cfg.get("mode") == "agent":
                return True, "探针接入: 由被控 agent 上报, 无需手动导入"
            n, _, _ = ingest_logfile(store, cfg["path"])
            return True, f"导入 {n} 条新记录"
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
