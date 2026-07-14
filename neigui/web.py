"""本地可视化控制后台(零依赖, 标准库 http.server)。

  python3 -m neigui.web            # http://127.0.0.1:8787

侧边栏分类导航: 仪表盘 / 接入管理(v2board·1Panel·aaPanel) / 风险管理 / 运行。
注意: 无鉴权, 仅绑定 127.0.0.1; 勿直接暴露公网(v2board 密码存在本地库)。
"""
from __future__ import annotations

import argparse
import html
import json
import math
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import asdict
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

from . import __version__, auth, sysinfo
from .config import BASE_DIR, CONFIG
from .log_parser import parse_line
from .pipeline import analyze, decide
from .runner import run_all, run_source
from .store import Store

# 风险配色: 正常=绿 低=淡黄 中=淡红 高=红
LEVEL_COLOR = {"高": "#e5484d", "中": "#ff7d7d", "低": "#f0d264", "正常": "#3ab76a"}
LEVEL_FG = {"高": "#fff", "中": "#fff", "低": "#6b5300", "正常": "#fff"}
LEVEL_TEXT = {"高": "高风险", "中": "中风险", "低": "低风险", "正常": "正常"}
TAG_COLOR = {
    "黑名单": "#e5484d", "UA伪造": "#e5484d", "已到期": "#e5484d",
    "机房IP": "#e6a23c", "流量背离": "#e6a23c", "注册侦察": "#e6a23c", "设备超限": "#e6a23c",
    "可疑客户端": "#d4a72c", "自动化": "#d4a72c",
}

# 侧边栏线性图标(aaPanel 风格)
ICONS = {
    "dashboard": '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
    "v2board": '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    "log": '<path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8z"/><path d="M14 3v5h5"/><path d="M8 13h8M8 17h5"/>',
    "risk": '<path d="M12 3l8 3v5c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6z"/><path d="M12 9v4M12 16h.01"/>',
    "rules": '<path d="M4 8h9M17 8h3M4 16h3M11 16h9"/><circle cx="15" cy="8" r="2"/><circle cx="9" cy="16" r="2"/>',
    "whitelist": '<path d="M12 3l8 3v5c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
    "domains": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18"/>',
    "runlog": '<path d="M8 6h13M8 12h13M8 18h13"/><path d="M3 6h.01M3 12h.01M3 18h.01"/>',
    "run": '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 3v6h-6"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.6-2-3.5-2.4 1a7 7 0 0 0-1.7-1L14.5 2h-4l-.3 2.4a7 7 0 0 0-1.7 1l-2.4-1-2 3.5L4.1 11a7 7 0 0 0 0 2l-2 1.6 2 3.5 2.4-1a7 7 0 0 0 1.7 1l.3 2.4h4l.3-2.4a7 7 0 0 0 1.7-1l2.4 1 2-3.5-2-1.6a7 7 0 0 0 .1-1z"/>',
    "update": '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 3v6h-6"/><path d="M12 8v4l3 2"/>',
    "backend": '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    "relay": '<path d="M4 8h12M4 8l3-3M4 8l3 3"/><path d="M20 16H8M20 16l-3-3M20 16l-3 3"/>',
    "template": '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/>',
}


def icon(key: str) -> str:
    return (f'<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" '
            f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{ICONS.get(key, "")}</svg>')

# 侧边栏导航: (分组标题, [(key, 名称, 路径)])
NAV = [
    ("", [("dashboard", "仪表盘", "/")]),
    ("接入管理", [
        ("v2board", "前端面板", "/panels/v2board"),
        ("log", "日志接入", "/panels/log"),
        ("logstore", "日志库", "/logstore"),
    ]),
    ("风险管理", [
        ("risk", "风险名单", "/risk"),
        ("rules", "风险规则", "/rules"),
        ("whitelist", "黑白名单", "/whitelist"),
        ("domains", "入口域名", "/domains"),
    ]),
    ("运行", [
        ("run", "运行控制", "/run"),
        ("runlog", "运行日志", "/runlog"),
    ]),
    ("系统", [
        ("settings", "系统设置", "/settings"),
    ]),
]

# 节点管理实体类型的中文名
ENTITY_META = {
    "backend": ("后端机", "落地/后端服务器(IP、端口、备注)"),
    "relay": ("中转", "中转/转发节点(入口→出口)"),
    "template": ("协议模板", "协议参数模板(vmess/vless/trojan/hysteria 等)"),
}

AGENT_PATH = os.path.join(BASE_DIR, "agent", "neigui-agent.py")

# 被控探针一键安装脚本(__MASTER__/__TOKEN__ 由主控按请求 Host 注入)
AGENT_INSTALL = """#!/bin/bash
set -e
MASTER="__MASTER__"
TOKEN="__TOKEN__"
LOG="${LOG:-/www/wwwlogs/neigui_sub.log}"
# 兼容旧版: 若装过 neigui-agent 先移除
systemctl disable --now neigui-agent 2>/dev/null || true
rm -f /etc/systemd/system/neigui-agent.service 2>/dev/null || true
mkdir -p /opt/spyware-agent
curl -fsS "$MASTER/agent/agent.py" -o /opt/spyware-agent/agent.py
cat >/etc/systemd/system/spyware-agent.service <<UNIT
[Unit]
Description=Spyware Agent (探针)
After=network.target
[Service]
ExecStart=/usr/bin/python3 /opt/spyware-agent/agent.py --master $MASTER --token $TOKEN --log $LOG --state /opt/spyware-agent/state.json
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now spyware-agent
echo "spyware-agent 已安装并启动 (log: $LOG)"
"""

# 分级入口域名: (key, 名称, 说明)
DOMAIN_TIERS = [
    ("normal", "正常用户", "风险正常的用户从此入口拉取订阅(真实节点)。"),
    ("low", "低风险", "低风险用户入口(可与正常相同, 或单独观察)。"),
    ("mid", "中风险", "中风险用户入口(可对应限速节点池)。"),
    ("high", "高风险", "高风险用户入口(隔离节点, 可随时封禁不影响正常用户)。"),
    ("insider", "内鬼专用", "命中黑名单的确认内鬼专用入口: 下发特定IP/蜜罐节点, 便于溯源/投毒。"),
]


# ————————————————— 通用 —————————————————

def esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _pull_count(store: Store) -> int:
    return store.conn.execute("SELECT COUNT(*) c FROM pulls").fetchone()["c"]


def _humanize(dt) -> str:
    if dt is None:
        return "-"
    try:
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
        sec = max(0, (now - dt).total_seconds())
    except (TypeError, ValueError):
        return "-"
    if sec < 60:
        return "刚刚"
    if sec < 3600:
        return f"{int(sec // 60)} 分钟前"
    if sec < 86400:
        return f"{int(sec // 3600)} 小时前"
    return f"{int(sec // 86400)} 天前"


def _source_detail(src) -> str:
    cfg = json.loads(src["config"] or "{}")
    if src["type"] == "logfile":
        if cfg.get("mode") == "push":
            return f'<span class="dim">推送接入 · key:</span> <span class="mono">{esc(cfg.get("key",""))}</span>'
        if cfg.get("mode") == "syslog":
            return f'<span class="dim">syslog 直发 · tag:</span> <span class="mono">{esc(cfg.get("tag",""))}</span>'
        return esc(cfg.get("path", ""))
    if src["type"] == "v2board":
        return esc(f"{cfg.get('user')}@{cfg.get('host')}:{cfg.get('port')}/{cfg.get('database')} (前缀 {cfg.get('prefix')})")
    return esc(src["config"])


def _paginate(size, page, total, default):
    """返回 (每页数, 当前页, 总页数, 是否全部)。"""
    if str(size) == "all":
        return (total or 1), 1, 1, True
    psize = int(size) if str(size).isdigit() else default
    pages = max(1, (total + psize - 1) // psize)
    pg = min(max(1, int(page) if str(page).isdigit() else 1), pages)
    return psize, pg, pages, False


def _pager_html(path, base, size, page, pages, sizes):
    """Element 风格分页: ‹ 1 2 … N › + 每页下拉。base=要保留的查询参数 dict。"""
    def purl(p, sz=None):
        q = dict(base); q["page"] = p; q["size"] = sz if sz is not None else size
        return path + "?" + "&".join(f"{k}={quote(str(v))}" for k, v in q.items())
    nums, prevd, show = [], None, {1, pages}
    for p in range(page - 2, page + 3):
        if 1 <= p <= pages:
            show.add(p)
    for p in sorted(show):
        if prevd is not None and p - prevd > 1:
            nums.append('<span class="pg dot">…</span>')
        nums.append(f'<a class="{"pg cur" if p==page else "pg"}" href="{purl(p)}">{p}</a>')
        prevd = p
    prev = f'<a class="pg" href="{purl(page-1)}">‹</a>' if page > 1 else '<span class="pg dis">‹</span>'
    nxt = f'<a class="pg" href="{purl(page+1)}">›</a>' if page < pages else '<span class="pg dis">›</span>'
    opts = "".join(f'<option value="{purl(1, s)}" {"selected" if str(size)==str(s) else ""}>'
                   f'{"全部" if s=="all" else str(s)+" 条/页"}</option>' for s in sizes)
    sel = f'<select class="pg-sel" onchange="location.href=this.value">{opts}</select>'
    return f'<div class="pager">{prev}{"".join(nums)}{nxt}{sel}</div>'


RISK_COLS = [("uid", "用户ID"), ("email", "邮箱"), ("panel", "机场"), ("token", "Token"),
             ("ips", "IP数"), ("online", "在线IP"), ("uas", "UA数"), ("shared", "共用账号"),
             ("pull", "拉取"), ("score", "风险分"), ("level", "风险等级"),
             ("tags", "风险标签"), ("created", "注册时间"), ("expired", "到期时间"), ("last", "最后活跃")]
_NUM_COLS = {"uid", "ips", "online", "uas", "shared", "pull", "score"}
_DASH = '<span class="dim">—</span>'


def _th_attr(k: str) -> str:
    return ' data-t="num"' if k in _NUM_COLS else ''


def _human_bytes(n) -> str:
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"


def _user_detail(store, tok: str) -> dict:
    from .enrich import Blacklist, IpClassifier, UaClassifier
    from .features import build_features
    from .pipeline import _disabled_signals
    from .scoring import score_token
    user = store.user(tok)
    pulls = list(store.pulls_for(tok))
    if not user and not pulls:
        return {"error": "未找到该用户"}
    from datetime import timedelta, timezone
    win_h = CONFIG.thresholds.online_window_hours
    _now = datetime.now(timezone.utc)
    _since = (_now - timedelta(hours=max(1, win_h))).isoformat()
    r = score_token(build_features(tok, pulls, user, IpClassifier(), UaClassifier(), Blacklist(),
                                   ip_users=store.ip_user_counts(_since), window_hours=win_h, now=_now),
                    CONFIG, _disabled_signals(store))
    plan = user["plan"] if user and "plan" in user.keys() else None
    has_plan = bool(plan and str(plan) not in ("", "0", "None"))
    if r.expired_at:
        exp = r.expired_at.strftime("%Y-%m-%d %H:%M")
    elif r.created_at:
        exp = "永久" if has_plan else "未购买"
    else:
        exp = "-"
    d = {
        "token": tok, "email": r.email, "user_id": r.user_id, "panel": r.panel,
        "plan": (f"套餐 #{plan}" if has_plan else None),
        "created_at": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else "-",
        "expired": exp,
        "banned": (user["banned"] if user and "banned" in user.keys() else 0),
        "traffic": _human_bytes(r.traffic_bytes), "score": r.score, "level": r.level,
        "signals": [s.name for s in r.signals],
        "pull_count": r.pull_count, "distinct_ips": r.distinct_ips,
        "distinct_uas": r.distinct_uas, "online_ips": r.online_ips,
        "ip_shared_users": r.ip_shared_users,
        "pulls": [{"ts": (p["ts"] or "")[:19].replace("T", " "), "ip": p["ip"],
                   "ua": (p["ua"] or "")[:30]} for p in pulls[-15:][::-1]],
    }
    orders, omsg = [], "无订单记录"
    if r.panel and r.user_id:
        src = next((s for s in store.list_sources()
                    if s["type"] == "v2board" and s["name"] == r.panel), None)
        if src:
            try:
                from .connectors.v2board import V2BoardConnector
                orders = V2BoardConnector(json.loads(src["config"] or "{}")).query_orders(r.user_id)
            except Exception as e:  # noqa: BLE001
                omsg = f"订单查询失败: {e}"
    d["orders"], d["orders_msg"] = orders, omsg
    return d


def _mask(s: str) -> str:
    """打码: 只显示首尾, 中间星号。用于二次编辑时不明文回显库名/IP。"""
    s = str(s or "")
    if len(s) <= 4:
        return "****" if s else ""
    return s[:2] + "****" + s[-2:]


def _source_by_key(store, key: str):
    if not key:
        return None
    for s in store.list_sources():
        try:
            if json.loads(s["config"] or "{}").get("key") == key:
                return s
        except (ValueError, TypeError):
            continue
    return None


def _seed_defaults(store: Store) -> None:
    if store.list_sources():
        return
    sample_log = os.path.join(BASE_DIR, "sample", "sub.log")
    if os.path.exists(sample_log):
        store.add_source("logfile", "示例日志", json.dumps({"path": sample_log}))
    users = os.path.join(BASE_DIR, "sample", "users.json")
    if os.path.exists(users):
        with open(users, encoding="utf-8") as f:
            for u in json.load(f):
                store.upsert_user(
                    token=u["token"], user_id=u.get("user_id"), email=u.get("email"),
                    plan=u.get("plan"), group_id=u.get("group_id"),
                    created_at=u.get("created_at"), traffic_bytes=u.get("traffic_bytes", 0),
                    banned=u.get("banned", 0))
    for src in store.list_sources():
        run_source(store, src)


# ————————————————— 后台自动运行 —————————————————

class SyslogListener(threading.Thread):
    """接收 Nginx 直发的 syslog 日志(UDP), 按源 tag 匹配后入库。远程零额外软件。"""

    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port = port

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.port))
        except OSError as e:
            print(f"syslog 监听启动失败(:{self.port}) {e}")
            return
        while True:
            try:
                data, _ = sock.recvfrom(65535)
                text = data.decode("utf-8", "replace")
                store = Store()
                try:
                    for s in store.list_sources():
                        cfg = json.loads(s["config"] or "{}")
                        tag = cfg.get("tag")
                        if not tag:
                            continue
                        i = text.find(tag + ": ")
                        if i >= 0:
                            rec = parse_line(text[i + len(tag) + 2:].strip())
                            if rec:
                                store.add_pulls([rec], src=s["name"])
                            break
                finally:
                    store.close()
            except Exception:  # noqa: BLE001
                pass


class Scheduler(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                sysinfo.get_metrics()  # 保持 CPU 采样新鲜
            except Exception:  # noqa: BLE001
                pass
            try:
                store = Store()
                master = store.get_kv("auto_enabled", "0") == "1"
                now = time.time()
                ran = []
                for src in store.list_sources():
                    if not src["enabled"]:
                        continue
                    try:
                        scfg = json.loads(src["config"] or "{}")
                    except (ValueError, TypeError):
                        scfg = {}
                    # 探针是被控主动上报, 中央无需按间隔"跑"它(否则每周期都强制+刷屏)
                    if scfg.get("mode") in ("agent", "push", "syslog"):
                        continue
                    mode = scfg.get("sync_mode", "manual")
                    # auto: 独立按间隔跑; follow: 仅当全局总开关开启才跑; manual: 不自动
                    if mode == "auto":
                        active = True
                    elif mode == "follow":
                        active = master
                    else:
                        continue
                    if not active:
                        continue
                    iv = (src["interval"] if "interval" in src.keys() else 300) or 300
                    last = float(store.get_kv(f"src_last_{src['id']}", "0") or 0)
                    if now - last >= iv:
                        ok, msg = run_source(store, src)
                        store.set_kv(f"src_last_{src['id']}", str(now))
                        ran.append(f"{'✓' if ok else '✗'} [{src['name']}] {msg}")
                if ran:
                    store.set_kv("last_run_summary", " · ".join(ran))
                    store.set_kv("last_run_ts", datetime.now().isoformat(timespec="seconds"))
                store.close()
            except Exception:  # noqa: BLE001
                pass
            self._stop.wait(5)


# ————————————————— 各视图内容 —————————————————

def _ring(label: str, pct, center: str, sub: str) -> str:
    """aaPanel 风格环形仪表: 绿<70, 橙<90, 红≥90。"""
    p = 0 if pct is None else max(0.0, min(100.0, pct))
    color = "#3ab76a" if p < 70 else ("#e6a23c" if p < 90 else "#e5484d")
    r, cx = 52, 60
    circ = 2 * math.pi * r
    dash = circ * p / 100
    center = center if pct is not None else "N/A"
    return f"""
    <div class="gauge">
      <div class="glabel">{esc(label)}</div>
      <svg viewBox="0 0 120 120" width="118" height="118">
        <circle cx="{cx}" cy="{cx}" r="{r}" fill="none" stroke="#eceff3" stroke-width="9"/>
        <circle cx="{cx}" cy="{cx}" r="{r}" fill="none" stroke="{color}" stroke-width="9"
          stroke-linecap="round" stroke-dasharray="{dash:.1f} {circ:.1f}"
          transform="rotate(-90 {cx} {cx})"/>
        <text x="{cx}" y="{cx+6}" text-anchor="middle" font-size="22" font-weight="700" fill="{color}">{esc(center)}</text>
      </svg>
      <div class="gsub">{esc(sub)}</div>
    </div>"""


def render_load_panel() -> str:
    m = sysinfo.get_metrics()
    load = m.get("load")
    load_center = f"{m['load_pct']:.0f}%" if m.get("load_pct") is not None else "N/A"
    load_sub = "运行平稳" if (load is not None and load < m["cores"]) else (f"负载 {load:.2f}" if load is not None else "-")
    cpu = m.get("cpu_pct")
    mem_p = m.get("mem_pct")
    mem_sub = (f"{m['mem_used']} / {m['mem_total']}(MB)" if m.get("mem_total") else "-")
    disk_p = m.get("disk_pct")
    disk_sub = (f"{m['disk_used']/1073741824:.2f}G / {m['disk_total']/1073741824:.2f}G" if m.get("disk_total") else "-")
    rings = "".join([
        _ring("负载状态", m.get("load_pct"), load_center, load_sub),
        _ring("CPU 使用", cpu, f"{cpu:.0f}%" if cpu is not None else "N/A", f"{m['cores']} 核"),
        _ring("内存使用", mem_p, f"{mem_p:.1f}%" if mem_p is not None else "N/A", mem_sub),
        _ring("磁盘 /", disk_p, f"{disk_p:.0f}%" if disk_p is not None else "N/A", disk_sub),
    ])
    return f'<div class="card"><div class="card-title">服务器实时负载</div><div class="gauges">{rings}</div></div>'


def render_dashboard(store: Store) -> str:
    results = analyze(store)
    counts = {"高": 0, "中": 0, "低": 0, "正常": 0}
    excluded = 0
    for r in results:
        counts[r.level] = counts.get(r.level, 0) + 1
        excluded += 1 if r.excluded else 0
    srcs = store.list_sources()
    n_v2b = sum(1 for s in srcs if s["type"] == "v2board")
    n_log = sum(1 for s in srcs if s["type"] == "logfile")
    auto = store.get_kv("auto_enabled", "0") == "1"
    last_run = store.get_kv("last_run_summary", "尚未运行")
    last_ts = store.get_kv("last_run_ts", "")

    def stat(label, val, color="#5b8def", sub="", href="#"):
        return (f'<a class="stat" href="{href}"><div class="sval" style="color:{color}">{val}</div>'
                f'<div class="slabel">{label}</div><div class="ssub">{esc(sub)}</div></a>')

    stats = "".join([
        stat("高风险", counts["高"], LEVEL_COLOR["高"], href="/risk?level=高"),
        stat("中风险", counts["中"], LEVEL_COLOR["中"], href="/risk?level=中"),
        stat("低风险", counts["低"], LEVEL_COLOR["低"], href="/risk?level=低"),
        stat("正常/排除", f'{counts["正常"]}/{excluded}', "#8b8f98", href="/risk"),
        stat("用户总数", len(results), href="/risk"),
        stat("拉取记录", _pull_count(store), href="/runlog"),
        stat("v2board 面板", n_v2b, "#7c5cff", href="/panels/v2board"),
        stat("日志源", n_log, "#7c5cff", href="/panels/log"),
    ])
    return f"""
    <div class="card">
      <div class="card-title">概览</div>
      <div class="stats">{stats}</div>
    </div>
    <div class="card">
      <div class="card-title">运行状态</div>
      <div class="lastrun">自动运行: <b>{'开启' if auto else '关闭'}</b> ·
        最近一次: <b>{esc(last_run)}</b> <span class="dim">{esc(last_ts)}</span></div>
      <div style="margin-top:10px"><a class="btn" href="/risk">查看风险名单 →</a></div>
    </div>"""


def render_source_page(store: Store, kind: str, msg: str = "", err: str = "") -> str:
    """kind = 'v2board' | 'logfile'"""
    verb = "同步" if kind == "v2board" else "导入"
    rows = ""
    for s in store.list_sources():
        if s["type"] != kind:
            continue
        on = s["enabled"]
        iv = (s["interval"] if "interval" in s.keys() else 300) or 300
        scfg = json.loads(s["config"] or "{}")
        smode = scfg.get("sync_mode", "manual")
        sync_txt = {"manual": '<span class="off">手动</span>',
                    "auto": f'<span class="on">自动</span> · 每 {iv}s',
                    "follow": f'<span style="color:#5b8def">跟随全局</span> · 每 {iv}s'}.get(smode, "手动")
        if scfg.get("mode") == "agent":
            tok = scfg.get("key", "")
            seen = float(store.get_kv(f"agent_seen::{tok}", "0") or 0)
            online = seen > 0 and (time.time() - seen) < max(60, iv * 3)
            log_ok = store.get_kv(f"agent_logok::{tok}", "1") == "1"
            met = {}
            try:
                met = json.loads(store.get_kv(f"agent_metrics::{tok}", "{}") or "{}")
            except ValueError:
                pass
            # 三色状态: 离线红 / 日志异常黄 / 正常绿
            if not online:
                dot = '<span style="color:#e5484d">● 离线</span>'
            elif not log_ok:
                dot = '<span style="color:#e6a23c">● 日志异常</span>'
            else:
                dot = '<span style="color:#3ab76a">● 正常运行</span>'
            metstr = (f'<span class="dim small">CPU {met.get("cpu","-")}% 内存 {met.get("mem","-")}% 磁盘 {met.get("disk","-")}%</span>'
                      if met and online else '')
            detail_cell = (
                f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">探针 · {dot}'
                f'<button class="btn sm ghost" type="button" onclick="cpAgent(\'{esc(tok)}\')">复制安装命令</button>'
                f'<button class="btn sm ghost" type="button" onclick="cpUninstall()">复制卸载命令</button></div>'
                f'{("<div>" + metstr + "</div>") if metstr else ""}')
            edit_attr = (f'data-id="{s["id"]}" data-name="{esc(s["name"])}" '
                         f'data-mode="agent" data-path="{esc(scfg.get("log_path",""))}" '
                         f'data-sync="{smode}" data-interval="{iv}"')
            edit_fn = "editLog"
        elif kind == "logfile":
            detail_cell = _source_detail(s)
            edit_attr = (f'data-id="{s["id"]}" data-name="{esc(s["name"])}" '
                         f'data-mode="file" data-path="{esc(scfg.get("path",""))}" '
                         f'data-sync="{smode}" data-interval="{iv}"')
            edit_fn = "editLog"
        else:  # v2board
            # 状态图标(不显示数据库连接明细)
            seen = float(store.get_kv(f"src_seen::{s['id']}", "0") or 0)
            if seen == 0:
                detail_cell = '<span class="dim">● 未同步</span>'
            elif store.get_kv(f"src_ok::{s['id']}", "1") == "1":
                detail_cell = '<span style="color:#3ab76a">● 正常</span>'
            else:
                detail_cell = '<span style="color:#e5484d">● 同步异常</span>'
            cm = scfg.get("cols", {})
            edit_attr = (f'data-id="{s["id"]}" data-name="{esc(s["name"])}" '
                         f'data-host="{esc(_mask(scfg.get("host","")))}" data-port="{esc(scfg.get("port","3306"))}" '
                         f'data-user="{esc(scfg.get("user",""))}" data-db="{esc(_mask(scfg.get("database","")))}" '
                         f'data-prefix="{esc(scfg.get("prefix","v2_"))}" '
                         f'data-email="{esc(cm.get("email",""))}" data-created="{esc(cm.get("created",""))}" '
                         f'data-expired="{esc(cm.get("expired",""))}" '
                         f'data-sync="{smode}" data-interval="{iv}"')
            edit_fn = "editV2b"
        rows += f"""
        <tr>
          <td>{esc(s['name'])}</td>
          <td class="mono small">{detail_cell}</td>
          <td>
            <form method="post" action="/sources/toggle" style="margin:0">
              <input type="hidden" name="id" value="{s['id']}">
              <label class="switch"><input type="checkbox" {'checked' if on else ''} onchange="this.form.submit()"><span class="track"></span></label>
            </form>
          </td>
          <td class="small">{sync_txt}</td>
          <td class="actions">
            <form method="post" action="/sources/run"><input type="hidden" name="id" value="{s['id']}"><button class="btn sm">{verb}</button></form>
            <button class="btn sm ghost" type="button" onclick="{edit_fn}(this)" {edit_attr}>编辑</button>
            <a class="btn sm ghost" href="/runlog?name={quote(s['name'])}">日志</a>
            <form method="post" action="/sources/delete" onsubmit="return confirm('删除?')"><input type="hidden" name="id" value="{s['id']}"><button class="btn sm danger">删除</button></form>
          </td>
        </tr>"""
    if not rows:
        rows = '<tr><td colspan="5" class="dim" style="padding:16px">暂无, 点右上「＋ 添加」</td></tr>'

    if kind == "v2board":
        title, run_label, add_id = "v2board 面板", "▶ 同步全部", "addV2b"
        hint = "读 v2_user 的 token/注册时间/流量/分组, 补全用户画像。建议单独建只读账号。"
        modals = _v2b_modals()
        extra = ""
    else:
        title, run_label, add_id = "1Panel / aaPanel 日志", "▶ 导入全部", "addLog"
        hint = ("远程面板用<b>探针接入</b>(一键安装, 自动上报日志+负载); 中央与面板同机可用本地文件。"
                "日志路径与上报间隔都可在每行「编辑」里改。")
        modals = _log_modals()
        extra = """
        <div class="card">
          <div class="card-title">远程面板如何接入(探针)</div>
          <div class="dim small" style="line-height:1.9">
            右上「＋ 添加」→ 探针接入, 添加后点该行「复制安装命令」在<b>面板服务器</b>执行:
            <pre class="filebox">curl -fsSL "http://&lt;中央地址&gt;/agent/install.sh?token=&lt;token&gt;" | bash</pre>
            装好后被控 agent 自动上报日志+VPS负载; <b>日志路径、上报间隔在该行「编辑」/「同步方式」里设置</b>, 无需改命令。
          </div>
        </div>"""

    return f"""{_card_alert(msg, err)}
    <div class="card">
      <div class="card-title">{title}
        <div style="margin-left:auto;display:flex;gap:8px">
          <button class="btn" type="button" onclick="openM('{add_id}')">＋ 添加</button>
          <form method="post" action="/run/all"><button class="btn ghost">{run_label}</button></form>
          <a class="btn ghost" href="/runlog?kind={kind}">日志</a>
        </div>
      </div>
      <div class="dim small" style="margin-bottom:10px">{hint}</div>
      <div class="tablewrap">
      <table class="grid">
        <thead><tr><th>名称</th><th>目标</th><th>状态</th><th>同步方式</th><th>操作</th></tr></thead>
        <tbody>{rows}</tbody>
      </table></div>
    </div>{extra}{modals}"""


def _sync_field(pfx: str) -> str:
    return f"""
    <div class="mfield"><label class="dim small">同步方式</label>
      <input type="hidden" name="sync_mode" id="{pfx}_sync" value="manual">
      <div class="segbar">
        <button type="button" class="seg" id="{pfx}_sm" onclick="setSync('{pfx}','manual')">手动</button>
        <button type="button" class="seg" id="{pfx}_sa" onclick="setSync('{pfx}','auto')">自动</button>
        <button type="button" class="seg" id="{pfx}_sf" onclick="setSync('{pfx}','follow')">跟随全局</button>
      </div>
      <div style="margin-top:8px" id="{pfx}_ivwrap">间隔 <input name="interval" id="{pfx}_iv" type="number" min="30" value="300" style="max-width:90px;display:inline-block;width:auto"> 秒
        <div class="dim small" style="margin-top:4px">自动: 按此间隔独立运行; 跟随全局: 仅当「运行控制」总开关开启时才自动。</div></div>
    </div>"""


def _log_modals() -> str:
    return """
    <div class="modal-bg" id="addLog"><div class="modal">
      <h3>添加日志源</h3>
      <div class="segbar" style="margin:10px 0">
        <button type="button" id="lm_a" class="seg active" onclick="logMode('agent')">探针接入</button>
        <button type="button" id="lm_f" class="seg" onclick="logMode('file')">本地文件</button>
      </div>
      <form method="post" action="/sources/add">
        <input type="hidden" name="type" value="logfile">
        <input type="hidden" name="mode" id="logMode" value="agent">
        <div class="mfield"><input name="name" placeholder="名称, 如: 机场A" required></div>
        <div class="mfield" id="lf_agenttip"><div class="dim small">探针: 添加后点该行「复制安装命令」在面板服务器执行; 日志路径/间隔装好后在该行编辑。</div></div>
        <div class="mfield" id="lf_path" style="display:none">
          <label class="dim small">日志路径(可多行/通配, 按日期滚动的日志用 * 匹配)</label>
          <textarea name="path" id="lf_path_i" rows="3" placeholder="/www/wwwlogs/neigui_sub.log&#10;/www/wwwlogs/*sub.log&#10;/path/2026*su.log"></textarea>
        </div>
        <div class="modal-actions"><button type="button" class="btn ghost" onclick="closeM('addLog')">取消</button><button class="btn">添加</button></div>
      </form>
    </div></div>
    <div class="modal-bg" id="editLog"><div class="modal">
      <h3>编辑日志源</h3>
      <form method="post" action="/sources/edit">
        <input type="hidden" name="id" id="el_id">
        <div class="mfield"><label class="dim small">名称</label><input name="name" id="el_name"></div>
        <div class="mfield"><label class="dim small" id="el_lbl">日志路径</label>
          <textarea name="path" id="el_path" rows="3" placeholder="每行一个路径或通配, 如 /www/wwwlogs/*sub.log"></textarea>
          <div class="dim small" style="margin-top:4px">多个路径每行一个; 按日期滚动的日志用通配 *(如 <code>/www/wwwlogs/2026*su.log</code>)。</div></div>
        """ + _sync_field("el") + """
        <div class="modal-actions"><button type="button" class="btn ghost" onclick="closeM('editLog')">取消</button><button class="btn">保存</button></div>
      </form>
    </div></div>"""


_V2B_COLS = (
    '<div class="mfield"><label class="dim small">字段映射(选填, 不同版本/魔改列名不同时填, 留空用默认)</label></div>'
    '<div class="mfield row2"><input name="col_email" {ph_email} placeholder="邮箱列(默认 email)">'
    '<input name="col_plan" placeholder="套餐列(默认 plan_id)"></div>'
    '<div class="mfield row2"><input name="col_created" {ph_created} placeholder="注册时间列(默认 created_at)">'
    '<input name="col_expired" {ph_expired} placeholder="到期时间列(默认 expired_at)"></div>')


def _v2b_modals() -> str:
    cols = _V2B_COLS.format(ph_email="", ph_created="", ph_expired="")
    cols_e = _V2B_COLS  # 编辑时由 JS 填占位
    return f"""
    <div class="modal-bg" id="addV2b"><div class="modal">
      <h3>添加 v2board 面板</h3>
      <form method="post" action="/sources/add">
        <input type="hidden" name="type" value="v2board">
        <div class="mfield"><label class="dim small">机场名称</label><input name="name" placeholder="如: 机场A" required></div>
        <div class="mfield row2"><div style="flex:1"><label class="dim small">数据库地址(IP/host)</label><input name="host" value="127.0.0.1" required></div>
          <div style="max-width:100px"><label class="dim small">端口</label><input name="port" value="3306"></div></div>
        <div class="mfield row2"><div style="flex:1"><label class="dim small">只读用户</label><input name="user" required></div>
          <div style="flex:1"><label class="dim small">密码</label><input name="password" type="password"></div></div>
        <div class="mfield row2"><div style="flex:1"><label class="dim small">数据库名</label><input name="database" required></div>
          <div style="max-width:120px"><label class="dim small">表前缀</label><input name="prefix" value="v2_"></div></div>
        {cols}
        <div class="modal-actions"><button type="button" class="btn ghost" onclick="closeM('addV2b')">取消</button><button class="btn">添加</button></div>
      </form>
    </div></div>
    <div class="modal-bg" id="editV2b"><div class="modal">
      <h3>编辑 v2board 面板</h3>
      <form method="post" action="/sources/edit">
        <input type="hidden" name="id" id="ev_id">
        <div class="mfield"><label class="dim small">机场名称</label><input name="name" id="ev_name"></div>
        <div class="mfield row2"><div style="flex:1"><label class="dim small">数据库地址(留空不改)</label><input name="host" id="ev_host"></div>
          <div style="max-width:100px"><label class="dim small">端口</label><input name="port" id="ev_port"></div></div>
        <div class="mfield row2"><div style="flex:1"><label class="dim small">只读用户</label><input name="user" id="ev_user"></div>
          <div style="flex:1"><label class="dim small">密码(留空不改)</label><input name="password" id="ev_pass" type="password"></div></div>
        <div class="mfield row2"><div style="flex:1"><label class="dim small">数据库名(留空不改)</label><input name="database" id="ev_db"></div>
          <div style="max-width:120px"><label class="dim small">表前缀</label><input name="prefix" id="ev_prefix"></div></div>
        <div class="mfield row2"><input name="col_email" id="ev_col_email" placeholder="邮箱列(默认 email)">
          <input name="col_plan" id="ev_col_plan" placeholder="套餐列(默认 plan_id)"></div>
        <div class="mfield row2"><input name="col_created" id="ev_col_created" placeholder="注册时间列(默认 created_at)">
          <input name="col_expired" id="ev_col_expired" placeholder="到期时间列(默认 expired_at)"></div>
        """ + _sync_field("ev") + """
        <div class="modal-actions"><button type="button" class="btn ghost" onclick="closeM('editV2b')">取消</button><button class="btn">保存</button></div>
      </form>
    </div></div>"""


def render_runlog(store: Store, kind: str = "", name: str = "", size: str = "10", page: str = "1") -> str:
    logs = store.list_runlog(500, kind or None, name or None)
    total = len(logs)
    psize, pg, pages, all_mode = _paginate(size, page, total, 10)
    page_logs = logs if all_mode else logs[(pg - 1) * psize: pg * psize]

    rows = ""
    for r in page_logs:
        icon = '<span class="on">✓</span>' if r["ok"] else '<span style="color:#e5484d">✗</span>'
        rows += (f'<tr><td class="small dim">{esc(r["ts"])}</td>'
                 f'<td>{icon}</td><td>{esc(r["kind"])}</td>'
                 f'<td>{esc(r["name"])}</td><td class="small">{esc(r["msg"])}</td></tr>')
    if not rows:
        rows = '<tr><td colspan="5" class="dim" style="padding:16px">暂无运行记录</td></tr>'

    # 一级: 全部 / 前端面板(v2board) / 日志接入(logfile)
    none_sel = not kind and not name
    top = (f'<a class="tab {"active" if none_sel else ""}" href="/runlog?size={quote(size)}">全部</a>'
           f'<a class="tab {"active" if kind=="v2board" else ""}" href="/runlog?kind=v2board&size={quote(size)}">前端面板</a>'
           f'<a class="tab {"active" if kind=="logfile" else ""}" href="/runlog?kind=logfile&size={quote(size)}">日志接入</a>')
    # 二级: 选了一级类型后, 展开该类下的数据源
    sub = ""
    if kind:
        subs = [s["name"] for s in store.list_sources() if s["type"] == kind]
        sub = f'<div class="tabs" style="margin-top:0"><a class="tab {"active" if not name else ""}" href="/runlog?kind={kind}&size={quote(size)}">该类全部</a>'
        for sn in subs:
            sub += f'<a class="tab {"active" if name==sn else ""}" href="/runlog?kind={kind}&name={quote(sn)}&size={quote(size)}">{esc(sn)}</a>'
        sub += "</div>"
    tabs = top

    pager = _pager_html("/runlog", {k: v for k, v in (("kind", kind), ("name", name)) if v},
                        size if str(size) in ("10", "20", "50", "100", "200") else "10",
                        pg, pages, ["10", "20", "50", "100", "200"])
    clear = (f'<form method="post" action="/runlog/clear" style="margin-left:auto" '
             f'onsubmit="return confirm(\'清除{"该源" if name else ""}运行日志?\')">'
             f'<input type="hidden" name="kind" value="{esc(kind)}">'
             f'<input type="hidden" name="name" value="{esc(name)}">'
             f'<button class="btn sm danger">清除日志</button></form>')
    return f"""
    <div class="card">
      <div class="card-title">运行日志 <span class="dim small" style="font-weight:400;margin-left:8px">共 {total} 条</span>{clear}</div>
      <div class="tabs">{tabs}</div>
      {sub}
      <div class="tablewrap"><table class="grid">
        <thead><tr><th>时间</th><th>结果</th><th>类型</th><th>名称</th><th>消息</th></tr></thead>
        <tbody>{rows}</tbody>
      </table></div>
      {pager}
    </div>"""


def render_logstore(store: Store, src: str = "", size: str = "50", page: str = "1") -> str:
    """日志库: 展示各接口/探针上报入库的拉取日志原文, 按来源(数据源)分类。"""
    total = store.count_pulls_by_src(src or None)
    psize, pg, pages, all_mode = _paginate(size, page, total, 50)
    off = 0 if all_mode else (pg - 1) * psize
    rows = ""
    for r in store.list_pulls(limit=(total or 1) if all_mode else psize, offset=off, src=src or None):
        cols = r.keys()
        st = r["status"]
        st_html = (f'<span class="on">{st}</span>' if st and 200 <= st < 400
                   else f'<span style="color:#e5484d">{st}</span>')
        rows += (f'<tr><td class="small dim">{esc(str(r["ts"])[:19].replace("T", " "))}</td>'
                 f'<td class="small">{esc(r["src"] if "src" in cols and r["src"] else "—")}</td>'
                 f'<td class="small mono">{esc(_mask(r["token"]))}</td>'
                 f'<td class="small">{esc(r["ip"] or "")}</td>'
                 f'<td class="small">{st_html}</td>'
                 f'<td class="small dim" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{esc(r["ua"] or "")}</td>'
                 f'<td class="small dim" style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{esc(r["uri"] or "")}</td></tr>')
    if not rows:
        rows = '<tr><td colspan="7" class="dim" style="padding:16px">暂无日志记录</td></tr>'

    # 分类: 全部 + 各来源(数据源名), 与运行日志同款标签样式
    none_sel = not src
    tabs = f'<a class="tab {"active" if none_sel else ""}" href="/logstore?size={quote(size)}">全部</a>'
    for sn in store.pull_srcs():
        tabs += (f'<a class="tab {"active" if src==sn else ""}" '
                 f'href="/logstore?src={quote(sn)}&size={quote(size)}">{esc(sn)}</a>')

    pager = _pager_html("/logstore", {"src": src} if src else {},
                        size if str(size) in ("20", "50", "100", "200", "500") else "50",
                        pg, pages, ["20", "50", "100", "200", "500"])
    return f"""
    <div class="card">
      <div class="card-title">日志库 <span class="dim small" style="font-weight:400;margin-left:8px">共 {total} 条拉取记录</span></div>
      <div class="tabs">{tabs}</div>
      <div class="tablewrap"><table class="grid">
        <thead><tr><th>时间</th><th>来源</th><th>Token</th><th>IP</th><th>状态</th><th>UA</th><th>接口</th></tr></thead>
        <tbody>{rows}</tbody>
      </table></div>
      {pager}
    </div>"""


def render_controls(store: Store) -> str:
    enabled = store.get_kv("auto_enabled", "0") == "1"
    last_run = store.get_kv("last_run_summary", "尚未运行")
    last_run_ts = store.get_kv("last_run_ts", "")
    man_cls = "seg active" if not enabled else "seg"
    auto_cls = "seg active" if enabled else "seg"
    def _smode(s):
        try:
            return json.loads(s["config"] or "{}").get("sync_mode", "manual")
        except (ValueError, TypeError):
            return "manual"
    n_follow = sum(1 for s in store.list_sources() if s["enabled"] and _smode(s) == "follow")
    n_auto = sum(1 for s in store.list_sources() if s["enabled"] and _smode(s) == "auto")
    return f"""
    <div class="card">
      <div class="card-title">运行模式</div>
      <form method="post" action="/auto/mode" class="autoform">
        <div class="segbar">
          <button name="mode" value="manual" class="{man_cls}">手动运行</button>
          <button name="mode" value="auto" class="{auto_cls}">自动运行</button>
        </div>
        <span class="autostat">
          {f'开启: {n_follow} 个「跟随全局」源会自动运行; 另有 {n_auto} 个「自动」源独立运行(不受此开关影响)。'
            if enabled else f'关闭: {n_follow} 个「跟随全局」源暂停; {n_auto} 个「自动」源仍独立运行。'}
        </span>
      </form>
      <div style="margin-top:14px"><form method="post" action="/run/all"><button class="btn">▶ 立即手动运行全部</button></form></div>
      <div class="lastrun" style="margin-top:12px">最近一次: <b>{esc(last_run)}</b> <span class="dim">{esc(last_run_ts)}</span></div>
    </div>
    <div class="card">
      <div class="dim small">每个源在「编辑」里设同步方式: <b>手动</b>(不自动)/ <b>自动</b>(按自己间隔独立跑)/ <b>跟随全局</b>(由此总开关决定)。此处总开关只控制「跟随全局」的源。</div>
    </div>"""


WEIGHT_CN = {
    "blacklist_hit": ("命中黑名单", "IP/UA/ASN 黑名单命中, 直接判高危并隔离下发"),
    "hosting_asn": ("机房ASN拉订阅", "订阅来自机房/IDC IP(真人应为住宅/移动)"),
    "ua_tool": ("工具类UA", "用 curl/python/Go 等工具或空 UA 拉订阅"),
    "ua_spoof": ("UA伪造", "声称客户端 UA 却来自机房 ASN, 疑似伪造"),
    "pull_regularity": ("机器规整拉取", "拉取间隔过于规整, 呈自动化定时特征"),
    "traffic_divergence": ("流量背离", "持续拉取却几乎零流量, 只拿节点不使用"),
    "reg_trajectory": ("注册即侦察", "注册后立即拉取且无流量, 疑似注册就为拿节点"),
    "multi_ua": ("多客户端UA", "一个 token 用了多个不同 UA, 疑似多人共享/工具轮换"),
    "online_ips": ("多IP在线", "一个 token 近期在多个不同 IP 活跃, 疑似分发/分布式扫描"),
    "ip_shared": ("IP共用账号", "该 token 的 IP 被多个账号共用, 疑似聚合点/攻击机"),
    "ip_silence": ("拉取后IP静默", "拉取IP 拉完就不通/从不连节点(需节点侧日志)"),
    "scan_pattern": ("扫描式短连", "遍历所有节点每个只碰一次(需节点侧日志)"),
    "tls_mismatch": ("TLS指纹矛盾", "UA 与 TLS/JA3 指纹不符(需 JA3 模块)"),
}
THRESH_CN = {
    "level_high": "高风险阈值(分)", "level_mid": "中风险阈值(分)", "level_low": "低风险阈值(分)",
    "divergence_min_pulls": "流量背离-最少拉取次数", "divergence_max_bytes": "流量背离-流量上限(字节)",
    "regular_cv": "规整判定-间隔变异系数上限", "regular_min_pulls": "规整判定-最少拉取次数",
    "reg_immediate_secs": "注册即拉-秒内算立即", "new_account_days": "新号判定-账龄天数",
    "self_exclude_ratio": "自有IP排除-占比阈值",
    "online_window_hours": "在线窗口(小时)-在线IP/共用账号按此统计",
    "multi_ua_min": "多UA判定-不同UA数下限", "online_ips_min": "多IP在线判定-在线IP数下限",
    "ip_shared_min": "IP共用判定-共用账号数下限",
}


def _rules_off(store) -> set:
    raw = store.get_kv("signals_off", "")
    try:
        return set(json.loads(raw)) if raw else set()
    except (ValueError, TypeError):
        return set()


def _rule_switch(key: str, off: set) -> str:
    checked = "" if key in off else "checked"
    return (f'<form method="post" action="/rules/toggle" style="margin:0">'
            f'<input type="hidden" name="key" value="{key}">'
            f'<label class="switch"><input type="checkbox" name="on" {checked} '
            f'onchange="this.form.submit()"><span class="track"></span></label></form>')


def render_rules(store) -> str:
    off = _rules_off(store)
    w = asdict(CONFIG.weights)
    th = asdict(CONFIG.thresholds)
    wl = "".join(
        f'<tr><td>{esc(WEIGHT_CN.get(k, (k, ""))[0])}</td>'
        f'<td class="dim small">{esc(WEIGHT_CN.get(k, ("", ""))[1])}</td>'
        f'<td class="num">{v}</td><td>{_rule_switch(k, off)}</td></tr>' for k, v in w.items())
    tl = "".join(
        f'<tr><td>{esc(THRESH_CN.get(k, k))}</td><td class="num">{v}</td>'
        f'<td>{_rule_switch(k, off)}</td></tr>' for k, v in th.items())
    return f"""
    <div class="card">
      <div class="card-title">信号权重(命中程度 × 权重 = 得分)</div>
      <table class="grid"><thead><tr><th>信号</th><th>说明</th><th>权重</th><th>启用</th></tr></thead><tbody>{wl}</tbody></table>
      <div class="dim small" style="margin-top:10px">开关关闭即停用该信号, 评分立即生效(刷新可见)。</div>
    </div>
    <div class="card">
      <div class="card-title">阈值参数</div>
      <table class="grid"><thead><tr><th>参数</th><th>值</th><th>启用</th></tr></thead><tbody>{tl}</tbody></table>
      <div class="dim small" style="margin-top:10px">「自有IP排除」开关关闭即停用排除层; 权重开关控制各信号。数值改动请编辑 config.py。</div>
    </div>"""


def _read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _count_cidrs(text: str) -> int:
    return sum(1 for ln in text.splitlines() if ln.split("#", 1)[0].strip())


def _setting_row(label, desc, action, content, extra="") -> str:
    """命名+提示在上, 可编辑字段在下。"""
    return f"""
    <form method="post" action="{action}" class="stackrow">
      <div class="sr-head"><b>{label}</b><div class="dim small">{desc}</div></div>
      <textarea name="content" rows="6">{esc(content)}</textarea>
      <div style="margin-top:8px;display:flex;gap:8px;align-items:center">{extra}<button class="btn">保存</button></div>
    </form>"""


def render_whitelist(msg="", err="", tab="white") -> str:
    tab = "black" if tab == "black" else "white"
    subtabs = (
        f'<div class="subtabs">'
        f'<a class="subtab {"active" if tab=="white" else ""}" href="/whitelist?tab=white">白名单</a>'
        f'<a class="subtab {"active" if tab=="black" else ""}" href="/whitelist?tab=black">黑名单</a>'
        f'</div>')

    if tab == "white":
        hosting = _read_file(CONFIG.hosting_cidrs_file)
        fetch_btn = ('<input name="url" form="fetchhosting" placeholder="CIDR 列表 URL" '
                     'style="flex:1;max-width:280px">'
                     '<button class="btn ghost" form="fetchhosting" formaction="/whitelist/fetch-hosting">'
                     '从URL拉取</button>')
        body = (
            _setting_row("自有基础设施 IP", "命中即排除(自己的节点/subconverter/监控)。只填自己的 IP/CIDR, 别填整个机房 ASN。",
                         "/whitelist/save-self", _read_file(CONFIG.self_ips_file))
            + _setting_row(f"IP / ASN 库(机房网段) · {_count_cidrs(hosting)} 条",
                           "判定“机房 ASN 拉订阅”依赖此库。可编辑或从 URL 拉取覆盖。生产建议接 MaxMind GeoLite2-ASN 更准。",
                           "/whitelist/save-hosting", hosting, extra=fetch_btn)
            + _setting_row("客户端 UA 白名单", "正规客户端 UA(clash/v2rayN/Shadowrocket 等), 每行一个正则; 配合住宅 ASN 视为正常。",
                           "/whitelist/save-ua", _read_file(CONFIG.ua_clients_file))
            + '<form id="fetchhosting" method="post" action="/whitelist/fetch-hosting"></form>')
        note = "白名单: 命中即视为正常 / 排除, 降低误杀。"
    else:
        body = (
            _setting_row("IP 黑名单", "已确认的攻击/侦察源 IP。命中即判高危, 进入隔离下发。每行一个 IP 或 CIDR。",
                         "/blacklist/save-ip", _read_file(CONFIG.ip_blacklist_file))
            + _setting_row("UA 黑名单", "攻击脚本/爬虫特征 UA。命中即判高危。每行一个正则。",
                           "/blacklist/save-ua", _read_file(CONFIG.ua_blacklist_file))
            + _setting_row("ASN 黑名单", "封整个恶意机房网段。每行 CIDR(现在生效)或 ASxxxx(需 GeoLite2)。",
                           "/blacklist/save-asn", _read_file(CONFIG.asn_blacklist_file)))
        note = "黑名单: 任一命中→用户直接标为高风险并强制隔离下发(见系统设置说明)。"

    return f"""{_card_alert(msg, err)}
    <div class="card">
      {subtabs}
      <div class="dim small" style="margin:6px 2px 4px">{note}</div>
      {body}
    </div>"""


DEFAULT_PROTOCOLS = ["vless", "vmess", "trojan", "hysteria2", "shadowsocks"]


def _panels(store) -> list:
    return [s["name"] for s in store.list_sources() if s["type"] == "v2board"]


def _protocols(store) -> list:
    raw = store.get_kv("protocols", "")
    if raw:
        return [x.strip() for x in raw.split(",") if x.strip()]
    return DEFAULT_PROTOCOLS


def _protocols_for(store, panel: str) -> tuple:
    """某面板的协议: 优先 v2board 同步自动读取的; 否则回退全局手填。返回 (协议列表, 是否自动)。"""
    raw = store.get_kv(f"protocols::{panel}", "")
    if raw:
        return [x.strip() for x in raw.split(",") if x.strip()], True
    return _protocols(store), False


def _domains_map(store) -> dict:
    raw = store.get_kv("domains_map", "")
    try:
        return json.loads(raw) if raw else {}
    except (ValueError, TypeError):
        return {}


def render_domains(store, panel_sel="", tier_sel="", msg="", err="") -> str:
    panels = _panels(store)
    protos = _protocols(store)
    dm = _domains_map(store)
    tier_keys = [t[0] for t in DOMAIN_TIERS]
    tier_labels = {t[0]: t[1] for t in DOMAIN_TIERS}

    scope = store.get_kv("rewrite_scope", "relay") or "relay"
    scope_card = f"""
    <div class="card">
      <div class="card-title">下发范围</div>
      <div class="dim small" style="margin-bottom:8px">方案B: 网关只改写<b>中转节点</b>(parent_id 非空)的入口域名; <b>直连节点保持原样不动</b>。</div>
      <form method="post" action="/domains/scope">
        <div class="segbar">
          <button name="mode" value="relay" class="seg {'active' if scope=='relay' else ''}">只改写中转节点</button>
          <button name="mode" value="all" class="seg {'active' if scope!='relay' else ''}">改写全部节点</button>
        </div>
      </form>
    </div>"""

    proto_card = f"""
    <div class="card">
      <div class="card-title">协议列表(全局兜底)</div>
      <div class="dim small" style="margin-bottom:8px">
        各面板协议<b>优先自动读取</b> v2board 节点表(同步时自动填, 见下方每面板标注);
        此处仅作<b>未同步到时的兜底</b>。逗号分隔。
      </div>
      <form method="post" action="/domains/protocols" class="autoform">
        <input name="protocols" value="{esc(', '.join(_protocols(store)))}" style="flex:1;min-width:260px">
        <button class="btn">保存兜底协议</button>
      </form>
    </div>"""

    if not panels:
        return f"""{_card_alert(msg, err)}{scope_card}{proto_card}
        <div class="card"><div class="dim">请先到「前端面板」添加 v2board 面板, 再来为每个面板配置入口域名。</div></div>"""

    panel_sel = panel_sel if panel_sel in panels else panels[0]
    tier_sel = tier_sel if tier_sel in tier_keys else "normal"

    opts = "".join(f'<option value="{esc(p)}" {"selected" if p==panel_sel else ""}>{esc(p)}</option>' for p in panels)
    panel_select = (f'<select onchange="location.href=\'/domains?panel=\'+encodeURIComponent(this.value)+\'&tier={tier_sel}\'"'
                    f' style="padding:7px 10px;border:1px solid #d5dae1;border-radius:6px">{opts}</select>')

    tier_tabs = ""
    for k in tier_keys:
        active = "active" if k == tier_sel else ""
        tier_tabs += f'<a class="subtab {active}" href="/domains?panel={quote(panel_sel)}&tier={quote(k)}">{tier_labels[k]}</a>'

    panel_protos, auto = _protocols_for(store, panel_sel)
    proto_src = ('<span class="on">已自动读取</span>(v2board 节点表)'
                 if auto else '<span class="off">未同步</span>, 用全局兜底; 到「前端面板」同步后自动填')
    cur = dm.get(panel_sel, {}).get(tier_sel, {})
    rows = ""
    for proto in panel_protos:
        val = esc(cur.get(proto, ""))
        rows += f"""
        <div class="settingrow">
          <div class="sr-label"><b>{esc(proto)}</b></div>
          <div class="sr-field"><input name="domain_{esc(proto)}" value="{val}" placeholder="如 {esc(proto)}-{tier_sel}.{esc(panel_sel)}.com"></div>
        </div>"""

    tier_desc = next((t[2] for t in DOMAIN_TIERS if t[0] == tier_sel), "")
    return f"""{_card_alert(msg, err)}{scope_card}{proto_card}
    <div class="card">
      <div class="card-title">入口域名 · 分面板 / 分等级 / 分协议</div>
      <div class="autoform" style="margin-bottom:6px">
        <span>前端面板:</span> {panel_select}
      </div>
      <div class="subtabs">{tier_tabs}</div>
      <div class="dim small" style="margin:6px 2px">协议: {proto_src} · 为「{esc(panel_sel)}」的「{tier_labels[tier_sel]}」用户配置各协议入口域名(留空=不单独分流)。</div>
      <form method="post" action="/domains/save">
        <input type="hidden" name="panel" value="{esc(panel_sel)}">
        <input type="hidden" name="tier" value="{esc(tier_sel)}">
        {rows}
        <div style="margin-top:14px"><button class="btn">保存 {esc(panel_sel)} / {tier_labels[tier_sel]}</button></div>
      </form>
    </div>
    <div class="card">
      <div class="card-title">如何正确下发到对应前端(方案B)</div>
      <div class="dim small" style="line-height:1.8">
        订阅网关对每次拉取调 <code>/api/decision?token=xxx</code>, 返回带 <code>panel</code>、<code>tier</code>、<code>scope</code>、
        <code>domains</code>(该面板+等级下每协议域名映射, 如 {{"vless":"...","trojan":"..."}})。<br>
        网关遍历订阅里每个节点, 按下面规则改写:<br>
        &nbsp;&nbsp;• <b>直连节点</b>(parent_id 为空)→ <b>忽略, 保持原样不动</b>;<br>
        &nbsp;&nbsp;• <b>中转节点</b>(parent_id 非空)→ 用 <code>domains[该节点协议]</code> 替换其入口 host;<br>
        &nbsp;&nbsp;• 映射里没有该协议 → 保留原样。<br>
        这样 8 面板子域名不同、每协议域名不同都能按 (面板×等级×协议) 精确命中; 高危/内鬼的中转节点被改写到隔离/蜜罐域名, 直连节点不受影响。
      </div>
    </div>"""


def render_entities(store: Store, kind: str) -> str:
    cn, hint = ENTITY_META.get(kind, (kind, ""))
    rows = ""
    for e in store.list_entities(kind):
        rows += f"""
        <tr>
          <td>{esc(e['name'])}</td>
          <td class="small">{esc(e['detail'])}</td>
          <td class="mono small dim">{esc((e['config'] or '')[:60])}</td>
          <td class="actions">
            <form method="post" action="/nodes/delete" onsubmit="return confirm('删除?')">
              <input type="hidden" name="kind" value="{kind}"><input type="hidden" name="id" value="{e['id']}">
              <button class="btn sm danger">删除</button></form>
          </td>
        </tr>"""
    if not rows:
        rows = '<tr><td colspan="4" class="dim" style="padding:16px">暂无, 用下方表单添加</td></tr>'
    return f"""
    <div class="card">
      <div class="card-title">{esc(cn)}管理</div>
      <div class="dim small" style="margin-bottom:10px">{esc(hint)}</div>
      <div class="tablewrap"><table class="grid">
        <thead><tr><th>名称</th><th>备注</th><th>配置</th><th>操作</th></tr></thead>
        <tbody>{rows}</tbody>
      </table></div>
      <div class="addforms">
        <form method="post" action="/nodes/add" class="addbox">
          <input type="hidden" name="kind" value="{kind}">
          <div class="ab-title">＋ 添加{esc(cn)}</div>
          <input name="name" placeholder="名称" required>
          <input name="detail" placeholder="备注(IP/端口/说明)">
          <input name="config" placeholder="配置(JSON 或参数, 可选)">
          <button class="btn">添加</button>
        </form>
      </div>
      <div class="dim small" style="margin-top:8px">当前为本地登记管理; 与 v2board 节点表的双向同步为后续增量。</div>
    </div>"""


def render_risklist(store: Store, flt: str, panel_flt: str = "all", search: str = "",
                    size: str = "10", page: str = "1") -> str:
    if str(size) not in ("10", "50", "100", "150"):
        size = "10"
    results = analyze(store)
    counts = {"高": 0, "中": 0, "低": 0, "正常": 0}
    excluded = 0
    panels = set()
    for r in results:
        counts[r.level] = counts.get(r.level, 0) + 1
        excluded += 1 if r.excluded else 0
        if r.panel:
            panels.add(r.panel)

    # 搜索: token / 邮箱 / IP
    search = (search or "").strip()
    ip_tokens = store.tokens_by_ip(search) if search else set()

    def chip(label, val, color):
        return f'<span class="chip"><b style="color:{color}">{val}</b> {label}</span>'

    chips = "".join([
        chip("高风险", counts["高"], LEVEL_COLOR["高"]), chip("中风险", counts["中"], LEVEL_COLOR["中"]),
        chip("低风险", counts["低"], LEVEL_COLOR["低"]), chip("正常", counts["正常"], LEVEL_COLOR["正常"]),
        chip("排除", excluded, "#8b8f98"), chip("用户", len(results), "#5b8def"),
    ])
    pf = quote(panel_flt or "all")
    tabs = ""
    for name, key in [("全部", "all"), ("高风险", "高"), ("中风险", "中"), ("低风险", "低"), ("正常", "正常")]:
        active = "active" if (flt or "all") == key else ""
        tabs += f'<a class="tab {active}" href="/risk?level={quote(key)}&panel={pf}">{name}</a>'

    # 机场/前端面板 筛选
    lf = quote(flt or "all")
    ptabs = f'<a class="tab {"active" if (panel_flt or "all")=="all" else ""}" href="/risk?level={lf}&panel=all">全部面板</a>'
    for pn in sorted(panels):
        active = "active" if panel_flt == pn else ""
        ptabs += f'<a class="tab {active}" href="/risk?level={lf}&panel={quote(pn)}">{esc(pn)}</a>'
    panel_bar = f'<div class="tabs">{ptabs}</div>' if panels else ""

    # 过滤(等级/机场/搜索)
    slc = search.lower()
    filtered = []
    for r in results:
        if flt in ("高", "中", "低", "正常") and r.level != flt:
            continue
        if panel_flt and panel_flt != "all" and (r.panel or "") != panel_flt:
            continue
        if search and not (slc in r.token.lower() or slc in (r.email or "").lower() or r.token in ip_tokens):
            continue
        filtered.append(r)

    # 分页(每页 10/50/100/150, 默认 10)
    total = len(filtered)
    psize, pg, pages, all_mode = _paginate(size, page, total, 10)
    page_rows = filtered if all_mode else filtered[(pg - 1) * psize: pg * psize]

    # 列显隐配置
    try:
        hidden = set(json.loads(store.get_kv("risk_hidden_cols", "[]") or "[]"))
    except (ValueError, TypeError):
        hidden = set()
    vis = [(k, lb) for k, lb in RISK_COLS if k not in hidden]

    now = datetime.now(timezone.utc)
    rows = ""
    for r in page_rows:
        color = LEVEL_COLOR.get(r.level, "#8b8f98")
        expired = r.expired_at is not None and r.expired_at < now
        tags = (["已到期"] + list(r.tags)) if expired else list(r.tags)
        tags_html = "".join(
            f'<span class="rtag" style="background:{TAG_COLOR.get(t, "#8b8f98")}22;'
            f'color:{TAG_COLOR.get(t, "#8b8f98")}">{esc(t)}</span>' for t in tags)
        if r.excluded:
            tags_html = '<span class="rtag" style="background:#8b8f8822;color:#8b8f98">自有基础设施</span>'
        detail = " | ".join(f"{s.name}(+{s.points})" for s in r.signals) or "无命中信号"
        reg = r.created_at.strftime("%Y-%m-%d") if r.created_at else "-"
        has_plan = bool(r.plan and str(r.plan) not in ("", "0", "None"))
        if r.expired_at:
            exp = r.expired_at.strftime("%Y-%m-%d")
        elif r.created_at:
            exp = "永久" if has_plan else "未购买"   # 有套餐=永久; 无套餐=未购买
        else:
            exp = "-"
        cell = {
            "uid": f'<td class="mono small">{esc(r.user_id if r.user_id is not None else "-")}</td>',
            "email": f'<td class="small">{esc(r.email or "-")}</td>',
            "panel": f'<td class="small">{esc(r.panel or "-")}</td>',
            "token": f'<td class="mono small dim">{esc(r.token[:12])}</td>',
            "ips": f'<td class="num">{r.distinct_ips}</td>',
            "online": f'<td class="num">{r.online_ips or _DASH}</td>',
            "uas": f'<td class="num">{r.distinct_uas or _DASH}</td>',
            "shared": (f'<td class="num" style="color:#e5484d;font-weight:600">{r.ip_shared_users}</td>'
                       if r.ip_shared_users >= 2 else f'<td class="num">{r.ip_shared_users or _DASH}</td>'),
            "pull": f'<td class="num">{r.pull_count}</td>',
            "score": (f'<td class="num" data-sort="{r.score}">'
                      f'<div class="scorebar"><div class="fill" style="width:{min(100, int(r.score))}%;background:{color}"></div></div>'
                      f'<span class="scoreval">{r.score}</span></td>'),
            "level": f'<td><span class="badge" style="background:{color};color:{LEVEL_FG.get(r.level, "#fff")}">{LEVEL_TEXT.get(r.level, r.level)}</span></td>',
            "tags": f'<td class="rtags">{tags_html or _DASH}</td>',
            "created": f'<td class="small dim">{reg}</td>',
            "expired": f'<td class="small" style="{"color:#e5484d" if expired else "color:#8a8a8a"}">{exp}</td>',
            "last": f'<td class="small dim">{_humanize(r.last_pull)}</td>',
        }
        rows += (f'<tr title="{esc(detail)}" style="cursor:pointer" onclick="userDetail(\'{esc(r.token)}\')">'
                 + "".join(cell[k] for k, _ in vis) + "</tr>")
    if not rows:
        rows = f'<tr><td colspan="{len(vis)}" class="dim" style="padding:20px">暂无用户</td></tr>'

    header = "".join(f"<th{_th_attr(k)}>{lb}</th>" for k, lb in vis)

    # 列显隐弹窗
    col_checks = "".join(
        f'<label><input type="checkbox" name="col" value="{k}" {"checked" if k not in hidden else ""}> {lb}</label>'
        for k, lb in RISK_COLS)
    col_modal = f"""
    <div class="modal-bg" id="colModal"><div class="modal">
      <h3>显示列</h3><div class="dim small">勾选要显示的列</div>
      <form method="post" action="/risk/cols">
        <div class="collist">{col_checks}</div>
        <div class="modal-actions"><button type="button" class="btn ghost" onclick="closeM('colModal')">取消</button><button class="btn">保存</button></div>
      </form>
    </div></div>"""

    searchbox = (
        f'<form method="get" action="/risk" style="margin-left:auto;display:flex;gap:6px">'
        f'<input type="hidden" name="level" value="{esc(flt or "all")}">'
        f'<input type="hidden" name="panel" value="{esc(panel_flt or "all")}">'
        f'<input type="hidden" name="size" value="{esc(size)}">'
        f'<input name="q" value="{esc(search)}" placeholder="搜索 token / 邮箱 / IP" style="width:200px;padding:6px 10px;border:1px solid #d5dae1;border-radius:6px">'
        f'<button class="btn sm">搜索</button>'
        + (f'<a class="btn sm ghost" href="/risk?level={quote(flt or "all")}&panel={pf}">清除</a>' if search else '')
        + '</form>')

    pager = _pager_html("/risk", {"level": flt or "all", "panel": panel_flt or "all", "q": search},
                        size if str(size) in ("10", "50", "100", "150") else "10",
                        pg, pages, ["10", "50", "100", "150"])

    return f"""
    <div class="card">
      <div class="card-title">用户风险管理
        <button class="btn sm ghost" type="button" style="margin-left:8px" onclick="openM('colModal')">显示列 ▾</button>
        {searchbox}</div>
      <div class="chips">{chips}</div>
      <div class="tabs">{tabs}</div>
      {panel_bar}
      <div class="tablewrap">
      <table class="grid sortable" id="risk">
        <thead><tr>{header}</tr></thead>
        <tbody>{rows}</tbody>
      </table></div>
      {pager}
      <div class="dim small" style="margin-top:8px">点用户行看详情(账号/流量/订单/拉取记录); 红色到期=已到期; 「显示列 ▾」可选列。</div>
    </div>{col_modal}
    <div class="modal-bg" id="userModal"><div class="modal" style="width:min(560px,94vw)">
      <div style="display:flex;align-items:center"><h3 style="margin:0">用户详情</h3>
        <button class="btn sm ghost" type="button" style="margin-left:auto" onclick="closeM('userModal')">关闭</button></div>
      <div id="userBody" class="udetail"><div class="dim">加载中…</div></div>
    </div></div>"""


# ————————————————— 登录/注册/找回 —————————————————

def _alert(err="", msg=""):
    if err:
        return f'<div class="alert err">{esc(err)}</div>'
    if msg:
        return f'<div class="alert ok">{esc(msg)}</div>'
    return ""


AUTH_STYLE = """
  :root { color-scheme: light; --pri:#14b8a6; --pri-d:#0d9488; }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    background:#eef1f5; color:#2b3038; font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif; }
  .authcard { background:#fff; border:1px solid #e8ebf0; border-radius:10px; padding:28px 30px;
    width:340px; box-shadow:0 6px 24px rgba(20,30,50,.08); }
  .authbrand { display:flex; align-items:center; gap:8px; font-weight:700; font-size:19px; color:var(--pri); margin-bottom:18px; }
  label { display:block; font-size:13px; color:#555555; margin:12px 0 5px; }
  input { width:100%; padding:9px 11px; border:1px solid #d5dae1; border-radius:6px; font-size:14px; }
  input:focus { outline:none; border-color:var(--pri); }
  .btn { display:inline-block; text-decoration:none; background:var(--pri); color:#fff; border:0; border-radius:6px;
    padding:9px 15px; font-size:14px; cursor:pointer; }
  .btn:hover { background:var(--pri-d); } .btn.wide { width:100%; margin-top:18px; }
  .authlinks { display:flex; justify-content:space-between; margin-top:16px; font-size:13px; }
  .authlinks a { color:var(--pri); text-decoration:none; }
  .authtip { background:#f6f8fa; border:1px solid #e8ebf0; border-radius:6px; padding:9px 11px; font-size:12px; color:#555555; margin-bottom:6px; }
  .authtip code { background:#ececec; padding:1px 5px; border-radius:4px; }
  .alert { border-radius:6px; padding:8px 11px; font-size:13px; margin-bottom:10px; }
  .alert.err { background:#efefef; color:#1a1a1a; } .alert.ok { background:#efefef; color:#1a1a1a; }
"""


def auth_layout(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>内鬼系统 · {esc(title)}</title>
<style>{AUTH_STYLE}</style></head><body>
<div class="authcard"><div class="authbrand">{icon('risk')}<span>内鬼系统</span></div>{body}</div>
</body></html>"""


def render_login(err="", msg="") -> str:
    return auth_layout("登录", f"""{_alert(err, msg)}
    <form method="post" action="/login">
      <label>用户名 / 邮箱</label><input name="username" required autofocus>
      <label>密码</label><input name="password" type="password" required>
      <button class="btn wide">登录</button>
    </form>
    <div class="authlinks"><a href="/forgot">忘记密码?</a><a href="/register">注册账号</a></div>""")


def render_register(err="", first=False) -> str:
    tip = '<div class="authtip">首次使用, 请创建管理员账号。</div>' if first else ""
    return auth_layout("注册", f"""{tip}{_alert(err)}
    <form method="post" action="/register">
      <label>用户名</label><input name="username" required autofocus>
      <label>邮箱(用于找回密码)</label><input name="email" type="email">
      <label>密码(≥6 位)</label><input name="password" type="password" required minlength="6">
      <button class="btn wide">创建账号</button>
    </form>
    <div class="authlinks"><a href="/login">已有账号? 登录</a></div>""")


def render_forgot(err="", msg="") -> str:
    return auth_layout("找回密码", f"""{_alert(err, msg)}
    <div class="authtip">提交后, 重置链接将输出到<b>服务器控制台</b>(自托管安全方式)。
      也可在服务器运行 <code>python3 -m neigui.web resetpw 用户名</code>。</div>
    <form method="post" action="/forgot">
      <label>用户名 / 邮箱</label><input name="username" required autofocus>
      <button class="btn wide">生成重置链接</button>
    </form>
    <div class="authlinks"><a href="/login">返回登录</a></div>""")


def render_reset(token: str, err="") -> str:
    return auth_layout("重置密码", f"""{_alert(err)}
    <form method="post" action="/reset">
      <input type="hidden" name="token" value="{esc(token)}">
      <label>新密码(≥6 位)</label><input name="password" type="password" required minlength="6" autofocus>
      <button class="btn wide">设置新密码</button>
    </form>
    <div class="authlinks"><a href="/login">返回登录</a></div>""")


# ————————————————— 系统设置 / 更新 —————————————————

def _card_alert(msg="", err=""):
    if err:
        return f'<div class="card" style="border-color:#d9d9d9"><div class="alert err">{esc(err)}</div></div>'
    if msg:
        return f'<div class="card" style="border-color:#bfe6c6"><div class="alert ok">{esc(msg)}</div></div>'
    return ""


def _git_status():
    """返回 (是否git仓库, 落后提交数, 错误信息)。"""
    try:
        inside = subprocess.run(["git", "-C", BASE_DIR, "rev-parse", "--is-inside-work-tree"],
                                capture_output=True, text=True, timeout=5)
        if inside.returncode != 0 or inside.stdout.strip() != "true":
            return False, 0, "未检测到 git 仓库, 无法自动升级"
        cnt = subprocess.run(["git", "-C", BASE_DIR, "rev-list", "--count", "HEAD..@{u}"],
                             capture_output=True, text=True, timeout=5)
        behind = int(cnt.stdout.strip()) if cnt.returncode == 0 and cnt.stdout.strip().isdigit() else 0
        return True, behind, ""
    except Exception as e:  # noqa: BLE001
        return False, 0, f"git 不可用: {e}"


def _update_card() -> str:
    is_git, behind, gerr = _git_status()
    if gerr:
        state = f'<span class="dim">{esc(gerr)}</span>'
        btn = ""
    elif behind > 0:
        state = f'<b>发现新版本, 落后 {behind} 个提交</b>'
        btn = '<form method="post" action="/update/run"><button class="btn">⬆ 升级并重启</button></form>'
    else:
        state = '<span class="on">已是最新</span>'
        btn = ('<form method="post" action="/update/run"><button class="btn ghost">强制拉取并重启</button></form>'
               if is_git else "")
    return f"""
    <div class="card">
      <div class="card-title">版本与更新</div>
      <table class="grid"><tbody>
        <tr><td style="width:120px">当前版本</td><td>v{esc(__version__)}</td></tr>
        <tr><td>更新状态</td><td>{state}</td></tr>
      </tbody></table>
      <div style="margin-top:12px;display:flex;gap:8px;align-items:center">
        <form method="post" action="/update/check"><button class="btn ghost">检查更新</button></form>
        {btn}
      </div>
      <div class="dim small" style="margin-top:10px">
        自动升级依赖 git 仓库: 点击后在项目目录执行 <code>git pull</code> 并自动重启进程。非 git 部署请手动更新代码。
      </div>
    </div>"""


def render_settings(admin, msg="", err="") -> str:
    dbp = CONFIG.db_path
    size = os.path.getsize(dbp) / 1024 if os.path.exists(dbp) else 0
    return f"""{_card_alert(msg, err)}
    <div class="card">
      <div class="card-title">数据库 / 迁移</div>
      <table class="grid"><tbody>
        <tr><td style="width:120px">数据库文件</td><td class="mono small">{esc(dbp)}</td></tr>
        <tr><td>大小</td><td>{size:.1f} KB</td></tr>
      </tbody></table>
      <div style="margin-top:12px"><a class="btn" href="/db/backup">⬇ 备份下载 (.db)</a></div>
      <div class="dim small" style="margin-top:10px">
        单文件 SQLite, 迁移只需把该 .db 拷到新服务器; 或设 <code>NEIGUI_DB=/路径/neigui.db</code>
        环境变量 / 在 config.json 配 <code>db_path</code> 指向它。
      </div>
    </div>
    <div class="card">
      <div class="card-title">修改密码 · {esc(admin['username'])}</div>
      <form method="post" action="/settings/password" class="autoform">
        <input name="old" type="password" placeholder="当前密码" required style="max-width:170px">
        <input name="new" type="password" placeholder="新密码(≥6位)" required minlength="6" style="max-width:170px">
        <button class="btn">更新密码</button>
      </form>
    </div>
    {_update_card()}"""


def _upgrade_and_restart():
    try:
        subprocess.run(["git", "-C", BASE_DIR, "pull", "--ff-only"], timeout=120)
    except Exception:  # noqa: BLE001
        pass
    os.execv(sys.executable, [sys.executable, "-m", "neigui.web", *sys.argv[1:]])


# ————————————————— 布局 —————————————————

def layout(active: str, title: str, content: str, admin_name: str = "") -> str:
    nav_html = ""
    for group, items in NAV:
        if group:
            nav_html += f'<div class="navgroup">{group}</div>'
        for key, name, href in items:
            cls = "navitem active" if key == active else "navitem"
            nav_html += f'<a class="{cls}" href="{href}">{icon(key)}<span>{name}</span></a>'

    return f"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>内鬼系统 · {esc(title)}</title>
<style>
  :root {{ color-scheme: light; --pri:#14b8a6; --pri-d:#0d9488; --bg:#f3f5f7; --card:#fff; --line:#e6e9ed; --txt:#1f2937; --dim:#8a94a3; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif; background:var(--bg); color:var(--txt); display:flex; min-height:100vh; }}
  .side {{ width:216px; flex-shrink:0; background:var(--card); border-right:1px solid var(--line); position:sticky; top:0; height:100vh; overflow:auto; padding-bottom:20px; }}
  .brand {{ display:flex; align-items:center; gap:8px; font-weight:700; font-size:16px; color:var(--pri); padding:16px 18px; border-bottom:1px solid var(--line); margin-bottom:6px; }}
  .navgroup {{ font-size:12px; color:var(--dim); padding:14px 18px 4px; letter-spacing:.5px; }}
  .navitem {{ display:flex; align-items:center; gap:10px; text-decoration:none; color:#444444; padding:9px 18px; font-size:14px; border-left:3px solid transparent; }}
  .navitem svg {{ opacity:.7; flex-shrink:0; }}
  .navitem:hover {{ background:#f5f5f5; color:var(--txt); }}
  .navitem.active {{ color:var(--pri); background:#e6f7f4; border-left-color:var(--pri); font-weight:500; }}
  .navitem.active svg {{ opacity:1; }}
  .main {{ flex:1; min-width:0; padding:22px 26px 60px; }}
  h1 {{ font-size:19px; margin:0 0 18px; font-weight:600; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px 18px; margin-bottom:16px; box-shadow:0 1px 2px rgba(20,30,50,.03); }}
  .card-title {{ display:flex; align-items:center; font-size:15px; font-weight:600; margin-bottom:12px; }}
  table.grid {{ width:100%; border-collapse:collapse; }}
  .grid th,.grid td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
  .grid thead th {{ background:#fafbfc; font-size:12px; color:var(--dim); font-weight:600; }}
  .grid tbody tr:hover {{ background:#fafafa; }}
  .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; }}
  .small {{ font-size:12px; }} .dim {{ color:var(--dim); }}
  .on {{ color:var(--pri); font-weight:600; }} .off {{ color:var(--dim); }}
  .actions {{ display:flex; gap:6px; }} .actions form {{ margin:0; }}
  .btn {{ background:var(--pri); color:#fff; border:0; border-radius:5px; padding:7px 15px; font-size:13px; cursor:pointer; text-decoration:none; display:inline-block; }}
  .btn:hover {{ background:var(--pri-d); }} .btn.sm {{ padding:4px 11px; font-size:12px; }}
  .btn.ghost {{ background:#ececec; color:#444444; }} .btn.ghost:hover {{ background:#e2e6eb; }}
  .btn.danger {{ background:#e5484d; }} .btn.danger:hover {{ background:#cf3a3f; }}
  .addforms {{ display:flex; gap:14px; margin-top:16px; flex-wrap:wrap; }}
  .addbox {{ flex:1; min-width:280px; background:#fafbfc; border:1px dashed #d5dae1; border-radius:8px; padding:12px; display:flex; flex-direction:column; gap:8px; }}
  .ab-title {{ font-weight:600; font-size:13px; }}
  .addbox input, textarea {{ padding:7px 9px; border:1px solid #d5dae1; border-radius:6px; background:#fff; color:var(--txt); font-size:13px; width:100%; font-family:inherit; }}
  .addbox input:focus, textarea:focus {{ outline:none; border-color:var(--pri); }}
  .row2 {{ display:flex; gap:8px; }}
  .autoform {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .autoform input[type=number] {{ padding:6px 8px; border:1px solid #d5dae1; border-radius:6px; background:#fff; color:var(--txt); }}
  .chk {{ display:flex; align-items:center; gap:6px; }} .autostat {{ color:var(--dim); font-size:13px; }}
  .inlineform {{ display:inline-flex; align-items:center; gap:6px; margin-left:10px; }}
  .inlineform input[type=number] {{ padding:3px 6px; border:1px solid #d5dae1; border-radius:5px; background:#fff; color:var(--txt); }}
  .segbar {{ display:inline-flex; border:1px solid #d5dae1; border-radius:7px; overflow:hidden; }}
  .seg {{ border:0; background:#fff; color:#444444; padding:8px 20px; font-size:14px; cursor:pointer; }}
  .seg.active {{ background:var(--pri); color:#fff; }}
  .modal-bg {{ position:fixed; inset:0; background:rgba(0,0,0,.4); display:none; z-index:100; }}
  .modal-bg.open {{ display:flex; align-items:flex-start; justify-content:center; padding-top:8vh; }}
  .modal {{ background:var(--card); border-radius:12px; padding:20px 22px; width:min(460px,92vw); max-height:82vh; overflow:auto; box-shadow:0 12px 44px rgba(0,0,0,.22); }}
  .modal h3 {{ margin:0 0 6px; font-size:16px; }}
  .modal .mfield {{ margin-top:12px; }}
  .modal .mfield label {{ display:block; margin-bottom:4px; }}
  .modal input, .modal textarea {{ width:100%; padding:8px 10px; border:1px solid #d5dae1; border-radius:7px; font-size:13px; font-family:inherit; }}
  .modal input[type=checkbox] {{ width:auto; padding:0; }}
  .modal .row2 {{ display:flex; gap:8px; }}
  .modal-actions {{ display:flex; gap:8px; justify-content:flex-end; margin-top:18px; }}
  .modal .collist {{ display:grid; grid-template-columns:1fr 1fr; gap:10px 18px; margin-top:12px; }}
  .modal .collist label {{ display:flex; align-items:center; gap:8px; font-size:14px; margin:0; white-space:nowrap; }}
  .udetail {{ font-size:13px; }}
  .udetail h4 {{ margin:16px 0 6px; font-size:14px; }}
  .udetail table {{ width:100%; border-collapse:collapse; }}
  .udetail td {{ padding:5px 8px; border-bottom:1px solid var(--line); }}
  .udetail td:first-child {{ color:var(--dim); width:96px; }}
  .pager {{ display:flex; gap:4px; align-items:center; justify-content:flex-end; margin-top:14px; flex-wrap:wrap; }}
  .pg {{ min-width:30px; height:30px; padding:0 8px; display:inline-flex; align-items:center; justify-content:center; border:1px solid var(--line); border-radius:6px; text-decoration:none; color:var(--txt); font-size:13px; }}
  .pg:hover {{ border-color:var(--pri); }}
  .pg.cur {{ background:var(--pri); color:#fff; border-color:var(--pri); }}
  .pg.dis {{ color:#c8c8c8; }} .pg.dot {{ border:0; }}
  .pg-sel {{ height:30px; border:1px solid var(--line); border-radius:6px; padding:0 6px; margin-left:8px; background:var(--card); color:var(--txt); }}
  .switch {{ position:relative; display:inline-block; width:38px; height:20px; vertical-align:middle; }}
  .switch input {{ opacity:0; width:0; height:0; }}
  .switch .track {{ position:absolute; inset:0; background:#cfd4da; border-radius:20px; transition:.15s; cursor:pointer; }}
  .switch .track:before {{ content:""; position:absolute; width:16px; height:16px; left:2px; top:2px; background:#fff; border-radius:50%; transition:.15s; }}
  .switch input:checked + .track {{ background:var(--pri); }}
  .switch input:checked + .track:before {{ transform:translateX(18px); }}
  .settingrow {{ display:flex; align-items:flex-start; gap:16px; padding:14px 2px; border-bottom:1px solid var(--line); }}
  .settingrow:last-child {{ border-bottom:0; }}
  .sr-label {{ width:230px; flex-shrink:0; }}
  .sr-label b {{ font-size:14px; }} .sr-label div {{ font-size:12px; color:var(--dim); margin-top:2px; }}
  .sr-field {{ flex:1; min-width:0; }}
  .sr-field textarea, .sr-field input {{ width:100%; }}
  .stackrow {{ padding:14px 2px; border-bottom:1px solid var(--line); display:block; }}
  .stackrow:last-child {{ border-bottom:0; }}
  .sr-head {{ margin-bottom:8px; }} .sr-head b {{ font-size:14px; }}
  .stackrow textarea, .stackrow input {{ width:100%; }}
  .subtabs {{ display:flex; gap:2px; border-bottom:1px solid var(--line); margin-bottom:6px; }}
  .subtab {{ text-decoration:none; color:var(--dim); padding:9px 18px; font-size:14px; border-bottom:2px solid transparent; margin-bottom:-1px; }}
  .subtab.active {{ color:var(--pri); border-bottom-color:var(--pri); font-weight:500; }}
  .stats {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(132px,1fr)); gap:12px; }}
  .stat {{ display:block; background:#fafbfc; border:1px solid var(--line); border-radius:8px; padding:14px; text-decoration:none; color:inherit; transition:.1s; }}
  .stat:hover {{ border-color:var(--pri); box-shadow:0 1px 4px rgba(20,30,50,.06); }}
  .sval {{ font-size:24px; font-weight:700; }} .slabel {{ font-size:13px; margin-top:2px; }} .ssub {{ font-size:11px; color:var(--dim); }}
  .gauges {{ display:flex; flex-wrap:wrap; gap:10px; justify-content:space-around; }}
  .gauge {{ text-align:center; flex:1; min-width:150px; }}
  .glabel {{ font-size:13px; color:#555555; margin-bottom:4px; }}
  .gsub {{ font-size:12px; color:var(--dim); margin-top:2px; }}
  .chips {{ display:flex; flex-wrap:wrap; gap:8px; margin-bottom:12px; }}
  .chip {{ background:#efefef; border:1px solid var(--line); border-radius:999px; padding:4px 11px; font-size:13px; }}
  .badge {{ color:#fff; padding:2px 10px; border-radius:4px; font-size:12px; font-weight:600; white-space:nowrap; }}
  .tabs {{ display:flex; gap:4px; margin-bottom:12px; }}
  .tab {{ text-decoration:none; color:#444444; padding:5px 13px; border-radius:5px; font-size:13px; background:#efefef; }}
  .tab.active {{ background:var(--pri); color:#fff; }}
  .tablewrap {{ overflow-x:auto; }}
  .grid.sortable th {{ user-select:none; white-space:nowrap; cursor:pointer; }}
  td.num {{ white-space:nowrap; }}
  .rtags {{ min-width:130px; }}
  .rtag {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:12px; margin:1px 3px 1px 0; white-space:nowrap; }}
  .scorebar {{ height:6px; background:#eaedf1; border-radius:3px; overflow:hidden; margin-bottom:4px; width:110px; }}
  .fill {{ height:100%; }} .scoreval {{ font-size:13px; font-weight:600; }}
  .lastrun {{ font-size:13px; }}
  .filebox {{ background:#f6f8fa; border:1px solid var(--line); border-radius:6px; padding:10px 12px; font-size:12px; overflow:auto; margin:0; white-space:pre-wrap; }}
  .topbar {{ display:flex; align-items:center; justify-content:space-between; margin-bottom:18px; }}
  .topbar h1 {{ margin:0; }}
  .userarea {{ display:flex; align-items:center; gap:10px; font-size:13px; }}
  .uname {{ color:#444444; max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .alert {{ border-radius:6px; padding:8px 11px; font-size:13px; }}
  .alert.err {{ background:#efefef; color:#1a1a1a; }} .alert.ok {{ background:#efefef; color:#1a1a1a; }}
  @media (max-width:720px) {{ body {{ display:block; }} .side {{ width:auto; height:auto; position:static; }} }}
</style></head>
<body>
  <div class="side">
    <div class="brand">{icon('risk')}<span>内鬼系统</span></div>
    {nav_html}
  </div>
  <div class="main">
    <div class="topbar">
      <h1>{esc(title)}</h1>
      <div class="userarea">
        <span class="uname">{esc(admin_name)}</span>
        <form method="post" action="/logout"><button class="btn sm ghost">退出登录</button></form>
      </div>
    </div>
    {content}
  </div>
<script>
  function openM(id){{document.getElementById(id).classList.add('open');}}
  function closeM(id){{document.getElementById(id).classList.remove('open');}}
  function setSync(pfx,m){{
    document.getElementById(pfx+'_sync').value=m;
    document.getElementById(pfx+'_sm').classList.toggle('active',m=='manual');
    document.getElementById(pfx+'_sa').classList.toggle('active',m=='auto');
    document.getElementById(pfx+'_sf').classList.toggle('active',m=='follow');
    document.getElementById(pfx+'_ivwrap').style.display=(m=='manual')?'none':'block';
  }}
  function logMode(m){{
    document.getElementById('logMode').value=m;
    document.getElementById('lm_a').classList.toggle('active',m=='agent');
    document.getElementById('lm_f').classList.toggle('active',m=='file');
    document.getElementById('lf_path').style.display=(m=='file')?'block':'none';
    document.getElementById('lf_path_i').required=(m=='file');
    document.getElementById('lf_agenttip').style.display=(m=='agent')?'block':'none';
  }}
  function editLog(b){{
    document.getElementById('el_id').value=b.dataset.id;
    document.getElementById('el_name').value=b.dataset.name;
    document.getElementById('el_path').value=b.dataset.path||'';
    document.getElementById('el_lbl').textContent=(b.dataset.mode=='agent')?'探针日志路径(下发给探针, 留空用默认)':'本地日志路径';
    document.getElementById('el_iv').value=b.dataset.interval||'300';
    setSync('el', b.dataset.sync||'manual');
    openM('editLog');
  }}
  function editV2b(b){{
    document.getElementById('ev_id').value=b.dataset.id;
    document.getElementById('ev_name').value=b.dataset.name||'';
    document.getElementById('ev_port').value=b.dataset.port||'';
    document.getElementById('ev_user').value=b.dataset.user||'';
    document.getElementById('ev_prefix').value=b.dataset.prefix||'';
    var h=document.getElementById('ev_host'); h.value=''; h.placeholder=(b.dataset.host||'')+' (留空不改)';
    var d=document.getElementById('ev_db'); d.value=''; d.placeholder=(b.dataset.db||'')+' (留空不改)';
    document.getElementById('ev_pass').value='';
    document.getElementById('ev_col_email').value=b.dataset.email||'';
    document.getElementById('ev_col_created').value=b.dataset.created||'';
    document.getElementById('ev_col_expired').value=b.dataset.expired||'';
    document.getElementById('ev_col_plan').value='';
    document.getElementById('ev_iv').value=b.dataset.interval||'300';
    setSync('ev', b.dataset.sync||'manual');
    openM('editV2b');
  }}
  function esc0(s){{return (s==null?'':(''+s)).replace(/[&<>]/g,function(c){{return {{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c];}});}}
  function userDetail(tok){{
    openM('userModal');
    document.getElementById('userBody').innerHTML='<div class="dim">加载中…</div>';
    fetch('/api/user?token='+encodeURIComponent(tok)).then(function(r){{return r.json();}}).then(function(d){{
      if(d.error){{document.getElementById('userBody').innerHTML='<div class="dim">'+esc0(d.error)+'</div>';return;}}
      var h='<h4>账号信息</h4><table>';
      h+='<tr><td>邮箱</td><td>'+esc0(d.email)+'</td></tr>';
      h+='<tr><td>用户ID</td><td>'+esc0(d.user_id)+'</td></tr>';
      h+='<tr><td>机场</td><td>'+esc0(d.panel)+'</td></tr>';
      h+='<tr><td>套餐</td><td>'+esc0(d.plan||'未购买')+'</td></tr>';
      h+='<tr><td>注册时间</td><td>'+esc0(d.created_at)+'</td></tr>';
      h+='<tr><td>到期时间</td><td>'+esc0(d.expired)+'</td></tr>';
      h+='<tr><td>状态</td><td>'+(d.banned?'<span style="color:#e5484d">已封禁</span>':'正常')+'</td></tr>';
      h+='<tr><td>Token</td><td style="font-family:monospace;word-break:break-all">'+esc0(d.token)+'</td></tr>';
      h+='<tr><td>已用流量</td><td>'+esc0(d.traffic)+'</td></tr>';
      h+='</table>';
      h+='<h4>风险</h4><table><tr><td>风险分</td><td>'+esc0(d.score)+' ('+esc0(d.level)+')</td></tr>';
      h+='<tr><td>命中信号</td><td>'+(d.signals&&d.signals.length?esc0(d.signals.join(' / ')):'无')+'</td></tr>';
      h+='<tr><td>拉取/IP</td><td>'+esc0(d.pull_count)+' 次 / '+esc0(d.distinct_ips)+' IP</td></tr>';
      h+='<tr><td>在线IP / UA数</td><td>'+esc0(d.online_ips)+' 个在线 / '+esc0(d.distinct_uas)+' 个UA</td></tr>';
      h+='<tr><td>IP共用账号</td><td>'+(d.ip_shared_users>=2?'<span style="color:#e5484d;font-weight:600">'+esc0(d.ip_shared_users)+' 个账号共用同一IP</span>':esc0(d.ip_shared_users)+' 个')+'</td></tr></table>';
      h+='<h4>最近拉取记录</h4>';
      if(d.pulls&&d.pulls.length){{h+='<table>';d.pulls.forEach(function(p){{h+='<tr><td>'+esc0(p.ts)+'</td><td>'+esc0(p.ip)+' · '+esc0(p.ua)+'</td></tr>';}});h+='</table>';}}
      else h+='<div class="dim">暂无拉取记录(未接入订阅日志)</div>';
      h+='<h4>订单记录</h4>';
      if(d.orders&&d.orders.length){{h+='<table>';d.orders.forEach(function(o){{h+='<tr><td>'+esc0(o.created_at)+'</td><td>￥'+esc0(o.amount)+' · '+esc0(o.status)+'</td></tr>';}});h+='</table>';}}
      else h+='<div class="dim">'+esc0(d.orders_msg||'无订单记录')+'</div>';
      document.getElementById('userBody').innerHTML=h;
    }}).catch(function(){{document.getElementById('userBody').innerHTML='<div class="dim">加载失败</div>';}});
  }}
  function cpAgent(t){{
    var c='curl -fsSL "'+location.origin+'/agent/install.sh?token='+t+'" | bash';
    if(navigator.clipboard) navigator.clipboard.writeText(c);
    alert('一键安装命令已复制, 在面板服务器上执行:\\n\\n'+c+'\\n\\n装好后探针会自动连上; 日志路径和上报间隔都在本页该探针行里设置, 无需改命令。');
  }}
  function cpUninstall(){{
    var c="systemctl disable --now spyware-agent 2>/dev/null; rm -f /etc/systemd/system/spyware-agent.service; systemctl daemon-reload; rm -rf /opt/spyware-agent; echo spyware-agent 已卸载";
    if(navigator.clipboard) navigator.clipboard.writeText(c);
    alert('卸载命令已复制, 在探针所在的面板服务器上执行:\\n\\n'+c+'\\n\\n然后在本页点该探针的「删除」移除数据源。');
  }}
(function(){{
  var t=document.getElementById('risk'); if(!t) return;
  t.querySelectorAll('thead th').forEach(function(th,ci){{
    th.addEventListener('click',function(){{
      var tb=t.tBodies[0], rows=Array.prototype.slice.call(tb.rows);
      var asc=th.dataset.asc!=='1'; th.dataset.asc=asc?'1':'0';
      var num=th.dataset.t==='num';
      rows.sort(function(a,b){{
        var x=a.cells[ci], y=b.cells[ci];
        var xv=x.dataset.sort||x.innerText, yv=y.dataset.sort||y.innerText;
        if(num){{return asc?(parseFloat(xv)||0)-(parseFloat(yv)||0):(parseFloat(yv)||0)-(parseFloat(xv)||0);}}
        return asc?(''+xv).localeCompare(yv):(''+yv).localeCompare(xv);
      }});
      rows.forEach(function(r){{tb.appendChild(r);}});
    }});
  }});
}})();
</script>
</body></html>"""


# ————————————————— HTTP —————————————————

VIEWS = {
    "/": ("dashboard", "仪表盘"),
    "/panels/v2board": ("v2board", "前端面板"),
    "/panels/log": ("log", "日志接入"),
    "/logstore": ("logstore", "日志库"),
    "/risk": ("risk", "风险名单"),
    "/rules": ("rules", "风险规则"),
    "/whitelist": ("whitelist", "黑白名单"),
    "/domains": ("domains", "入口域名"),
    "/run": ("run", "运行控制"),
    "/runlog": ("runlog", "运行日志"),
    "/settings": ("settings", "系统设置"),
}

PUBLIC = {"/login", "/register", "/forgot", "/reset"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    # —— 基础响应 ——
    def _send(self, body: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, s: str):
        self._send(s.encode(), "text/html; charset=utf-8")

    def _to(self, loc: str, set_cookie: str = None):
        self.send_response(303)
        self.send_header("Location", loc)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()

    def _back(self):
        self._to(self.headers.get("Referer") or "/")

    def _admin(self, store):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        ck = SimpleCookie(raw)
        if "sid" not in ck:
            return None
        return auth.session_admin(store, ck["sid"].value)

    # —— HEAD(健康检查/监控) ——
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    # —— GET ——
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)
        store = Store()
        try:
            # 被控探针: 安装脚本 / agent 源码 / 配置(免登录, 供远程 agent 调用)
            if path == "/agent/install.sh":
                tok = q.get("token", [""])[0]
                host = self.headers.get("Host") or "127.0.0.1:8787"
                proto = self.headers.get("X-Forwarded-Proto", "http")  # 反代 HTTPS 时用 https
                script = AGENT_INSTALL.replace("__MASTER__", f"{proto}://{host}").replace("__TOKEN__", tok)
                self._send(script.encode(), "text/x-shellscript; charset=utf-8")
                return
            if path == "/agent/agent.py":
                try:
                    with open(AGENT_PATH, "rb") as f:
                        self._send(f.read(), "text/x-python; charset=utf-8")
                except OSError:
                    self._send(b"agent not found", "text/plain")
                return
            if path == "/api/agent/config":
                key = q.get("token", [""])[0]
                src = _source_by_key(store, key)
                interval = (src["interval"] if src and "interval" in src.keys() else 60) or 60
                lp = json.loads(src["config"] or "{}").get("log_path", "") if src else ""
                force = store.get_kv(f"agent_force::{key}", "") == "1"
                if force:
                    store.set_kv(f"agent_force::{key}", "0")  # 一次性
                    if src:  # 探针已取走指令 = 下发成功
                        try:
                            store.add_runlog(src["type"], src["name"], True,
                                             "『立即上报』指令已下发探针, 等待回传")
                        except Exception:  # noqa: BLE001
                            pass
                # 手动「导入」时一并让探针从头重读(reset), 把已有日志补齐(中央去重, 不会重复)
                self._send(json.dumps({"interval": interval, "log_path": lp,
                                       "report_now": force, "reset": force,
                                       "commands": []}).encode(),
                           "application/json; charset=utf-8")
                return

            # 订阅网关决策接口(免登录, 供 Nginx/网关服务端调用; 请仅内网访问)
            if path == "/api/decision":
                tok = q.get("token", [""])[0]
                body = json.dumps(decide(store, tok) if tok else {"error": "missing token"},
                                  ensure_ascii=False).encode()
                self._send(body, "application/json; charset=utf-8")
                return

            n_admin = store.admin_count()
            admin = self._admin(store)

            # 首次使用: 强制建管理员
            if n_admin == 0 and path != "/register":
                self._to("/register")
                return
            # 认证门禁
            if n_admin > 0 and admin is None and path not in PUBLIC:
                self._to("/login")
                return
            if admin is not None and path in PUBLIC:
                self._to("/")
                return

            # 公开认证页
            if path == "/login":
                self._html(render_login(q.get("err", [""])[0], q.get("msg", [""])[0])); return
            if path == "/register":
                self._html(render_register(q.get("err", [""])[0], first=(n_admin == 0))); return
            if path == "/forgot":
                self._html(render_forgot(q.get("err", [""])[0], q.get("msg", [""])[0])); return
            if path == "/reset":
                tok = q.get("token", [""])[0]
                if not tok:
                    self._to("/login"); return
                self._html(render_reset(tok, q.get("err", [""])[0])); return

            # 数据库备份下载
            if path == "/db/backup":
                if os.path.exists(CONFIG.db_path):
                    with open(CONFIG.db_path, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", 'attachment; filename="neigui.db"')
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self._send(b"no db", "text/plain")
                return

            if path == "/api/risks":
                results = analyze(store)
                payload = [{"token": r.token, "score": r.score, "level": r.level, "excluded": r.excluded,
                            "email": r.email, "user_id": r.user_id, "tags": r.tags,
                            "signals": [{"name": s.name, "points": s.points, "detail": s.detail} for s in r.signals]}
                           for r in results]
                self._send(json.dumps(payload, ensure_ascii=False, indent=2).encode(),
                           "application/json; charset=utf-8")
                return

            if path == "/api/user":
                self._send(json.dumps(_user_detail(store, q.get("token", [""])[0]),
                                      ensure_ascii=False).encode(), "application/json; charset=utf-8")
                return

            if path not in VIEWS:
                self._send(b"404", "text/plain; charset=utf-8")
                return
            active, title = VIEWS[path]
            if active == "dashboard":
                content = render_dashboard(store)
            elif active == "v2board":
                content = render_source_page(store, "v2board", q.get("msg", [""])[0], q.get("err", [""])[0])
            elif active == "log":
                content = render_source_page(store, "logfile", q.get("msg", [""])[0], q.get("err", [""])[0])
            elif active == "risk":
                content = render_risklist(store, q.get("level", ["all"])[0],
                                          q.get("panel", ["all"])[0], q.get("q", [""])[0],
                                          q.get("size", ["10"])[0], q.get("page", ["1"])[0])
            elif active == "rules":
                content = render_rules(store)
            elif active == "whitelist":
                content = render_whitelist(q.get("msg", [""])[0], q.get("err", [""])[0],
                                           q.get("tab", ["white"])[0])
            elif active == "domains":
                content = render_domains(store, q.get("panel", [""])[0], q.get("tier", [""])[0],
                                         q.get("msg", [""])[0], q.get("err", [""])[0])
            elif active == "settings":
                content = render_settings(admin, q.get("msg", [""])[0], q.get("err", [""])[0])
            elif active == "logstore":
                content = render_logstore(store, q.get("src", [""])[0],
                                          q.get("size", ["50"])[0], q.get("page", ["1"])[0])
            elif active == "runlog":
                content = render_runlog(store, q.get("kind", [""])[0], q.get("name", [""])[0],
                                        q.get("size", ["10"])[0], q.get("page", ["1"])[0])
            else:
                content = render_controls(store)
            self._html(layout(active, title, content, admin["username"] if admin else ""))
        finally:
            store.close()

    # —— POST ——
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        parsed = urlparse(self.path)
        path = parsed.path
        store = Store()

        # 被控探针上报(免登录, 按源 token 鉴权): logs + VPS 负载
        if path == "/api/agent/report":
            try:
                key = parse_qs(parsed.query).get("token", [""])[0]
                src = _source_by_key(store, key)
                if not src:
                    self._send(b'{"error":"invalid token"}', "application/json; charset=utf-8"); return
                try:
                    payload = json.loads(raw.decode("utf-8", "replace") or "{}")
                except ValueError:
                    payload = {}
                raw = payload.get("logs", []) or []
                recs = [r for r in (parse_line(ln) for ln in raw) if r]
                n = store.add_pulls(recs, src=src["name"])
                sent = len(raw)
                met = payload.get("metrics", {}) or {}
                log_ok = bool(payload.get("log_ok"))
                forced = bool(payload.get("forced"))
                first = store.get_kv(f"agent_seen::{key}", "") == ""
                prev_logok = store.get_kv(f"agent_logok::{key}", "1") == "1"
                store.set_kv(f"agent_metrics::{key}", json.dumps(met))
                store.set_kv(f"agent_seen::{key}", str(time.time()))
                store.set_kv(f"agent_logok::{key}", "1" if log_ok else "0")
                store.set_kv(f"src_ok::{src['id']}", "1")
                store.set_kv(f"src_seen::{src['id']}", str(time.time()))
                # 记入运行日志: 强制上报 / 有新日志 / 首次 / 日志状态变化 才记, 避免心跳刷屏
                if forced or n > 0 or first or (log_ok != prev_logok):
                    mstr = f"CPU {met.get('cpu','-')}% 内存 {met.get('mem','-')}%" if met else ""
                    warn = "" if log_ok else " · ⚠ 未读到日志文件"
                    tag = "强制上报" if forced else ("首次上报" if first else "上报")
                    try:
                        store.add_runlog(src["type"], src["name"], log_ok,
                                         f"探针{tag}成功: 收到 {sent} 行日志, 入库 {n} 条订阅记录"
                                         + (f" · {mstr}" if mstr else "") + warn)
                    except Exception:  # noqa: BLE001
                        pass
                self._send(json.dumps({"ok": n}).encode(), "application/json; charset=utf-8")
            finally:
                store.close()
            return

        # 远程日志推送接入(免登录, 按源 key 鉴权; 供远程 1Panel/aaPanel 服务器推送)
        if path == "/api/ingest":
            try:
                key = parse_qs(parsed.query).get("key", [""])[0]
                src = _source_by_key(store, key)
                if not src:
                    self._send(b'{"error":"invalid key"}', "application/json; charset=utf-8"); return
                text = raw.decode("utf-8", "replace")
                recs = [r for r in (parse_line(ln) for ln in text.splitlines()) if r]
                n = store.add_pulls(recs, src=src["name"])
                self._send(json.dumps({"ok": n}).encode(), "application/json; charset=utf-8")
            finally:
                store.close()
            return

        formq = parse_qs(raw.decode("utf-8", "replace"))
        form = {k: v[0] for k, v in formq.items()}
        try:
            # 公开: 认证相关
            if path == "/login":
                a = auth.authenticate(store, form.get("username", ""), form.get("password", ""))
                if not a:
                    self._to("/login?err=" + quote("用户名或密码错误")); return
                tok = auth.new_session(store, a["id"])
                self._to("/", f"sid={tok}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax"); return
            if path == "/register":
                u = form.get("username", "").strip()
                p = form.get("password", "")
                e = form.get("email", "").strip() or None
                if not u or len(p) < 6:
                    self._to("/register?err=" + quote("用户名必填, 密码至少 6 位")); return
                if store.get_admin_by_name(u):
                    self._to("/register?err=" + quote("用户名已存在")); return
                auth.create_admin(store, u, p, e)
                a = store.get_admin_by_name(u)
                tok = auth.new_session(store, a["id"])
                self._to("/", f"sid={tok}; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax"); return
            if path == "/forgot":
                login = form.get("username", "")
                a = store.get_admin_by_name(login) or store.get_admin_by_email(login)
                if a:
                    t = auth.new_reset(store, a["id"])
                    print(f"\n[内鬼系统] 用户 {a['username']} 的密码重置链接(30 分钟内有效):"
                          f"\n  http://<面板地址>/reset?token={t}\n", flush=True)
                self._to("/forgot?msg=" + quote("若账号存在, 重置链接已输出到服务器控制台")); return
            if path == "/reset":
                t = form.get("token", "")
                p = form.get("password", "")
                if len(p) < 6:
                    self._to(f"/reset?token={quote(t)}&err=" + quote("密码至少 6 位")); return
                if auth.consume_reset(store, t, p):
                    self._to("/login?msg=" + quote("密码已重置, 请登录"))
                else:
                    self._to("/login?err=" + quote("重置链接无效或已过期"))
                return
            if path == "/logout":
                raw = self.headers.get("Cookie")
                if raw:
                    ck = SimpleCookie(raw)
                    if "sid" in ck:
                        store.delete_session(ck["sid"].value)
                self._to("/login", "sid=; Path=/; Max-Age=0"); return

            # 受保护: 需登录
            admin = self._admin(store)
            if admin is None:
                self._to("/login"); return

            if path == "/sources/add":
                t = form.get("type", "logfile")
                name = form.get("name") or t
                if t == "logfile":
                    mode = form.get("mode", "file")
                    if mode == "push":
                        cfg = {"mode": "push", "key": secrets.token_hex(12)}
                    elif mode == "agent":
                        cfg = {"mode": "agent", "key": secrets.token_hex(12)}
                    elif mode == "syslog":
                        cfg = {"mode": "syslog", "tag": "ng_" + secrets.token_hex(4)}
                    else:
                        cfg = {"mode": "file", "path": form.get("path", "").strip()}
                else:
                    cfg = {"host": form.get("host", "127.0.0.1"), "port": form.get("port", "3306"),
                           "user": form.get("user", ""), "password": form.get("password", ""),
                           "database": form.get("database", ""), "prefix": form.get("prefix", "v2_")}
                    cols = {k: form.get(f, "").strip() for k, f in
                            (("email", "col_email"), ("plan", "col_plan"),
                             ("created", "col_created"), ("expired", "col_expired"))
                            if form.get(f, "").strip()}
                    if cols:
                        cfg["cols"] = cols
                store.add_source(t, name, json.dumps(cfg))
                self._back(); return
            if path == "/sources/edit":
                src = store.get_source(int(form["id"]))
                if src:
                    cfg = json.loads(src["config"] or "{}")
                    name = form.get("name", "").strip() or src["name"]
                    if src["type"] == "v2board":
                        # 留空则保留原值(库名/IP 二次编辑打码, 不改就留空)
                        for field in ("host", "port", "user", "database", "prefix"):
                            v = form.get(field, "").strip()
                            if v:
                                cfg[field] = v
                        if form.get("password", ""):
                            cfg["password"] = form["password"]
                        cols = {k: form.get(f, "").strip() for k, f in
                                (("email", "col_email"), ("plan", "col_plan"),
                                 ("created", "col_created"), ("expired", "col_expired"))
                                if form.get(f, "").strip()}
                        if cols:
                            cfg["cols"] = cols
                        else:
                            cfg.pop("cols", None)
                    else:
                        p = form.get("path", "").strip()
                        if cfg.get("mode") == "agent":
                            cfg["log_path"] = p
                        else:
                            cfg["path"] = p
                    # 同步方式: 手动/自动/跟随全局 + 间隔
                    smode = form.get("sync_mode", "manual")
                    if smode not in ("manual", "auto", "follow"):
                        smode = "manual"
                    cfg["sync_mode"] = smode
                    iv = int(form.get("interval", "300") or 300)
                    store.update_source(src["id"], name, json.dumps(cfg))
                    store.set_source_auto(src["id"], 1 if smode != "manual" else 0, iv)
                self._back(); return
            if path == "/risk/cols":
                checked = set(formq.get("col", []))
                hidden = [k for k, _ in RISK_COLS if k not in checked]
                store.set_kv("risk_hidden_cols", json.dumps(hidden))
                self._to("/risk"); return
            if path == "/runlog/clear":
                store.clear_runlog(form.get("kind") or None, form.get("name") or None)
                self._to("/runlog"); return
            if path == "/sources/delete":
                store.delete_source(int(form["id"])); self._back(); return
            if path == "/sources/toggle":
                store.toggle_source(int(form["id"])); self._back(); return
            if path == "/sources/run":
                src = store.get_source(int(form["id"]))
                if not src:
                    self._back(); return
                ok, msg = run_source(store, src)
                store.set_kv("last_run_summary", f"{'✓' if ok else '✗'} [{src['name']}] {msg}")
                store.set_kv("last_run_ts", datetime.now().isoformat(timespec="seconds"))
                # 结果直接回显在当前页
                page = "/panels/v2board" if src["type"] == "v2board" else "/panels/log"
                param = "msg" if ok else "err"
                self._to(f"{page}?{param}=" + quote(f"[{src['name']}] {msg}"))
                return
            if path == "/run/all":
                run_all(store); self._back(); return
            if path == "/auto/mode":
                store.set_kv("auto_enabled", "1" if form.get("mode") == "auto" else "0")
                self._back(); return
            if path == "/rules/toggle":
                key = form.get("key", "")
                off = _rules_off(store)
                if form.get("on"):
                    off.discard(key)
                else:
                    off.add(key)
                store.set_kv("signals_off", json.dumps(sorted(off)))
                self._back(); return
            if path == "/agent/logpath":
                src = store.get_source(int(form["id"]))
                if src:
                    c = json.loads(src["config"] or "{}")
                    c["log_path"] = form.get("log_path", "").strip()
                    store.update_source_config(src["id"], json.dumps(c))
                self._back(); return
            if path == "/sources/auto":
                store.set_source_auto(int(form["id"]), 1 if form.get("auto") else 0,
                                      int(form.get("interval", "300") or 300))
                self._back(); return
            if path == "/whitelist/save-self":
                with open(CONFIG.self_ips_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?msg=" + quote("自有IP已保存")); return
            if path == "/whitelist/save-hosting":
                with open(CONFIG.hosting_cidrs_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?msg=" + quote("机房库已保存")); return
            if path == "/domains/protocols":
                store.set_kv("protocols", form.get("protocols", ""))
                self._to("/domains?msg=" + quote("协议列表已更新")); return
            if path == "/domains/scope":
                store.set_kv("rewrite_scope", "all" if form.get("mode") == "all" else "relay")
                self._to("/domains?msg=" + quote("下发范围已更新")); return
            if path == "/domains/save":
                panel = form.get("panel", "")
                tier = form.get("tier", "normal")
                dm = _domains_map(store)
                slot = dm.setdefault(panel, {}).setdefault(tier, {})
                for proto in _protocols_for(store, panel)[0]:
                    v = form.get(f"domain_{proto}", "").strip()
                    if v:
                        slot[proto] = v
                    else:
                        slot.pop(proto, None)
                store.set_kv("domains_map", json.dumps(dm, ensure_ascii=False))
                self._to(f"/domains?panel={quote(panel)}&tier={quote(tier)}&msg=" + quote("已保存")); return
            if path == "/whitelist/save-ua":
                with open(CONFIG.ua_clients_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?msg=" + quote("UA 白名单已保存")); return
            if path == "/blacklist/save-ip":
                with open(CONFIG.ip_blacklist_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?tab=black&msg=" + quote("IP 黑名单已保存")); return
            if path == "/blacklist/save-ua":
                with open(CONFIG.ua_blacklist_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?tab=black&msg=" + quote("UA 黑名单已保存")); return
            if path == "/blacklist/save-asn":
                with open(CONFIG.asn_blacklist_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?tab=black&msg=" + quote("ASN 黑名单已保存")); return
            if path == "/whitelist/fetch-hosting":
                url = form.get("url", "").strip()
                if not url:
                    self._to("/whitelist?err=" + quote("请填写 URL")); return
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "neigui/1.0"})
                    with urllib.request.urlopen(req, timeout=20) as resp:
                        data = resp.read().decode("utf-8", "replace")
                    with open(CONFIG.hosting_cidrs_file, "w", encoding="utf-8") as f:
                        f.write(data)
                    self._to("/whitelist?msg=" + quote(f"已从 URL 拉取 {_count_cidrs(data)} 条"))
                except Exception as e:  # noqa: BLE001
                    self._to("/whitelist?err=" + quote(f"拉取失败: {e}"))
                return
            if path == "/nodes/add":
                store.add_entity(form.get("kind", "backend"), form.get("name", "").strip(),
                                 form.get("detail", ""), form.get("config", ""))
                self._back(); return
            if path == "/nodes/delete":
                store.delete_entity(int(form["id"])); self._back(); return
            if path == "/settings/password":
                if not auth.verify_password(form.get("old", ""), admin["salt"], admin["pwd_hash"]):
                    self._to("/settings?err=" + quote("当前密码不正确")); return
                if len(form.get("new", "")) < 6:
                    self._to("/settings?err=" + quote("新密码至少 6 位")); return
                salt, h = auth.hash_password(form["new"])
                store.update_admin_password(admin["id"], salt, h)
                self._to("/settings?msg=" + quote("密码已更新")); return
            if path == "/update/check":
                try:
                    subprocess.run(["git", "-C", BASE_DIR, "fetch"], timeout=30)
                except Exception:  # noqa: BLE001
                    pass
                self._to("/settings?msg=" + quote("已检查更新")); return
            if path == "/update/run":
                self._to("/settings?msg=" + quote("正在升级并重启, 请稍候刷新..."))
                threading.Timer(1.0, _upgrade_and_restart).start()
                return

            self._back()
        finally:
            store.close()


def _cli_resetpw(args) -> None:
    import getpass
    if not args:
        print("用法: python3 -m neigui.web resetpw <用户名>")
        return
    store = Store()
    a = store.get_admin_by_name(args[0])
    if not a:
        print(f"未找到管理员: {args[0]}")
        store.close()
        return
    pw = getpass.getpass("新密码(≥6位): ")
    if len(pw) < 6:
        print("密码至少 6 位")
        store.close()
        return
    salt, h = auth.hash_password(pw)
    store.update_admin_password(a["id"], salt, h)
    store.close()
    print(f"已重置 {args[0]} 的密码")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "resetpw":
        _cli_resetpw(argv[1:])
        return
    if argv and argv[0] == "purge-demo":
        s = Store()
        n = s.purge_demo()
        s.close()
        print(f"已清除演示数据: {n} 条示例拉取记录 + 示例用户/日志源")
        return

    p = argparse.ArgumentParser(prog="neigui.web", description="内鬼系统 · 可视化控制后台")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--syslog-port", type=int, default=0, help="Nginx syslog 直发接收端口(默认0关闭; 探针接入无需它)")
    args = p.parse_args(argv)

    seed = Store()
    n_admin = seed.admin_count()
    seed.close()
    Scheduler().start()
    if args.syslog_port:
        SyslogListener(args.syslog_port).start()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"控制后台已启动 → {url}  (Ctrl+C 停止)")
    if args.syslog_port:
        print(f"syslog 直发接收 → udp/{args.syslog_port}")
    if n_admin == 0:
        print(f"首次使用: 浏览器打开 {url}/register 创建管理员账号")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
