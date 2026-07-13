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
from datetime import datetime
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
    "黑名单": "#e5484d", "UA伪造": "#e5484d",
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
    ]),
    ("风险管理", [
        ("risk", "风险名单", "/risk"),
        ("rules", "风险规则", "/rules"),
        ("whitelist", "白名单/黑名单", "/whitelist"),
        ("domains", "入口域名", "/domains"),
    ]),
    ("运行", [("run", "运行控制", "/run")]),
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
mkdir -p /opt/neigui-agent
curl -fsS "$MASTER/agent/agent.py" -o /opt/neigui-agent/agent.py
cat >/etc/systemd/system/neigui-agent.service <<UNIT
[Unit]
Description=neigui agent
After=network.target
[Service]
ExecStart=/usr/bin/python3 /opt/neigui-agent/agent.py --master $MASTER --token $TOKEN --log $LOG
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now neigui-agent
echo "neigui-agent 已安装并启动 (log: $LOG)"
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
                                store.add_pulls([rec])
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
                if master:
                    now = time.time()
                    ran = []
                    for src in store.list_sources():
                        auto = src["auto"] if "auto" in src.keys() else 0
                        if not src["enabled"] or not auto:
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

    def stat(label, val, color="#5b8def", sub=""):
        return (f'<div class="stat"><div class="sval" style="color:{color}">{val}</div>'
                f'<div class="slabel">{label}</div><div class="ssub">{esc(sub)}</div></div>')

    stats = "".join([
        stat("高风险", counts["高"], LEVEL_COLOR["高"]),
        stat("中风险", counts["中"], LEVEL_COLOR["中"]),
        stat("低风险", counts["低"], LEVEL_COLOR["低"]),
        stat("正常/排除", f'{counts["正常"]}/{excluded}', "#8b8f98"),
        stat("用户总数", len(results)),
        stat("拉取记录", _pull_count(store)),
        stat("v2board 面板", n_v2b, "#7c5cff"),
        stat("日志源", n_log, "#7c5cff"),
    ])
    return f"""
    {render_load_panel()}
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
        auto = s["auto"] if "auto" in s.keys() else 0
        iv = (s["interval"] if "interval" in s.keys() else 300) or 300
        sync_mode = (f'<span class="on">自动</span> · 每 {iv}s' if auto else '<span class="off">手动</span>')
        scfg = json.loads(s["config"] or "{}")
        if scfg.get("mode") == "agent":
            tok = scfg.get("key", "")
            seen = float(store.get_kv(f"agent_seen::{tok}", "0") or 0)
            online = seen > 0 and (time.time() - seen) < max(60, iv * 3)
            met = {}
            try:
                met = json.loads(store.get_kv(f"agent_metrics::{tok}", "{}") or "{}")
            except ValueError:
                pass
            status = '<span class="on">● 在线</span>' if online else '<span class="off">○ 离线</span>'
            metstr = (f'CPU {met.get("cpu","-")}% 内存 {met.get("mem","-")}% 磁盘 {met.get("disk","-")}%'
                      if met else "尚无数据")
            detail_cell = (
                f'<div>探针 · {status} <span class="dim small">{metstr}</span></div>'
                f'<button class="btn sm ghost" type="button" style="margin-top:5px" '
                f'onclick="cpAgent(\'{esc(tok)}\')">复制一键安装命令</button>')
        else:
            detail_cell = _source_detail(s)
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
          <td>
            {sync_mode}
            <form method="post" action="/sources/auto" class="inlineform">
              <input type="hidden" name="id" value="{s['id']}">
              <label class="chk small"><input type="checkbox" name="auto" {'checked' if auto else ''}> 自动</label>
              <input name="interval" type="number" min="30" value="{iv}" style="max-width:78px" title="间隔秒">
              <button class="btn sm ghost">保存</button>
            </form>
          </td>
          <td class="actions">
            <form method="post" action="/sources/run"><input type="hidden" name="id" value="{s['id']}"><button class="btn sm">{verb}</button></form>
            <form method="post" action="/sources/delete" onsubmit="return confirm('删除?')"><input type="hidden" name="id" value="{s['id']}"><button class="btn sm danger">删除</button></form>
          </td>
        </tr>"""
    if not rows:
        rows = '<tr><td colspan="5" class="dim" style="padding:16px">暂无, 用下方表单添加</td></tr>'

    run_action = "/run/all"
    run_label = "▶ 同步全部" if kind == "v2board" else "▶ 导入全部"

    if kind == "v2board":
        title = "v2board 面板"
        add_form = f"""
        <form method="post" action="/sources/add" class="addbox">
          <input type="hidden" name="type" value="v2board">
          <div class="ab-title">＋ 添加 v2board 面板(MySQL 只读账号)</div>
          <input name="name" placeholder="机场名称, 如: 机场A" required>
          <div class="row2"><input name="host" placeholder="host" value="127.0.0.1" required>
            <input name="port" placeholder="port" value="3306" style="max-width:90px"></div>
          <div class="row2"><input name="user" placeholder="只读用户" required>
            <input name="password" type="password" placeholder="密码"></div>
          <div class="row2"><input name="database" placeholder="库名, 如 v2board" required>
            <input name="prefix" placeholder="表前缀" value="v2_" style="max-width:110px"></div>
          <button class="btn">添加面板</button>
        </form>"""
        hint = "读 v2_user 的 token/注册时间/流量/分组, 补全用户画像。建议单独建只读账号。"
    else:
        title = "1Panel / aaPanel 日志"
        add_form = """
        <form method="post" action="/sources/add" class="addbox">
          <input type="hidden" name="type" value="logfile">
          <input type="hidden" name="mode" value="agent">
          <div class="ab-title">＋ 探针接入(主控/被控, 日志+VPS负载, 推荐)</div>
          <div class="dim small">添加后复制一键安装命令, 在面板服务器跑一行装好; 上报间隔跟随下方设置。</div>
          <input name="name" placeholder="名称, 如: 机场A" required>
          <button class="btn">添加探针源</button>
        </form>
        <form method="post" action="/sources/add" class="addbox">
          <input type="hidden" name="type" value="logfile">
          <input type="hidden" name="mode" value="file">
          <div class="ab-title">＋ 本地文件(中央与面板同机时)</div>
          <input name="name" placeholder="名称" required>
          <input name="path" placeholder="日志路径, 如 /www/wwwlogs/neigui_sub.log" required>
          <button class="btn">添加本地源</button>
        </form>"""
        hint = ("面板里给订阅路由配 neigui 日志格式 + real_ip。远程面板用<b>探针接入</b>"
                "(一键安装, 自动上报日志+负载); 中央与面板同机可用本地文件。")

    extra = ""
    if kind == "logfile":
        extra = """
        <div class="card">
          <div class="card-title">远程面板如何接入(探针)</div>
          <div class="dim small" style="line-height:1.9">
            用上表「探针接入」添加一个源, 点其「复制一键安装命令」, 在<b>面板服务器</b>上执行:
            <pre class="filebox">curl -fsSL "http://&lt;中央地址&gt;/agent/install.sh?token=&lt;token&gt;" | bash</pre>
            (默认日志路径 <code>/www/wwwlogs/neigui_sub.log</code>, 需改则在命令前加 <code>LOG=/你的路径</code>。)
            装好后被控 agent 自动: 本地增量读订阅日志 + 采集本机 VPS 负载, 按中央设置的同步间隔上报;
            在线状态和负载显示在上表「目标」列。中央需对面板服务器 HTTP 可达, 生产建议加反代/防火墙限源。
          </div>
        </div>"""

    return f"""{_card_alert(msg, err)}
    <div class="card">
      <div class="card-title">{title}
        <form method="post" action="{run_action}" style="margin-left:auto"><button class="btn">{run_label}</button></form>
      </div>
      <div class="dim small" style="margin-bottom:10px">{hint}</div>
      <div class="tablewrap">
      <table class="grid">
        <thead><tr><th>名称</th><th>目标</th><th>状态</th><th>同步方式</th><th>操作</th></tr></thead>
        <tbody>{rows}</tbody>
      </table></div>
      <div class="addforms">{add_form}</div>
    </div>{extra}"""


def render_controls(store: Store) -> str:
    enabled = store.get_kv("auto_enabled", "0") == "1"
    last_run = store.get_kv("last_run_summary", "尚未运行")
    last_run_ts = store.get_kv("last_run_ts", "")
    man_cls = "seg active" if not enabled else "seg"
    auto_cls = "seg active" if enabled else "seg"
    n_auto = sum(1 for s in store.list_sources() if (s["auto"] if "auto" in s.keys() else 0) and s["enabled"])
    return f"""
    <div class="card">
      <div class="card-title">运行模式</div>
      <form method="post" action="/auto/mode" class="autoform">
        <div class="segbar">
          <button name="mode" value="manual" class="{man_cls}">手动运行</button>
          <button name="mode" value="auto" class="{auto_cls}">自动运行</button>
        </div>
        <span class="autostat">
          {'自动模式: 后台按各数据源的「同步方式」定时运行, 当前 ' + str(n_auto) + ' 个源开启自动。'
            if enabled else '手动模式: 后台不自动运行, 需手动触发。'}
        </span>
      </form>
      <div style="margin-top:14px"><form method="post" action="/run/all"><button class="btn">▶ 立即手动运行全部</button></form></div>
      <div class="lastrun" style="margin-top:12px">最近一次: <b>{esc(last_run)}</b> <span class="dim">{esc(last_run_ts)}</span></div>
    </div>
    <div class="card">
      <div class="dim small">提示: 每个 v2board / 日志源可在各自页面单独设「自动/手动」及间隔; 此处的「自动运行」是总开关, 关闭则所有源都不自动执行。</div>
    </div>"""


WEIGHT_CN = {
    "blacklist_hit": ("命中黑名单", "IP/UA/ASN 黑名单命中, 直接判高危并隔离下发"),
    "hosting_asn": ("机房ASN拉订阅", "订阅来自机房/IDC IP(真人应为住宅/移动)"),
    "ua_tool": ("工具类UA", "用 curl/python/Go 等工具或空 UA 拉订阅"),
    "ua_spoof": ("UA伪造", "声称客户端 UA 却来自机房 ASN, 疑似伪造"),
    "pull_regularity": ("机器规整拉取", "拉取间隔过于规整, 呈自动化定时特征"),
    "traffic_divergence": ("流量背离", "持续拉取却几乎零流量, 只拿节点不使用"),
    "reg_trajectory": ("注册即侦察", "注册后立即拉取且无流量, 疑似注册就为拿节点"),
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


def render_risklist(store: Store, flt: str, panel_flt: str = "all") -> str:
    results = analyze(store)
    counts = {"高": 0, "中": 0, "低": 0, "正常": 0}
    excluded = 0
    panels = set()
    for r in results:
        counts[r.level] = counts.get(r.level, 0) + 1
        excluded += 1 if r.excluded else 0
        if r.panel:
            panels.add(r.panel)

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
    panel_bar = f'<div class="tabs"><span class="dim small" style="align-self:center;margin-right:4px">机场:</span>{ptabs}</div>' if panels else ""

    rows = ""
    for r in results:
        if flt in ("高", "中", "低", "正常") and r.level != flt:
            continue
        if panel_flt and panel_flt != "all" and (r.panel or "") != panel_flt:
            continue
        color = LEVEL_COLOR.get(r.level, "#8b8f98")
        uid = esc(r.user_id if r.user_id is not None else "-")
        tags_html = "".join(
            f'<span class="rtag" style="background:{TAG_COLOR.get(t, "#8b8f98")}22;'
            f'color:{TAG_COLOR.get(t, "#8b8f98")}">{esc(t)}</span>' for t in r.tags)
        if r.excluded:
            tags_html = '<span class="rtag" style="background:#8b8f8822;color:#8b8f98">自有基础设施</span>'
        detail = " | ".join(f"{s.name}(+{s.points})" for s in r.signals) or "无命中信号"
        rows += f"""
        <tr title="{esc(detail)}">
          <td class="mono small">{uid}</td>
          <td class="small">{esc(r.email or '-')}</td>
          <td class="small">{esc(r.panel or '-')}</td>
          <td class="mono small dim">{esc(r.token[:12])}</td>
          <td class="num">{r.distinct_ips}</td>
          <td class="num">{r.pull_count}</td>
          <td class="num" data-sort="{r.score}">
            <div class="scorebar"><div class="fill" style="width:{min(100, int(r.score))}%;background:{color}"></div></div>
            <span class="scoreval">{r.score}</span></td>
          <td><span class="badge" style="background:{color};color:{LEVEL_FG.get(r.level, '#fff')}">{LEVEL_TEXT.get(r.level, r.level)}</span></td>
          <td class="rtags">{tags_html or '<span class="dim">—</span>'}</td>
          <td class="small dim">待接入</td>
          <td class="small dim">{_humanize(r.last_pull)}</td>
        </tr>"""
    if not rows:
        rows = '<tr><td colspan="11" class="dim" style="padding:20px">暂无用户</td></tr>'

    return f"""
    <div class="card">
      <div class="card-title">用户风险管理
        <span class="dim small" style="font-weight:400;margin-left:8px">点表头排序</span></div>
      <div class="chips">{chips}</div>
      <div class="tabs">{tabs}</div>
      {panel_bar}
      <div class="tablewrap">
      <table class="grid sortable" id="risk">
        <thead><tr>
          <th data-t="num">用户ID</th><th>邮箱</th><th>机场</th><th>Token</th>
          <th data-t="num">IP数</th><th data-t="num">拉取</th>
          <th data-t="num">风险分</th><th>风险等级</th>
          <th>风险标签</th><th>访问画像</th><th>最后活跃</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table></div>
      <div class="dim small" style="margin-top:8px">机场归属来自 v2board 面板同步; 「访问画像」需接入节点侧流量日志后点亮。</div>
    </div>"""


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
  .stat {{ background:#fafbfc; border:1px solid var(--line); border-radius:8px; padding:14px; }}
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
  function cpAgent(t){{
    var c='curl -fsSL "'+location.origin+'/agent/install.sh?token='+t+'" | bash';
    if(navigator.clipboard) navigator.clipboard.writeText(c);
    alert('一键安装命令已复制, 在面板服务器上执行:\\n\\n'+c+'\\n\\n(默认日志路径 /www/wwwlogs/neigui_sub.log, 需改则在命令前加 LOG=/你的路径 )');
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
    "/risk": ("risk", "风险名单"),
    "/rules": ("rules", "风险规则"),
    "/whitelist": ("whitelist", "白名单/黑名单"),
    "/domains": ("domains", "入口域名"),
    "/run": ("run", "运行控制"),
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
                self._send(json.dumps({"interval": interval, "commands": []}).encode(),
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
                content = render_risklist(store, q.get("level", ["all"])[0], q.get("panel", ["all"])[0])
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
                recs = [r for r in (parse_line(ln) for ln in payload.get("logs", [])) if r]
                n = store.add_pulls(recs)
                store.set_kv(f"agent_metrics::{key}", json.dumps(payload.get("metrics", {})))
                store.set_kv(f"agent_seen::{key}", str(time.time()))
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
                n = store.add_pulls(recs)
                self._send(json.dumps({"ok": n}).encode(), "application/json; charset=utf-8")
            finally:
                store.close()
            return

        form = {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}
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
                store.add_source(t, name, json.dumps(cfg))
                self._back(); return
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

    p = argparse.ArgumentParser(prog="neigui.web", description="内鬼系统 · 可视化控制后台")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--syslog-port", type=int, default=0, help="Nginx syslog 直发接收端口(默认0关闭; 探针接入无需它)")
    args = p.parse_args(argv)

    seed = Store()
    _seed_defaults(seed)
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
