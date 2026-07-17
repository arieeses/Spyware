"""本地可视化控制后台(零依赖, 标准库 http.server)。

  python3 -m spyware.web            # http://127.0.0.1:8787

侧边栏分类导航: 仪表盘 / 接入管理(v2board·1Panel·aaPanel) / 风险管理 / 运行。
注意: 无鉴权, 仅绑定 127.0.0.1; 勿直接暴露公网(v2board 密码存在本地库)。
"""
from __future__ import annotations

import argparse
import html
import json
import math
import os
import re
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
from .log_parser import load_proxy_nets, parse_line
from .pipeline import decide
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
        ("featlib", "特征库", "/featlib"),
        ("insiders", "内鬼库", "/insiders"),
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

AGENT_PATH = os.path.join(BASE_DIR, "agent", "spyware-agent.py")

# 被控探针一键安装脚本(__MASTER__/__TOKEN__ 由主控按请求 Host 注入)
AGENT_INSTALL = """#!/bin/bash
set -e
MASTER="__MASTER__"
TOKEN="__TOKEN__"
LOG="${LOG:-/www/wwwlogs/spyware_sub.log}"
# 先停掉所有旧版/同名探针, 避免多个进程同时上报(旧进程会读默认路径→"未读到日志文件")
for SVC in spyware-agent spyware-agent spywarp; do
  systemctl disable --now "$SVC" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SVC.service" 2>/dev/null || true
done
# 兜底: 杀掉任何游离的 agent.py 进程(手动跑起来的)
pkill -f "spyware-agent/agent.py" 2>/dev/null || true
pkill -f "spyware-agent" 2>/dev/null || true
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "错误: 未找到 python3。请先安装, 如 Debian/Ubuntu: apt -y install python3 ; CentOS: yum -y install python3"
  exit 1
fi
mkdir -p /opt/spyware-agent
curl -fsS "$MASTER/agent/agent.py" -o /opt/spyware-agent/agent.py
# 校验下载到的是 python 脚本而非错误页(WAF/404 可能返回 HTML)
head -1 /opt/spyware-agent/agent.py | grep -q "python" || {
  echo "错误: 下载到的 agent.py 不是脚本(可能被 WAF 拦截或地址错误), 内容开头:"; head -3 /opt/spyware-agent/agent.py; exit 1; }
cat >/etc/systemd/system/spyware-agent.service <<UNIT
[Unit]
Description=Spyware Agent (探针)
After=network.target
[Service]
ExecStart=$PY /opt/spyware-agent/agent.py --master $MASTER --token $TOKEN --log $LOG --state /opt/spyware-agent/state.json
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl reset-failed spyware-agent 2>/dev/null || true   # 清除之前快速失败的限流
systemctl enable spyware-agent 2>/dev/null || true
systemctl restart spyware-agent   # restart 而非 start: 确保加载最新 agent.py
sleep 2
echo "spyware-agent 已安装 (python: $PY, log: $LOG)"
if systemctl is-active --quiet spyware-agent; then
  echo "自检: 正常运行 · 进程数 $(pgrep -fc 'spyware-agent/agent.py')"
else
  echo "自检: 启动失败 ✗  最近日志:"
  journalctl -u spyware-agent -n 12 --no-pager 2>/dev/null || tail -n 12 /var/log/syslog 2>/dev/null
fi
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


def _iso_dt(s):
    """ISO 字符串 → datetime(供 _humanize); 解析失败或空返回 None。"""
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


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
    if sec < 2592000:
        return f"{int(sec // 86400)} 天前"
    if sec < 31536000:
        return f"{int(sec // 2592000)} 个月前"
    return f"{int(sec // 31536000)} 年前"


def _ago_cell(iso_str, cls="small dim") -> str:
    """相对时间单元格, 带 data-sort=epoch 供按时间排序。"""
    dt = _iso_dt(iso_str)
    return f'<td class="{cls}" data-sort="{int(dt.timestamp()) if dt else 0}">{_humanize(dt)}</td>'


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
             ("sameip", "同IP"), ("pull", "拉取"), ("score", "风险分"), ("level", "风险等级"),
             ("tags", "风险标签"), ("created", "注册时间"), ("expired", "到期时间"), ("last", "最新拉取订阅")]
_NUM_COLS = {"uid", "ips", "online", "uas", "shared", "pull", "score", "last"}
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
    from .pipeline import load_config
    _cfg = load_config(store)
    _ipc0 = IpClassifier()
    win_h = _cfg.thresholds.online_window_hours
    _now = datetime.now(timezone.utc)
    _since = (_now - timedelta(hours=max(1, win_h))).isoformat()
    from .enrich import FeatureLib, InsiderMatcher
    r = score_token(build_features(tok, pulls, user, IpClassifier(), UaClassifier(), Blacklist(),
                                   ip_users=store.ip_user_counts_for_token(tok, _since),
                                   window_hours=win_h, now=_now,
                                   ip_panels=store.ip_panel_map(), email_panels=store.email_panel_map(),
                                   featlib=FeatureLib(store), burst_window=_cfg.thresholds.burst_ua_window,
                                   night_start=_cfg.thresholds.night_start_hour,
                                   night_end=_cfg.thresholds.night_end_hour,
                                   insmatch=InsiderMatcher(store, _cfg.thresholds.insider_subnet_prefix)),
                    _cfg, _disabled_signals(store))
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
        "signals": [(s.detail if s.name == "命中特征库" and s.detail else s.name) for s in r.signals],
        "pull_count": r.pull_count, "distinct_ips": r.distinct_ips,
        "distinct_uas": r.distinct_uas, "online_ips": r.online_ips,
        "ip_shared_users": r.ip_shared_users,
        "pulls": [{"ts": (p["ts"] or "")[:19].replace("T", " "), "ip": p["ip"],
                   "asn": _ip_asn_label(_ipc0, p["ip"]),
                   "ua": (p["ua"] or "")[:30]} for p in pulls[-15:][::-1]],
    }
    return d


_ASN_TYPE_CN = {"hosting": "机房", "residential": "住宅", "self": "自有", "unknown": "?"}


def _ip_asn_label(ipc, ip: str) -> str:
    """给详情页每条拉取标注 ASN + 类型, 如 'AS4812 CHINANET · 住宅'。"""
    asn, org = ipc.asn_info(ip)
    typ = _ASN_TYPE_CN.get(ipc.classify(ip), "")
    if asn:
        return f"AS{asn} {(org or '')[:22]} · {typ}"
    return typ or "-"


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
                            rec = parse_line(text[i + len(tag) + 2:].strip(), load_proxy_nets())
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
                # 后台物化风险评分: 数据/配置变化或超 5 分钟就重算, 页面永远读现成结果
                try:
                    from .pipeline import recompute_scores, scores_stale
                    if scores_stale(store):
                        recompute_scores(store)
                except Exception:  # noqa: BLE001
                    pass
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
    counts = store.score_counts()
    excluded = counts["excluded"]
    total_users = counts["total"]
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
        stat("用户总数", total_users, href="/risk"),
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
    kind_srcs = [s for s in store.list_sources() if s["type"] == kind]
    n_kind = len(kind_srcs)
    rows = ""
    for pos, s in enumerate(kind_srcs):
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
                         f'data-panel="{esc(scfg.get("panel",""))}" '
                         f'data-sync="{smode}" data-interval="{iv}"')
            edit_fn = "editLog"
        elif kind == "logfile":
            detail_cell = _source_detail(s)
            edit_attr = (f'data-id="{s["id"]}" data-name="{esc(s["name"])}" '
                         f'data-mode="file" data-path="{esc(scfg.get("path",""))}" '
                         f'data-panel="{esc(scfg.get("panel",""))}" '
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
            <form method="post" action="/sources/move" style="display:inline-flex;gap:2px">
              <input type="hidden" name="id" value="{s['id']}">
              <button class="btn sm ghost" name="dir" value="up" title="上移" {'disabled' if pos == 0 else ''}>↑</button>
              <button class="btn sm ghost" name="dir" value="down" title="下移" {'disabled' if pos == n_kind - 1 else ''}>↓</button>
            </form>
            <form method="post" action="/sources/run"><input type="hidden" name="id" value="{s['id']}"><button class="btn sm">{verb}</button></form>
            <button class="btn sm ghost" type="button" onclick="{edit_fn}(this)" {edit_attr}>编辑</button>
            <a class="btn sm ghost" href="/runlog?name={quote(s['name'])}">日志</a>
            <form method="post" action="/sources/delete" onsubmit="return confirm('删除该源? 会一并清除它带进来的用户/日志数据')"><input type="hidden" name="id" value="{s['id']}"><button class="btn sm danger">删除</button></form>
          </td>
        </tr>"""
    if not rows:
        rows = '<tr><td colspan="5" class="dim" style="padding:16px">暂无, 点右上「＋ 添加」</td></tr>'

    if kind == "v2board":
        title, run_label, add_id = "v2board 面板", "▶ 同步全部", "addV2b"
        hint = "读 v2_user 的 token/注册时间/流量/分组, 补全用户画像。建议单独建只读账号。"
        modals = _v2b_modals()
        extra = """
        <div class="card">
          <div class="dim small">改了面板名后, 已同步的用户面板已自动跟着改。若风险名单里仍有<b>改名前的旧名或已删除的面板</b>(遗留数据), 点下面清理:
            <form method="post" action="/panels/cleanup" style="margin-top:8px"
                  onsubmit="return confirm('删除面板不属于当前任何 v2board 源的遗留用户/评分? 建议先把要保留的面板都同步一遍再清理。')">
              <button class="btn ghost">🧹 清理改名/删除遗留的面板数据</button></form>
          </div>
        </div>"""
    else:
        title, run_label, add_id = "1Panel / aaPanel 日志", "▶ 导入全部", "addLog"
        hint = ("远程面板用<b>探针接入</b>(一键安装, 自动上报日志+负载); 中央与面板同机可用本地文件。"
                "日志路径与上报间隔都可在每行「编辑」里改。")
        modals = _log_modals([p["name"] for p in store.list_sources() if p["type"] == "v2board"])
        extra = """
        <div class="card">
          <div class="card-title">远程面板如何接入(探针)</div>
          <div class="dim small" style="line-height:1.9">
            右上「＋ 添加」→ 探针接入, 添加后点该行「复制安装命令」在<b>面板服务器</b>执行:
            <pre class="filebox">curl -fsSL "http://&lt;中央地址&gt;/agent/install.sh?token=&lt;token&gt;" | bash</pre>
            装好后被控 agent 自动上报日志+VPS负载; <b>日志路径、上报间隔在该行「编辑」/「同步方式」里设置</b>, 无需改命令。
          </div>
        </div>"""

    rebuild = ("" if kind == "v2board" else
               '<form method="post" action="/logs/rebuild" '
               'onsubmit="return confirm(\'清空全部拉取日志并从头重新导入? 用于修复早期反代IP重复/面板标错的脏数据。日志仍在磁盘, 会重读。\')">'
               '<button class="btn ghost">🔄 清空并重建</button></form>')
    return f"""{_card_alert(msg, err)}
    <div class="card">
      <div class="card-title">{title}
        <div style="margin-left:auto;display:flex;gap:8px">
          <button class="btn" type="button" onclick="openM('{add_id}')">＋ 添加</button>
          <form method="post" action="/run/all"><button class="btn ghost">{run_label}</button></form>
          {rebuild}
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


def _panel_options(panels, sel_id="") -> str:
    opts = '<option value="">(不归属 / 用名称)</option>'
    for p in panels:
        opts += f'<option value="{esc(p)}">{esc(p)}</option>'
    return f'<select name="panel" id="{sel_id}">{opts}</select>' if sel_id else \
           f'<select name="panel">{opts}</select>'


def _log_modals(panels=None) -> str:
    panels = panels or []
    add_sel = _panel_options(panels)
    edit_sel = _panel_options(panels, "el_panel")
    plist = ("、".join(esc(p) for p in panels)) if panels else "(还没建前端面板)"
    # 每行 "路径 | 面板名" 单独归属; 末尾没写 | 的行用下面「默认归属面板」
    path_hint = (
        '<div class="dim small" style="margin-top:4px;line-height:1.7">'
        '每行一个路径; 填目录=读其下所有 .log; 通配用 *。<br>'
        '一个源里多个站点分别归属: 行末加 <code>| 面板名</code> 指定该路径归哪个前端面板。<br>'
        f'没写 <code>|</code> 的行用上面的「默认归属面板」。可选面板: <b>{plist}</b>。</div>')
    panel_hint = ('<div class="dim small" style="margin-top:4px">'
                  '路径行没单独写 <code>| 面板名</code> 时用它。</div>')
    ph = "&#47;path&#47;siteA&#47;log | 面板A&#10;&#47;path&#47;siteB&#47;log | 面板B"
    wide = 'style="width:min(680px,95vw)"'
    return """
    <div class="modal-bg" id="addLog"><div class="modal" """ + wide + """>
      <h3>添加日志源</h3>
      <div class="segbar" style="margin:10px 0">
        <button type="button" id="lm_a" class="seg active" onclick="logMode('agent')">探针接入</button>
        <button type="button" id="lm_f" class="seg" onclick="logMode('file')">本地文件</button>
      </div>
      <form method="post" action="/sources/add">
        <input type="hidden" name="type" value="logfile">
        <input type="hidden" name="mode" id="logMode" value="agent">
        <div class="mfield"><input name="name" placeholder="名称, 如: VPS-1" required></div>
        <div class="mfield"><label class="dim small">默认归属前端面板</label>""" + add_sel + panel_hint + """</div>
        <div class="mfield" id="lf_agenttip"><div class="dim small">探针: 添加后点该行「复制安装命令」在面板服务器执行; 日志路径/间隔装好后在该行编辑。</div></div>
        <div class="mfield" id="lf_path" style="display:none">
          <label class="dim small">日志路径</label>
          <textarea name="path" id="lf_path_i" rows="4" placeholder=\"""" + ph + """\"></textarea>
          """ + path_hint + """
        </div>
        <div class="modal-actions"><button type="button" class="btn ghost" onclick="closeM('addLog')">取消</button><button class="btn">添加</button></div>
      </form>
    </div></div>
    <div class="modal-bg" id="editLog"><div class="modal" """ + wide + """>
      <h3>编辑日志源</h3>
      <form method="post" action="/sources/edit">
        <input type="hidden" name="id" id="el_id">
        <div class="mfield"><label class="dim small">名称</label><input name="name" id="el_name"></div>
        <div class="mfield"><label class="dim small">默认归属前端面板</label>""" + edit_sel + panel_hint + """</div>
        <div class="mfield"><label class="dim small" id="el_lbl">日志路径</label>
          <textarea name="path" id="el_path" rows="4" placeholder=\"""" + ph + """\"></textarea>
          """ + path_hint + """</div>
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


def render_logstore(store: Store, src: str = "", size: str = "10", page: str = "1") -> str:
    """日志库: 展示各接口/探针上报入库的拉取日志原文, 按来源(数据源)分类。"""
    total = store.count_pulls_by_src(src or None)
    psize, pg, pages, all_mode = _paginate(size, page, total, 10)
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
                        size if str(size) in ("10", "20", "50", "100", "200") else "10",
                        pg, pages, ["10", "20", "50", "100", "200"])
    clear = (f'<form method="post" action="/logstore/clear" style="margin-left:auto" '
             f'onsubmit="return confirm(\'清空{("来源 " + src) if src else "全部"}的日志库记录? 不可恢复\')">'
             f'<input type="hidden" name="src" value="{esc(src)}">'
             f'<button class="btn sm danger">清空{("本来源" if src else "全部")}</button></form>')
    return f"""
    <div class="card">
      <div class="card-title">日志库 <span class="dim small" style="font-weight:400;margin-left:8px">共 {total} 条拉取记录</span>{clear}</div>
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
    "multi_cloud": ("跨云机房拉取", "订阅同时来自多个云厂商(阿里云/AWS/腾讯云/UCloud/Google/Azure等), 真人不会跨云, 极可疑"),
    "ua_tool": ("工具类UA", "用 curl/python/Go 等工具或空 UA 拉订阅"),
    "ua_spoof": ("UA伪造", "声称客户端 UA 却来自机房 ASN, 疑似伪造"),
    "pull_regularity": ("机器规整拉取", "拉取间隔过于规整, 呈自动化定时特征"),
    "traffic_divergence": ("流量背离", "近三月实际使用的每一天上/下行都<5MB(哪怕只用了几天), 只探节点不真用"),
    "reg_trajectory": ("注册即侦察", "注册后立即拉取且无流量, 疑似注册就为拿节点"),
    "multi_ua": ("多客户端UA", "一个 token 用了多个不同 UA, 疑似多人共享/工具轮换"),
    "ua_burst": ("短时多UA轮换", "短时窗口内秒级切换多个客户端UA, 真人不可能, 自动化探测铁证"),
    "online_ips": ("多IP在线", "一个 token 近期在多个不同 IP 活跃, 疑似分发/分布式扫描"),
    "ip_shared": ("IP共用账号", "该 token 的 IP 被多个账号共用, 疑似聚合点/攻击机"),
    "active_lowtraffic": ("有效期内零流量新号", "2025年后注册+订阅有效期内+流量<5MB, 付费却几乎不用, 疑似只拉节点攻击"),
    "cross_panel_ip": ("跨面板同IP", "同一拉取 IP 出现在多个前端面板, 疑似一台机器打多个机场"),
    "email_multi_panel": ("同邮箱多面板", "同一邮箱在多个面板注册, 疑似批量身份"),
    "fixed_schedule": ("固定时段拉取", "拉取时刻跨多天却高度集中在某窄时段, 呈 cron/自动化"),
    "traffic_symmetry": ("流量上下行对称", "近30天上下行接近对称(真人应下行远大于上行), 疑似中转/攻击"),
    "feature_lib": ("命中特征库", "命中你手工登记的特征(IP/UA/ASN/邮箱), 强信号"),
    "insider_ip": ("内鬼同IP", "与内鬼库已确认账号用同一个 IP(精确), 极强"),
    "insider_subnet": ("内鬼同网段", "与内鬼在同一网段(默认/24, 机房常整段作恶)"),
    "insider_asn": ("内鬼同ASN", "与内鬼在同一 ASN(同机房)"),
    "insider_ua": ("内鬼同UA", "与内鬼用同一客户端/UA(整串精确)"),
    "insider_pattern": ("内鬼行为相似", "命中与某已确认内鬼相同的一组信号, 行为高度相似"),
    "insider_prefix": ("内鬼同邮箱前缀", "邮箱前缀与内鬼相同(如 bintest_vpn@任意域名)"),
    "night_pull": ("深夜拉取", "北京时间凌晨2-6点仍在规律拉订阅, 非真人作息, 疑似自动化"),
    "ip_silence": ("拉取后IP静默", "拉取IP 拉完就不通/从不连节点(需节点侧日志)"),
    "scan_pattern": ("扫描式短连", "遍历所有节点每个只碰一次(需节点侧日志)"),
    "tls_mismatch": ("TLS指纹矛盾", "UA 与 TLS/JA3 指纹不符(需 JA3 模块)"),
}
THRESH_CN = {
    "level_high": "高风险阈值(分)", "level_mid": "中风险阈值(分)", "level_low": "低风险阈值(分)",
    "multi_cloud_min": "跨云机房-最少不同云厂商数(2=跨2云即判)",
    "divergence_active_days": "流量背离-最少实际使用天数(达到即按实际天判)", "divergence_day_up_bytes": "流量背离-每日上行上限(字节)",
    "divergence_day_down_bytes": "流量背离-每日下行上限(字节)",
    "divergence_max_bytes": "注册即侦察-累计流量上限(字节)",
    "regular_cv": "规整判定-间隔变异系数上限", "regular_min_pulls": "规整判定-最少拉取次数",
    "reg_immediate_secs": "注册即拉-秒内算立即", "new_account_days": "新号判定-账龄天数",
    "self_exclude_ratio": "自有IP排除-占比阈值",
    "reg_year_from": "重点排查-注册年份下限(含)", "active_lowtraffic_max_bytes": "重点排查-流量上限(字节)",
    "burst_ua_min": "短时多UA-窗口内UA数下限", "burst_ua_window": "短时多UA-窗口秒数",
    "night_start_hour": "深夜拉取-起点(北京时,含)", "night_end_hour": "深夜拉取-终点(北京时,不含)",
    "night_min_pulls": "深夜拉取-次数下限",
    "insider_subnet_prefix": "内鬼同网段-网段长度(24=/24)",
    "insider_pattern_min": "内鬼行为相似-共享信号数下限",
    "cross_panel_ip_min": "跨面板同IP-面板数下限", "email_panel_min": "同邮箱多面板-面板数下限",
    "fixed_min_pulls": "固定时段-最少拉取次数", "fixed_min_days": "固定时段-最少跨天数",
    "fixed_concentration": "固定时段-时刻聚集度阈值(0~1)",
    "symmetry_ratio": "流量对称-上下行比阈值(0~1)", "symmetry_min_bytes": "流量对称-30天总量下限(字节)",
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


_RNUM = ('style="width:92px;padding:5px 8px;border:1px solid #d5dae1;border-radius:6px;'
         'text-align:right;font-family:inherit"')


def _rule_toggle(key: str, off: set) -> str:
    """并入大表单的开关(不再独立提交)。"""
    checked = "" if key in off else "checked"
    return (f'<label class="switch"><input type="checkbox" name="on_{key}" {checked}>'
            f'<span class="track"></span></label>')


def render_rules(store, msg="", err="") -> str:
    from .pipeline import load_config
    off = _rules_off(store)
    cfg = load_config(store)          # 显示当前生效值(含面板改过的)
    w = asdict(cfg.weights)
    th = asdict(cfg.thresholds)
    wl = "".join(
        f'<tr><td>{esc(WEIGHT_CN.get(k, (k, ""))[0])}</td>'
        f'<td class="dim small">{esc(WEIGHT_CN.get(k, ("", ""))[1])}</td>'
        f'<td><input type="number" step="0.1" name="w_{k}" value="{v}" {_RNUM}></td>'
        f'<td>{_rule_toggle(k, off)}</td></tr>' for k, v in w.items())
    tl = "".join(
        f'<tr><td>{esc(THRESH_CN.get(k, k))}</td>'
        f'<td><input type="number" step="any" name="t_{k}" value="{v}" {_RNUM}></td>'
        f'<td>{_rule_toggle(k, off)}</td></tr>' for k, v in th.items())
    return f"""{_card_alert(msg, err)}
    <div class="card">
      <form method="post" action="/rules/save">
        <div class="tabs" style="align-items:center;margin-bottom:12px">
          <a class="tab active" id="rtab_w" onclick="rTab(1)">信号权重</a>
          <a class="tab" id="rtab_t" onclick="rTab(0)">阈值参数</a>
          <button class="btn sm" style="margin-left:auto">保存全部</button>
          <button class="btn sm ghost" formaction="/rules/reset" formnovalidate
                  onclick="return confirm('恢复为代码内置默认值?')">恢复默认</button>
        </div>
        <div id="rw_weights">
          <div class="dim small" style="margin:4px 0 10px">命中程度 × 权重 = 得分。直接改数值或开关, 点「保存全部」即生效。</div>
          <table class="grid" id="tbl_w"><thead><tr><th>信号</th><th>说明</th><th>权重</th><th>启用</th></tr></thead><tbody>{wl}</tbody></table>
          <div class="pager" id="pg_w"></div>
        </div>
        <div id="rw_thresh" style="display:none">
          <div class="dim small" style="margin:4px 0 10px">阈值参数; 「自有IP排除」开关关闭即停用排除层。</div>
          <table class="grid" id="tbl_t"><thead><tr><th>参数</th><th>值</th><th>启用</th></tr></thead><tbody>{tl}</tbody></table>
          <div class="pager" id="pg_t"></div>
        </div>
      </form>
    </div>""" + _RULES_JS


_RULES_JS = """
<script>
function rTab(w){
  document.getElementById('rw_weights').style.display = w ? '' : 'none';
  document.getElementById('rw_thresh').style.display = w ? 'none' : '';
  document.getElementById('rtab_w').className = 'tab' + (w ? ' active' : '');
  document.getElementById('rtab_t').className = 'tab' + (w ? '' : ' active');
}
function rPage(tbl, pg){
  var per = 10, tb = document.querySelector('#'+tbl+' tbody'), rows = tb.rows, n = rows.length;
  var pages = Math.max(1, Math.ceil(n/per));
  pg = Math.min(Math.max(1, pg), pages);
  for (var i=0;i<n;i++) rows[i].style.display = (i>=(pg-1)*per && i<pg*per) ? '' : 'none';
  var pgid = tbl=='tbl_w' ? 'pg_w' : 'pg_t', h='';
  h += '<a class="pg'+(pg<=1?' dis':'')+'" onclick="rPage(\\''+tbl+'\\','+(pg-1)+')">‹</a>';
  for (var p=1;p<=pages;p++) h += '<a class="pg'+(p==pg?' cur':'')+'" onclick="rPage(\\''+tbl+'\\','+p+')">'+p+'</a>';
  h += '<a class="pg'+(pg>=pages?' dis':'')+'" onclick="rPage(\\''+tbl+'\\','+(pg+1)+')">›</a>';
  document.getElementById(pgid).innerHTML = h;
}
rPage('tbl_w',1); rPage('tbl_t',1); rTab(1);
</script>"""


def _read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def _count_cidrs(text: str) -> int:
    return sum(1 for ln in text.splitlines() if ln.split("#", 1)[0].strip())


def _append_hosting_keywords(keywords) -> int:
    """把机房组织名(大写)追加到机房关键词文件, 去重, 返回新增条数。"""
    path = CONFIG.asn_hosting_kw_file
    lines, existing = [], set()
    try:
        with open(path, encoding="utf-8") as f:
            for ln in f:
                lines.append(ln.rstrip("\n"))
                kw = ln.split("#", 1)[0].strip().upper()
                if kw:
                    existing.add(kw)
    except FileNotFoundError:
        pass
    new = []
    for kw in sorted(keywords):
        k = (kw or "").strip().upper()
        if k and k not in existing:
            existing.add(k)
            new.append(k)
    if new:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines + ["# —— 内鬼库导入的机房名称 ——"] + new) + "\n")
    return len(new)


def _setting_row(label, desc, action, content, extra="", rows=6) -> str:
    """命名+提示在上, 可编辑字段在下。rows 控制文本框高度。"""
    return f"""
    <form method="post" action="{action}" class="stackrow">
      <div class="sr-head"><b>{label}</b><div class="dim small">{desc}</div></div>
      <textarea name="content" rows="{rows}" style="resize:vertical">{esc(content)}</textarea>
      <div style="margin-top:8px;display:flex;gap:8px;align-items:center">{extra}<button class="btn">保存</button></div>
    </form>"""


def _asn_db_card() -> str:
    """ASN 库(GeoLite2-ASN / iptoasn)状态 + 一键更新。"""
    import os as _os
    active = None
    for p in (CONFIG.asn_mmdb_file, CONFIG.asn_db_file):
        if _os.path.exists(p):
            active = p
            break
    if active:
        sz = _os.path.getsize(active) / 1048576
        mt = datetime.fromtimestamp(_os.path.getmtime(active)).strftime("%Y-%m-%d %H:%M")
        from .asn import get_asndb
        db = get_asndb()
        src = getattr(db, "source", "?") if db else "?"
        status = f'<span class="on">● 已启用</span> · {src} · {sz:.0f}MB · 更新于 {mt}'
    else:
        status = '<span class="off">● 未安装</span> · 点下方按钮下载后, 机房判定/ASN黑名单自动精确化'
    return f"""
    <form method="post" action="/whitelist/update-asn" class="stackrow"
          onsubmit="this.querySelector('button').disabled=true;this.querySelector('button').textContent='下载中(约30-90秒)…'">
      <div class="sr-head"><b>IP → ASN 库(免费离线, 判定住宅/机房的核心)</b>
        <div class="dim small">默认下载 P3TERX 每日同步的 MaxMind <code>GeoLite2-ASN.mmdb</code>(无需账号)。下载一次离线生效, 覆盖全球 ASN, 比手工 CIDR 准得多。建议每月更新。</div></div>
      <div style="margin-top:6px">{status}</div>
      <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
        <input name="url" placeholder="留空=GeoLite2-ASN.mmdb; 也可填 iptoasn 的 ...ip2asn-v4.tsv.gz" style="flex:1;max-width:460px">
        <button class="btn">下载 / 更新 ASN 库</button></div>
    </form>"""


_SIG_KIND_CN = {"ip": "IP / CIDR", "ua": "UA(正则/子串)", "asn": "ASN 号", "email": "邮箱(子串)"}


def _guess_sig_kind(v: str) -> str:
    """自动判断一行特征属于 ip / asn / email / ua。"""
    s = (v or "").strip()
    if "@" in s:
        return "email"
    if re.match(r"(?i)^as\d+$", s) or s.isdigit():
        return "asn"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", s):
        return "ip"
    if s.count(":") >= 2 and re.match(r"^[0-9a-fA-F:]+(/\d{1,3})?$", s):
        return "ip"   # IPv6
    return "ua"


def _parse_sig_lines(text: str, kind: str = "auto"):
    """多行文本 → [(kind, value, '')]。kind='auto' 逐行判断, 否则整体用指定类型; 跳过空行/# 注释。"""
    out = []
    for ln in (text or "").splitlines():
        v = ln.strip()
        if not v or v.startswith("#"):
            continue
        out.append((_guess_sig_kind(v) if kind == "auto" else kind, v, ""))
    return out


def render_featurelib(store, msg="", err="", search="") -> str:
    all_rows = store.list_signatures()
    total = len(all_rows)
    s = (search or "").strip()
    if s:
        sl = s.lower()
        rows = [r for r in all_rows if sl in (
            f'{_SIG_KIND_CN.get(r["kind"], r["kind"])} {r["value"] or ""} {r["note"] or ""}').lower()]
    else:
        rows = all_rows
    trs = ""
    for r in rows:
        trs += (f'<tr><td>{esc(_SIG_KIND_CN.get(r["kind"], r["kind"]))}</td>'
                f'<td class="mono small">{esc(r["value"])}</td>'
                f'<td class="small dim">{esc(r["note"] or "")}</td>'
                f'<td class="small dim">{esc((r["created_at"] or "")[:16])}</td>'
                f'<td><form method="post" action="/featlib/delete" onsubmit="return confirm(\'删除?\')" style="margin:0">'
                f'<input type="hidden" name="id" value="{r["id"]}"><button class="btn sm danger">删除</button></form></td></tr>')
    if not trs:
        trs = (f'<tr><td colspan="5" class="dim" style="padding:16px">没有匹配「{esc(s)}」的特征</td></tr>'
               if s else '<tr><td colspan="5" class="dim" style="padding:16px">还没登记特征, 用上面的表单添加</td></tr>')
    count_label = (f'共 {total} 条 · 匹配 {len(rows)} 条' if s else f'共 {total} 条')
    searchbox = (
        f'<form method="get" action="/featlib" style="margin-left:auto;display:flex;gap:6px">'
        f'<input name="q" value="{esc(s)}" placeholder="搜索 类型/特征值/备注" '
        f'style="width:220px;padding:6px 10px;border:1px solid #d5dae1;border-radius:6px">'
        f'<button class="btn sm">搜索</button>'
        + ('<a class="btn sm ghost" href="/featlib">清除</a>' if s else '')
        + '</form>')
    return f"""{_card_alert(msg, err)}
    <div class="card">
      <div style="display:flex;align-items:center;flex-wrap:wrap;gap:8px">
        <div class="card-title" style="margin:0">特征库 <span class="dim small" style="font-weight:400;margin-left:8px">{count_label}</span></div>
        {searchbox}
      </div>
      <div class="dim small" style="margin-bottom:10px">手工登记特征(IP/UA/ASN/邮箱), 任何用户命中即触发「命中特征库」信号(强, 权重可在风险规则页调)。与「内鬼库」独立: 这里是手工规则, 内鬼库是一键移入的账号。</div>
      <form method="post" action="/featlib/add" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <select name="kind" style="padding:6px 10px;border:1px solid #d5dae1;border-radius:6px">
          <option value="ip">IP / CIDR</option>
          <option value="ua">UA(正则/子串)</option>
          <option value="asn">ASN 号(如 AS45090)</option>
          <option value="email">邮箱(子串)</option>
        </select>
        <input name="value" required placeholder="特征值, 如 1.2.3.0/24 / Surfboard / AS4134 / @example.com"
               style="flex:1;min-width:240px;padding:6px 10px;border:1px solid #d5dae1;border-radius:6px">
        <input name="note" placeholder="备注(选填)" style="width:160px;padding:6px 10px;border:1px solid #d5dae1;border-radius:6px">
        <button class="btn">添加</button>
      </form>
      <div style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap">
        <button type="button" class="btn ghost sm" onclick="document.getElementById('fbatch').style.display='block';this.style.display='none'">批量添加</button>
        <form method="post" action="/featlib/import" enctype="multipart/form-data"
              style="display:flex;gap:6px;align-items:center;margin:0">
          <input type="file" name="files" multiple
                 style="font-size:12px;max-width:230px" title="可多选文件, 或在文件夹里全选">
          <button class="btn ghost sm">导入文件</button>
        </form>
        <a class="btn ghost sm" href="/featlib/export{('?q=' + quote(s)) if s else ''}">⬇ 导出CSV{('(匹配 ' + str(len(rows)) + ')') if s else ''}</a>
        <span class="dim small">导入/批量: 逐行自动识别 IP·CIDR / AS号 / @邮箱 / UA, 自动去重</span>
        <form method="post" action="/featlib/delete-all" style="margin:0 0 0 auto"
              onsubmit="return confirm('确定删除特征库全部特征? 此操作不可恢复!')">
          <button class="btn sm danger">删除全部</button></form>
      </div>
      <div id="fbatch" style="display:none;margin-top:10px;padding:12px;border:1px solid #e3e7ec;border-radius:8px;background:#fafbfc">
        <form method="post" action="/featlib/batch-add">
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
            <select name="kind" style="padding:6px 10px;border:1px solid #d5dae1;border-radius:6px">
              <option value="auto">自动识别(逐行)</option>
              <option value="ip">全部当 IP / CIDR</option>
              <option value="ua">全部当 UA</option>
              <option value="asn">全部当 ASN</option>
              <option value="email">全部当邮箱</option>
            </select>
            <span class="dim small">一行一个;空行和 # 开头的注释会跳过</span>
          </div>
          <textarea name="text" rows="8" placeholder="1.2.3.0/24&#10;AS4134&#10;@example.com&#10;Surfboard"
                    style="width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid #d5dae1;border-radius:6px;font-family:monospace;font-size:13px"></textarea>
          <div style="margin-top:8px;display:flex;gap:8px">
            <button class="btn">批量添加</button>
            <button type="button" class="btn ghost" onclick="document.getElementById('fbatch').style.display='none';document.querySelector('[onclick*=fbatch]').style.display=''">取消</button>
          </div>
        </form>
      </div>
      <div class="tablewrap" style="margin-top:12px"><table class="grid">
        <thead><tr><th>类型</th><th>特征值</th><th>备注</th><th>添加时间</th><th>操作</th></tr></thead>
        <tbody>{trs}</tbody>
      </table></div>
    </div>"""


_COPYLIST_JS = """<script>
function _copyList(arr, btn){
  var txt = arr.join('\\n');
  var done = function(){
    var old = btn.getAttribute('data-old') || btn.textContent;
    btn.setAttribute('data-old', old);
    btn.textContent = '已复制 ' + arr.length + ' 条';
    setTimeout(function(){ btn.textContent = old; }, 1500);
  };
  if (navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(txt).then(done, function(){ _copyFallback(txt, done); });
  } else { _copyFallback(txt, done); }
}
function _copyFallback(txt, done){
  var ta = document.createElement('textarea');
  ta.value = txt; ta.style.position='fixed'; ta.style.left='-9999px';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); done(); } catch(e){ alert('复制失败, 请手动复制'); }
  document.body.removeChild(ta);
}
</script>"""


_IMPFEAT_JS = """<script>
function _impEsc(s){return String(s).replace(/[&<>\"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c];});}
function _impGrp(title, name, vals, warn){
  if(!vals || !vals.length) return '';
  var h='<div style=\"margin:10px 0 4px;font-weight:600\">'+title+(warn?' <span style=\"color:#e5484d;font-weight:400;font-size:12px\">'+warn+'</span>':'')+
        ' <a href=\"#\" onclick=\"_impTgl(this);return false\" style=\"font-weight:400;font-size:12px;margin-left:6px\">全选/全不选</a></div>';
  h+='<div style=\"display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:2px 12px\">';
  vals.forEach(function(v){
    h+='<label style=\"display:block;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis\"><input type=\"checkbox\" name=\"'+name+'\" value=\"'+_impEsc(v)+'\"> '+_impEsc(v)+'</label>';
  });
  h+='</div>';
  return h;
}
function impFeat(token){
  var d = token ? _INS_FEAT[token] : _INS_FEAT_ALL;
  if(!d) return;
  var who = token ? ('该内鬼 '+token.slice(0,12)) : '全部内鬼';
  var h='<div class=\"dim small\" style=\"margin-bottom:4px\">来源: '+who+' · 勾选要导入的具体项(默认都不勾), 已存在的自动去重</div>';
  h+=_impGrp('IP','ip',d.ip,'');
  h+=_impGrp('UA(整串精确)','ua',d.ua,'');
  h+=_impGrp('邮箱前缀','email',d.email,'');
  h+=_impGrp('ASN','asn',d.asn,'整机房, 慎选');
  h+=_impGrp('机房名称 → 机房关键词库','hostname',d.host,'整机房, 慎选');
  document.getElementById('impFeatBody').innerHTML = (h.indexOf('checkbox')>=0) ? h : '<div class=\"dim\">该内鬼无可导入的特征</div>';
  openM('impFeatModal');
}
function _impTgl(a){
  var grp=a.parentNode.nextElementSibling;
  var boxes=grp.querySelectorAll('input[type=checkbox]');
  var toCheck=Array.prototype.some.call(boxes,function(b){return !b.checked;});
  Array.prototype.forEach.call(boxes,function(b){b.checked=toCheck;});
}
</script>"""


def render_insiders(store, msg="", err="") -> str:
    import json as _json
    rows = store.list_insiders()
    spy_group = store.get_kv("spy_group_name", "Lv.spy") or "Lv.spy"
    try:
        spy_status = _json.loads(store.get_kv("spy_status", "{}") or "{}")
    except (ValueError, TypeError):
        spy_status = {}
    spy_status_at = store.get_kv("spy_status_at", "")
    ptimes = store.insider_pull_times([r["token"] for r in rows])   # 首次/最后订阅拉取时间
    all_emails = sorted({(r["email"] or "").strip() for r in rows if (r["email"] or "").strip()})
    all_ips = sorted({ip for r in rows for ip in _json.loads(r["ips"] or "[]") if ip})
    emails_js = _json.dumps(all_emails, ensure_ascii=False)
    ips_js = _json.dumps(all_ips, ensure_ascii=False)

    # 每个内鬼可导入的细分特征值 + 全部聚合(导入弹层逐项勾选)
    try:
        from .asn import get_asndb
        asndb = get_asndb()
    except Exception:  # noqa: BLE001
        asndb = None
    from .enrich import IpClassifier, UaClassifier
    ipc = IpClassifier()   # 导入时过滤自有/反代 IP
    uac = UaClassifier()   # 导入时过滤自有 UA
    feat = {}
    agg = {"ip": set(), "ua": set(), "email": set(), "asn": set(), "host": set()}
    for r in rows:
        ips = _json.loads(r["ips"] or "[]")
        uas = _json.loads(r["uas"] or "[]")
        asns = _json.loads(r["asns"] or "[]")
        email = (r["email"] or "").strip()
        prefix = email.split("@", 1)[0] if email else ""
        ips_imp = [i for i in ips if i and not ipc.is_self_ip(i)]   # 自有/反代IP不导入
        uas_imp = [u for u in uas if u and not uac.is_self(u)]      # 自有UA不导入
        hosts = []
        if asndb is not None:
            for ip in ips_imp:
                org = (asndb.lookup(ip)[1] or "").strip().upper()
                if org:
                    hosts.append(org)
        entry = {
            "ip": sorted(set(ips_imp)),
            "ua": sorted(set(uas_imp)),
            "email": [prefix] if prefix else [],
            "asn": ["AS" + str(a) for a in sorted(set(asns))],
            "host": sorted(set(hosts)),
        }
        feat[r["token"]] = entry
        for k in agg:
            agg[k].update(entry[k])
    feat_js = _json.dumps(feat, ensure_ascii=False)
    agg_js = _json.dumps({k: sorted(v) for k, v in agg.items()}, ensure_ascii=False)

    trs = ""
    for r in rows:
        ips = _json.loads(r["ips"] or "[]")
        uas = _json.loads(r["uas"] or "[]")
        asns = _json.loads(r["asns"] or "[]")
        _st = spy_status.get(r["token"])
        if _st is True:
            stcell = '<td><span class="badge" style="background:#2f9e44;color:#fff">✓ 在组</span></td>'
        elif _st is False:
            stcell = '<td><span class="badge" style="background:#e5484d;color:#fff">✗ 不在</span></td>'
        else:
            stcell = '<td class="dim" title="未检查或该token在面板查不到账号">—</td>'
        trs += (f'<tr style="cursor:pointer" onclick="userDetail(\'{esc(r["token"])}\')">'
                f'<td style="white-space:nowrap"><button class="btn sm ghost" type="button" '
                f'onclick="event.stopPropagation();impFeat(\'{esc(r["token"])}\')">导入特征库</button></td>'
                f'<td class="small">{esc(r["email"] or "-")}</td>'
                f'<td class="small">{esc(r["panel"] or "-")}</td>'
                + stcell
                + f'<td class="small dim">{esc(", ".join(ips[:4]))}{"…" if len(ips) > 4 else ""}</td>'
                + _ago_cell(ptimes.get(r["token"], (None, None))[1])
                + f'<td class="small dim">{len(uas)} 个</td>'
                f'<td class="small dim">{esc((r["added_at"] or "")[:16])}</td>'
                f'<td><form method="post" action="/insiders/remove" style="margin:0" '
                f'onclick="event.stopPropagation()">'
                f'<input type="hidden" name="token" value="{esc(r["token"])}">'
                f'<button class="btn sm ghost">移出</button></form></td></tr>')
    if not trs:
        trs = '<tr><td colspan="9" class="dim" style="padding:16px">还没有内鬼, 在风险名单里点某行「移入内鬼」</td></tr>'
    return f"""{_card_alert(msg, err)}
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
        <div class="card-title" style="margin:0">内鬼库 <span class="dim small" style="font-weight:400;margin-left:8px">共 {len(rows)} 个已确认内鬼</span></div>
        <div style="display:flex;gap:8px">
          <button class="btn sm ghost" onclick="_copyList(_INS_EMAILS,this)">复制邮箱 ({len(all_emails)})</button>
          <button class="btn sm ghost" onclick="_copyList(_INS_IPS,this)">复制IP ({len(all_ips)})</button>
          <button class="btn sm" type="button" onclick="impFeat(null)">导入特征到特征库</button>
          <button class="btn sm" type="button" onclick="openM('spyGroupModal')">移入权限组</button>
          <form method="post" action="/insiders/check-group" style="margin:0">
            <button class="btn sm ghost">检查{esc(spy_group)}分组</button></form>
        </div>
      </div>
      {f'<div class="dim small" style="margin-top:6px">分组状态上次检查: {esc(spy_status_at)}</div>' if spy_status_at else ''}
      <div class="dim small" style="margin:8px 0 10px">在风险名单点「移入内鬼」把已确认内鬼移到这里: 它<b>不再出现在风险名单</b>(但在名单里<b>搜索仍可找到并标注「内鬼」</b>), 它的 IP/UA/ASN/邮箱<b>继续参与检测</b>——其他账号命中即触发「命中内鬼库」信号(同伙)。<b>点某行看详情</b>, 每行「导入」可单独导入该号特征, 「移出」还原回名单。</div>
      <script>var _INS_EMAILS={emails_js}, _INS_IPS={ips_js}, _INS_FEAT={feat_js}, _INS_FEAT_ALL={agg_js};</script>
      {_COPYLIST_JS}{_IMPFEAT_JS}
      <div class="tablewrap"><table class="grid sortable">
        <thead><tr><th></th><th>邮箱</th><th>机场</th><th>{esc(spy_group)}</th><th>IP</th><th data-t="num">最新拉取订阅</th><th>UA</th><th>移入时间</th><th>操作</th></tr></thead>
        <tbody>{trs}</tbody>
      </table></div>
    </div>
    <div class="modal-bg" id="impFeatModal"><div class="modal" style="width:min(680px,95vw)">
      <h3>导入内鬼特征到特征库</h3>
      <form method="post" action="/insiders/to-featlib">
        <div id="impFeatBody" class="modalscroll" style="max-height:56vh;margin:8px 0"></div>
        <div class="modal-actions">
          <button type="button" class="btn ghost" onclick="closeM('impFeatModal')">取消</button>
          <button class="btn">导入勾选项</button>
        </div>
      </form>
    </div></div>
    <div class="modal-bg" id="spyGroupModal"><div class="modal">
      <h3>把内鬼移入 v2board 权限组</h3>
      <div class="dim small">对内鬼库里每个内鬼, 到它<b>所属面板</b>的 v2board, 按下面的组名查到<b>该面板对应的组ID</b>, 把该用户的权限组改成这个组。<br><b style="color:#e5484d">⚠ 这会写入你的 v2board 生产数据库, 不能自动撤销。</b>请确保各面板都已建好同名权限组。</div>
      <form method="post" action="/insiders/to-group"
            onsubmit="return confirm('确认把全部内鬼在各自面板移入该权限组? 会写入 v2board 生产库, 不可自动撤销')">
        <div style="margin:12px 0">
          <label class="dim small">权限组名称(需在各面板都存在)</label><br>
          <input name="group_name" value="{esc(spy_group)}" style="margin-top:4px;padding:6px 10px;border:1px solid #d5dae1;border-radius:6px;width:220px">
        </div>
        <div class="modal-actions">
          <button type="button" class="btn ghost" onclick="closeM('spyGroupModal')">取消</button>
          <button class="btn danger">移入该组</button>
        </div>
      </form>
    </div></div>"""


_WL_CATS = [
    ("self", "自有基础设施 IP", "你自己的节点 / subconverter / 监控 IP。白名单命中即排除; 同页可维护 IP 黑名单。"),
    ("ua", "客户端 UA", "正规客户端 UA 白名单(clash / v2rayN 等); 同页可维护 UA 黑名单。"),
    ("hosting", "机房 / ASN", "机房关键词、机房网段 CIDR、ASN 黑名单——判定并封禁机房来源(黑名单侧)。"),
    ("proxy", "反代 / 中转过滤", "上层反代 IP: 解析日志时跳过它们、取真实客户端 IP(与自有基础设施作用不同)。"),
]


_HOSTING_SUBS = [
    ("kw", "机房关键词", "ASN 组织名命中这些词即判机房/IDC(判定用)"),
    ("cidr", "机房网段 CIDR", "ASN 库覆盖不到的机房网段, 手工补充"),
    ("asn", "ASN 黑名单", "封整个恶意机房网段, 或 ASxxxx"),
]


def _wl_subtabs(cat, cur):
    return (f'<div class="subtabs">'
            f'<a class="subtab {"active" if cur=="white" else ""}" href="/whitelist?cat={cat}&tab=white">白名单</a>'
            f'<a class="subtab {"active" if cur=="black" else ""}" href="/whitelist?cat={cat}&tab=black">黑名单</a>'
            f'</div>')


def _wl_hub(items, title, intro, back_href, msg="", err="") -> str:
    """入口页: 一排卡片按钮。items=[(href, label, desc)]; back_href 为空则不显示返回。"""
    cards = ""
    for href, label, desc in items:
        cards += (
            f'<a href="{href}" style="display:block;text-decoration:none;color:inherit;'
            f'border:1px solid #e3e7ec;border-radius:8px;padding:14px 16px;background:#fff">'
            f'<div style="font-weight:600;margin-bottom:4px">{label} ›</div>'
            f'<div class="dim small">{desc}</div></a>')
    if back_href:
        head = (f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">'
                f'<a class="btn sm ghost" href="{back_href}">← 返回</a>'
                f'<div class="card-title" style="margin:0">{title}</div></div>')
    else:
        head = f'<div class="card-title">{title}</div>'
    return f"""{_card_alert(msg, err)}
    <div class="card">
      {head}
      <div class="dim small" style="margin-bottom:12px">{intro}</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px">{cards}</div>
    </div>"""


def render_whitelist(msg="", err="", cat="", tab="white", sub="") -> str:
    if tab not in ("white", "black", "self"):
        tab = "white"

    # 顶层入口页: 四个分类按钮
    if cat not in ("self", "ua", "hosting", "proxy"):
        return _wl_hub([(f"/whitelist?cat={k}", lb, ds) for k, lb, ds in _WL_CATS],
                       "黑白名单",
                       "点进各类单独维护。白名单=命中即视为正常/排除(降误杀); 黑名单=命中即判高危并强制隔离下发。",
                       back_href="", msg=msg, err=err)

    # 机房/ASN 二级入口页: 三个子项按钮
    if cat == "hosting" and sub not in ("kw", "cidr", "asn"):
        return _wl_hub([(f"/whitelist?cat=hosting&sub={k}", lb, ds) for k, lb, ds in _HOSTING_SUBS],
                       "机房 / ASN(黑名单侧)",
                       "这三类都用于判定/封禁机房来源, 点进各自单独维护。",
                       back_href="/whitelist", msg=msg, err=err)

    back = '<a class="btn sm ghost" href="/whitelist">← 返回</a>'
    subtabs = ""
    if cat == "self":
        title = "自有基础设施 IP"
        subtabs = _wl_subtabs("self", tab)
        if tab == "black":
            body = _setting_row("IP 黑名单", "已确认的攻击/侦察源 IP。命中即判高危, 进入隔离下发。每行一个 IP 或 CIDR。",
                                "/blacklist/save-ip", _read_file(CONFIG.ip_blacklist_file), rows=22)
        else:
            body = _setting_row("自有基础设施 IP", "命中即排除(自己的节点/subconverter/监控)。只填自己的 IP/CIDR, 别填整个机房 ASN。",
                                "/whitelist/save-self", _read_file(CONFIG.self_ips_file), rows=22)
    elif cat == "ua":
        title = "客户端 UA"
        subtabs = (
            f'<div class="subtabs">'
            f'<a class="subtab {"active" if tab=="white" else ""}" href="/whitelist?cat=ua&tab=white">白名单</a>'
            f'<a class="subtab {"active" if tab=="black" else ""}" href="/whitelist?cat=ua&tab=black">黑名单</a>'
            f'<a class="subtab {"active" if tab=="self" else ""}" href="/whitelist?cat=ua&tab=self">自有UA</a>'
            f'</div>')
        if tab == "black":
            body = _setting_row("UA 黑名单", "攻击脚本/爬虫特征 UA。命中即判高危。每行一个正则。",
                                "/blacklist/save-ua", _read_file(CONFIG.ua_blacklist_file), rows=22)
        elif tab == "self":
            body = _setting_row("自有 UA", "你自己的抓取/监控工具 UA(subconverter/健康检查等), 每行一个正则; 命中即视为<b>自有设备, 不参与评分</b>。",
                                "/whitelist/save-uaself", _read_file(CONFIG.ua_self_file), rows=22)
        else:
            body = _setting_row("客户端 UA 白名单", "正规客户端 UA(clash/v2rayN/Shadowrocket 等), 每行一个正则; 配合住宅 ASN 视为正常。",
                                "/whitelist/save-ua", _read_file(CONFIG.ua_clients_file), rows=22)
    elif cat == "hosting":
        back = '<a class="btn sm ghost" href="/whitelist?cat=hosting">← 返回</a>'
        if sub == "kw":
            title = "机房关键词"
            body = _setting_row("机房关键词(ASN 库判定用)", "ASN 库启用后, AS 组织名命中这些关键词即判为机房/IDC。可增删。",
                                "/whitelist/save-asnkw", _read_file(CONFIG.asn_hosting_kw_file), rows=24)
        elif sub == "cidr":
            title = "机房网段 CIDR"
            hosting = _read_file(CONFIG.hosting_cidrs_file)
            fetch_btn = ('<input name="url" form="fetchhosting" placeholder="CIDR 列表 URL" '
                         'style="flex:1;max-width:280px">'
                         '<button class="btn ghost" form="fetchhosting" formaction="/whitelist/fetch-hosting">'
                         '从URL拉取</button>')
            body = (_setting_row(f"机房网段 CIDR(补充) · {_count_cidrs(hosting)} 条",
                                 "ASN 库覆盖不到的机房网段可在此手工补。可从 URL 拉取覆盖。",
                                 "/whitelist/save-hosting", hosting, extra=fetch_btn, rows=24)
                    + '<form id="fetchhosting" method="post" action="/whitelist/fetch-hosting"></form>')
        else:  # asn
            title = "ASN 黑名单"
            body = _setting_row("ASN 黑名单", "封整个恶意机房网段。每行 CIDR, 或 ASxxxx(装了 ASN 库即生效, 如 AS4134)。",
                                "/blacklist/save-asn", _read_file(CONFIG.asn_blacklist_file), rows=24)
    else:  # proxy
        title = "反代 / 中转过滤"
        body = _setting_row("反代 / 中转 IP 过滤", "上层反代的 IP。系统默认已优先取日志末段的真实客户端 IP; 若转发链里混入反代 IP, 在此登记会被自动剔除。每行一个 IP 或 CIDR。<br>与「自有基础设施」不同: 这个影响<b>解析日志时取哪个IP</b>, 自有基础设施影响<b>评分是否排除</b>。",
                            "/whitelist/save-proxy", _read_file(CONFIG.proxy_ips_file), rows=20)

    return f"""{_card_alert(msg, err)}
    <div class="card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
        {back}<div class="card-title" style="margin:0">{title}</div>
      </div>
      {subtabs}
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


# 用户详情 / 同IP / 流量 三个弹窗: 放进全局页壳, 所有页面(风险名单/内鬼库)都能调 userDetail()
_DETAIL_MODALS = """
    <div class="modal-bg" id="sameIpModal"><div class="modal" style="width:min(520px,94vw);position:relative;overflow:hidden">
      <button class="modalx" type="button" onclick="closeM('sameIpModal')" aria-label="关闭">×</button>
      <h4 style="margin:0 0 10px" id="sameIpTitle">同 IP 账号</h4>
      <div id="sameIpBody" class="udetail modalscroll"><div class="dim">加载中…</div></div>
    </div></div>
    <div class="modal-bg" id="userModal"><div class="modal" style="width:min(720px,95vw);position:relative;overflow:hidden">
      <button class="modalx" type="button" onclick="closeM('userModal')" aria-label="关闭">×</button>
      <div id="userBody" class="udetail modalscroll"><div class="dim">加载中…</div></div>
    </div></div>
    <div class="modal-bg" id="trafficModal"><div class="modal" style="width:min(640px,95vw);position:relative;overflow:hidden">
      <button class="modalx" type="button" onclick="closeM('trafficModal')" aria-label="关闭">×</button>
      <h4 style="margin:0 0 10px">流量记录</h4>
      <div id="trafficBody" class="modalscroll"><div class="dim">加载中…</div></div>
    </div></div>"""


def _render_insider_hits(store, search: str) -> str:
    """搜索时: 命中搜索词的已确认内鬼(已移出名单)单独列出, 红色「内鬼」标注, 点行看详情。"""
    import json as _json
    s = (search or "").strip().lower()
    if not s:
        return ""
    hits = []
    for r in store.list_insiders():
        ips = _json.loads(r["ips"] or "[]")
        asns = _json.loads(r["asns"] or "[]")
        hay = " ".join([r["token"] or "", r["email"] or "", r["panel"] or "",
                        " ".join(ips), " ".join(_json.loads(r["uas"] or "[]")),
                        " ".join("as" + str(a) for a in asns)]).lower()
        if s in hay:
            hits.append((r, ips, asns))
    if not hits:
        return ""
    ptimes = store.insider_pull_times([r["token"] for r, _, _ in hits])   # 最新拉取时间
    trs = ""
    for r, ips, asns in hits:
        trs += (f'<tr style="cursor:pointer" onclick="userDetail(\'{esc(r["token"])}\')">'
                f'<td><span class="badge" style="background:#e5484d;color:#fff">内鬼</span></td>'
                f'<td class="mono small dim">{esc(r["token"][:12])}</td>'
                f'<td class="small">{esc(r["email"] or "-")}</td>'
                f'<td class="small">{esc(r["panel"] or "-")}</td>'
                f'<td class="small dim">{esc(", ".join(ips[:4]))}{"…" if len(ips) > 4 else ""}</td>'
                f'<td class="small dim">{esc(", ".join("AS" + str(a) for a in asns[:4]))}</td>'
                + _ago_cell(ptimes.get(r["token"], (None, None))[1]) + "</tr>")
    return (f'<div class="card" style="border-left:3px solid #e5484d;margin-bottom:12px">'
            f'<div class="card-title" style="margin:0 0 8px">内鬼库命中 '
            f'<span class="dim small" style="font-weight:400;margin-left:6px">共 {len(hits)} 个 · 已确认内鬼(已移出名单), 点行看详情</span></div>'
            f'<div class="tablewrap"><table class="grid"><thead><tr>'
            f'<th>标注</th><th>Token</th><th>邮箱</th><th>机场</th><th>IP</th><th>ASN</th><th>最新拉取订阅</th></tr></thead>'
            f'<tbody>{trs}</tbody></table></div></div>')


_RISK_SORTABLE = {"uid", "ips", "online", "uas", "shared", "pull", "score", "last", "created", "expired"}


def render_risklist(store: Store, flt: str, panel_flt: str = "all", search: str = "",
                    size: str = "10", page: str = "1", sort: str = "", sdir: str = "desc") -> str:
    if str(size) not in ("10", "50", "100", "150"):
        size = "10"
    if sort not in _RISK_SORTABLE:
        sort = ""
    sdir = "asc" if sdir == "asc" else "desc"
    counts = store.score_counts()      # 直接读物化评分, 与总用户数解耦
    excluded = counts["excluded"]

    # 搜索: token / 邮箱 / IP / UA / ASN
    search = (search or "").strip()
    if search:
        from .asn import get_asndb
        ip_tokens = store.tokens_by_search(search, get_asndb())
    else:
        ip_tokens = set()

    sortq = (f"&sort={sort}&sdir={sdir}" if sort else "")   # 筛选/翻页时保持排序

    # 等级筛选按钮(自带数字): 全部/高/中/低/正常/排除
    pf = quote(panel_flt or "all")
    cnt = {"all": counts["total"], "高": counts["高"], "中": counts["中"],
           "低": counts["低"], "正常": counts["正常"], "排除": excluded}
    tabs = ""
    for name, key in [("全部", "all"), ("高风险", "高"), ("中风险", "中"),
                      ("低风险", "低"), ("正常", "正常"), ("排除", "排除")]:
        active = "active" if (flt or "all") == key else ""
        tabs += (f'<a class="tab {active}" href="/risk?level={quote(key)}&panel={pf}{sortq}">'
                 f'{name} <b>{cnt[key]}</b></a>')

    # 机场/前端面板 筛选
    lf = quote(flt or "all")
    panels = store.score_panels()
    ptabs = f'<a class="tab {"active" if (panel_flt or "all")=="all" else ""}" href="/risk?level={lf}&panel=all{sortq}">全部面板</a>'
    for pn in panels:
        active = "active" if panel_flt == pn else ""
        ptabs += f'<a class="tab {active}" href="/risk?level={lf}&panel={quote(pn)}{sortq}">{esc(pn)}</a>'
    panel_bar = f'<div class="tabs">{ptabs}</div>' if panels else ""

    # SQL 分页/筛选/搜索: 只取当前页的行, 不再全量载入内存
    total = store.count_scores(flt, panel_flt, search, ip_tokens)
    psize, pg, pages, all_mode = _paginate(size, page, total, 10)
    page_rows = store.list_scores(flt, panel_flt, search, ip_tokens,
                                  limit=(total or 1) if all_mode else psize,
                                  offset=0 if all_mode else (pg - 1) * psize,
                                  sort=sort, sdir=sdir)

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
            "sameip": (f'<td class="small"><a href="#" onclick="event.stopPropagation();sameIp(\'{esc(r.main_ip)}\');return false" '
                       f'style="color:#5b8def">{esc(r.main_ip)}</a></td>' if r.main_ip else f'<td>{_DASH}</td>'),
            "pull": f'<td class="num">{r.pull_count}</td>',
            "score": (f'<td class="num" data-sort="{r.score}">'
                      f'<div class="scorebar"><div class="fill" style="width:{min(100, int(r.score))}%;background:{color}"></div></div>'
                      f'<span class="scoreval">{r.score}</span></td>'),
            "level": f'<td><span class="badge" style="background:{color};color:{LEVEL_FG.get(r.level, "#fff")}">{LEVEL_TEXT.get(r.level, r.level)}</span></td>',
            "tags": f'<td class="rtags">{tags_html or _DASH}</td>',
            "created": f'<td class="small dim">{reg}</td>',
            "expired": f'<td class="small" style="{"color:#e5484d" if expired else "color:#8a8a8a"}">{exp}</td>',
            "last": f'<td class="small dim" data-sort="{int(r.last_pull.timestamp()) if r.last_pull else 0}">{_humanize(r.last_pull)}</td>',
        }
        action = (f'<td><form method="post" action="/insiders/add" style="margin:0" '
                  f'onclick="event.stopPropagation()" onsubmit="return confirm(\'移入内鬼库? 该账号将从名单移除, 但其特征继续参与检测\')">'
                  f'<input type="hidden" name="token" value="{esc(r.token)}">'
                  f'<button class="btn sm danger" type="submit">移入内鬼</button></form></td>')
        rows += (f'<tr title="{esc(detail)}" style="cursor:pointer" onclick="userDetail(\'{esc(r.token)}\')">'
                 + "".join(cell[k] for k, _ in vis) + action + "</tr>")
    if not rows:
        rows = f'<tr><td colspan="{len(vis) + 1}" class="dim" style="padding:20px">暂无用户</td></tr>'

    def _hcell(k, lb):
        if k not in _RISK_SORTABLE:
            return f"<th{_th_attr(k)}>{lb}</th>"
        ndir = "asc" if (sort == k and sdir == "desc") else "desc"
        arrow = (" ▼" if sdir == "desc" else " ▲") if sort == k else ""
        href = (f"/risk?level={quote(flt or 'all')}&panel={quote(panel_flt or 'all')}"
                f"&q={quote(search)}&size={quote(str(size))}&sort={k}&sdir={ndir}")
        return (f'<th{_th_attr(k)} style="cursor:pointer">'
                f'<a href="{href}" style="color:inherit;text-decoration:none">{lb}{arrow}</a></th>')
    header = "".join(_hcell(k, lb) for k, lb in vis) + "<th>操作</th>"

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
        f'<input type="hidden" name="sort" value="{esc(sort)}">'
        f'<input type="hidden" name="sdir" value="{esc(sdir)}">'
        f'<input name="q" value="{esc(search)}" placeholder="搜索 token/邮箱/IP/UA/ASN" style="width:220px;padding:6px 10px;border:1px solid #d5dae1;border-radius:6px">'
        f'<button class="btn sm">搜索</button>'
        + (f'<a class="btn sm ghost" href="/risk?level={quote(flt or "all")}&panel={pf}{sortq}">清除</a>' if search else '')
        + '</form>')

    pager = _pager_html("/risk", {"level": flt or "all", "panel": panel_flt or "all", "q": search,
                                  "sort": sort, "sdir": sdir},
                        size if str(size) in ("10", "50", "100", "150") else "10",
                        pg, pages, ["10", "50", "100", "150"])

    insider_hits = _render_insider_hits(store, search)   # 搜索命中的已确认内鬼(标注内鬼)

    return f"""
    {insider_hits}
    <div class="card">
      <div style="display:flex;flex-wrap:wrap;gap:12px 8px;align-items:flex-start;margin-bottom:12px">
        <div style="flex:1 1 300px;min-width:0">
          <div class="tabs" style="margin:0 0 10px">{tabs}</div>
          {panel_bar}
        </div>
        <div style="margin-left:auto;display:flex;flex-direction:column;gap:8px;align-items:flex-start">
          {searchbox}
          <div style="display:flex;gap:8px">
            <button class="btn sm" type="button" onclick="openM('colModal')">编辑标签</button>
            <button class="btn sm ghost" type="button" onclick="openM('exportModal')">⬇ 导出CSV</button>
          </div>
        </div>
      </div>
      <div class="tablewrap">
      <table class="grid" id="risk">
        <thead><tr>{header}</tr></thead>
        <tbody>{rows}</tbody>
      </table></div>
      {pager}
      <div class="dim small" style="margin-top:8px">点用户行看详情; 「同IP」点开列出同 IP 账号; 「移入内鬼」把确认内鬼移进内鬼库(从名单移除, 特征继续检测)。</div>
    </div>{col_modal}
    <div class="modal-bg" id="exportModal"><div class="modal">
      <h3>导出CSV</h3><div class="dim small">选要导出的风险等级(可多选), 按当前面板/搜索筛选导出</div>
      <form method="get" action="/risk/export">
        <input type="hidden" name="panel" value="{esc(panel_flt or 'all')}">
        <input type="hidden" name="q" value="{esc(search)}">
        <div class="collist" style="margin:12px 0">
          <label><input type="checkbox" name="lv" value="高" checked> 高风险</label>
          <label><input type="checkbox" name="lv" value="中" checked> 中风险</label>
          <label><input type="checkbox" name="lv" value="低"> 低风险</label>
        </div>
        <div class="modal-actions"><button type="button" class="btn ghost" onclick="closeM('exportModal')">取消</button><button class="btn">导出</button></div>
      </form>
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


def render_login(err="", msg="", allow_register=False) -> str:
    reg = '<a href="/register">注册账号</a>' if allow_register else ''
    return auth_layout("登录", f"""{_alert(err, msg)}
    <form method="post" action="/login">
      <label>用户名 / 邮箱</label><input name="username" required autofocus>
      <label>密码</label><input name="password" type="password" required>
      <button class="btn wide">登录</button>
    </form>
    <div class="authlinks"><a href="/forgot">忘记密码?</a>{reg}</div>""")


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
      也可在服务器运行 <code>python3 -m spyware.web resetpw 用户名</code>。</div>
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


def render_settings(admin, msg="", err="", store=None) -> str:
    dbp = CONFIG.db_path
    size_mb = (os.path.getsize(dbp) / 1048576) if os.path.exists(dbp) else 0
    paid_only = (store.get_kv("sync_paid_only", "0") == "1") if store else False
    paid_card = f"""
    <div class="card">
      <div class="card-title">数据同步范围</div>
      <form method="post" action="/settings/sync-scope" class="autoform">
        <label class="switch" style="margin-right:8px"><input type="checkbox" name="paid_only" {'checked' if paid_only else ''} onchange="this.form.submit()"><span class="track"></span></label>
        <span>只同步<b>购买过的用户</b>(跳过从未购买的免费注册)</span>
      </form>
      <div class="dim small" style="margin-top:8px">开启后: 同步只拉有套餐或有到期时间的用户, 并<b>清除本地已同步的"从未购买"用户</b>——
      大幅减小数据量、面板更快。有拉取记录的用户仍会出现在风险名单(通过日志), 不受影响。改后请到「运行控制」重新同步。</div>
    </div>"""
    feed_key = store.get_kv("gateway_feed_key", "") if store else ""
    feed_line = (f'<div class="dim small">拉取地址: <code>/api/gateway_feed?key={esc(feed_key)}</code>'
                 f'(给网关配这个)</div>' if feed_key else '<div class="dim small">尚未生成密钥</div>')
    gw_card = f"""
    <div class="card">
      <div class="card-title">网关联动 · Feed</div>
      <div class="dim small" style="margin-bottom:8px">网关每 30s 拉此接口, 取<b>特征库/内鬼库</b>的 IP·ASN·UA·token(邮箱前缀已翻译成 token)去发假。给网关配下面的 URL + 密钥。</div>
      {feed_line}
      <form method="post" action="/settings/gateway-key" style="margin-top:10px"
            onsubmit="return confirm('重新生成会使旧密钥失效, 网关需同步更新')">
        <button class="btn ghost">{'重新生成密钥' if feed_key else '生成密钥'}</button>
      </form>
    </div>"""
    return f"""{_card_alert(msg, err)}
    {paid_card}
    <div class="card">
      {_asn_db_card()}
    </div>
    {gw_card}
    <div class="card">
      <div class="card-title">数据库 / 迁移</div>
      <table class="grid"><tbody>
        <tr><td style="width:120px">数据库文件</td><td class="mono small">{esc(dbp)}</td></tr>
        <tr><td>大小</td><td>{size_mb:.1f} MB</td></tr>
      </tbody></table>
      <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <a class="btn" href="/db/backup">⬇ 备份下载 (.db)</a>
        <form method="post" action="/db/vacuum" onsubmit="this.querySelector('button').disabled=true;this.querySelector('button').textContent='压缩中…'">
          <button class="btn ghost">🗜 压缩数据库</button></form>
      </div>
      <div class="dim small" style="margin-top:8px">压缩=VACUUM: 回收删除/更新留下的空洞、整理碎片, <b>数据不变、照常读写</b>, 只让文件变小更快。</div>
      <form method="post" action="/db/import" enctype="multipart/form-data" style="margin-top:16px"
            onsubmit="return confirm('用上传的库覆盖当前数据库? 会先自动备份当前库, 之后自动重启。')">
        <div class="dim small" style="margin-bottom:6px"><b>导入数据库</b>: 上传一个备份的 .db 覆盖当前库(先自动备份当前库 → 校验 → 替换 → 重启)</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <input type="file" name="dbfile" accept=".db" required style="max-width:320px">
          <button class="btn danger">导入并重启</button>
        </div>
      </form>
      <div class="dim small" style="margin-top:10px">
        也可手动迁移: 把该 .db 拷到新服务器, 或设 <code>SPYWARE_DB=/路径/spyware.db</code> / config.json 的 <code>db_path</code> 指向它。
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
    os.execv(sys.executable, [sys.executable, "-m", "spyware.web", *sys.argv[1:]])


def _restart_only():
    os.execv(sys.executable, [sys.executable, "-m", "spyware.web", *sys.argv[1:]])


def _relabel_log_sources(store, old: str, new: str) -> None:
    """v2board 改名后, 把日志源里用旧名做的归属标签/面板改成新名, 让新拉取也用新名(不再分裂)。"""
    for ls in store.list_sources():
        if ls["type"] != "logfile":
            continue
        try:
            c = json.loads(ls["config"] or "{}")
        except (ValueError, TypeError):
            continue
        changed = False
        if c.get("panel") == old:
            c["panel"] = new
            changed = True
        key = "log_path" if c.get("mode") == "agent" else "path"
        spec = c.get(key)
        if spec:
            lines = []
            for line in spec.splitlines():
                if "|" in line:
                    p, _, lb = line.partition("|")
                    if lb.strip() == old:
                        line = p.rstrip() + " | " + new
                        changed = True
                lines.append(line)
            c[key] = "\n".join(lines)
        if changed:
            store.update_source_config(ls["id"], json.dumps(c))
            if c.get("mode") == "agent":
                store.set_kv(f"agent_force::{c.get('key', '')}", "1")   # 通知探针用新标签重传


def _extract_multipart_file(content_type: str, raw: bytes):
    """从 multipart/form-data 里取出上传文件的原始字节(单文件)。"""
    import re
    m = re.search(r"boundary=(.+)", content_type or "")
    if not m:
        return None
    boundary = ("--" + m.group(1).strip().strip('"')).encode()
    for part in raw.split(boundary):
        if b"filename=" in part and b"\r\n\r\n" in part:
            body = part.split(b"\r\n\r\n", 1)[1]
            if body.endswith(b"\r\n"):
                body = body[:-2]
            return body
    return None


def _extract_multipart_files(content_type: str, raw: bytes):
    """从 multipart/form-data 里取出所有上传文件的原始字节(多文件/文件夹)。返回 [bytes]。"""
    m = re.search(r"boundary=(.+)", content_type or "")
    if not m:
        return []
    boundary = ("--" + m.group(1).strip().strip('"')).encode()
    out = []
    for part in raw.split(boundary):
        if b"filename=" in part and b"\r\n\r\n" in part:
            header, body = part.split(b"\r\n\r\n", 1)
            if b'filename=""' in header:   # 没选文件的空 part
                continue
            if body.endswith(b"\r\n"):
                body = body[:-2]
            if body:
                out.append(body)
    return out


def _import_db(store, content_type: str, raw: bytes):
    """校验并用上传的 .db 覆盖当前库。返回 (ok, err)。"""
    import shutil
    import sqlite3
    import time as _t
    if "multipart" not in (content_type or ""):
        return False, "请选择 .db 文件上传"
    data = _extract_multipart_file(content_type, raw)
    if not data or len(data) < 100:
        return False, "未收到文件或文件为空"
    if data[:16] != b"SQLite format 3\x00":
        return False, "不是有效的 SQLite 数据库文件"
    tmp = CONFIG.db_path + ".import.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    try:
        c = sqlite3.connect(tmp)
        tabs = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        c.close()
    except Exception as e:  # noqa: BLE001
        os.path.exists(tmp) and os.remove(tmp)
        return False, f"文件损坏无法打开: {e}"
    if not ({"admins", "users"} <= tabs):
        os.remove(tmp)
        return False, "缺少关键表(admins/users), 不像本系统的数据库"
    store.checkpoint()
    store.close()
    try:
        if os.path.exists(CONFIG.db_path):
            shutil.copy2(CONFIG.db_path, CONFIG.db_path + ".bak-" + _t.strftime("%Y%m%d%H%M%S"))
        os.replace(tmp, CONFIG.db_path)
        for ext in ("-wal", "-shm"):
            p = CONFIG.db_path + ext
            if os.path.exists(p):
                os.remove(p)
    except Exception as e:  # noqa: BLE001
        return False, f"替换失败: {e}"
    return True, None


def _import_wait_page() -> bytes:
    return ('<!doctype html><meta charset="utf-8">'
            '<meta http-equiv="refresh" content="5;url=/">'
            '<body style="font-family:sans-serif;padding:48px;text-align:center;color:#333">'
            '<h3>✓ 数据库已导入, 正在重启…</h3>'
            '<p style="color:#888">约几秒后自动返回。当前库已备份为 spyware.db.bak-时间戳。</p>'
            '</body>').encode("utf-8")


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
  .udgrid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:6px 22px; }}
  .udkv {{ display:flex; gap:10px; padding:5px 0; border-bottom:1px solid var(--line); min-width:0; }}
  .udk {{ color:var(--dim); flex:0 0 64px; }}
  .udv {{ min-width:0; word-break:break-all; }}
  .modalx {{ position:absolute; top:10px; right:12px; width:30px; height:30px; border:0; background:transparent;
    font-size:22px; line-height:1; color:#98a0ab; cursor:pointer; border-radius:6px; z-index:2; }}
  .modalx:hover {{ background:#eceff3; color:#333; }}
  /* 滚动放内层(外框圆角完整); 隐藏滚动条但仍可滚(滚轮/触控板/拖动内容) */
  .modalscroll {{ max-height:74vh; overflow-y:auto; overflow-x:hidden; scrollbar-width:none; -ms-overflow-style:none; }}
  .modalscroll::-webkit-scrollbar {{ width:0; height:0; }}
  @media (max-width:560px) {{ .udgrid {{ grid-template-columns:1fr; }} }}
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
  {_DETAIL_MODALS}
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
    var ep=document.getElementById('el_panel'); if(ep) ep.value=b.dataset.panel||'';
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
  function sameIp(ip){{
    openM('sameIpModal');
    document.getElementById('sameIpTitle').textContent='同 IP 账号 · '+ip;
    document.getElementById('sameIpBody').innerHTML='<div class="dim">加载中…</div>';
    fetch('/api/same_ip?ip='+encodeURIComponent(ip)).then(function(r){{return r.json();}}).then(function(list){{
      if(!list||!list.length){{document.getElementById('sameIpBody').innerHTML='<div class="dim">无</div>';return;}}
      var h='<div class="dim small" style="margin-bottom:6px">共 '+list.length+' 个账号用过此 IP</div><table>';
      h+='<tr><td><b>邮箱</b></td><td><b>面板</b></td><td><b>Token</b></td></tr>';
      list.forEach(function(a){{h+='<tr><td>'+esc0(a.email||'-')+'</td><td>'+esc0(a.panel||'-')+'</td><td style="font-family:monospace;font-size:12px">'+esc0((a.token||'').slice(0,12))+'</td></tr>';}});
      h+='</table>';
      document.getElementById('sameIpBody').innerHTML=h;
    }});
  }}
  function udkv(k,v){{return '<div class="udkv"><span class="udk">'+k+'</span><span class="udv">'+v+'</span></div>';}}
  function userDetail(tok){{
    openM('userModal');
    document.getElementById('userBody').innerHTML='<div class="dim">加载中…</div>';
    fetch('/api/user?token='+encodeURIComponent(tok)).then(function(r){{return r.json();}}).then(function(d){{
      if(d.error){{document.getElementById('userBody').innerHTML='<div class="dim">'+esc0(d.error)+'</div>';return;}}
      var h='<h4>账号信息</h4><div class="udgrid">';
      h+=udkv('邮箱',esc0(d.email));
      h+=udkv('套餐',esc0(d.plan||'未购买'));
      h+=udkv('机场',esc0(d.panel||'-'));
      h+=udkv('状态',(d.banned?'<span style="color:#e5484d">已封禁</span>':'正常'));
      h+=udkv('注册时间',esc0(d.created_at));
      h+=udkv('到期时间',esc0(d.expired));
      h+=udkv('流量','<a href="#" onclick="trafficRecords(\\''+esc0(d.token)+'\\',1);return false" style="color:#5b8def">流量记录 ›</a>');
      h+='</div>';
      h+='<h4>风险</h4><div class="udgrid">';
      h+=udkv('风险分',esc0(d.score)+' ('+esc0(d.level)+')');
      h+=udkv('拉取/IP',esc0(d.pull_count)+' 次 / '+esc0(d.distinct_ips)+' IP');
      h+=udkv('在线IP/UA',esc0(d.online_ips)+' / '+esc0(d.distinct_uas));
      h+=udkv('IP共用',(d.ip_shared_users>=2?'<span style="color:#e5484d;font-weight:600">'+esc0(d.ip_shared_users)+' 个共用</span>':esc0(d.ip_shared_users)+' 个'));
      h+='</div>';
      h+='<div class="udkv" style="margin-top:6px"><span class="udk">命中信号</span><span class="udv">'+(d.signals&&d.signals.length?esc0(d.signals.join(' / ')):'无')+'</span></div>';
      h+='<h4>最近拉取记录</h4>';
      if(d.pulls&&d.pulls.length){{h+='<table>';d.pulls.forEach(function(p){{h+='<tr><td>'+esc0(p.ts)+'</td><td>'+esc0(p.ip)+(p.asn?' <span class="dim">['+esc0(p.asn)+']</span>':'')+' · '+esc0(p.ua)+'</td></tr>';}});h+='</table>';}}
      else h+='<div class="dim">暂无拉取记录(未接入订阅日志)</div>';
      document.getElementById('userBody').innerHTML=h;
    }}).catch(function(){{document.getElementById('userBody').innerHTML='<div class="dim">加载失败</div>';}});
  }}
  var _trafRows=null, _trafTok=null;
  function trafficRecords(tok,page){{
    openM('trafficModal');
    if(_trafTok===tok && _trafRows){{trafPage(page);return;}}  // 已取过: 直接本地翻页
    document.getElementById('trafficBody').innerHTML='<div class="dim">加载中…(查询远程数据库)</div>';
    fetch('/api/traffic?token='+encodeURIComponent(tok)).then(function(r){{return r.json();}}).then(function(d){{
      if(d.error){{document.getElementById('trafficBody').innerHTML='<div class="dim">'+esc0(d.error)+'</div>';return;}}
      _trafRows=d.rows||[]; _trafTok=tok; trafPage(1);
    }}).catch(function(){{document.getElementById('trafficBody').innerHTML='<div class="dim">加载失败</div>';}});
  }}
  function trafPage(page){{
    var rows=_trafRows||[], total=rows.length, per=10, pages=Math.max(1,Math.ceil(total/per));
    page=Math.min(Math.max(1,page||1),pages);
    var h='<div class="dim small" style="margin-bottom:6px">近三个月每日流量 · 共 '+total+' 天</div>';
    if(!total){{document.getElementById('trafficBody').innerHTML=h+'<div class="dim">无流量记录</div>';return;}}
    h+='<table class="grid"><thead><tr><th>日期</th><th>上行</th><th>下行</th><th>倍率</th></tr></thead><tbody>';
    rows.slice((page-1)*per,page*per).forEach(function(x){{h+='<tr><td>'+esc0(x.date)+'</td><td>'+esc0(x.up)+'</td><td>'+esc0(x.down)+'</td><td>'+esc0(x.rate)+'</td></tr>';}});
    h+='</tbody></table><div class="pager" style="margin-top:10px">';
    h+=(page>1?'<a class="pg" href="#" onclick="trafPage('+(page-1)+');return false">‹</a>':'<span class="pg dis">‹</span>');
    h+='<span class="pg cur">'+page+'</span> / '+pages;
    h+=(page<pages?'<a class="pg" href="#" onclick="trafPage('+(page+1)+');return false">›</a>':'<span class="pg dis">›</span>');
    h+='</div>';
    document.getElementById('trafficBody').innerHTML=h;
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
document.querySelectorAll('table.sortable').forEach(function(t){{
  t.querySelectorAll('thead th').forEach(function(th,ci){{
    th.addEventListener('click',function(){{
      var tb=t.tBodies[0]; if(!tb) return;
      var rows=Array.prototype.slice.call(tb.rows);
      var asc=th.dataset.asc!=='1'; th.dataset.asc=asc?'1':'0';
      var num=th.dataset.t==='num';
      rows.sort(function(a,b){{
        var x=a.cells[ci], y=b.cells[ci]; if(!x||!y) return 0;
        var xv=x.dataset.sort||x.innerText, yv=y.dataset.sort||y.innerText;
        if(num){{return asc?(parseFloat(xv)||0)-(parseFloat(yv)||0):(parseFloat(yv)||0)-(parseFloat(xv)||0);}}
        return asc?(''+xv).localeCompare(yv):(''+yv).localeCompare(xv);
      }});
      rows.forEach(function(r){{tb.appendChild(r);}});
    }});
  }});
}});
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
    "/featlib": ("featlib", "特征库"),
    "/insiders": ("insiders", "内鬼库"),
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

            if path == "/api/gateway_feed":
                # 网关拉取: 从特征库/内鬼库吐出 {ips, asns, uas, tokens}(邮箱前缀已翻译成token)
                fk = store.get_kv("gateway_feed_key", "")
                if not fk or q.get("key", [""])[0] != fk:
                    self._send(b'{"error":"invalid key"}', "application/json; charset=utf-8"); return
                sigs = store.list_signatures()
                ips = sorted({r["value"] for r in sigs if r["kind"] == "ip" and r["value"]})
                uas = sorted({r["value"] for r in sigs if r["kind"] == "ua" and r["value"]})
                asns = sorted({int(re.sub(r"(?i)^as", "", (r["value"] or "").strip()))
                               for r in sigs if r["kind"] == "asn"
                               and re.sub(r"(?i)^as", "", (r["value"] or "").strip()).isdigit()})
                emails = [r["value"] for r in sigs if r["kind"] == "email" and r["value"]]
                tokens = sorted(store.insider_tokens() | store.tokens_by_email_substrings(emails))
                out = {"ips": ips, "asns": asns, "uas": uas, "tokens": tokens,
                       "counts": {"ips": len(ips), "asns": len(asns), "uas": len(uas), "tokens": len(tokens)}}
                self._send(json.dumps(out, ensure_ascii=False).encode(), "application/json; charset=utf-8")
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
                self._html(render_login(q.get("err", [""])[0], q.get("msg", [""])[0],
                                        allow_register=(n_admin == 0))); return
            if path == "/register":
                # 仅首次(无管理员)开放注册; 已有管理员后关闭, 防止外人注册看到全部数据
                if n_admin > 0:
                    self._to("/login?err=" + quote("注册已关闭(仅首次初始化开放)")); return
                self._html(render_register(q.get("err", [""])[0], first=True)); return
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
                    store.checkpoint()   # 先把 WAL 合进主库, 导出才完整
                    with open(CONFIG.db_path, "rb") as f:
                        data = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", 'attachment; filename="spyware.db"')
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self._send(b"no db", "text/plain")
                return

            if path == "/api/same_ip":
                ip = q.get("ip", [""])[0]
                self._send(json.dumps(store.accounts_by_ip(ip) if ip else [],
                                      ensure_ascii=False).encode(), "application/json; charset=utf-8")
                return

            if path == "/risk/export":
                # 导出选中等级(lv 可多选)命中的账号为 CSV, 最多 2 万行
                import csv as _csv
                import io as _io
                levels = [x for x in q.get("lv", []) if x in ("高", "中", "低", "正常")]
                pf = q.get("panel", ["all"])[0]
                sq = (q.get("q", [""])[0] or "").strip()
                from .asn import get_asndb
                asndb = get_asndb()
                ipt = store.tokens_by_search(sq, asndb) if sq else set()
                total = min(20000, store.count_scores("all", pf, sq, ipt, levels=levels or None))
                rows = store.list_scores("all", pf, sq, ipt, limit=total or 1, offset=0,
                                         levels=levels or None)
                ipmap = store.pull_ips_for_tokens([r.token for r in rows])
                buf = _io.StringIO()
                wr = _csv.writer(buf)
                wr.writerow(["token", "邮箱", "用户ID", "面板", "风险分", "等级", "命中信号",
                             "IP", "ASN", "IP数", "在线IP", "UA数", "共用账号", "拉取次数",
                             "已用流量", "注册时间", "到期时间", "最新拉取订阅"])
                for r in rows:
                    ips = ipmap.get(r.token, [])
                    asns = sorted({f"AS{asndb.lookup(ip)[0]}" for ip in ips
                                   if asndb and asndb.lookup(ip)[0]}) if asndb else []
                    wr.writerow([
                        r.token, r.email or "", r.user_id if r.user_id is not None else "",
                        r.panel or "", r.score, r.level, " ".join(r.tags),
                        " ".join(ips[:10]), " ".join(asns),
                        r.distinct_ips, r.online_ips, r.distinct_uas, r.ip_shared_users, r.pull_count,
                        _human_bytes(r.traffic_bytes),
                        r.created_at.strftime("%Y-%m-%d") if r.created_at else "",
                        r.expired_at.strftime("%Y-%m-%d") if r.expired_at else "",
                        r.last_pull.strftime("%Y-%m-%d %H:%M") if r.last_pull else ""])
                data = ("﻿" + buf.getvalue()).encode("utf-8")  # BOM: Excel 正确识别中文
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="insiders.csv"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

            if path == "/featlib/export":
                import csv as _csv
                import io as _io
                sq = (q.get("q", [""])[0] or "").strip().lower()
                srows = store.list_signatures()
                if sq:
                    srows = [r for r in srows if sq in
                             f'{_SIG_KIND_CN.get(r["kind"], r["kind"])} {r["value"] or ""} {r["note"] or ""}'.lower()]
                buf = _io.StringIO()
                wr = _csv.writer(buf)
                wr.writerow(["类型", "特征值", "备注", "添加时间"])
                for r in srows:
                    wr.writerow([_SIG_KIND_CN.get(r["kind"], r["kind"]), r["value"] or "",
                                 r["note"] or "", (r["created_at"] or "")[:19]])
                data = ("﻿" + buf.getvalue()).encode("utf-8")   # BOM: Excel 正确识别中文
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="featlib.csv"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

            if path == "/api/risks":
                # 读物化评分, 默认只回风险(非正常)用户, 按分数从高到低, 最多 5000 条
                lvl = q.get("level", ["risky"])[0]
                try:
                    lim = min(20000, max(1, int(q.get("limit", ["5000"])[0])))
                except ValueError:
                    lim = 5000
                if lvl in ("高", "中", "低", "正常"):
                    results = store.list_scores(level=lvl, limit=lim)
                else:  # risky: 高+中+低
                    results = [r for r in store.list_scores(limit=lim) if r.level != "正常"]
                payload = [{"token": r.token, "score": r.score, "level": r.level, "excluded": r.excluded,
                            "email": r.email, "user_id": r.user_id, "panel": r.panel, "tags": r.tags,
                            "signals": [{"name": s.name, "points": s.points, "detail": s.detail} for s in r.signals]}
                           for r in results]
                self._send(json.dumps(payload, ensure_ascii=False, indent=2).encode(),
                           "application/json; charset=utf-8")
                return

            if path == "/api/user":
                self._send(json.dumps(_user_detail(store, q.get("token", [""])[0]),
                                      ensure_ascii=False).encode(), "application/json; charset=utf-8")
                return

            if path == "/api/traffic":
                tok = q.get("token", [""])[0]
                try:
                    page = max(1, int(q.get("page", ["1"])[0]))
                except ValueError:
                    page = 1
                out = {"rows": [], "total": 0}
                # 优先读本地(同步时已拉入); 本地没有再回退实时查远程
                local = store.traffic_daily_for(tok)
                if local:
                    rows = [{"date": datetime.utcfromtimestamp(r["day"]).strftime("%Y-%m-%d"),
                             "up": _human_bytes(r["u"]), "down": _human_bytes(r["d"]),
                             "rate": f'{float(r["rate"] or 1):.2f}'} for r in local]
                    out = {"rows": rows, "total": len(rows)}
                else:
                    user = store.user(tok)
                    if user and user["user_id"] and "panel" in user.keys() and user["panel"]:
                        src = next((s for s in store.list_sources()
                                    if s["type"] == "v2board" and s["name"] == user["panel"]), None)
                        if src:
                            try:
                                from .connectors.v2board import V2BoardConnector
                                conn = V2BoardConnector(json.loads(src["config"] or "{}"))
                                rows = conn.query_traffic(user["user_id"], days=90)
                                out = {"rows": rows, "total": len(rows), "live": True}
                            except Exception as e:  # noqa: BLE001
                                out = {"error": f"流量查询失败: {e}"}
                        else:
                            out = {"error": "该机场未接入 v2board 数据库"}
                    else:
                        out = {"error": "该用户暂无本地流量, 同步 v2board 后可见"}
                self._send(json.dumps(out, ensure_ascii=False).encode(),
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
                content = render_risklist(store, q.get("level", ["all"])[0],
                                          q.get("panel", ["all"])[0], q.get("q", [""])[0],
                                          q.get("size", ["10"])[0], q.get("page", ["1"])[0],
                                          q.get("sort", [""])[0], q.get("sdir", ["desc"])[0])
            elif active == "rules":
                content = render_rules(store, q.get("msg", [""])[0], q.get("err", [""])[0])
            elif active == "whitelist":
                content = render_whitelist(q.get("msg", [""])[0], q.get("err", [""])[0],
                                           q.get("cat", [""])[0], q.get("tab", ["white"])[0],
                                           q.get("sub", [""])[0])
            elif active == "featlib":
                content = render_featurelib(store, q.get("msg", [""])[0], q.get("err", [""])[0],
                                            q.get("q", [""])[0])
            elif active == "insiders":
                content = render_insiders(store, q.get("msg", [""])[0], q.get("err", [""])[0])
            elif active == "domains":
                content = render_domains(store, q.get("panel", [""])[0], q.get("tier", [""])[0],
                                         q.get("msg", [""])[0], q.get("err", [""])[0])
            elif active == "settings":
                content = render_settings(admin, q.get("msg", [""])[0], q.get("err", [""])[0], store=store)
            elif active == "logstore":
                content = render_logstore(store, q.get("src", [""])[0],
                                          q.get("size", ["10"])[0], q.get("page", ["1"])[0])
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
                pnets = load_proxy_nets()
                try:
                    _scfg = json.loads(src["config"] or "{}")
                except (ValueError, TypeError):
                    _scfg = {}
                src_default = _scfg.get("panel") or src["name"]  # 归属面板优先作分类
                groups = payload.get("groups")
                if isinstance(groups, dict) and groups:
                    # 探针按「归属标签」分组上报: 每组各自打 src 标签(标签空则用面板/数据源名)
                    n = sent = 0
                    for label, lines in groups.items():
                        lines = lines or []
                        sent += len(lines)
                        recs = [r for r in (parse_line(ln, pnets) for ln in lines) if r]
                        n += store.add_pulls(recs, src=(label or src_default))
                else:
                    raw = payload.get("logs", []) or []
                    recs = [r for r in (parse_line(ln, pnets) for ln in raw) if r]
                    n = store.add_pulls(recs, src=src_default)
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
                pnets = load_proxy_nets()
                try:
                    _sp = json.loads(src["config"] or "{}").get("panel")
                except (ValueError, TypeError):
                    _sp = None
                recs = [r for r in (parse_line(ln, pnets) for ln in text.splitlines()) if r]
                n = store.add_pulls(recs, src=(_sp or src["name"]))
                self._send(json.dumps({"ok": n}).encode(), "application/json; charset=utf-8")
            finally:
                store.close()
            return

        # 数据库导入(二进制 multipart, 需在 form 解析之前拦截)
        if path == "/db/import":
            try:
                admin = self._admin(store)
                if admin is None:
                    self._to("/login"); return
                ok, err = _import_db(store, self.headers.get("Content-Type", ""), raw)
            finally:
                store.close()
            if ok:
                threading.Timer(0.8, _restart_only).start()
                self._send(_import_wait_page(), "text/html; charset=utf-8")
            else:
                self._to("/settings?err=" + quote(err or "导入失败"))
            return

        # 特征库文件导入(multipart, 多文件/文件夹; 需在 form 解析前拦截)
        if path == "/featlib/import":
            added = nlines = 0
            try:
                admin = self._admin(store)
                if admin is None:
                    self._to("/login"); return
                files = _extract_multipart_files(self.headers.get("Content-Type", ""), raw)
                text = "\n".join(b.decode("utf-8", "replace") for b in files)
                items = _parse_sig_lines(text, "auto")
                nlines = len(items)
                added = store.add_signatures_bulk(items) if items else 0
            finally:
                store.close()
            if not nlines:
                self._to("/featlib?err=" + quote("未读到有效内容(空文件或未选文件)"))
            else:
                self._to("/featlib?msg=" + quote(f"已导入 {added} 条新特征(解析 {nlines} 行, 去重跳过 {nlines - added} 条)"))
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
                # 已有管理员后禁止再注册(仅首次初始化开放), 防外人注册看到全部数据
                if store.admin_count() > 0:
                    self._to("/login?err=" + quote("注册已关闭(仅首次初始化开放)")); return
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
                    if form.get("panel", "").strip():
                        cfg["panel"] = form["panel"].strip()
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
                        pn = form.get("panel", "").strip()
                        if pn:
                            cfg["panel"] = pn
                        else:
                            cfg.pop("panel", None)
                    # 同步方式: 手动/自动/跟随全局 + 间隔
                    smode = form.get("sync_mode", "manual")
                    if smode not in ("manual", "auto", "follow"):
                        smode = "manual"
                    cfg["sync_mode"] = smode
                    iv = int(form.get("interval", "300") or 300)
                    store.update_source(src["id"], name, json.dumps(cfg))
                    store.set_source_auto(src["id"], 1 if smode != "manual" else 0, iv)
                    if src["type"] == "v2board" and name != src["name"]:
                        store.rename_panel(src["name"], name)   # 改名同步到已存数据
                        _relabel_log_sources(store, src["name"], name)  # 日志源标签也跟着改
                self._back(); return
            if path == "/risk/cols":
                checked = set(formq.get("col", []))
                hidden = [k for k, _ in RISK_COLS if k not in checked]
                store.set_kv("risk_hidden_cols", json.dumps(hidden))
                self._to("/risk"); return
            if path == "/runlog/clear":
                store.clear_runlog(form.get("kind") or None, form.get("name") or None)
                self._to("/runlog"); return
            if path == "/logstore/clear":
                sname = form.get("src") or None
                store.clear_pulls(sname)
                self._to("/logstore" + (f"?src={quote(sname)}" if sname else "")); return
            if path == "/sources/delete":
                store.delete_source(int(form["id"])); self._back(); return
            if path == "/sources/move":
                d = form.get("dir", "up")
                store.move_source(int(form["id"]), "down" if d == "down" else "up")
                self._back(); return
            if path == "/panels/cleanup":
                valid = {s["name"] for s in store.list_sources() if s["type"] == "v2board"}
                n = store.purge_orphan_panels(valid)
                self._to("/panels/v2board?msg=" + quote(f"已清理改名/删除遗留的面板数据 {n} 条用户"))
                return
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
            if path == "/rules/save":
                wkeys = list(asdict(CONFIG.weights).keys())
                tkeys = list(asdict(CONFIG.thresholds).keys())
                weights, ths = {}, {}
                for k in wkeys:
                    v = form.get(f"w_{k}", "")
                    if v != "":
                        try:
                            weights[k] = float(v)
                        except ValueError:
                            pass
                for k in tkeys:
                    v = form.get(f"t_{k}", "")
                    if v != "":
                        try:
                            ths[k] = float(v)
                        except ValueError:
                            pass
                store.set_kv("risk_overrides", json.dumps({"weights": weights, "thresholds": ths}))
                # 未勾选的开关 → 停用
                off = [k for k in wkeys + tkeys if not form.get(f"on_{k}")]
                store.set_kv("signals_off", json.dumps(sorted(off)))
                self._to("/rules?msg=" + quote("已保存, 评分即时生效")); return
            if path == "/rules/reset":
                store.set_kv("risk_overrides", "")
                store.set_kv("signals_off", "")
                self._to("/rules?msg=" + quote("已恢复内置默认")); return
            if path == "/featlib/add":
                kind = form.get("kind", "ip")
                value = form.get("value", "").strip()
                if kind in ("ip", "ua", "asn", "email") and value:
                    store.add_signature(kind, value, form.get("note", ""))
                    self._to("/featlib?msg=" + quote("已添加特征"))
                else:
                    self._to("/featlib?err=" + quote("类型或特征值无效"))
                return
            if path == "/featlib/batch-add":
                kind = form.get("kind", "auto")
                if kind not in ("auto", "ip", "ua", "asn", "email"):
                    kind = "auto"
                items = _parse_sig_lines(form.get("text", ""), kind)
                added = store.add_signatures_bulk(items) if items else 0
                if not items:
                    self._to("/featlib?err=" + quote("没有可添加的内容"))
                else:
                    self._to("/featlib?msg=" + quote(f"批量添加 {added} 条新特征(去重跳过 {len(items) - added} 条)"))
                return
            if path == "/featlib/delete":
                store.delete_signature(int(form["id"]))
                self._to("/featlib?msg=" + quote("已删除")); return
            if path == "/featlib/delete-all":
                n = store.delete_all_signatures()
                self._to("/featlib?msg=" + quote(f"已删除全部 {n} 条特征")); return
            if path == "/insiders/add":
                tok = form.get("token", "").strip()
                if tok:
                    u = store.user(tok)
                    pulls = list(store.pulls_for(tok))
                    from .asn import get_asndb
                    asndb = get_asndb()
                    ips = sorted({p["ip"] for p in pulls if p["ip"]})
                    uas = sorted({p["ua"] for p in pulls if p["ua"]})
                    asns = sorted({asndb.lookup(ip)[0] for ip in ips
                                   if asndb and asndb.lookup(ip)[0]}) if asndb else []
                    tags = store.score_tags(tok)   # 快照其行为标签(供「内鬼行为相似」比对)
                    store.add_insider(tok, email=(u["email"] if u else None),
                                      panel=(u["panel"] if u and "panel" in u.keys() else None),
                                      ips=ips, uas=uas, asns=list(asns), tags=tags)
                    store.delete_score(tok)   # 立即从名单移除, 不等后台重算
                self._back(); return
            if path == "/insiders/to-featlib":
                # 勾选的是具体特征值(不是类型); 字段名即类型
                ip_v = [x for x in formq.get("ip", []) if x]
                ua_v = [x for x in formq.get("ua", []) if x]
                em_v = [x for x in formq.get("email", []) if x]
                asn_v = [x for x in formq.get("asn", []) if x]
                host_v = [x for x in formq.get("hostname", []) if x]
                if not (ip_v or ua_v or em_v or asn_v or host_v):
                    self._to("/insiders?err=" + quote("没有勾选任何项")); return
                from .enrich import IpClassifier, UaClassifier
                _ipc = IpClassifier()
                _uac = UaClassifier()
                ip_v = [ip for ip in ip_v if not _ipc.is_self_ip(ip)]   # 自有/反代IP不导入
                ua_v = [ua for ua in ua_v if not _uac.is_self(ua)]      # 自有UA不导入
                items = []
                for ip in ip_v:
                    items.append(("ip", ip, "内鬼库导入"))
                for ua in ua_v:
                    items.append(("ua", "^" + re.escape(ua) + "$", "内鬼库导入"))
                for e in em_v:
                    items.append(("email", e, "内鬼库导入(前缀)"))
                for a in asn_v:
                    items.append(("asn", a if a.upper().startswith("AS") else "AS" + a, "内鬼库导入"))
                added = store.add_signatures_bulk(items) if items else 0
                msg = f"内鬼库导入: 特征库 +{added} 条"
                if host_v:
                    msg += f", 机房关键词 +{_append_hosting_keywords([h.upper() for h in host_v])} 条"
                self._to("/featlib?msg=" + quote(msg + "(已去重)"))
                return
            if path == "/insiders/check-group":
                group_name = store.get_kv("spy_group_name", "Lv.spy") or "Lv.spy"
                panel_cfg = {}
                for s in store.list_sources():
                    if s["type"] != "v2board" or not s["enabled"]:
                        continue
                    try:
                        cfg = json.loads(s["config"] or "{}")
                    except (ValueError, TypeError):
                        continue
                    panel_cfg[cfg.get("panel") or s["name"]] = cfg
                by_panel, no_panel = {}, []
                for r in store.list_insiders():
                    p = (r["panel"] or "").strip()
                    (by_panel.setdefault(p, []).append(r["token"]) if p else no_panel.append(r["token"]))
                from .connectors.v2board import V2BoardConnector
                status, errs = {}, []
                for panel, toks in by_panel.items():
                    cfg = panel_cfg.get(panel)
                    if not cfg:
                        continue
                    try:
                        st, err = V2BoardConnector(cfg).group_status(toks, group_name)
                        if err:
                            errs.append(f"{panel}: {err}")
                        status.update({t: bool(v) for t, v in st.items()})
                    except Exception as e:  # noqa: BLE001
                        errs.append(f"{panel}: {e}")
                for panel, cfg in (panel_cfg.items() if no_panel else []):
                    try:
                        st, _err = V2BoardConnector(cfg).group_status(no_panel, group_name)
                        status.update({t: bool(v) for t, v in st.items()})
                    except Exception:  # noqa: BLE001
                        pass
                store.set_kv("spy_status", json.dumps(status))
                store.set_kv("spy_status_at", datetime.now().isoformat(timespec="minutes"))
                msg = f"已检查 {len(status)} 个内鬼的「{group_name}」分组状态"
                if errs:
                    msg += " · 问题: " + "; ".join(errs[:5])
                self._to("/insiders?msg=" + quote(msg)); return
            if path == "/insiders/to-group":
                group_name = (form.get("group_name", "") or "").strip() or "Lv.spy"
                store.set_kv("spy_group_name", group_name)
                # 面板名 -> v2board source config
                panel_cfg = {}
                for s in store.list_sources():
                    if s["type"] != "v2board" or not s["enabled"]:
                        continue
                    try:
                        cfg = json.loads(s["config"] or "{}")
                    except (ValueError, TypeError):
                        continue
                    panel_cfg[cfg.get("panel") or s["name"]] = cfg
                by_panel, no_panel = {}, []
                for r in store.list_insiders():
                    p = (r["panel"] or "").strip()
                    if p:
                        by_panel.setdefault(p, []).append(r["token"])
                    else:
                        no_panel.append(r["token"])   # 无账号/无面板: 稍后在所有面板里试
                from .connectors.v2board import V2BoardConnector
                moved_total, errs = 0, []
                for panel, toks in by_panel.items():
                    cfg = panel_cfg.get(panel)
                    if not cfg:
                        errs.append(f"{panel}: 无匹配的启用面板")
                        continue
                    try:
                        moved, _gid, err = V2BoardConnector(cfg).move_users_to_group(toks, group_name)
                        if err:
                            errs.append(f"{panel}: {err}")
                        moved_total += moved
                    except Exception as e:  # noqa: BLE001
                        errs.append(f"{panel}: {e}")
                # 无面板(无账号)的内鬼: token 唯一, 在每个启用面板里试, 命中哪个就在哪改
                for panel, cfg in (panel_cfg.items() if no_panel else []):
                    try:
                        moved, _gid, err = V2BoardConnector(cfg).move_users_to_group(no_panel, group_name)
                        if err:
                            errs.append(f"{panel}(无账号批): {err}")
                        else:
                            moved_total += moved
                    except Exception as e:  # noqa: BLE001
                        errs.append(f"{panel}(无账号批): {e}")
                msg = f"已把 {moved_total} 个内鬼移入「{group_name}」组"
                if no_panel:
                    msg += f"(含 {len(no_panel)} 个无面板内鬼在各面板逐一尝试)"
                if errs:
                    msg += " · 未完成: " + "; ".join(errs[:6])
                self._to("/insiders?msg=" + quote(msg)); return
            if path == "/insiders/remove":
                tok = form.get("token", "").strip()
                store.remove_insider(tok)
                try:
                    from .pipeline import recompute_one
                    recompute_one(store, tok)   # 立即算回名单, 不等后台
                except Exception:  # noqa: BLE001
                    pass
                self._to("/insiders?msg=" + quote("已移出内鬼库, 已回到风险名单")); return
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
                self._to("/whitelist?cat=self&tab=white&msg=" + quote("自有IP已保存")); return
            if path == "/whitelist/save-hosting":
                with open(CONFIG.hosting_cidrs_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?cat=hosting&sub=cidr&msg=" + quote("机房库已保存")); return
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
                self._to("/whitelist?cat=ua&tab=white&msg=" + quote("UA 白名单已保存")); return
            if path == "/whitelist/save-uaself":
                with open(CONFIG.ua_self_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?cat=ua&tab=self&msg=" + quote("自有 UA 已保存")); return
            if path == "/whitelist/save-proxy":
                with open(CONFIG.proxy_ips_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?cat=proxy&msg=" + quote("反代 IP 过滤已保存")); return
            if path == "/whitelist/save-asnkw":
                with open(CONFIG.asn_hosting_kw_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?cat=hosting&sub=kw&msg=" + quote("机房关键词已保存")); return
            if path == "/whitelist/update-asn":
                url = ((form.get("url", "") or "").strip()
                       or "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb")
                try:
                    import gzip as _gz
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=180) as r:
                        raw = r.read()
                    if url.endswith(".mmdb"):
                        with open(CONFIG.asn_mmdb_file, "wb") as f:
                            f.write(raw)
                    else:
                        data = _gz.decompress(raw) if url.endswith(".gz") else raw
                        with open(CONFIG.asn_db_file, "wb") as f:
                            f.write(data)
                    from .asn import get_asndb
                    db = get_asndb()
                    src = getattr(db, "source", "?") if db else "?"
                    self._to("/settings?msg=" + quote(f"ASN 库已更新({src}), 已启用"))
                except Exception as e:  # noqa: BLE001
                    self._to("/settings?err=" + quote(f"下载失败: {e}"))
                return
            if path == "/blacklist/save-ip":
                with open(CONFIG.ip_blacklist_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?cat=self&tab=black&msg=" + quote("IP 黑名单已保存")); return
            if path == "/blacklist/save-ua":
                with open(CONFIG.ua_blacklist_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?cat=ua&tab=black&msg=" + quote("UA 黑名单已保存")); return
            if path == "/blacklist/save-asn":
                with open(CONFIG.asn_blacklist_file, "w", encoding="utf-8") as f:
                    f.write(form.get("content", ""))
                self._to("/whitelist?cat=hosting&sub=asn&msg=" + quote("ASN 黑名单已保存")); return
            if path == "/whitelist/fetch-hosting":
                url = form.get("url", "").strip()
                if not url:
                    self._to("/whitelist?cat=hosting&sub=cidr&err=" + quote("请填写 URL")); return
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "spyware/1.0"})
                    with urllib.request.urlopen(req, timeout=20) as resp:
                        data = resp.read().decode("utf-8", "replace")
                    with open(CONFIG.hosting_cidrs_file, "w", encoding="utf-8") as f:
                        f.write(data)
                    self._to("/whitelist?cat=hosting&sub=cidr&msg=" + quote(f"已从 URL 拉取 {_count_cidrs(data)} 条"))
                except Exception as e:  # noqa: BLE001
                    self._to("/whitelist?cat=hosting&sub=cidr&err=" + quote(f"拉取失败: {e}"))
                return
            if path == "/nodes/add":
                store.add_entity(form.get("kind", "backend"), form.get("name", "").strip(),
                                 form.get("detail", ""), form.get("config", ""))
                self._back(); return
            if path == "/nodes/delete":
                store.delete_entity(int(form["id"])); self._back(); return
            if path == "/settings/gateway-key":
                store.set_kv("gateway_feed_key", secrets.token_hex(16))
                self._to("/settings?msg=" + quote("网关 Feed 密钥已生成, 去网关侧配置")); return
            if path == "/settings/sync-scope":
                on = form.get("paid_only") in ("on", "1", "true")
                store.set_kv("sync_paid_only", "1" if on else "0")
                if on:
                    removed = store.purge_unpaid_users()
                    self._to("/settings?msg=" + quote(f"已开启: 清除本地未购买用户 {removed} 个, 下次同步只拉购买过的"))
                else:
                    self._to("/settings?msg=" + quote("已关闭: 恢复同步全部用户")); return
                return
            if path == "/db/vacuum":
                import os as _os
                before = _os.path.getsize(CONFIG.db_path) / 1048576 if _os.path.exists(CONFIG.db_path) else 0
                try:
                    store.vacuum()
                    after = _os.path.getsize(CONFIG.db_path) / 1048576 if _os.path.exists(CONFIG.db_path) else 0
                    self._to("/settings?msg=" + quote(f"压缩完成: {before:.1f}MB → {after:.1f}MB"))
                except Exception as e:  # noqa: BLE001
                    self._to("/settings?err=" + quote(f"压缩失败: {e}"))
                return
            if path == "/logs/rebuild":
                store.clear_pulls()                 # 清掉旧的(含反代IP重复/标错面板的)
                for s in store.list_sources():      # 所有源从头重导
                    try:
                        cfg = json.loads(s["config"] or "{}")
                        if s["type"] == "logfile" and cfg.get("mode") == "agent":
                            store.set_kv(f"agent_force::{cfg.get('key', '')}", "1")  # 探针 reset 重读
                        else:
                            run_source(store, s)
                    except Exception:  # noqa: BLE001
                        pass
                self._to("/panels/log?msg=" + quote("已清空并触发重建: 探针源约数秒内从头重读, 本地源已重导"))
                return
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
        print("用法: python3 -m spyware.web resetpw <用户名>")
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

    p = argparse.ArgumentParser(prog="spyware.web", description="内鬼系统 · 可视化控制后台")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--syslog-port", type=int, default=0, help="Nginx syslog 直发接收端口(默认0关闭; 探针接入无需它)")
    args = p.parse_args(argv)

    seed = Store()
    n_admin = seed.admin_count()
    # 启动时若评分表空或过期, 先算一次(避免重启后风险名单短暂空白)
    try:
        from .pipeline import recompute_scores, scores_stale
        if scores_stale(seed):
            recompute_scores(seed)
    except Exception:  # noqa: BLE001
        pass
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
