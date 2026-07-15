#!/usr/bin/env python3
"""内鬼系统 · 被控探针(Agent)

在面板服务器本地运行: 增量读 Nginx 订阅日志 + 采集本机 VPS 负载, 上报主控;
上报间隔跟随主控 /api/agent/config 返回的 interval(即中央设置的同步时间)。
纯标准库, 零依赖。由主控的一键安装命令自动部署。
"""
import argparse
import json
import os
import shutil
import time
import urllib.request

_cpu_prev = {}


# 用普通 UA, 否则 aaPanel/宝塔 等 WAF 会拦截默认的 Python-urllib(403)
_UA = "Mozilla/5.0 (compatible; ng-agent/1.0)"


def http_get(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def http_post(url, obj, timeout=15):
    try:
        req = urllib.request.Request(
            url, data=json.dumps(obj).encode(),
            headers={"Content-Type": "application/json", "User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _cpu_pct():
    try:
        with open("/proc/stat", encoding="utf-8") as f:
            p = [float(x) for x in f.readline().split()[1:]]
        idle = p[3] + (p[4] if len(p) > 4 else 0)
        total = sum(p)
        prev = _cpu_prev.get("v")
        _cpu_prev["v"] = (idle, total)
        if prev:
            di, dt = idle - prev[0], total - prev[1]
            if dt > 0:
                return round(max(0.0, min(100.0, (1 - di / dt) * 100)), 1)
    except Exception:
        pass
    return None


def _mem_pct():
    try:
        info = {}
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                k, _, v = line.partition(":")
                info[k.strip()] = int(v.split()[0])
        t = info.get("MemTotal", 0)
        a = info.get("MemAvailable", info.get("MemFree", 0))
        return round((t - a) / t * 100, 1) if t else None
    except Exception:
        return None


def metrics():
    m = {}
    try:
        m["load"] = round(os.getloadavg()[0], 2)
        m["cores"] = os.cpu_count() or 1
    except Exception:
        pass
    m["cpu"] = _cpu_pct()
    m["mem"] = _mem_pct()
    try:
        du = shutil.disk_usage("/")
        m["disk"] = round(du.used / du.total * 100, 1) if du.total else None
    except Exception:
        pass
    return m


import glob as _glob


def parse_spec(spec):
    """每行 '路径' 或 '路径 | 归属标签'。返回 [(路径spec, 标签), ...]。"""
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


def expand_one(pathspec):
    """单条路径展开: 目录→目录下 *.log; 通配→展开; 文件→自身。"""
    if os.path.isdir(pathspec):
        return sorted(_glob.glob(os.path.join(pathspec, "*.log")))
    if any(ch in pathspec for ch in "*?["):
        return sorted(_glob.glob(pathspec))
    if os.path.isfile(pathspec):
        return [pathspec]
    return []


# 只上报订阅拉取行(含 token=); 其余 App 轮询行中央本就丢弃, 在探针侧先滤掉可省 ~97% 上行带宽
_MAX_LINES_PER_READ = 50000   # 单文件单次上报上限, 防首次同步一次性灌爆内存/带宽


def read_new_file(path, st):
    """单文件增量读, 只保留含 token= 的行; st=该文件的 {offset,inode}。返回 (新行, 新st)。
    达到单次上限即停(offset 停在已读处), 剩余下次继续, 避免大日志一次性上传。"""
    stat = os.stat(path)
    off = st.get("offset", 0)
    if st.get("inode") != stat.st_ino or stat.st_size < off:
        off = 0
    lines = []
    with open(path, encoding="utf-8", errors="replace") as f:
        f.seek(off)
        while len(lines) < _MAX_LINES_PER_READ:
            ln = f.readline()
            if not ln:
                break
            ln = ln.rstrip("\n")
            if ln and "token=" in ln:   # 只送订阅拉取行, 丢弃海量无 token 的轮询
                lines.append(ln)
        end = f.tell()
    capped = len(lines) >= _MAX_LINES_PER_READ
    return lines, {"offset": end, "inode": stat.st_ino}, capped


def collect(spec, state):
    """按 spec 读新增行, 按「归属标签」分组(state 按文件路径分别记 offset)。
    返回 (groups={标签:[行]}, 新state, 是否有可读文件, 是否还有积压未读完)。"""
    groups, newstate, has_file, more = {}, dict(state), False, False
    for pathspec, label in parse_spec(spec):
        for fp in expand_one(pathspec):
            has_file = True
            try:
                fl, fst, capped = read_new_file(fp, state.get(fp, {}))
                newstate[fp] = fst
                more = more or capped
                if fl:
                    groups.setdefault(label, []).extend(fl)
            except Exception:
                pass
    return groups, newstate, has_file, more


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--master", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--log", default="/www/wwwlogs/spyware_sub.log")  # 兜底; 中央可下发覆盖
    ap.add_argument("--state", default="/opt/spyware-agent/state.json")
    a = ap.parse_args()

    state = {}
    try:
        with open(a.state, encoding="utf-8") as f:
            state = json.load(f)
    except Exception:
        pass
    if not isinstance(state, dict):
        state = {}

    POLL = 5           # 每 5s 拉一次配置(轻), 用于立即上报
    report_interval = 300
    log_path = a.log
    last_report = 0.0
    backlog = False    # 上次上报还有积压未读完 → 尽快再报一次直到清空
    while True:
        cfg = http_get(f"{a.master}/api/agent/config?token={a.token}")
        force = False
        if cfg:
            try:
                report_interval = max(5, int(cfg.get("interval") or report_interval))
            except (ValueError, TypeError):
                pass
            if cfg.get("log_path"):
                log_path = cfg["log_path"]
            force = bool(cfg.get("report_now"))
            if cfg.get("reset"):   # 中央要求从头重读(手动导入): 清空各文件 offset
                state = {}
        now = time.time()
        if force or backlog or (now - last_report) >= report_interval:
            groups, newstate, has_file, more = collect(log_path, state)
            lines = [ln for v in groups.values() for ln in v]  # 兼容旧中央
            ok = http_post(f"{a.master}/api/agent/report?token={a.token}",
                           {"logs": lines, "groups": groups, "metrics": metrics(),
                            "log_ok": has_file, "log_path": log_path,
                            "forced": force})
            if ok:
                state = newstate
                last_report = now
                backlog = more   # 还有积压则下个 POLL 继续报, 每次上限 5 万行
                try:
                    os.makedirs(os.path.dirname(a.state), exist_ok=True)
                    with open(a.state, "w", encoding="utf-8") as f:
                        json.dump(state, f)
                except Exception:
                    pass
        time.sleep(POLL)


if __name__ == "__main__":
    main()
