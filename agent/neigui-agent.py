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


def expand_paths(spec):
    """spec 可多行; 每行为文件/通配/目录。目录→目录下 *.log; 通配→展开。返回实际文件列表。"""
    files = []
    for line in (spec or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if os.path.isdir(line):
            files.extend(_glob.glob(os.path.join(line, "*.log")))
        elif any(ch in line for ch in "*?["):
            files.extend(_glob.glob(line))
        elif os.path.isfile(line):
            files.append(line)
    return sorted(set(files))


def read_new_file(path, st):
    """单文件增量读; st=该文件的 {offset,inode}。返回 (新行, 新st)。"""
    stat = os.stat(path)
    off = st.get("offset", 0)
    if st.get("inode") != stat.st_ino or stat.st_size < off:
        off = 0
    lines = []
    with open(path, encoding="utf-8", errors="replace") as f:
        f.seek(off)
        while True:
            ln = f.readline()
            if not ln:
                break
            ln = ln.rstrip("\n")
            if ln:
                lines.append(ln)
        end = f.tell()
    return lines, {"offset": end, "inode": stat.st_ino}


def collect(spec, state):
    """按 spec 读所有匹配文件的新增行(state 按文件路径分别记 offset)。
    返回 (行列表, 新state, 是否有可读文件)。"""
    files = expand_paths(spec)
    lines, newstate = [], dict(state)
    for fp in files:
        try:
            fl, fst = read_new_file(fp, state.get(fp, {}))
            lines.extend(fl)
            newstate[fp] = fst
        except Exception:
            pass
    return lines, newstate, bool(files)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--master", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--log", default="/www/wwwlogs/neigui_sub.log")  # 兜底; 中央可下发覆盖
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
        now = time.time()
        if force or (now - last_report) >= report_interval:
            lines, newstate, has_file = collect(log_path, state)
            ok = http_post(f"{a.master}/api/agent/report?token={a.token}",
                           {"logs": lines, "metrics": metrics(),
                            "log_ok": has_file, "log_path": log_path})
            if ok:
                state = newstate
                last_report = now
                try:
                    os.makedirs(os.path.dirname(a.state), exist_ok=True)
                    with open(a.state, "w", encoding="utf-8") as f:
                        json.dump(state, f)
                except Exception:
                    pass
        time.sleep(POLL)


if __name__ == "__main__":
    main()
