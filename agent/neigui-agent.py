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


def http_get(url, timeout=10):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def http_post(url, obj, timeout=15):
    try:
        req = urllib.request.Request(
            url, data=json.dumps(obj).encode(),
            headers={"Content-Type": "application/json"})
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


def read_new(path, state):
    """增量读 + 轮转/截断处理(inode 变或 size<offset → 从头)。"""
    st = os.stat(path)
    off = state.get("offset", 0)
    if state.get("inode") != st.st_ino or st.st_size < off:
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
    return lines, {"offset": end, "inode": st.st_ino}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--master", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--log", default="/www/wwwlogs/neigui_sub.log")  # 兜底; 中央可下发覆盖
    ap.add_argument("--state", default="/opt/neigui-agent/state.json")
    a = ap.parse_args()

    state = {}
    try:
        with open(a.state, encoding="utf-8") as f:
            state = json.load(f)
    except Exception:
        pass

    interval = 5
    log_path = a.log
    while True:
        cfg = http_get(f"{a.master}/api/agent/config?token={a.token}")
        if cfg:
            if cfg.get("interval"):
                try:
                    interval = int(cfg["interval"])
                except (ValueError, TypeError):
                    pass
            if cfg.get("log_path"):          # 中央下发的日志路径优先
                log_path = cfg["log_path"]
        lines, newstate = [], state
        log_ok = os.path.exists(log_path)
        try:
            if log_ok:
                lines, newstate = read_new(log_path, state)
        except Exception:
            log_ok = False
        ok = http_post(f"{a.master}/api/agent/report?token={a.token}",
                       {"logs": lines, "metrics": metrics(),
                        "log_ok": log_ok, "log_path": log_path})
        if ok:  # 上报成功才推进 offset, 不丢日志
            state = newstate
            try:
                os.makedirs(os.path.dirname(a.state), exist_ok=True)
                with open(a.state, "w", encoding="utf-8") as f:
                    json.dump(state, f)
            except Exception:
                pass
        time.sleep(max(2, interval))


if __name__ == "__main__":
    main()
