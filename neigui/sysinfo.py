"""VPS 实时负载(aaPanel 风格): 负载/CPU/内存/磁盘。纯标准库, Linux 最全, 其它系统降级。"""
from __future__ import annotations

import os
import shutil

_cpu_prev = {}  # /proc/stat 采样缓存, 用于算 CPU 使用率增量


def _linux_cpu_percent():
    try:
        with open("/proc/stat", encoding="utf-8") as f:
            parts = [float(x) for x in f.readline().split()[1:]]
        idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
        total = sum(parts)
        prev = _cpu_prev.get("v")
        _cpu_prev["v"] = (idle, total)
        if prev:
            di, dt = idle - prev[0], total - prev[1]
            if dt > 0:
                return max(0.0, min(100.0, (1 - di / dt) * 100))
    except (OSError, ValueError, IndexError):
        pass
    return None


def _linux_mem():
    try:
        info = {}
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                k, _, v = line.partition(":")
                info[k.strip()] = int(v.split()[0])  # kB
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        return (total - avail) // 1024, total // 1024  # MB
    except (OSError, ValueError):
        return None


def get_metrics() -> dict:
    m = {"cores": os.cpu_count() or 1}
    # 负载
    try:
        la = os.getloadavg()
        m["load"] = la[0]
        m["load_pct"] = min(100.0, la[0] / m["cores"] * 100)
    except (OSError, AttributeError):
        m["load"] = None
        m["load_pct"] = None
    # CPU 使用率(Linux 精确, 否则用负载估算)
    m["cpu_pct"] = _linux_cpu_percent()
    if m["cpu_pct"] is None:
        m["cpu_pct"] = m.get("load_pct")
    # 内存
    mem = _linux_mem()
    if mem:
        m["mem_used"], m["mem_total"] = mem
        m["mem_pct"] = (mem[0] / mem[1] * 100) if mem[1] else None
    else:
        m["mem_used"] = m["mem_total"] = m["mem_pct"] = None
    # 磁盘 /
    try:
        du = shutil.disk_usage("/")
        m["disk_used"], m["disk_total"] = du.used, du.total
        m["disk_pct"] = du.used / du.total * 100 if du.total else None
    except OSError:
        m["disk_used"] = m["disk_total"] = m["disk_pct"] = None
    return m
