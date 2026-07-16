"""IP → ASN 查询 + 机房/住宅判定。

数据源: iptoasn.com 的免费 ip2asn TSV(无需 API key, 下载后离线用)。
格式(每行, TAB 分隔): 起始IP  结束IP  ASN号  国家码  AS组织名
例:  1.0.0.0	1.0.0.255	13335	US	CLOUDFLARENET

判定「机房/IDC」: AS 组织名命中机房关键词表(可编辑)即视为 hosting。
文件不存在时整体降级——由 enrich 回退到 CIDR 名单, 不影响运行。
"""
from __future__ import annotations

import bisect
import ipaddress
import os
import threading
from typing import List, Optional, Tuple

from .config import CONFIG

_LOCK = threading.Lock()
_CACHE = {"path": None, "mtime": None, "db": None}


def _ip_to_int(s: str) -> Optional[int]:
    try:
        return int(ipaddress.ip_address(s.strip()))
    except ValueError:
        return None


class MmdbAsnDB:
    """MaxMind GeoLite2-ASN(.mmdb)后端, 纯 Python 读取。"""
    source = "GeoLite2-ASN"

    def __init__(self, path: str):
        from .mmdb import MMDBReader
        self.r = MMDBReader(path)
        self.count = self.r.node_count  # 树节点数(规模指示, 非条目数)

    def lookup(self, ip: str) -> Tuple[int, str]:
        d = self.r.get(ip)
        if not d:
            return (0, "")
        return (int(d.get("autonomous_system_number", 0) or 0),
                d.get("autonomous_system_organization", "") or "")


class AsnDB:
    source = "iptoasn"

    def __init__(self, path: str):
        self.starts: List[int] = []
        self.ends: List[int] = []
        self.asns: List[int] = []
        self.descs: List[str] = []
        self.count = 0
        self._load(path)

    def _load(self, path: str) -> None:
        intern: dict = {}
        rows = []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5:
                    continue
                s = _ip_to_int(parts[0])
                e = _ip_to_int(parts[1])
                if s is None or e is None:
                    continue
                try:
                    asn = int(parts[2])
                except ValueError:
                    asn = 0
                if asn == 0:  # iptoasn 用 0 表示"未分配", 跳过
                    continue
                desc = parts[4]
                desc = intern.setdefault(desc, desc)  # 去重字符串, 省内存
                rows.append((s, e, asn, desc))
        rows.sort(key=lambda r: r[0])
        self.starts = [r[0] for r in rows]
        self.ends = [r[1] for r in rows]
        self.asns = [r[2] for r in rows]
        self.descs = [r[3] for r in rows]
        self.count = len(rows)

    def lookup(self, ip: str) -> Tuple[int, str]:
        """返回 (asn, 组织名); 查不到返回 (0, "")。"""
        v = _ip_to_int(ip)
        if v is None or not self.starts:
            return (0, "")
        i = bisect.bisect_right(self.starts, v) - 1
        if 0 <= i < self.count and v <= self.ends[i]:
            return (self.asns[i], self.descs[i])
        return (0, "")


def get_asndb():
    """按文件 mtime 缓存的单例。优先用 GeoLite2-ASN.mmdb, 否则 iptoasn TSV; 都没有返回 None。"""
    # 优先 mmdb
    for path, kind in ((CONFIG.asn_mmdb_file, "mmdb"), (CONFIG.asn_db_file, "tsv")):
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        with _LOCK:
            if _CACHE["path"] == path and _CACHE["mtime"] == mtime and _CACHE["db"] is not None:
                return _CACHE["db"]
            db = MmdbAsnDB(path) if kind == "mmdb" else AsnDB(path)
            _CACHE.update(path=path, mtime=mtime, db=db)
            return db
    return None


_HOSTING_KW_CACHE = {"mtime": None, "kw": None}
_DEFAULT_HOSTING_KW = [
    "AMAZON", "AWS", "GOOGLE", "MICROSOFT", "AZURE", "OVH", "HETZNER", "DIGITALOCEAN",
    "LINODE", "AKAMAI", "VULTR", "CHOOPA", "CONTABO", "LEASEWEB", "M247", "DATACAMP",
    "ORACLE", "ALIBABA", "ALICLOUD", "TENCENT", "HUAWEI", "UCLOUD", "CLOUD", "HOSTING",
    "SERVER", "DATACENTER", "DATA CENTER", "IDC", "COLO", "VPS", "DEDICATED", "GTHOST",
    "KAOPU", "BANDWAGON", "MULTACOM", "PACKET", "SCALEWAY", "GCORE", "STARK",
]


def _hosting_keywords() -> List[str]:
    path = CONFIG.asn_hosting_kw_file
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return _DEFAULT_HOSTING_KW
    if _HOSTING_KW_CACHE["mtime"] == mtime and _HOSTING_KW_CACHE["kw"] is not None:
        return _HOSTING_KW_CACHE["kw"]
    kws = []
    try:
        with open(path, encoding="utf-8") as f:
            for ln in f:
                ln = ln.split("#", 1)[0].strip()
                if ln:
                    kws.append(ln.upper())
    except OSError:
        kws = []
    kws = kws or _DEFAULT_HOSTING_KW
    _HOSTING_KW_CACHE.update(mtime=mtime, kw=kws)
    return kws


def is_hosting_org(desc: str) -> bool:
    if not desc:
        return False
    d = desc.upper()
    return any(kw in d for kw in _hosting_keywords())


# 主流公有云厂商 → 中文名(ASN 组织名关键词匹配)。用于「跨云机房」信号: 同一账号跨多个云 = 极可疑。
_CLOUD_MAP = [
    ("阿里云", ("ALIBABA", "ALICLOUD", "ALIYUN")),
    ("AWS", ("AMAZON", "AWS")),
    ("腾讯云", ("TENCENT",)),
    ("UCloud", ("UCLOUD",)),
    ("Google", ("GOOGLE",)),
    ("Azure", ("AZURE", "MICROSOFT")),
    ("Oracle", ("ORACLE",)),
    ("华为云", ("HUAWEI",)),
]


def cloud_of(desc: str):
    """ASN 组织名 → 云厂商中文名; 非主流云返回 None。"""
    if not desc:
        return None
    d = desc.upper()
    for name, kws in _CLOUD_MAP:
        if any(k in d for k in kws):
            return name
    return None
