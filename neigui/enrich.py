"""富化: IP→ASN 类型分类, UA 分类。

IP 分类 MVP 用 CIDR 名单(self / hosting), 名单外默认 residential。
生产环境强烈建议替换为 MaxMind GeoLite2-ASN 精确判定住宅/机房/移动。
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional

from .config import CONFIG


def _load_cidrs(path: str) -> List:
    nets = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                try:
                    nets.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    continue
    except FileNotFoundError:
        pass
    return nets


class IpClassifier:
    """返回 self / hosting / residential / unknown。

    判定顺序: 自有名单 > 机房 CIDR 名单 > ASN 库(iptoasn, 若已下载) > 内网 > 默认住宅。
    """

    def __init__(self, self_file: Optional[str] = None, hosting_file: Optional[str] = None):
        self.self_nets = _load_cidrs(self_file or CONFIG.self_ips_file)
        self.hosting_nets = _load_cidrs(hosting_file or CONFIG.hosting_cidrs_file)
        from .asn import get_asndb
        self.asndb = get_asndb()  # 缓存单例; 无库时为 None

    def classify(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "unknown"
        # 显式名单优先于 is_private(TEST-NET 等特殊段会被 is_private 误判)
        for net in self.self_nets:
            if addr in net:
                return "self"
        for net in self.hosting_nets:
            if addr in net:
                return "hosting"
        # ASN 库: 组织名命中机房关键词 → hosting(比手工 CIDR 覆盖广得多)
        if self.asndb is not None:
            from .asn import is_hosting_org
            _asn, desc = self.asndb.lookup(ip)
            if desc and is_hosting_org(desc):
                return "hosting"
        if addr.is_private:
            return "self"  # 内网视为自有基础设施
        return "residential"  # 名单外默认住宅

    def asn_info(self, ip: str):
        """返回 (asn, 组织名); 无 ASN 库时 (0, "")。"""
        if self.asndb is None:
            return (0, "")
        return self.asndb.lookup(ip)


# —— UA 分类 ——

_TOOL_UA = re.compile(
    r"(curl|wget|python-requests|python-urllib|go-http-client|okhttp|libwww|"
    r"java/|axios|node-fetch|httpie|scrapy|aiohttp|got |winhttp)",
    re.IGNORECASE,
)


@dataclass
class UaInfo:
    raw: str
    is_client: bool
    is_tool: bool
    client_name: Optional[str]


def _load_patterns(path: str) -> List[str]:
    pats = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    pats.append(line)
    except FileNotFoundError:
        pass
    return pats


def _load_asn_numbers(path: str):
    """从名单文件里取 ASxxxx / asxxxx / 纯数字行 → ASN 号集合。"""
    nums = set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip().upper()
                if not line:
                    continue
                if line.startswith("AS") and line[2:].isdigit():
                    nums.add(int(line[2:]))
                elif line.isdigit():
                    nums.add(int(line))
    except FileNotFoundError:
        pass
    return nums


class Blacklist:
    """IP/ASN(CIDR)与 UA(正则)黑名单。命中即高危。"""

    def __init__(self):
        # ASN 黑名单文件里的 CIDR 并入 IP 网段匹配; ASxxxx 号经 ASN 库解析(需已下载)
        self.ip_nets = _load_cidrs(CONFIG.ip_blacklist_file) + _load_cidrs(CONFIG.asn_blacklist_file)
        self.ua_patterns = _load_patterns(CONFIG.ua_blacklist_file)
        self.asn_numbers = _load_asn_numbers(CONFIG.asn_blacklist_file)
        from .asn import get_asndb
        self.asndb = get_asndb() if self.asn_numbers else None

    def ip_hit(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if any(addr in net for net in self.ip_nets):
            return True
        # ASxxxx 黑名单: 用 ASN 库解析该 IP 的 ASN 号比对
        if self.asndb is not None and self.asn_numbers:
            asn, _ = self.asndb.lookup(ip)
            if asn and asn in self.asn_numbers:
                return True
        return False

    def ua_hit(self, ua: str) -> bool:
        ua = ua or ""
        return any(re.search(p, ua, re.IGNORECASE) for p in self.ua_patterns)


class UaClassifier:
    def __init__(self, clients_file: Optional[str] = None):
        self.client_patterns = _load_patterns(clients_file or CONFIG.ua_clients_file)

    def classify(self, ua: str) -> UaInfo:
        ua = ua or ""
        name = None
        for pat in self.client_patterns:
            if re.search(pat, ua, re.IGNORECASE):
                name = pat
                break
        is_client = name is not None
        is_tool = bool(_TOOL_UA.search(ua)) or ua.strip() in ("", "-")
        if is_client:
            # 命中客户端名则不算工具; UA↔指纹矛盾留给 TLS 指纹层(增量5)
            is_tool = False
        return UaInfo(raw=ua, is_client=is_client, is_tool=is_tool, client_name=name)
