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
    """返回 self / hosting / residential / unknown。"""

    def __init__(self, self_file: Optional[str] = None, hosting_file: Optional[str] = None):
        self.self_nets = _load_cidrs(self_file or CONFIG.self_ips_file)
        self.hosting_nets = _load_cidrs(hosting_file or CONFIG.hosting_cidrs_file)

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
        if addr.is_private:
            return "self"  # 内网视为自有基础设施
        return "residential"  # 名单外默认住宅(生产用 ASN 库精确化)


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


class Blacklist:
    """IP/ASN(CIDR)与 UA(正则)黑名单。命中即高危。"""

    def __init__(self):
        # ASN 黑名单文件里的 CIDR 也并入 IP 网段匹配; 纯 ASxxxx 号需 GeoLite2 才生效
        self.ip_nets = _load_cidrs(CONFIG.ip_blacklist_file) + _load_cidrs(CONFIG.asn_blacklist_file)
        self.ua_patterns = _load_patterns(CONFIG.ua_blacklist_file)

    def ip_hit(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.ip_nets)

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
