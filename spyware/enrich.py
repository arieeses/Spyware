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
        self.proxy_nets = _load_cidrs(CONFIG.proxy_ips_file)   # 反代/中转也算自有设备
        self.hosting_nets = _load_cidrs(hosting_file or CONFIG.hosting_cidrs_file)
        from .asn import get_asndb
        self.asndb = get_asndb()  # 缓存单例; 无库时为 None

    def is_self_ip(self, ip: str) -> bool:
        """自有设备 IP: 自有基础设施名单 / 反代中转名单 / 内网。"""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if any(addr in n for n in self.self_nets) or any(addr in n for n in self.proxy_nets):
            return True
        return addr.is_private

    def classify(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "unknown"
        # 显式名单优先于 is_private(TEST-NET 等特殊段会被 is_private 误判)
        for net in self.self_nets:
            if addr in net:
                return "self"
        for net in self.proxy_nets:
            if addr in net:
                return "self"   # 反代/中转 IP 视为自有设备
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


class FeatureLib:
    """特征库匹配器: IP/CIDR、UA(正则/子串)、ASN 号、邮箱(子串)。命中即算特征命中。
    默认从手工「特征库」(signatures)加载; from_insiders() 从「内鬼库」账号快照加载。"""

    def __init__(self, store=None, _rows=None):
        self.ip_nets: List = []
        self.ua_pats: List[str] = []
        self.asns = set()
        self.emails: List[str] = []
        self.exempt_nets = _load_cidrs(CONFIG.self_ips_file) + _load_cidrs(CONFIG.proxy_ips_file)
        if _rows is None:
            try:
                _rows = [(r["kind"], r["value"]) for r in store.list_signatures()]
            except Exception:  # noqa: BLE001
                _rows = []
        for k, v in _rows:
            v = str(v if v is not None else "").strip()   # ASN 是 int, 先转字符串
            if not v:
                continue
            self._add(k, v)
        self.empty = not (self.ip_nets or self.ua_pats or self.asns or self.emails)

    def _add(self, k, v):
        if k == "ip":
            try:
                self.ip_nets.append(ipaddress.ip_network(v, strict=False))
            except ValueError:
                pass
        elif k == "ua":
            self.ua_pats.append(v)
        elif k == "asn":
            vv = str(v).lower().lstrip("a").lstrip("s")
            if vv.isdigit():
                self.asns.add(int(vv))
        elif k == "email":
            self.emails.append(str(v).lower())

    @classmethod
    def from_insiders(cls, store):
        """从内鬼库账号的快照特征(ips/uas/asns/emails)构建匹配器。"""
        import json as _json
        rows = []
        try:
            insiders = store.list_insiders()
        except Exception:  # noqa: BLE001
            insiders = []
        for r in insiders:
            for ip in _json.loads(r["ips"] or "[]"):
                rows.append(("ip", ip))
            for ua in _json.loads(r["uas"] or "[]"):
                rows.append(("ua", "^" + re.escape(ua) + "$"))   # 精确整串匹配, 避免 clash 等泛化 UA 误伤
            for asn in _json.loads(r["asns"] or "[]"):
                rows.append(("asn", asn))
            if r["email"]:
                rows.append(("email", r["email"]))
        return cls(_rows=rows)

    def match(self, ips, uas, email, asndb=None) -> str:
        """返回命中的具体特征(逗号分隔, 列出全部命中项; 空串=未命中)。"""
        if self.empty:
            return ""
        hits = []

        def add(lab):
            if lab not in hits:
                hits.append(lab)

        for ip in ips or ():
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(addr in n for n in self.exempt_nets):
                continue   # 自有IP/反代IP 不参与特征库匹配
            for n in self.ip_nets:
                if addr in n:
                    add(f"IP {ip}" if n.num_addresses == 1 else f"IP段 {n}")
            if self.asns and asndb is not None:
                asn, _ = asndb.lookup(ip)
                if asn in self.asns:
                    add(f"AS{asn}")
        for ua in uas or ():
            for p in self.ua_pats:
                try:
                    hit = bool(re.search(p, ua or "", re.IGNORECASE))
                except re.error:
                    hit = p.lower() in (ua or "").lower()
                if hit:
                    add(f"UA {p}")
        if email:
            el = email.lower()
            for e in self.emails:
                if e in el:
                    add(f"邮箱 {e}")
        if len(hits) > 8:
            hits = hits[:8] + [f"…等{len(hits)}项"]
        return ", ".join(hits)

    def match_kinds(self, ips, uas, email, asndb=None) -> set:
        """返回命中的特征"类型"集合: {'ip','subnet','asn','ua','email'} 的子集。供自动入库规则判定。
        ip=精确IP(/32 单址命中); subnet=网段(CIDR 段命中)。"""
        kinds = set()
        if self.empty:
            return kinds
        for ip in ips or ():
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(addr in n for n in self.exempt_nets):
                continue   # 自有IP/反代IP 不算命中
            for n in self.ip_nets:
                if addr in n:
                    kinds.add("ip" if n.num_addresses == 1 else "subnet")
            if "asn" not in kinds and self.asns and asndb is not None:
                asn, _ = asndb.lookup(ip)
                if asn in self.asns:
                    kinds.add("asn")
        if "ua" not in kinds:
            for ua in uas or ():
                for p in self.ua_pats:
                    try:
                        hit = bool(re.search(p, ua or "", re.IGNORECASE))
                    except re.error:
                        hit = p.lower() in (ua or "").lower()
                    if hit:
                        kinds.add("ua")
                        break
                if "ua" in kinds:
                    break
        if email:
            el = email.lower()
            if any(e in el for e in self.emails):
                kinds.add("email")
        return kinds


class InsiderMatcher:
    """内鬼库分维度匹配: 精确IP / 同网段 / 同ASN / 同UA / 邮箱前缀 / 行为模式相似。
    数据来自内鬼库(已确认账号快照的 ips/uas/asns/email/tags)。"""

    def __init__(self, store, subnet_prefix: int = 24):
        import json as _json
        self.ips = set()
        self.subnets: List = []
        self.asns = set()
        self.uas = set()
        self.prefixes = set()
        self.tag_sets: List = []
        try:
            rows = store.list_insiders()
        except Exception:  # noqa: BLE001
            rows = []
        for r in rows:
            keys = r.keys()
            for ip in _json.loads(r["ips"] or "[]"):
                self.ips.add(ip)
                try:
                    self.subnets.append(ipaddress.ip_network(f"{ip}/{subnet_prefix}", strict=False))
                except ValueError:
                    pass
            for ua in _json.loads(r["uas"] or "[]"):
                if ua:
                    self.uas.add(ua)
            for a in _json.loads(r["asns"] or "[]"):
                try:
                    self.asns.add(int(a))
                except (ValueError, TypeError):
                    pass
            if r["email"] and "@" in r["email"]:
                self.prefixes.add(r["email"].split("@")[0].lower())
            if "tags" in keys and r["tags"]:
                try:
                    ts = _json.loads(r["tags"])
                    if ts:
                        self.tag_sets.append(frozenset(ts))
                except (ValueError, TypeError):
                    pass
        self.empty = not (self.ips or self.asns or self.uas or self.prefixes or self.tag_sets)

    def hit_ip(self, ips) -> bool:
        return any(ip in self.ips for ip in (ips or ()))

    def hit_subnet(self, ips) -> bool:
        for ip in (ips or ()):
            if ip in self.ips:
                continue   # 精确的归「同IP」, 不重复计
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(addr in n for n in self.subnets):
                return True
        return False

    def hit_asn(self, ips, asndb) -> bool:
        if not self.asns or asndb is None:
            return False
        for ip in (ips or ()):
            asn, _ = asndb.lookup(ip)
            if asn and asn in self.asns:
                return True
        return False

    def hit_ua(self, uas) -> bool:
        return any(u in self.uas for u in (uas or ()))

    def hit_prefix(self, email) -> bool:
        if not email or "@" not in email:
            return False
        return email.split("@")[0].lower() in self.prefixes

    def pattern_shared(self, tags) -> int:
        """与某个内鬼共享的信号标签数(取最大)。"""
        if not self.tag_sets or not tags:
            return 0
        mine = set(tags)
        return max((len(mine & ts) for ts in self.tag_sets), default=0)


class UaClassifier:
    def __init__(self, clients_file: Optional[str] = None):
        self.client_patterns = _load_patterns(clients_file or CONFIG.ua_clients_file)
        self.self_patterns = _load_patterns(CONFIG.ua_self_file)   # 自有UA(你自己的工具)

    def is_self(self, ua: str) -> bool:
        """自有 UA: 命中自有UA名单(你自己的抓取/监控工具), 不参与评分。"""
        ua = ua or ""
        return any(re.search(p, ua, re.IGNORECASE) for p in self.self_patterns)

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
