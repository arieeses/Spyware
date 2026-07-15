"""极简 MaxMind DB(.mmdb)只读解析器 —— 纯标准库, 零依赖。

只实现查询 GeoLite2-ASN 所需的部分: 搜索树遍历 + 数据段解码(map/字符串/无符号整数/指针/数组)。
参考 MaxMind DB 文件格式规范。够用即可, 不追求覆盖全部类型。
"""
from __future__ import annotations

import ipaddress
import struct
from typing import Optional

_METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


class MMDBReader:
    def __init__(self, path: str):
        with open(path, "rb") as f:
            self._buf = f.read()
        self._meta = self._read_metadata()
        self.node_count = self._meta["node_count"]
        self.record_size = self._meta["record_size"]
        self.ip_version = self._meta["ip_version"]
        self._node_bytes = self.record_size * 2 // 8
        self._tree_size = self.node_count * self._node_bytes
        # 数据段起点 = 搜索树 + 16 字节分隔符
        self._data_start = self._tree_size + 16
        self._ipv4_start = self._find_ipv4_start()

    # —— 元数据(文件末尾, marker 之后是一段 data-section 编码的 map) ——
    def _read_metadata(self) -> dict:
        idx = self._buf.rfind(_METADATA_MARKER)
        if idx < 0:
            raise ValueError("不是有效的 mmdb 文件(缺 metadata marker)")
        val, _ = self._decode(idx + len(_METADATA_MARKER), meta=True)
        return val

    def _find_ipv4_start(self) -> int:
        """ipv6 库里 ipv4 从 ::/96 之后开始; 预走 96 个 0-bit 找到起点节点。"""
        if self.ip_version == 4:
            return 0
        node = 0
        for _ in range(96):
            if node >= self.node_count:
                break
            node = self._read_node(node, 0)
        return node

    # —— 搜索树 ——
    def _read_node(self, node: int, index: int) -> int:
        base = node * self._node_bytes
        b = self._buf
        rs = self.record_size
        if rs == 24:
            off = base + index * 3
            return (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]
        if rs == 28:
            if index == 0:
                return ((b[base + 3] & 0xF0) << 20) | (b[base] << 16) | (b[base + 1] << 8) | b[base + 2]
            return ((b[base + 3] & 0x0F) << 24) | (b[base + 4] << 16) | (b[base + 5] << 8) | b[base + 6]
        if rs == 32:
            off = base + index * 4
            return struct.unpack(">I", b[off:off + 4])[0]
        raise ValueError(f"不支持的 record_size: {rs}")

    def get(self, ip: str) -> Optional[dict]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version == 4:
            bits = 32
            node = self._ipv4_start
            packed = int(addr)
        else:
            bits = 128
            node = 0
            packed = int(addr)
        for i in range(bits - 1, -1, -1):
            if node >= self.node_count:
                break
            bit = (packed >> i) & 1
            node = self._read_node(node, bit)
        if node == self.node_count:
            return None                    # 空记录
        if node > self.node_count:
            # 指向数据段: 绝对偏移 = (node - node_count) + tree_size
            offset = (node - self.node_count) + self._tree_size
            val, _ = self._decode(offset)
            return val
        return None

    # —— 数据段解码 ——
    def _decode(self, offset: int, meta: bool = False):
        b = self._buf
        ctrl = b[offset]
        offset += 1
        dtype = ctrl >> 5
        if dtype == 0:  # 扩展类型
            dtype = 7 + b[offset]
            offset += 1
        # 指针(在 metadata 解码时指针基准同样是数据段起点; metadata 场景不会用到)
        if dtype == 1:
            return self._decode_pointer(ctrl, offset)
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + b[offset]; offset += 1
        elif size == 30:
            size = 285 + ((b[offset] << 8) | b[offset + 1]); offset += 2
        elif size == 31:
            size = 65821 + ((b[offset] << 16) | (b[offset + 1] << 8) | b[offset + 2]); offset += 3
        if dtype == 2:  # utf8 字符串
            return b[offset:offset + size].decode("utf-8", "replace"), offset + size
        if dtype == 5:  # uint16
            return int.from_bytes(b[offset:offset + size], "big"), offset + size
        if dtype == 6:  # uint32
            return int.from_bytes(b[offset:offset + size], "big"), offset + size
        if dtype == 7:  # map
            out = {}
            for _ in range(size):
                k, offset = self._decode(offset)
                v, offset = self._decode(offset)
                out[k] = v
            return out, offset
        if dtype == 11:  # array
            arr = []
            for _ in range(size):
                v, offset = self._decode(offset)
                arr.append(v)
            return arr, offset
        if dtype in (9, 10):  # uint64 / uint128
            return int.from_bytes(b[offset:offset + size], "big"), offset + size
        if dtype == 8:  # int32
            return int.from_bytes(b[offset:offset + size], "big", signed=True), offset + size
        if dtype == 14:  # boolean
            return bool(size), offset
        if dtype == 15:  # float
            return struct.unpack(">f", b[offset:offset + size])[0], offset + size
        if dtype == 3:  # double
            return struct.unpack(">d", b[offset:offset + size])[0], offset + size
        # bytes(4) 等其余类型: 原样返回
        return b[offset:offset + size], offset + size

    def _decode_pointer(self, ctrl: int, offset: int):
        b = self._buf
        psize = (ctrl >> 3) & 0x3
        if psize == 0:
            pval = ((ctrl & 0x7) << 8) | b[offset]; offset += 1
        elif psize == 1:
            pval = ((ctrl & 0x7) << 16) | (b[offset] << 8) | b[offset + 1]; offset += 2
            pval += 2048
        elif psize == 2:
            pval = ((ctrl & 0x7) << 24) | (b[offset] << 16) | (b[offset + 1] << 8) | b[offset + 2]; offset += 3
            pval += 526336
        else:
            pval = struct.unpack(">I", b[offset:offset + 4])[0]; offset += 4
        target = self._data_start + pval
        val, _ = self._decode(target)
        return val, offset
