// client_ip 提取、去端口、合法性校验、私有/保留地址判定。
import ipaddr from 'ipaddr.js';

// 把 "ip:port" / "[ipv6]:port" / 裸 ip 归一化为裸 ip。
// Node 的 socket.remoteAddress 是裸 ip（不含端口），但反代传入的
// X-Forwarded-For / 手工构造场景可能带端口，这里统一处理。
export function stripPort(addr) {
  if (!addr) return '';
  let s = String(addr).trim();
  // IPv6 带端口: [::1]:1234
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    if (end !== -1) return s.slice(1, end);
    return s;
  }
  // 纯 IPv6（含多个冒号且无方括号）保持原样
  const colonCount = (s.match(/:/g) || []).length;
  if (colonCount > 1) return s;
  // IPv4 或 IPv4:port
  if (colonCount === 1) return s.split(':')[0];
  return s;
}

// 归一化 IPv4-mapped IPv6（::ffff:1.2.3.4 -> 1.2.3.4），便于统一比对。
export function normalizeIp(addr) {
  const s = stripPort(addr);
  if (!s) return '';
  try {
    let parsed = ipaddr.parse(s);
    if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) {
      parsed = parsed.toIPv4Address();
    }
    return parsed.toNormalizedString();
  } catch {
    return '';
  }
}

export function isValidIp(addr) {
  const s = stripPort(addr);
  return s !== '' && ipaddr.isValid(s);
}

// 私有 / 保留地址：RFC1918、loopback、link-local、CGNAT 100.64/10、
// IPv6 ULA(fc00::/7)、未指定地址等。ipaddr.js 的 range() 覆盖这些类别。
const PRIVATE_RANGES = new Set([
  'private',
  'loopback',
  'linkLocal',
  'uniqueLocal',
  'carrierGradeNat',
  'unspecified',
  'reserved',
  'broadcast',
]);

export function isPrivateOrReserved(addr) {
  const s = stripPort(addr);
  if (!s) return false;
  try {
    const parsed = ipaddr.parse(s);
    return PRIVATE_RANGES.has(parsed.range());
  } catch {
    return false;
  }
}
