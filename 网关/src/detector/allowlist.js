// 白名单：ip / cidr / asn 任一命中即永远返回真订阅。
import { CidrSet } from './cidr.js';
import { normalizeIp } from './ip.js';

export class Allowlist {
  constructor({ ips = [], cidrs = [], asns = [] } = {}) {
    this.ipSet = new Set();
    for (const ip of ips) {
      const norm = normalizeIp(ip);
      if (norm) this.ipSet.add(norm);
    }
    this.cidrSet = new CidrSet();
    for (const c of cidrs) this.cidrSet.addIpOrCidr(c);
    this.asnSet = new Set((asns || []).map((n) => Number(n)).filter((n) => Number.isInteger(n)));
  }

  // 返回命中说明字符串（用于日志），未命中返回 null。
  match(clientIp, asn) {
    const norm = normalizeIp(clientIp);
    if (norm && this.ipSet.has(norm)) return `ip:${norm}`;
    const cidrHit = this.cidrSet.match(clientIp);
    if (cidrHit) return `cidr:${cidrHit}`;
    if (asn != null && this.asnSet.has(Number(asn))) return `asn:${asn}`;
    return null;
  }
}
