// GeoLite2 ASN 本地查询。启动时同步加载 mmdb，每次请求仅本地查询。
import maxmind from 'maxmind';
import { stripPort } from './ip.js';

export class GeoIp {
  // reader: maxmind Reader; blockAsns: Set<number>; keywords: string[](已小写)
  constructor(reader, blockAsns, keywords) {
    this.reader = reader;
    this.blockAsns = blockAsns;
    this.keywords = keywords;
  }

  static async load(dbPath, blockAsns = [], blockKeywords = []) {
    const reader = await maxmind.open(dbPath);
    return new GeoIp(
      reader,
      new Set((blockAsns || []).map((n) => Number(n)).filter(Number.isInteger)),
      (blockKeywords || []).map((k) => String(k).toLowerCase()),
    );
  }

  // 返回 { asn, org }，查询不到返回 { asn: null, org: '' }。
  lookup(clientIp) {
    const s = stripPort(clientIp);
    if (!s) return { asn: null, org: '' };
    const rec = this.reader.get(s);
    if (!rec) return { asn: null, org: '' };
    return {
      asn: rec.autonomous_system_number ?? null,
      org: rec.autonomous_system_organization ?? '',
    };
  }

  // 判断是否命中拦截：优先 ASN 号码，其次组织名关键词。
  // 返回 { blocked, asn, org, reason }
  check(clientIp) {
    const { asn, org } = this.lookup(clientIp);
    if (asn != null && this.blockAsns.has(Number(asn))) {
      return { blocked: true, asn, org, reason: 'asn_number' };
    }
    if (org) {
      const lower = org.toLowerCase();
      for (const kw of this.keywords) {
        if (kw && lower.includes(kw)) {
          return { blocked: true, asn, org, reason: 'asn_keyword' };
        }
      }
    }
    return { blocked: false, asn, org, reason: '' };
  }
}
