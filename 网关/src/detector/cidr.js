// CIDR 集合：加载/匹配 IPv4 与 IPv6 网段。用于 trusted_proxies、
// allowlist.cidrs、以及云厂商 CIDR 兜底检测。
import fs from 'node:fs';
import ipaddr from 'ipaddr.js';
import { stripPort } from './ip.js';

// 单个 CIDR 集合，v4/v6 分表。返回命中的原始 CIDR 字符串。
export class CidrSet {
  constructor() {
    this.v4 = []; // { cidr: [addr, prefix], raw }
    this.v6 = [];
  }

  addCidr(raw) {
    const text = String(raw).trim();
    if (!text || text.startsWith('#')) return false;
    let parsed;
    try {
      parsed = ipaddr.parseCIDR(text);
    } catch {
      return false;
    }
    const entry = { cidr: parsed, raw: text };
    if (parsed[0].kind() === 'ipv4') this.v4.push(entry);
    else this.v6.push(entry);
    return true;
  }

  // 同时接受单 IP（无掩码），内部按 /32 或 /128 处理。
  addIpOrCidr(raw) {
    const text = String(raw).trim();
    if (!text || text.startsWith('#')) return false;
    if (text.includes('/')) return this.addCidr(text);
    let parsed;
    try {
      parsed = ipaddr.parse(text);
    } catch {
      return false;
    }
    const prefix = parsed.kind() === 'ipv4' ? 32 : 128;
    return this.addCidr(`${text}/${prefix}`);
  }

  // 返回命中的原始 CIDR 字符串，未命中返回 null。
  match(addr) {
    const s = stripPort(addr);
    if (!s) return null;
    let ip;
    try {
      ip = ipaddr.parse(s);
    } catch {
      return null;
    }
    // 归一 IPv4-mapped
    if (ip.kind() === 'ipv6' && ip.isIPv4MappedAddress()) ip = ip.toIPv4Address();
    const list = ip.kind() === 'ipv4' ? this.v4 : this.v6;
    for (const entry of list) {
      try {
        if (ip.match(entry.cidr)) return entry.raw;
      } catch {
        // v4/v6 不匹配的 match 会抛错，跳过
      }
    }
    return null;
  }

  contains(addr) {
    return this.match(addr) !== null;
  }

  get size() {
    return this.v4.length + this.v6.length;
  }
}

// 从多个文件加载云厂商 CIDR。忽略注释/空行/非法行（记录 warn）。
export function loadCidrFiles(files, warn = () => {}) {
  const set = new CidrSet();
  for (const file of files) {
    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch (err) {
      warn({ msg: 'cidr_file_read_failed', file, error: err.message });
      continue;
    }
    let lineNo = 0;
    for (const rawLine of content.split(/\r?\n/)) {
      lineNo++;
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      if (!set.addCidr(line)) {
        warn({ msg: 'cidr_line_invalid', file, line: lineNo, value: line });
      }
    }
  }
  return set;
}
