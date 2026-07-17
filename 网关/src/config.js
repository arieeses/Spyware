// 鍔犺浇涓庢牎楠?config.yaml銆傛牎楠屽け璐ユ姏閿欙紝鐢卞叆鍙?fail-fast銆?
import fs from 'node:fs';
import yaml from 'js-yaml';
import ipaddr from 'ipaddr.js';
import { validateAndNormalizeNodes } from './gateway/nodes.js';
import { normalizeAnalyticsPaths } from './analytics/pathFilter.js';

function fail(msg) {
  throw new Error(`config invalid: ${msg}`);
}

function isValidCidrOrIp(text) {
  const s = String(text).trim();
  try {
    if (s.includes('/')) ipaddr.parseCIDR(s);
    else ipaddr.parse(s);
    return true;
  } catch {
    return false;
  }
}

function normalizeId(text, ctx) {
  const s = String(text || '').trim();
  if (!s || !/^[a-zA-Z0-9_.:-]+$/.test(s)) fail(`${ctx} invalid id: ${text}`);
  return s;
}

export function loadConfig(path) {
  let raw;
  try {
    raw = fs.readFileSync(path, 'utf8');
  } catch (err) {
    fail(`cannot read ${path}: ${err.message}`);
  }
  let cfg;
  try {
    cfg = yaml.load(raw);
  } catch (err) {
    fail(`yaml parse error: ${err.message}`);
  }
  if (!cfg || typeof cfg !== 'object') fail('empty or non-object config');

  const server = cfg.server || {};

  // 榛樿鍊?
  server.reject_direct_access = server.reject_direct_access !== false;
  server.origin_timeout_seconds = server.origin_timeout_seconds || 10;
  server.max_origin_response_bytes = server.max_origin_response_bytes || 5 * 1024 * 1024;
  server.allowed_methods = (server.allowed_methods || ['GET', 'HEAD']).map((m) => String(m).toUpperCase());
  server.tls = server.tls || { enabled: false };

  // 鏍￠獙 TLS 閰嶇疆骞舵鏌ヨ瘉涔︽枃浠跺瓨鍦ㄦ€?
  function normTls(tls, ctx) {
    const t = tls || { enabled: false };
    if (t.enabled) {
      if (!t.cert_path || !t.key_path) fail(`${ctx}: tls.cert_path/key_path required when tls enabled`);
      if (!fs.existsSync(t.cert_path)) fail(`${ctx}: tls cert not found: ${t.cert_path}`);
      if (!fs.existsSync(t.key_path)) fail(`${ctx}: tls key not found: ${t.key_path}`);
    }
    return t;
  }
  // 灞曞紑鐩戝惉鍦板潃锛氭敮鎸佺鍙ｅ尯闂?"host:START-END" -> 澶氫釜鍏蜂綋鍦板潃
  //   "0.0.0.0:36001-36008" -> 8 涓湴鍧€
  //   "0.0.0.0:8443"        -> 1 涓湴鍧€
  function expandAddrs(addr, ctx) {
    if (typeof addr !== 'string' || !addr.includes(':')) fail(`${ctx}: invalid listen addr: ${addr}`);
    const idx = addr.lastIndexOf(':');
    const host = addr.slice(0, idx);
    const portPart = addr.slice(idx + 1);
    if (!portPart.includes('-')) {
      const p = parseInt(portPart, 10);
      // 0 = 鐢辩郴缁熻嚜鍔ㄥ垎閰嶇┖闂茬鍙ｏ紙鍚堟硶鐗规畩鍊硷級
      if (!Number.isInteger(p) || p < 0 || p > 65535) fail(`${ctx}: invalid port: ${portPart}`);
      return [`${host}:${p}`];
    }
    const [a, b] = portPart.split('-');
    const start = parseInt(a, 10);
    const end = parseInt(b, 10);
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end > 65535 || start > end) {
      fail(`${ctx}: invalid port range: ${portPart}`);
    }
    if (end - start > 1024) fail(`${ctx}: port range too large (>1024): ${portPart}`);
    const out = [];
    for (let p = start; p <= end; p++) out.push(`${host}:${p}`);
    return out;
  }

  // 褰掍竴鍖栫洃鍚櫒鍒楄〃 -> server._listeners = [{ addr, tls }]
  // 鏀寔鍐欐硶:
  //   1) listen: "0.0.0.0:8080"                     鍗曠鍙? 鐢?server.tls
  //   2) listen: ["0.0.0.0:80", "0.0.0.0:443"]      澶氱鍙? 鍏辩敤 server.tls
  //   3) listen: "0.0.0.0:36001-36008"              绔彛鍖洪棿, 鍏辩敤 server.tls
  //   4) listeners: [{addr, tls}, ...]              姣忎釜鍙嫭绔?TLS, addr 涔熸敮鎸佸尯闂?
  const listeners = [];
  const seen = new Set();
  const addEntry = (addr, tls, ctx) => {
    for (const a of expandAddrs(addr, ctx)) {
      if (seen.has(a)) fail(`${ctx}: duplicate listen addr: ${a}`);
      seen.add(a);
      listeners.push({ addr: a, tls });
    }
  };
  if (Array.isArray(server.listeners) && server.listeners.length) {
    server.listeners.forEach((l, i) => {
      const addr = typeof l === 'string' ? l : l.addr;
      const tls = normTls(typeof l === 'string' ? server.tls : (l.tls || server.tls), `server.listeners[${i}]`);
      addEntry(addr, tls, `server.listeners[${i}]`);
    });
  } else if (Array.isArray(server.listen) && server.listen.length) {
    const tls = normTls(server.tls, 'server.listen');
    server.listen.forEach((addr, i) => addEntry(addr, tls, `server.listen[${i}]`));
  } else if (typeof server.listen === 'string') {
    addEntry(server.listen, normTls(server.tls, 'server.listen'), 'server.listen');
  } else {
    fail('server.listen or server.listeners required');
  }
  server._listeners = listeners;

  // 鍐呴儴鎺ュ彛
  if (server.internal_listen && server.reload_token && String(server.reload_token).includes('CHANGE_ME')) {
    // 浠呰鍛婄骇鍒紝涓嶉樆鏂惎鍔紱鐪熸閮ㄧ讲搴旀浛鎹?
  }

  // trusted_proxies
  const trusted = cfg.trusted_proxies || [];
  if (!Array.isArray(trusted)) fail('trusted_proxies must be a list');
  for (const t of trusted) {
    if (!isValidCidrOrIp(t)) fail(`trusted_proxies invalid entry: ${t}`);
  }

  // origins
  const origins = cfg.origins || {};
  if (typeof origins !== 'object') fail('origins must be a map');
  for (const [host, o] of Object.entries(origins)) {
    if (!o || !o.base_url) fail(`origins.${host}.base_url required`);
    o.tenant_id = normalizeId(o.tenant_id || host, `origins.${host}.tenant_id`);
    try {
      const u = new URL(o.base_url);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') fail(`origins.${host}.base_url must be http/https`);
    } catch {
      fail(`origins.${host}.base_url invalid url: ${o.base_url}`);
    }
    if (o.decoy_host != null) {
      const decoyHost = String(o.decoy_host).trim();
      if (!decoyHost || /[/?#@]/.test(decoyHost)) fail(`origins.${host}.decoy_host invalid host: ${o.decoy_host}`);
      o.decoy_host = decoyHost;
    }
    try {
      o.analytics_paths = normalizeAnalyticsPaths(o.analytics_paths, `origins.${host}.analytics_paths`);
    } catch (err) {
      fail(err.message);
    }
  }

  // allowlist
  const allow = cfg.allowlist || {};
  for (const ip of allow.ips || []) if (!isValidCidrOrIp(ip)) fail(`allowlist.ips invalid: ${ip}`);
  for (const c of allow.cidrs || []) if (!isValidCidrOrIp(c)) fail(`allowlist.cidrs invalid: ${c}`);
  for (const a of allow.asns || []) if (!Number.isInteger(Number(a))) fail(`allowlist.asns invalid: ${a}`);

  // cloud_detection
  const cd = cfg.cloud_detection || {};
  const geo = cd.geoip || {};
  if (geo.enabled) {
    if (!geo.db_path) fail('cloud_detection.geoip.db_path required when enabled');
    if (!fs.existsSync(geo.db_path)) fail(`geoip db not found: ${geo.db_path}`);
  }
  const cidr = cd.cidr || {};
  if (cidr.enabled) {
    for (const f of cidr.files || []) {
      if (!fs.existsSync(f)) fail(`cidr file not found: ${f}`);
    }
  }

  // 鍏跺畠榛樿
  cfg.origin_failure_mode = cfg.origin_failure_mode === 'error' ? 'error' : 'fake';
  cfg.private_ip_decision = ['proxy', 'allowlist', 'fake'].includes(cfg.private_ip_decision)
    ? cfg.private_ip_decision
    : 'fake';
  cfg.rate_limit = cfg.rate_limit || { enabled: false };
  cfg.fake_latency = cfg.fake_latency || { enabled: false };
  cfg.fake_subscription = cfg.fake_subscription || {};
  // 鐪熷疄 userinfo 鎷夊彇锛堝亣鑺傜偣 + 鐪熷埌鏈?娴侀噺锛夈€傞粯璁ゅ叧闂€?
  cfg.fake_subscription.real_userinfo = cfg.fake_subscription.real_userinfo || { enabled: false };

  const analytics = cfg.analytics || {};
  analytics.enabled = analytics.enabled === true;
  analytics.flush_interval_ms = Number(analytics.flush_interval_ms || 1000);
  analytics.batch_size = Number(analytics.batch_size || 1000);
  analytics.max_queue_size = Number(analytics.max_queue_size || 100000);
  analytics.spool_dir = analytics.spool_dir || './data/analytics_spool';
  analytics.clickhouse = analytics.clickhouse || {};
  analytics.clickhouse.url = analytics.clickhouse.url || '';
  analytics.clickhouse.database = analytics.clickhouse.database || 'sub_gateway';
  analytics.clickhouse.table = analytics.clickhouse.table || 'subscription_access_events';
  analytics.clickhouse.username = analytics.clickhouse.username || '';
  analytics.clickhouse.password = analytics.clickhouse.password || '';
  if (analytics.enabled && !analytics.clickhouse.url) fail('analytics.clickhouse.url required when analytics.enabled=true');
  if (!Number.isFinite(analytics.flush_interval_ms) || analytics.flush_interval_ms < 100) fail('analytics.flush_interval_ms invalid');
  if (!Number.isInteger(analytics.batch_size) || analytics.batch_size < 1) fail('analytics.batch_size invalid');
  if (!Number.isInteger(analytics.max_queue_size) || analytics.max_queue_size < analytics.batch_size) fail('analytics.max_queue_size invalid');
  cfg.analytics = analytics;

  const suspiciousIp = cfg.suspicious_ip || {};
  suspiciousIp.enabled = suspiciousIp.enabled === true;
  suspiciousIp.refresh_interval_seconds = Number(suspiciousIp.refresh_interval_seconds || 30);
  suspiciousIp.table = suspiciousIp.table || 'global_suspicious_ips';
  suspiciousIp.clickhouse = { ...analytics.clickhouse, ...(suspiciousIp.clickhouse || {}) };
  if (suspiciousIp.enabled && !suspiciousIp.clickhouse.url) fail('suspicious_ip.clickhouse.url required when suspicious_ip.enabled=true');
  if (!Number.isFinite(suspiciousIp.refresh_interval_seconds) || suspiciousIp.refresh_interval_seconds < 1) {
    fail('suspicious_ip.refresh_interval_seconds invalid');
  }
  cfg.suspicious_ip = suspiciousIp;

  // fake_nodes 鏍￠獙 + 褰掍竴鍖栵紙绗竴鐗堝繀椤绘彁渚涳紝鐢ㄤ簬鍋囪闃呮覆鏌擄級
  try {
    cfg._fake_nodes = validateAndNormalizeNodes(cfg.fake_nodes);
  } catch (err) {
    fail(err.message);
  }

  cfg.server = server;
  cfg.trusted_proxies = trusted;
  cfg.origins = origins;
  cfg.allowlist = allow;
  cfg.cloud_detection = cd;
  cfg.analytics = analytics;
  cfg.suspicious_ip = suspiciousIp;
  return cfg;
}
