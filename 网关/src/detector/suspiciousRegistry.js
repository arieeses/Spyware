import ipaddr from 'ipaddr.js';
import { CidrSet } from './cidr.js';
import { logger } from '../logger.js';

function normalizeIpOrCidr(value) {
  const text = String(value || '').trim();
  if (!text) throw new Error('ip_or_cidr required');
  try {
    if (text.includes('/')) ipaddr.parseCIDR(text);
    else ipaddr.parse(text);
  } catch {
    throw new Error(`invalid ip_or_cidr: ${value}`);
  }
  return text;
}

function normalizeClickHouseUrl(url) {
  return String(url || '').replace(/\/+$/, '');
}

function authHeaders(ch) {
  const headers = {};
  if (ch.username || ch.password) {
    headers.authorization = `Basic ${Buffer.from(`${ch.username || ''}:${ch.password || ''}`).toString('base64')}`;
  }
  return headers;
}

async function clickhouseRequest(ch, query, body = null) {
  if (!ch.url) throw new Error('clickhouse.url required');
  const url = `${normalizeClickHouseUrl(ch.url)}/?query=${encodeURIComponent(query)}`;
  const headers = { ...authHeaders(ch) };
  if (body != null) headers['content-type'] = 'application/x-ndjson';
  const resp = await fetch(url, { method: 'POST', headers, body });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`clickhouse request failed: ${resp.status} ${text.slice(0, 300)}`);
  }
  return resp.text();
}

function buildSet(entries) {
  const cidr = new CidrSet();
  for (const entry of entries) cidr.addIpOrCidr(entry.ip_or_cidr);
  return cidr;
}

export class SuspiciousIpRegistry {
  constructor(config = {}) {
    this.config = config || {};
    this.entries = [];
    this.cidr = new CidrSet();
  }

  static async load(config = {}) {
    const registry = new SuspiciousIpRegistry(config);
    await registry.refresh();
    return registry;
  }

  get enabled() {
    return this.config.enabled === true;
  }

  get clickhouse() {
    return this.config.clickhouse || {};
  }

  get table() {
    const ch = this.clickhouse;
    const database = ch.database || 'sub_gateway';
    const table = this.config.table || ch.suspicious_table || 'global_suspicious_ips';
    return `${database}.${table}`;
  }

  async refresh() {
    if (!this.enabled) return;
    try {
      const query = `
SELECT ip_or_cidr, any(reason) AS reason, any(note) AS note, any(added_by) AS added_by
FROM ${this.table}
WHERE enabled = 1 AND (expires_at IS NULL OR expires_at > now64(3))
GROUP BY ip_or_cidr
FORMAT JSONEachRow`;
      const text = await clickhouseRequest(this.clickhouse, query);
      this.entries = text.split(/\r?\n/)
        .filter(Boolean)
        .map((line) => JSON.parse(line));
      this.cidr = buildSet(this.entries);
      logger.info({ msg: 'suspicious_ip_registry_loaded', count: this.entries.length });
    } catch (err) {
      logger.warn({ msg: 'suspicious_ip_registry_load_failed', error: err.message });
    }
  }

  match(ip) {
    const hit = this.cidr.match(ip);
    if (!hit) return null;
    return this.entries.find((entry) => entry.ip_or_cidr === hit) || { ip_or_cidr: hit, reason: 'manual_suspicious', note: '' };
  }

  list() {
    return [...this.entries];
  }

  async add({ ip_or_cidr, reason = 'manual_suspicious', note = '', added_by = 'internal', expires_at = null }) {
    const normalized = normalizeIpOrCidr(ip_or_cidr);
    const entry = {
      ip_or_cidr: normalized,
      reason: String(reason || 'manual_suspicious'),
      note: String(note || ''),
      added_by: String(added_by || 'internal'),
      added_at: new Date().toISOString().replace('T', ' ').replace('Z', ''),
      expires_at: expires_at || null,
      enabled: 1,
    };
    if (this.enabled) {
      const body = JSON.stringify(entry) + '\n';
      await clickhouseRequest(this.clickhouse, `INSERT INTO ${this.table} FORMAT JSONEachRow`, body);
    }
    this.entries = this.entries.filter((item) => item.ip_or_cidr !== normalized);
    this.entries.push(entry);
    this.cidr = buildSet(this.entries);
    return entry;
  }

  async remove(ip_or_cidr) {
    const normalized = normalizeIpOrCidr(ip_or_cidr);
    if (this.enabled) {
      await clickhouseRequest(this.clickhouse, `ALTER TABLE ${this.table} DELETE WHERE ip_or_cidr = '${normalized.replace(/'/g, "\\'")}'`);
    }
    this.entries = this.entries.filter((item) => item.ip_or_cidr !== normalized);
    this.cidr = buildSet(this.entries);
    return { ip_or_cidr: normalized, removed: true };
  }
}
