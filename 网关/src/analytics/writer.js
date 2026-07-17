import fs from 'node:fs';
import path from 'node:path';
import { logger } from '../logger.js';

const DEFAULTS = {
  enabled: false,
  flush_interval_ms: 1000,
  batch_size: 1000,
  max_queue_size: 100000,
  spool_dir: './data/analytics_spool',
};

function toClickHouseDateTime64(ms) {
  const d = new Date(ms);
  const iso = d.toISOString();
  return iso.replace('T', ' ').replace('Z', '');
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function normalizeUrl(url) {
  return String(url || '').replace(/\/+$/, '');
}

export class AnalyticsWriter {
  constructor(config = {}) {
    this.queue = [];
    this.timer = null;
    this.flushing = false;
    this.updateConfig(config);
  }

  updateConfig(config = {}) {
    const merged = { ...DEFAULTS, ...(config || {}) };
    merged.clickhouse = merged.clickhouse || {};
    this.config = merged;
    if (this.config.enabled) {
      ensureDir(this.config.spool_dir);
      this.start();
    } else {
      this.stopTimer();
    }
  }

  start() {
    if (this.timer || !this.config.enabled) return;
    this.timer = setInterval(() => {
      this.flush().catch((err) => logger.warn({ msg: 'analytics_flush_error', error: err.message }));
      this.replaySpool().catch((err) => logger.warn({ msg: 'analytics_spool_replay_error', error: err.message }));
    }, this.config.flush_interval_ms);
    this.timer.unref?.();
  }

  stopTimer() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  enqueue(event) {
    if (!this.config.enabled || !event) return false;
    if (this.queue.length >= this.config.max_queue_size) {
      logger.warn({ msg: 'analytics_queue_full', dropped: 1 });
      return false;
    }
    this.queue.push(normalizeEvent(event));
    if (this.queue.length >= this.config.batch_size) {
      this.flush().catch((err) => logger.warn({ msg: 'analytics_flush_error', error: err.message }));
    }
    return true;
  }

  async flush() {
    if (!this.config.enabled || this.flushing || this.queue.length === 0) return;
    this.flushing = true;
    const batch = this.queue.splice(0, this.config.batch_size);
    try {
      await this.writeBatch(batch);
    } catch (err) {
      this.writeSpool(batch);
      throw err;
    } finally {
      this.flushing = false;
    }
  }

  async close() {
    this.stopTimer();
    await this.flush();
  }

  async writeBatch(batch) {
    if (!batch.length) return;
    const ch = this.config.clickhouse || {};
    if (!ch.url) throw new Error('analytics clickhouse.url required');
    const database = ch.database || 'default';
    const table = ch.table || 'subscription_access_events';
    const query = `INSERT INTO ${database}.${table} FORMAT JSONEachRow`;
    const url = `${normalizeUrl(ch.url)}/?query=${encodeURIComponent(query)}`;
    const headers = { 'content-type': 'application/x-ndjson' };
    if (ch.username || ch.password) {
      headers.authorization = `Basic ${Buffer.from(`${ch.username || ''}:${ch.password || ''}`).toString('base64')}`;
    }
    const body = batch.map((e) => JSON.stringify(toClickHouseEvent(e))).join('\n') + '\n';
    const resp = await fetch(url, { method: 'POST', headers, body });
    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      throw new Error(`clickhouse insert failed: ${resp.status} ${text.slice(0, 300)}`);
    }
  }

  writeSpool(batch) {
    if (!batch.length) return;
    ensureDir(this.config.spool_dir);
    const file = path.join(this.config.spool_dir, `${Date.now()}-${process.pid}-${Math.random().toString(16).slice(2)}.jsonl`);
    const body = batch.map((e) => JSON.stringify(e)).join('\n') + '\n';
    fs.writeFileSync(file, body, 'utf8');
    logger.warn({ msg: 'analytics_spooled', file, count: batch.length });
  }

  async replaySpool() {
    if (!this.config.enabled || this.flushing) return;
    ensureDir(this.config.spool_dir);
    const files = fs.readdirSync(this.config.spool_dir)
      .filter((name) => name.endsWith('.jsonl'))
      .sort()
      .slice(0, 5);
    for (const name of files) {
      const file = path.join(this.config.spool_dir, name);
      const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean);
      const batch = lines.map((line) => JSON.parse(line));
      await this.writeBatch(batch);
      fs.unlinkSync(file);
      logger.info({ msg: 'analytics_spool_replayed', file, count: batch.length });
    }
  }
}

export function normalizeEvent(event) {
  const now = Date.now();
  return {
    ts_ms: event.ts_ms || now,
    tenant_id: event.tenant_id || '',
    host: event.host || '',
    origin_base_url: event.origin_base_url || '',
    token_raw: event.token_raw || '',
    token_hash: event.token_hash || '',
    client_ip: event.client_ip || '',
    remote_addr: event.remote_addr || '',
    decision: event.decision || '',
    risk_reason: event.risk_reason || '',
    risk_level: Number(event.risk_level || 0),
    is_suspicious: event.is_suspicious ? 1 : 0,
    flag: event.flag || '',
    client_type: event.client_type || '',
    user_agent: event.user_agent || '',
  };
}

export function toClickHouseEvent(event) {
  return {
    ts: toClickHouseDateTime64(event.ts_ms),
    tenant_id: event.tenant_id,
    host: event.host,
    origin_base_url: event.origin_base_url,
    token_raw: event.token_raw,
    token_hash: event.token_hash,
    client_ip: event.client_ip,
    remote_addr: event.remote_addr,
    decision: event.decision,
    risk_reason: event.risk_reason,
    risk_level: event.risk_level,
    is_suspicious: event.is_suspicious,
    flag: event.flag,
    client_type: event.client_type,
    user_agent: event.user_agent,
  };
}
