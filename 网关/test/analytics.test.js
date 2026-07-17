import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AnalyticsWriter, normalizeEvent, toClickHouseEvent } from '../src/analytics/writer.js';

test('normalizeEvent preserves raw token and hash fields', () => {
  const event = normalizeEvent({
    ts_ms: 1720000000123,
    tenant_id: 'site1',
    host: 'site1.example.com',
    origin_base_url: 'https://origin.example.com',
    token_raw: 'raw-token-value',
    token_hash: 'a'.repeat(64),
    client_ip: '1.2.3.4',
    remote_addr: '127.0.0.1',
    decision: 'fake_rewrite',
    risk_reason: 'cidr',
    risk_level: 1,
    is_suspicious: true,
    flag: 'clash',
    client_type: 'clash',
    user_agent: 'ua',
  });

  assert.equal(event.token_raw, 'raw-token-value');
  assert.equal(event.token_hash, 'a'.repeat(64));
  assert.equal(event.is_suspicious, 1);
});

test('toClickHouseEvent converts timestamp and keeps query fields', () => {
  const row = toClickHouseEvent(normalizeEvent({
    ts_ms: Date.UTC(2026, 0, 2, 3, 4, 5, 678),
    tenant_id: 'site1',
    token_raw: 'raw-token-value',
    token_hash: 'b'.repeat(64),
    client_ip: '2001:db8::1',
    decision: 'proxy',
  }));

  assert.equal(row.ts, '2026-01-02 03:04:05.678');
  assert.equal(row.tenant_id, 'site1');
  assert.equal(row.token_raw, 'raw-token-value');
  assert.equal(row.token_hash, 'b'.repeat(64));
  assert.equal(row.client_ip, '2001:db8::1');
});

test('disabled AnalyticsWriter does not enqueue', () => {
  const writer = new AnalyticsWriter({ enabled: false });
  assert.equal(writer.enqueue({ token_raw: 'x' }), false);
  assert.equal(writer.queue.length, 0);
});
