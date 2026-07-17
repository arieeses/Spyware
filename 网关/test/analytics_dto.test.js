import { test } from 'node:test';
import assert from 'node:assert/strict';
import { accessRecordDto, globalIpDto, ipTokenGraphDto, relatedIpDto, riskSummaryDto, suspiciousIpDto, tokenEdgeDto } from '../src/analytics/dto.js';

test('tokenEdgeDto normalizes numeric fields', () => {
  const dto = tokenEdgeDto({ token_hash: 'abc', hits: '12', suspicious_hits: '3' });
  assert.deepEqual(dto, {
    token_hash: 'abc',
    first_seen: '',
    last_seen: '',
    hits: 12,
    suspicious_hits: 3,
  });
});

test('relatedIpDto normalizes arrays and counters', () => {
  const dto = relatedIpDto({ client_ip: '1.1.1.1', shared_tokens: '2', token_hashes: ['a', '', 'b'], seed_ips: '8.8.8.8' });
  assert.equal(dto.shared_tokens, 2);
  assert.deepEqual(dto.token_hashes, ['a', 'b']);
  assert.deepEqual(dto.seed_ips, ['8.8.8.8']);
});

test('ipTokenGraphDto normalizes reverse token graph rows', () => {
  const dto = ipTokenGraphDto({ token_hash: 'abc', seed_hits: '2', ip_count: '3', hits: '8', other_ips: ['1.1.1.1', '', '2.2.2.2'] });
  assert.equal(dto.seed_hits, 2);
  assert.equal(dto.ip_count, 3);
  assert.equal(dto.hits, 8);
  assert.deepEqual(dto.other_ips, ['1.1.1.1', '2.2.2.2']);
});

test('accessRecordDto preserves raw access fields', () => {
  const dto = accessRecordDto({
    ts: '2026-07-16 03:10:00.000',
    tenant_id: '0318',
    host: 'test.0318.cyou',
    origin_base_url: 'https://ep.0318.cyou',
    token_raw: 'raw-token',
    token_hash: 'abc',
    client_ip: '47.243.132.26',
    risk_level: '1',
    is_suspicious: '1',
    user_agent: 'Shadowrocket',
  });
  assert.equal(dto.tenant_id, '0318');
  assert.equal(dto.token_raw, 'raw-token');
  assert.equal(dto.risk_level, 1);
  assert.equal(dto.is_suspicious, 1);
  assert.equal(dto.user_agent, 'Shadowrocket');
});

test('suspiciousIpDto cleans reasons and assigns risk level', () => {
  const dto = suspiciousIpDto({ client_ip: '8.8.8.8', reasons: ['cidr', 'cidr', 'geoip_asn'], hits: '5' }, 1);
  assert.equal(dto.risk_level, 1);
  assert.equal(dto.hits, 5);
  assert.deepEqual(dto.reasons, ['cidr', 'geoip_asn']);
});

test('globalIpDto returns empty profile for missing row', () => {
  const dto = globalIpDto(null, '1.1.1.1');
  assert.equal(dto.client_ip, '1.1.1.1');
  assert.equal(dto.hits, 0);
});

test('riskSummaryDto preserves level buckets', () => {
  const dto = riskSummaryDto({
    level1: [{ client_ip: '8.8.8.8', hits: '1' }],
    level2: [{ client_ip: '1.1.1.1', shared_tokens: '1' }],
    level3: [{ client_ip: '2.2.2.2', shared_tokens: '3' }],
  });
  assert.equal(dto.level1[0].risk_level, 1);
  assert.equal(dto.level2[0].shared_tokens, 1);
  assert.equal(dto.level3[0].shared_tokens, 3);
});
