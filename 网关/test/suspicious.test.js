import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SuspiciousIpRegistry } from '../src/detector/suspiciousRegistry.js';
import { decide } from '../src/gateway/decision.js';
import { Allowlist } from '../src/detector/allowlist.js';

test('SuspiciousIpRegistry add/remove updates memory matches', async () => {
  const registry = new SuspiciousIpRegistry({ enabled: false });
  await registry.add({ ip_or_cidr: '8.8.8.0/24', reason: 'manual_suspicious', note: 'test' });

  assert.equal(registry.match('8.8.8.8').ip_or_cidr, '8.8.8.0/24');
  assert.equal(registry.match('1.1.1.1'), null);

  await registry.remove('8.8.8.0/24');
  assert.equal(registry.match('8.8.8.8'), null);
});

test('decision uses manual suspicious registry after allowlist', async () => {
  const registry = new SuspiciousIpRegistry({ enabled: false });
  await registry.add({ ip_or_cidr: '8.8.8.8', reason: 'manual_suspicious' });
  const state = {
    config: { private_ip_decision: 'fake' },
    allowlist: new Allowlist({ ips: [], cidrs: [], asns: [] }),
    suspiciousIpRegistry: registry,
    geoip: null,
    cloudCidr: null,
  };

  const result = decide(state, '8.8.8.8');
  assert.equal(result.decision, 'fake');
  assert.equal(result.risk_reason, 'manual_suspicious');
  assert.equal(result.matched_cidr, '8.8.8.8/32');
});

test('allowlist beats manual suspicious registry', async () => {
  const registry = new SuspiciousIpRegistry({ enabled: false });
  await registry.add({ ip_or_cidr: '8.8.8.8', reason: 'manual_suspicious' });
  const state = {
    config: { private_ip_decision: 'fake' },
    allowlist: new Allowlist({ ips: ['8.8.8.8'], cidrs: [], asns: [] }),
    suspiciousIpRegistry: registry,
    geoip: null,
    cloudCidr: null,
  };

  const result = decide(state, '8.8.8.8');
  assert.equal(result.decision, 'proxy');
  assert.equal(result.risk_reason, 'allowlist');
});
