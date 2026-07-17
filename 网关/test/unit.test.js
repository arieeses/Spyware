import { test } from 'node:test';
import assert from 'node:assert/strict';
import { stripPort, normalizeIp, isValidIp, isPrivateOrReserved } from '../src/detector/ip.js';
import { CidrSet } from '../src/detector/cidr.js';
import { Allowlist } from '../src/detector/allowlist.js';
import { decide } from '../src/gateway/decision.js';

test('stripPort handles ipv4/ipv6/bare', () => {
  assert.equal(stripPort('1.2.3.4:5678'), '1.2.3.4');
  assert.equal(stripPort('1.2.3.4'), '1.2.3.4');
  assert.equal(stripPort('[2001:db8::1]:443'), '2001:db8::1');
  assert.equal(stripPort('2001:db8::1'), '2001:db8::1');
  assert.equal(stripPort('::1'), '::1');
});

test('normalizeIp unwraps ipv4-mapped ipv6', () => {
  assert.equal(normalizeIp('::ffff:1.2.3.4'), '1.2.3.4');
  assert.equal(normalizeIp('1.2.3.4:80'), '1.2.3.4');
});

test('isValidIp', () => {
  assert.ok(isValidIp('8.8.8.8'));
  assert.ok(isValidIp('2001:db8::1'));
  assert.ok(!isValidIp('not-an-ip'));
  assert.ok(!isValidIp(''));
});

test('isPrivateOrReserved covers private ranges and CGNAT', () => {
  assert.ok(isPrivateOrReserved('10.0.0.1'));
  assert.ok(isPrivateOrReserved('192.168.1.1'));
  assert.ok(isPrivateOrReserved('127.0.0.1'));
  assert.ok(isPrivateOrReserved('100.64.0.1')); // CGNAT
  assert.ok(isPrivateOrReserved('fc00::1')); // ULA
  assert.ok(!isPrivateOrReserved('8.8.8.8'));
});

test('CidrSet matches v4 and v6, ip-or-cidr', () => {
  const s = new CidrSet();
  s.addCidr('8.8.8.0/24');
  s.addCidr('2001:db8::/32');
  s.addIpOrCidr('9.9.9.9');
  assert.equal(s.match('8.8.8.8'), '8.8.8.0/24');
  assert.equal(s.match('2001:db8::5'), '2001:db8::/32');
  assert.equal(s.match('9.9.9.9'), '9.9.9.9/32');
  assert.equal(s.match('1.1.1.1'), null);
  // ipv4-mapped 命中 v4 表
  assert.equal(s.match('::ffff:8.8.8.8'), '8.8.8.0/24');
});

test('Allowlist matches ip/cidr/asn', () => {
  const a = new Allowlist({ ips: ['198.51.100.20'], cidrs: ['203.0.113.0/24'], asns: [4134] });
  assert.equal(a.match('198.51.100.20', null), 'ip:198.51.100.20');
  assert.equal(a.match('203.0.113.9', null), 'cidr:203.0.113.0/24');
  assert.equal(a.match('8.8.8.8', 4134), 'asn:4134');
  assert.equal(a.match('8.8.8.8', 9999), null);
});

// 决策引擎：构造最小 state
function makeState(overrides = {}) {
  return {
    config: { private_ip_decision: 'fake', ...(overrides.config || {}) },
    allowlist: overrides.allowlist || new Allowlist({}),
    geoip: overrides.geoip || null,
    cloudCidr: overrides.cloudCidr || null,
  };
}

test('decide: private ip -> fake by default', () => {
  const r = decide(makeState(), '10.0.0.1');
  assert.equal(r.decision, 'fake');
  assert.equal(r.risk_reason, 'private_ip');
});

test('decide: allowlist beats cidr', () => {
  const cloudCidr = new CidrSet();
  cloudCidr.addCidr('8.8.8.0/24');
  const state = makeState({
    allowlist: new Allowlist({ ips: ['8.8.8.9'] }),
    cloudCidr,
  });
  const r = decide(state, '8.8.8.9');
  assert.equal(r.decision, 'proxy');
  assert.equal(r.risk_reason, 'allowlist');
});

test('decide: cidr fallback -> fake', () => {
  const cloudCidr = new CidrSet();
  cloudCidr.addCidr('8.8.8.0/24');
  const r = decide(makeState({ cloudCidr }), '8.8.8.9');
  assert.equal(r.decision, 'fake');
  assert.equal(r.risk_reason, 'cidr');
  assert.equal(r.matched_cidr, '8.8.8.0/24');
});

test('decide: clean residential -> proxy', () => {
  const cloudCidr = new CidrSet();
  cloudCidr.addCidr('8.8.8.0/24');
  const r = decide(makeState({ cloudCidr }), '1.1.1.1');
  assert.equal(r.decision, 'proxy');
});

test('decide: geoip asn block -> fake', () => {
  const fakeGeo = {
    check: () => ({ blocked: true, asn: 16509, org: 'Amazon', reason: 'asn_number' }),
  };
  const r = decide(makeState({ geoip: fakeGeo }), '8.8.8.8');
  assert.equal(r.decision, 'fake');
  assert.equal(r.risk_reason, 'geoip_asn');
  assert.equal(r.asn, 16509);
});
