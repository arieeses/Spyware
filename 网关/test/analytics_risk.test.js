import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isRiskReason,
  isRiskSuspicious,
  riskLevelFor,
  riskReasonSqlList,
} from '../src/analytics/risk.js';

test('reject and operational reasons are not graph seeds', () => {
  for (const risk_reason of ['method_not_allowed', 'unknown_host', 'rate_limited', 'origin_failure', '']) {
    assert.equal(isRiskSuspicious({ decision: 'fake', risk_reason }), false);
    assert.equal(riskLevelFor({ decision: 'fake', risk_reason }), 0);
  }
});

test('real suspicious reasons are graph seeds', () => {
  for (const risk_reason of ['geoip_asn', 'cidr', 'private_ip', 'xff_multiple', 'manual_suspicious']) {
    assert.equal(isRiskReason(risk_reason), true);
    assert.equal(isRiskSuspicious({ decision: 'fake_rewrite', risk_reason }), true);
    assert.equal(riskLevelFor({ decision: 'fake_rewrite', risk_reason }), 1);
  }
});

test('risk reason sql list is stable for ClickHouse filters', () => {
  assert.equal(
    riskReasonSqlList(),
    "'geoip_asn', 'cidr', 'private_ip', 'xff_multiple', 'manual_suspicious'",
  );
});
