import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '../src/logger.js';
import {
  buildEventFilterClause,
  queryDirectSuspiciousIps,
  queryAccessEvents,
  queryRiskIp,
  queryRiskSummary,
  querySecondLevelIps,
  tokenHashFromInput,
} from '../src/analytics/queries.js';

test('tokenHashFromInput prefers token_hash', () => {
  assert.equal(tokenHashFromInput({ token_hash: 'abc', token: 'raw' }, sha256), 'abc');
});

test('tokenHashFromInput hashes raw token when needed', () => {
  assert.equal(tokenHashFromInput({ token: 'raw-token' }, sha256), sha256('raw-token'));
});

test('tokenHashFromInput returns empty without token', () => {
  assert.equal(tokenHashFromInput({}, sha256), '');
});

test('risk query exports are available', () => {
  assert.equal(typeof queryAccessEvents, 'function');
  assert.equal(typeof queryDirectSuspiciousIps, 'function');
  assert.equal(typeof querySecondLevelIps, 'function');
  assert.equal(typeof queryRiskSummary, 'function');
  assert.equal(typeof queryRiskIp, 'function');
});

test('buildEventFilterClause supports safe event filters', () => {
  const clause = buildEventFilterClause([
    { field: 'user_agent', op: 'ne', value: 'curl' },
    { field: 'tenant_id', op: 'eq', value: '0318' },
    { field: 'client_type', op: 'contains', value: 'clash' },
  ]);
  assert.match(clause, /user_agent != 'curl'/);
  assert.match(clause, /tenant_id = '0318'/);
  assert.match(clause, /positionCaseInsensitive\(client_type, 'clash'\) > 0/);
});

test('buildEventFilterClause rejects unsupported fields and operators', () => {
  assert.throws(() => buildEventFilterClause([{ field: '1=1', op: 'eq', value: 'x' }]), /unsupported filter field/);
  assert.throws(() => buildEventFilterClause([{ field: 'tenant_id', op: 'sql', value: 'x' }]), /unsupported filter op/);
});
