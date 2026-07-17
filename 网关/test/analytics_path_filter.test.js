import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAnalyticsPaths, shouldAnalyzePath } from '../src/analytics/pathFilter.js';

test('missing analytics_paths keeps legacy analyze-all behavior', () => {
  assert.equal(shouldAnalyzePath({}, '/api/v1/user/notice/fetch'), true);
});

test('configured analytics_paths only allows exact subscription paths', () => {
  const origin = {
    analytics_paths: normalizeAnalyticsPaths(['/api/baidu/baidu/baidu', '/sub']),
  };

  assert.equal(shouldAnalyzePath(origin, '/api/baidu/baidu/baidu'), true);
  assert.equal(shouldAnalyzePath(origin, '/sub'), true);
  assert.equal(shouldAnalyzePath(origin, '/api/v1/user/notice/fetch'), false);
  assert.equal(shouldAnalyzePath(origin, '/api/baidu/baidu/baidu/extra'), false);
});

test('analytics_paths must be path-only values', () => {
  assert.throws(() => normalizeAnalyticsPaths('api/no-leading-slash'), /invalid path/);
  assert.throws(() => normalizeAnalyticsPaths('/api/sub?token=x'), /invalid path/);
  assert.throws(() => normalizeAnalyticsPaths('/api/sub#x'), /invalid path/);
});
