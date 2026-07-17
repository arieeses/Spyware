// 鍐呴儴鎺ュ彛锛?-/health /-/ready /-/reload銆傜嫭绔嬬洃鍚湰鏈虹鍙ｏ紝
// 涓嶅鐢?reject_direct_access锛屼笉瀵瑰鏆撮湶銆?
import { logger } from '../logger.js';
import { sha256 } from '../logger.js';
import {
  queryAccessEvents,
  queryDirectSuspiciousIps,
  queryGlobalIp,
  queryIpAccessRecords,
  queryIpTokenGraph,
  queryIpProfile,
  queryRelatedIps,
  queryRiskIp,
  queryRiskSummary,
  querySecondLevelIps,
  queryTokenProfile,
  tokenHashFromInput,
} from '../analytics/queries.js';
import { accessRecordDto, globalIpDto, ipEdgeDto, ipTokenGraphDto, relatedIpDto, riskIpDto, riskSummaryDto, suspiciousIpDto, tokenEdgeDto } from '../analytics/dto.js';
import { adminPage } from './adminPage.js';

function json(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(body);
}

function html(res, status, body) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(body);
}

function searchParams(req) {
  return new URL(req.url || '/', 'http://internal').searchParams;
}

function authorized(stateHolder, req) {
  const token = stateHolder.current.config.server.reload_token;
  const auth = req.headers['authorization'] || '';
  const provided = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  return !!token && provided === token;
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

// reload: 鐢卞叆鍙ｆ敞鍏ョ殑寮傛鍑芥暟锛屾垚鍔熻繑鍥?true銆?
export function createInternalHandler(stateHolder, reloadFn) {
  return async function handle(req, res) {
    const url = req.url || '';
    const path = url.split('?')[0];

    if (req.method === 'GET' && path === '/-/health') {
      json(res, 200, { ok: true });
      return;
    }

    if (req.method === 'GET' && path === '/-/admin') {
      html(res, 200, adminPage());
      return;
    }

    if (req.method === 'GET' && path === '/-/ready') {
      const state = stateHolder.current;
      const cfg = state.config;
      const checks = {
        config: !!cfg,
        geoip: cfg.cloud_detection.geoip?.enabled ? !!state.geoip : true,
        cidr: cfg.cloud_detection.cidr?.enabled ? !!state.cloudCidr : true,
      };
      const ready = Object.values(checks).every(Boolean);
      json(res, ready ? 200 : 503, { ready, checks });
      return;
    }

    if (req.method === 'POST' && path === '/-/reload') {
      if (!authorized(stateHolder, req)) {
        json(res, 401, { ok: false, error: 'unauthorized' });
        return;
      }
      try {
        await reloadFn();
        json(res, 200, { ok: true, reloaded: true });
      } catch (err) {
        logger.error({ msg: 'reload_error', error: err.message });
        json(res, 500, { ok: false, error: err.message });
      }
      return;
    }

    if (path === '/-/suspicious-ip') {
      if (!authorized(stateHolder, req)) {
        json(res, 401, { ok: false, error: 'unauthorized' });
        return;
      }
      const registry = stateHolder.current.suspiciousIpRegistry;
      if (!registry) {
        json(res, 503, { ok: false, error: 'suspicious registry unavailable' });
        return;
      }
      try {
        if (req.method === 'GET') {
          json(res, 200, { ok: true, entries: registry.list() });
          return;
        }
        if (req.method === 'POST') {
          const body = await readJson(req);
          const entry = await registry.add(body);
          json(res, 200, { ok: true, entry });
          return;
        }
        if (req.method === 'DELETE') {
          const body = await readJson(req);
          const result = await registry.remove(body.ip_or_cidr || body.ip || body.cidr);
          json(res, 200, { ok: true, ...result });
          return;
        }
      } catch (err) {
        logger.error({ msg: 'suspicious_ip_api_error', error: err.message });
        json(res, 400, { ok: false, error: err.message });
        return;
      }
    }

    if (path.startsWith('/-/analytics/')) {
      if (!authorized(stateHolder, req)) {
        json(res, 401, { ok: false, error: 'unauthorized' });
        return;
      }
      const state = stateHolder.current;
      const params = searchParams(req);
      const limit = params.get('limit') || undefined;
      try {
        if (req.method === 'GET' && path === '/-/analytics/ip') {
          const ip = params.get('ip');
          if (!ip) throw new Error('ip required');
          const tokens = await queryIpProfile(state.config, ip, { limit });
          json(res, 200, { ok: true, ip, tokens: tokens.map(tokenEdgeDto) });
          return;
        }
        if (req.method === 'GET' && path === '/-/analytics/ip-access-records') {
          const ip = params.get('ip');
          if (!ip) throw new Error('ip required');
          const days = params.get('days') || undefined;
          const records = await queryIpAccessRecords(state.config, ip, { days, limit });
          json(res, 200, { ok: true, ip, days: Number(days || 30), records: records.map(accessRecordDto) });
          return;
        }
        if (req.method === 'GET' && path === '/-/analytics/events') {
          const days = params.get('days') || undefined;
          const rawFilters = params.get('filters') || '[]';
          const filters = JSON.parse(rawFilters);
          const records = await queryAccessEvents(state.config, { days, limit, filters });
          json(res, 200, { ok: true, days: Number(days || 30), records: records.map(accessRecordDto) });
          return;
        }
        if (req.method === 'GET' && path === '/-/analytics/token') {
          const tokenHash = tokenHashFromInput({ token_hash: params.get('token_hash'), token: params.get('token') }, sha256);
          if (!tokenHash) throw new Error('token or token_hash required');
          const ips = await queryTokenProfile(state.config, tokenHash, { limit });
          json(res, 200, { ok: true, token_hash: tokenHash, ips: ips.map(ipEdgeDto) });
          return;
        }
        if (req.method === 'GET' && path === '/-/analytics/related-ip') {
          const ip = params.get('ip');
          if (!ip) throw new Error('ip required');
          const related_ips = await queryRelatedIps(state.config, ip, { limit });
          json(res, 200, { ok: true, ip, related_ips: related_ips.map(relatedIpDto) });
          return;
        }
        if (req.method === 'GET' && path === '/-/analytics/ip-token-graph') {
          const ip = params.get('ip');
          if (!ip) throw new Error('ip required');
          const days = params.get('days') || undefined;
          const tokens = await queryIpTokenGraph(state.config, ip, { days, limit });
          json(res, 200, { ok: true, ip, days: Number(days || 30), tokens: tokens.map(ipTokenGraphDto) });
          return;
        }
        if (req.method === 'GET' && path === '/-/analytics/global-ip') {
          const ip = params.get('ip');
          if (!ip) throw new Error('ip required');
          const profile = await queryGlobalIp(state.config, ip);
          json(res, 200, { ok: true, ip, profile: globalIpDto(profile, ip) });
          return;
        }
        if (req.method === 'GET' && path === '/-/analytics/suspicious') {
          const days = params.get('days') || undefined;
          const direct = await queryDirectSuspiciousIps(state.config, { days, limit });
          const second_level = await querySecondLevelIps(state.config, { days, limit });
          json(res, 200, {
            ok: true,
            days: Number(days || 30),
            direct: direct.map((row) => suspiciousIpDto(row, 1)),
            second_level: second_level.map(relatedIpDto),
          });
          return;
        }
        if (req.method === 'GET' && path === '/-/analytics/risk-summary') {
          const days = params.get('days') || undefined;
          const summary = await queryRiskSummary(state.config, { days, limit });
          json(res, 200, { ok: true, days: Number(days || 30), ...riskSummaryDto(summary) });
          return;
        }
        if (req.method === 'GET' && path === '/-/analytics/risk-ip') {
          const ip = params.get('ip');
          if (!ip) throw new Error('ip required');
          const days = params.get('days') || undefined;
          const profile = await queryRiskIp(state.config, ip, { days, related_limit: limit || 1000 });
          json(res, 200, { ok: true, ip, days: Number(days || 30), ...riskIpDto(profile, ip) });
          return;
        }
      } catch (err) {
        logger.error({ msg: 'analytics_api_error', error: err.message });
        json(res, 400, { ok: false, error: err.message });
        return;
      }
    }

    json(res, 404, { ok: false, error: 'not found' });
  };
}
