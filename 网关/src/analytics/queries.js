import { riskReasonSqlList } from './risk.js';

function normalizeUrl(url) {
  return String(url || '').replace(/\/+$/, '');
}

function authHeaders(ch) {
  const headers = {};
  if (ch.username || ch.password) {
    headers.authorization = `Basic ${Buffer.from(`${ch.username || ''}:${ch.password || ''}`).toString('base64')}`;
  }
  return headers;
}

function q(value) {
  return `'${String(value ?? '').replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

async function queryJsonEachRow(ch, sql) {
  if (!ch?.url) throw new Error('analytics clickhouse.url required');
  const url = `${normalizeUrl(ch.url)}/?query=${encodeURIComponent(sql.trim())}`;
  const resp = await fetch(url, { method: 'POST', headers: authHeaders(ch) });
  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`clickhouse query failed: ${resp.status} ${text.slice(0, 300)}`);
  }
  const text = await resp.text();
  return text.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

function tables(config) {
  const ch = config.analytics?.clickhouse || {};
  const database = ch.database || 'sub_gateway';
  return {
    ch,
    events: `${database}.${ch.table || 'subscription_access_events'}`,
    edges: `${database}.ip_token_edges`,
  };
}

function windowClause(days, field = 'ts') {
  const n = Math.min(Math.max(parseInt(days || 30, 10) || 30, 1), 365);
  return `${field} >= now64(3) - INTERVAL ${n} DAY`;
}

function dateWindowClause(days, field = 'event_date') {
  const n = Math.min(Math.max(parseInt(days || 30, 10) || 30, 1), 365);
  return `${field} >= today() - INTERVAL ${n} DAY`;
}

function limitClause(limit, max = 5000) {
  const n = Math.min(Math.max(parseInt(limit || 1000, 10) || 1000, 1), max);
  return `LIMIT ${n}`;
}

function querySettingsClause() {
  return 'SETTINGS max_threads = 1, max_execution_time = 8';
}

const EVENT_FILTER_FIELDS = Object.freeze({
  tenant_id: 'tenant_id',
  host: 'host',
  origin_base_url: 'origin_base_url',
  token_raw: 'token_raw',
  token_hash: 'token_hash',
  client_ip: 'client_ip',
  decision: 'decision',
  risk_reason: 'risk_reason',
  flag: 'flag',
  client_type: 'client_type',
  user_agent: 'user_agent',
});

const EVENT_FILTER_OPERATORS = new Set(['eq', 'ne', 'contains', 'not_contains', 'starts_with', 'empty', 'not_empty']);

function cleanEventFilters(filters = []) {
  if (!Array.isArray(filters)) return [];
  return filters
    .map((filter) => ({
      field: String(filter?.field || '').trim(),
      op: String(filter?.op || 'eq').trim(),
      value: String(filter?.value ?? '').trim(),
    }))
    .filter((filter) => filter.field || filter.value || filter.op === 'empty' || filter.op === 'not_empty')
    .slice(0, 12);
}

export function buildEventFilterClause(filters = []) {
  const clauses = [];
  for (const filter of cleanEventFilters(filters)) {
    const column = EVENT_FILTER_FIELDS[filter.field];
    if (!column) throw new Error(`unsupported filter field: ${filter.field}`);
    if (!EVENT_FILTER_OPERATORS.has(filter.op)) throw new Error(`unsupported filter op: ${filter.op}`);
    if (filter.op === 'empty') {
      clauses.push(`${column} = ''`);
    } else if (filter.op === 'not_empty') {
      clauses.push(`${column} != ''`);
    } else if (filter.op === 'eq') {
      clauses.push(`${column} = ${q(filter.value)}`);
    } else if (filter.op === 'ne') {
      clauses.push(`${column} != ${q(filter.value)}`);
    } else if (filter.op === 'contains') {
      clauses.push(`positionCaseInsensitive(${column}, ${q(filter.value)}) > 0`);
    } else if (filter.op === 'not_contains') {
      clauses.push(`positionCaseInsensitive(${column}, ${q(filter.value)}) = 0`);
    } else if (filter.op === 'starts_with') {
      clauses.push(`startsWith(${column}, ${q(filter.value)})`);
    }
  }
  return clauses.length ? `\n  AND ${clauses.join('\n  AND ')}` : '';
}

export function tokenHashFromInput({ token_hash, token }, sha256) {
  if (token_hash) return String(token_hash);
  if (token) return sha256(token);
  return '';
}

export async function queryIpProfile(config, ip, { limit = 1000 } = {}) {
  const { ch, edges } = tables(config);
  const sql = `
SELECT
  token_hash,
  minMerge(first_seen) AS first_seen,
  maxMerge(last_seen) AS last_seen,
  countMerge(hit_count) AS hits,
  sumMerge(suspicious_count) AS suspicious_hits
FROM ${edges}
WHERE client_ip = ${q(ip)}
GROUP BY token_hash
ORDER BY last_seen DESC
${limitClause(limit)}
FORMAT JSONEachRow`;
  return queryJsonEachRow(ch, sql);
}

export async function queryIpAccessRecords(config, ip, { days = 30, limit = 1000 } = {}) {
  const { ch, events } = tables(config);
  const sql = `
SELECT
  ts,
  tenant_id,
  host,
  origin_base_url,
  token_raw,
  token_hash,
  client_ip,
  decision,
  risk_reason,
  risk_level,
  is_suspicious,
  flag,
  client_type,
  user_agent
FROM ${events}
WHERE ${windowClause(days)}
  AND client_ip = ${q(ip)}
ORDER BY ts DESC
${limitClause(limit, 10000)}
FORMAT JSONEachRow`;
  return queryJsonEachRow(ch, sql);
}

export async function queryAccessEvents(config, { days = 30, limit = 1000, filters = [] } = {}) {
  const { ch, events } = tables(config);
  const filterClause = buildEventFilterClause(filters);
  const sql = `
SELECT
  ts,
  tenant_id,
  host,
  origin_base_url,
  token_raw,
  token_hash,
  client_ip,
  decision,
  risk_reason,
  risk_level,
  is_suspicious,
  flag,
  client_type,
  user_agent
FROM ${events}
WHERE ${windowClause(days)}
  ${filterClause}
ORDER BY ts DESC
${limitClause(limit, 10000)}
FORMAT JSONEachRow`;
  return queryJsonEachRow(ch, sql);
}

export async function queryTokenProfile(config, tokenHash, { limit = 5000 } = {}) {
  const { ch, edges } = tables(config);
  const sql = `
SELECT
  tenant_id,
  client_ip,
  minMerge(first_seen) AS first_seen,
  maxMerge(last_seen) AS last_seen,
  countMerge(hit_count) AS hits,
  sumMerge(suspicious_count) AS suspicious_hits
FROM ${edges}
WHERE token_hash = ${q(tokenHash)}
GROUP BY tenant_id, client_ip
ORDER BY suspicious_hits DESC, hits DESC, last_seen DESC
${limitClause(limit, 10000)}
FORMAT JSONEachRow`;
  return queryJsonEachRow(ch, sql);
}

export async function queryRelatedIps(config, seedIp, { limit = 5000 } = {}) {
  const { ch, edges } = tables(config);
  const sql = `
WITH seed_tokens AS
(
  SELECT token_hash
  FROM ${edges}
  WHERE client_ip = ${q(seedIp)}
  GROUP BY token_hash
)
SELECT
  client_ip,
  uniqExact(token_hash) AS shared_tokens,
  countMerge(hit_count) AS hits,
  sumMerge(suspicious_count) AS suspicious_hits,
  groupArray(token_hash) AS token_hashes
FROM ${edges}
WHERE token_hash IN seed_tokens
  AND client_ip != ${q(seedIp)}
GROUP BY client_ip
ORDER BY shared_tokens DESC, suspicious_hits DESC, hits DESC
${limitClause(limit, 10000)}
FORMAT JSONEachRow`;
  return queryJsonEachRow(ch, sql);
}

export async function queryIpTokenGraph(config, seedIp, { days = 30, limit = 1000 } = {}) {
  const { ch, events } = tables(config);
  const riskReasons = riskReasonSqlList();
  const sql = `
WITH seed_tokens AS
(
  SELECT DISTINCT token_hash
  FROM ${events}
  WHERE ${windowClause(days)}
    AND client_ip = ${q(seedIp)}
    AND token_hash != ''
)
SELECT
  token_hash,
  anyIf(token_raw, client_ip = ${q(seedIp)} AND token_raw != '') AS token_raw,
  countIf(client_ip = ${q(seedIp)}) AS seed_hits,
  uniqExact(client_ip) AS ip_count,
  count() AS hits,
  sum(if(is_suspicious = 1 AND risk_reason IN (${riskReasons}), 1, 0)) AS suspicious_hits,
  groupUniqArrayIf(client_ip, client_ip != ${q(seedIp)}) AS other_ips,
  min(ts) AS first_seen,
  max(ts) AS last_seen
FROM ${events}
WHERE ${windowClause(days)}
  AND token_hash IN seed_tokens
GROUP BY token_hash
ORDER BY ip_count DESC, hits DESC, last_seen DESC
${limitClause(limit, 10000)}
FORMAT JSONEachRow`;
  return queryJsonEachRow(ch, sql);
}

export async function queryGlobalIp(config, ip) {
  const { ch, edges } = tables(config);
  const sql = `
SELECT
  client_ip,
  uniqExact(tenant_id) AS tenant_count,
  uniqExact(token_hash) AS token_count,
  countMerge(hit_count) AS hits,
  sumMerge(suspicious_count) AS suspicious_hits,
  min(minMerge(first_seen)) AS first_seen,
  max(maxMerge(last_seen)) AS last_seen
FROM ${edges}
WHERE client_ip = ${q(ip)}
GROUP BY client_ip
FORMAT JSONEachRow`;
  const rows = await queryJsonEachRow(ch, sql);
  return rows[0] || null;
}

export async function queryDirectSuspiciousIps(config, { days = 30, limit = 1000 } = {}) {
  const { ch, events } = tables(config);
  const riskReasons = riskReasonSqlList();
  const sql = `
SELECT
  client_ip,
  uniqExact(tenant_id) AS tenant_count,
  uniqExact(token_hash) AS token_count,
  count() AS hits,
  groupUniqArray(risk_reason) AS reasons,
  min(ts) AS first_seen,
  max(ts) AS last_seen
FROM ${events}
WHERE ${windowClause(days)}
  AND is_suspicious = 1
  AND risk_reason IN (${riskReasons})
  AND token_hash != ''
GROUP BY client_ip
ORDER BY hits DESC, token_count DESC
${limitClause(limit, 10000)}
${querySettingsClause()}
FORMAT JSONEachRow`;
  return queryJsonEachRow(ch, sql);
}

export async function querySecondLevelIps(config, { days = 30, limit = 1000 } = {}) {
  const { ch, events, edges } = tables(config);
  const riskReasons = riskReasonSqlList();
  const sql = `
WITH level1_edges AS
(
  SELECT DISTINCT token_hash, client_ip AS seed_ip
  FROM ${events}
  WHERE ${windowClause(days)}
    AND is_suspicious = 1
    AND risk_reason IN (${riskReasons})
    AND token_hash != ''
),
all_edges AS
(
  SELECT
    token_hash,
    client_ip,
    countMerge(hit_count) AS hits,
    sumMerge(suspicious_count) AS suspicious_hits,
    maxMerge(last_seen) AS last_seen
  FROM ${edges}
  WHERE token_hash IN (SELECT DISTINCT token_hash FROM level1_edges)
    AND token_hash != ''
    AND ${dateWindowClause(days)}
  GROUP BY token_hash, client_ip
  HAVING ${windowClause(days, 'last_seen')}
)
SELECT
  a.client_ip,
  uniqExact(a.token_hash) AS shared_tokens,
  uniqExact(l.seed_ip) AS seed_ip_count,
  sum(a.hits) AS hits,
  sum(a.suspicious_hits) AS suspicious_hits,
  groupUniqArray(a.token_hash) AS token_hashes,
  groupUniqArray(l.seed_ip) AS seed_ips
FROM all_edges a
INNER JOIN level1_edges l ON a.token_hash = l.token_hash
WHERE a.client_ip != l.seed_ip
GROUP BY a.client_ip
ORDER BY shared_tokens DESC, seed_ip_count DESC
${limitClause(limit, 10000)}
${querySettingsClause()}
FORMAT JSONEachRow`;
  return queryJsonEachRow(ch, sql);
}

export async function queryRiskSummary(config, { days = 30, limit = 1000 } = {}) {
  const direct = await queryDirectSuspiciousIps(config, { days, limit });
  const second = await querySecondLevelIps(config, { days, limit });
  const directSet = new Set(direct.map((row) => row.client_ip));
  const level2 = second.filter((row) => !directSet.has(row.client_ip));
  const level3 = level2.filter((row) => Number(row.shared_tokens || 0) >= 2 || Number(row.seed_ip_count || 0) >= 2);
  return { level1: direct, level2, level3 };
}

export async function queryRiskIp(config, ip, { days = 30, related_limit = 1000 } = {}) {
  const { ch, events } = tables(config);
  const riskReasons = riskReasonSqlList();
  const directSql = `
SELECT
  client_ip,
  uniqExact(tenant_id) AS tenant_count,
  uniqExact(token_hash) AS token_count,
  count() AS hits,
  sum(if(is_suspicious = 1 AND risk_reason IN (${riskReasons}), 1, 0)) AS suspicious_hits,
  groupUniqArrayIf(risk_reason, risk_reason IN (${riskReasons})) AS reasons,
  min(ts) AS first_seen,
  max(ts) AS last_seen
FROM ${events}
WHERE ${windowClause(days)}
  AND client_ip = ${q(ip)}
GROUP BY client_ip
FORMAT JSONEachRow`;
  const rows = await queryJsonEachRow(ch, directSql);
  const profile = rows[0] || { client_ip: ip, tenant_count: 0, token_count: 0, hits: 0, suspicious_hits: 0, reasons: [] };
  const related_ips = await queryRelatedIps(config, ip, { limit: related_limit });
  const suspiciousHits = Number(profile.suspicious_hits || 0);
  const tokenCount = Number(profile.token_count || 0);
  const relatedStrong = related_ips.filter((row) => Number(row.shared_tokens || 0) >= 2).length;
  let risk_level = 0;
  if (suspiciousHits > 0) risk_level = 1;
  if (risk_level === 0 && related_ips.length > 0) risk_level = 2;
  if (risk_level >= 2 && (tokenCount >= 3 || relatedStrong > 0 || Number(profile.tenant_count || 0) >= 2)) risk_level = 3;
  return { profile, related_ips, risk_level };
}
