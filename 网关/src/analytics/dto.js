function intValue(value) {
  const n = Number(value || 0);
  return Number.isFinite(n) ? n : 0;
}

function arrayValue(value) {
  if (Array.isArray(value)) return value.filter((item) => item != null && item !== '');
  if (value == null || value === '') return [];
  return [value];
}

function cleanReasons(value) {
  return [...new Set(arrayValue(value).filter(Boolean))];
}

export function tokenEdgeDto(row) {
  return {
    token_hash: row.token_hash || '',
    first_seen: row.first_seen || '',
    last_seen: row.last_seen || '',
    hits: intValue(row.hits),
    suspicious_hits: intValue(row.suspicious_hits),
  };
}

export function ipEdgeDto(row) {
  return {
    tenant_id: row.tenant_id || '',
    client_ip: row.client_ip || '',
    first_seen: row.first_seen || '',
    last_seen: row.last_seen || '',
    hits: intValue(row.hits),
    suspicious_hits: intValue(row.suspicious_hits),
  };
}

export function accessRecordDto(row) {
  return {
    ts: row.ts || '',
    tenant_id: row.tenant_id || '',
    host: row.host || '',
    origin_base_url: row.origin_base_url || '',
    token_raw: row.token_raw || '',
    token_hash: row.token_hash || '',
    client_ip: row.client_ip || '',
    decision: row.decision || '',
    risk_reason: row.risk_reason || '',
    risk_level: intValue(row.risk_level),
    is_suspicious: intValue(row.is_suspicious),
    flag: row.flag || '',
    client_type: row.client_type || '',
    user_agent: row.user_agent || '',
  };
}

export function relatedIpDto(row) {
  return {
    client_ip: row.client_ip || '',
    shared_tokens: intValue(row.shared_tokens),
    seed_ip_count: intValue(row.seed_ip_count),
    hits: intValue(row.hits),
    suspicious_hits: intValue(row.suspicious_hits),
    token_hashes: arrayValue(row.token_hashes),
    seed_ips: arrayValue(row.seed_ips),
  };
}

export function ipTokenGraphDto(row) {
  return {
    token_hash: row.token_hash || '',
    token_raw: row.token_raw || '',
    seed_hits: intValue(row.seed_hits),
    ip_count: intValue(row.ip_count),
    hits: intValue(row.hits),
    suspicious_hits: intValue(row.suspicious_hits),
    other_ips: arrayValue(row.other_ips),
    first_seen: row.first_seen || '',
    last_seen: row.last_seen || '',
  };
}

export function suspiciousIpDto(row, riskLevel = 1) {
  return {
    client_ip: row.client_ip || '',
    tenant_count: intValue(row.tenant_count),
    token_count: intValue(row.token_count),
    hits: intValue(row.hits),
    suspicious_hits: intValue(row.suspicious_hits ?? row.hits),
    reasons: cleanReasons(row.reasons),
    first_seen: row.first_seen || '',
    last_seen: row.last_seen || '',
    risk_level: riskLevel,
  };
}

export function globalIpDto(row, ip = '') {
  if (!row) {
    return {
      client_ip: ip,
      tenant_count: 0,
      token_count: 0,
      hits: 0,
      suspicious_hits: 0,
      first_seen: '',
      last_seen: '',
    };
  }
  return {
    client_ip: row.client_ip || ip,
    tenant_count: intValue(row.tenant_count),
    token_count: intValue(row.token_count),
    hits: intValue(row.hits),
    suspicious_hits: intValue(row.suspicious_hits),
    first_seen: row.first_seen || '',
    last_seen: row.last_seen || '',
  };
}

export function riskIpDto(result, ip = '') {
  const profile = suspiciousIpDto(result.profile || {}, result.risk_level || 0);
  profile.client_ip = profile.client_ip || ip;
  return {
    profile,
    related_ips: (result.related_ips || []).map(relatedIpDto),
    risk_level: intValue(result.risk_level),
  };
}

export function riskSummaryDto(summary) {
  return {
    level1: (summary.level1 || []).map((row) => suspiciousIpDto(row, 1)),
    level2: (summary.level2 || []).map((row) => relatedIpDto({ ...row, seed_ip_count: row.seed_ip_count || 1 })),
    level3: (summary.level3 || []).map((row) => relatedIpDto({ ...row, seed_ip_count: row.seed_ip_count || 1 })),
  };
}
