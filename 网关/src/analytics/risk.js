export const RISK_REASONS = Object.freeze([
  'geoip_asn',
  'cidr',
  'private_ip',
  'xff_multiple',
  'manual_suspicious',
]);

const RISK_REASON_SET = new Set(RISK_REASONS);

export function isRiskReason(reason) {
  return RISK_REASON_SET.has(String(reason || ''));
}

export function isRiskSuspicious({ risk_reason = '' } = {}) {
  return isRiskReason(risk_reason);
}

export function riskLevelFor(event = {}) {
  return isRiskSuspicious(event) ? 1 : 0;
}

export function riskReasonSqlList() {
  return RISK_REASONS.map((reason) => `'${reason}'`).join(', ');
}
