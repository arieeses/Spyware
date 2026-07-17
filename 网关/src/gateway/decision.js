// 鍐崇瓥寮曟搸锛氭寜鏂囨。绗?7 鑺傞『搴忓垽瀹?proxy / fake銆?// 杈撳叆 state锛堜笉鍙彉杩愯鎬侊級涓?clientIp锛岃緭鍑哄喅绛栧強鏃ュ織瀛楁銆?
import { isPrivateOrReserved } from '../detector/ip.js';

export function decide(state, clientIp) {
  const result = {
    decision: 'proxy',
    risk_reason: '',
    allowlist_match: '',
    asn: null,
    asn_org: '',
    matched_cidr: '',
    geoip_error: '',
  };

  // 1. 绉佹湁 / 淇濈暀鍦板潃
  if (isPrivateOrReserved(clientIp)) {
    const mode = state.config.private_ip_decision || 'fake';
    if (mode === 'proxy') {
      result.decision = 'proxy';
      result.risk_reason = 'private_ip_proxy';
      return result;
    }
    if (mode === 'allowlist') {
      result.decision = 'proxy';
      result.risk_reason = 'private_ip_allowlist';
      return result;
    }
    // 榛樿 fake
    result.decision = 'fake';
    result.risk_reason = 'private_ip';
    return result;
  }

  // 2. 鍏堟煡 GeoIP 鍙栧緱 ASN锛堢櫧鍚嶅崟 ASN 鍒ゆ柇闇€瑕侊級銆傛煡璇㈠け璐ヤ笉闃绘柇銆?
  let asn = null;
  let asnOrg = '';
  let geoCheck = null;
  if (state.geoip) {
    try {
      geoCheck = state.geoip.check(clientIp);
      asn = geoCheck.asn;
      asnOrg = geoCheck.org;
    } catch (err) {
      result.geoip_error = err.message;
    }
  }
  result.asn = asn;
  result.asn_org = asnOrg;

  // 3. 鐧藉悕鍗曪紙ip / cidr / asn锛夛紝浼樺厛绾ф渶楂?
  const allowMatch = state.allowlist.match(clientIp, asn);
  if (allowMatch) {
    result.decision = 'proxy';
    result.risk_reason = 'allowlist';
    result.allowlist_match = allowMatch;
    return result;
  }

  const manualHit = state.suspiciousIpRegistry?.match(clientIp);
  if (manualHit) {
    result.decision = 'fake';
    result.risk_reason = manualHit.reason || 'manual_suspicious';
    result.matched_cidr = manualHit.ip_or_cidr;
    return result;
  }

  // 4. GeoIP ASN 闃绘柇
  if (geoCheck && geoCheck.blocked) {
    result.decision = 'fake';
    result.risk_reason = 'geoip_asn';
    return result;
  }

  // 5. CIDR 鍏滃簳
  if (state.cloudCidr) {
    const hit = state.cloudCidr.match(clientIp);
    if (hit) {
      result.decision = 'fake';
      result.risk_reason = 'cidr';
      result.matched_cidr = hit;
      return result;
    }
  }

  // 6. 榛樿鏀捐
  result.decision = 'proxy';
  return result;
}
