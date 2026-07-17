// 涓昏姹傚鐞嗭細鏂规硶闄愬埗 -> 鎻愬彇 client_ip -> Host 璺敱 -> 闄愭祦 ->
// 鍐崇瓥 -> 鐪熻闃呭洖婧?/ 鍋囪闃呫€傛墍鏈夎姹傝褰曚竴鏉＄粨鏋勫寲璁块棶鏃ュ織銆?
import { URL } from 'node:url';
import { logger, sha256 } from '../logger.js';
import { stripPort, isValidIp } from '../detector/ip.js';
import { decide } from './decision.js';
import { detectClientType, buildFakeSubscription } from './fake.js';
import { forwardToOrigin, OriginError } from './proxy.js';
import { parseUserInfo } from './userinfo.js';
import { rewriteSubscriptionBody } from './rewrite.js';
import { isRiskSuspicious, riskLevelFor } from '../analytics/risk.js';
import { shouldAnalyzePath } from '../analytics/pathFilter.js';

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// 浠庡彲淇′唬鐞嗗ご鎴栫洿杩炴彁鍙?client_ip銆?
function extractClientIp(state, req) {
  const remoteAddr = stripPort(req.socket.remoteAddress || '');
  const trusted = state.trustedProxies.contains(remoteAddr);
  const xRealIp = (req.headers['x-real-ip'] || '').trim();
  const xff = (req.headers['x-forwarded-for'] || '').trim();

  if (trusted) {
    let suspicious = false;
    let clientIp = '';
    if (xRealIp) {
      clientIp = xRealIp;
    } else if (xff) {
      // 澶氫釜 IP -> 鍙枒
      if (xff.includes(',')) {
        suspicious = true;
        clientIp = xff.split(',')[0].trim();
      } else {
        clientIp = xff;
      }
    }
    return { remoteAddr, trusted, xRealIp, xff, clientIp, suspicious, rejected: false };
  }

  // 闈炲彲淇℃潵婧愶細蹇界暐鍏惰浆鍙戝ご
  return {
    remoteAddr,
    trusted: false,
    xRealIp,
    xff,
    clientIp: remoteAddr,
    suspicious: false,
    rejected: state.config.server.reject_direct_access,
  };
}

function hostOf(req) {
  const h = req.headers['host'] || '';
  return stripPort(h.trim()) || h.trim().replace(/:\d+$/, '');
}

function tokenHashFromUrl(urlObj) {
  const token = urlObj.searchParams.get('token');
  return token ? sha256(token) : '';
}

function sendResponse(res, status, headers, body) {
  res.writeHead(status, headers);
  res.end(body);
}

// 杩斿洖涓€涓?(req, res) 澶勭悊鍣紝闂寘鎸佹湁 stateHolder銆?
export function createHandler(stateHolder, { analytics = null } = {}) {
  return async function handle(req, res) {
    const start = Date.now();
    const state = stateHolder.current; // 鍘熷瓙璇诲彇锛屾暣璇锋眰鐢熷懡鍛ㄦ湡涓€鑷?
    const cfg = state.config;

    let urlObj;
    try {
      urlObj = new URL(req.url, 'http://placeholder');
    } catch {
      sendResponse(res, 400, { 'content-type': 'text/plain' }, 'Bad Request');
      return;
    }

    const host = hostOf(req);
    const flag = urlObj.searchParams.get('flag') || '';
    const userAgent = req.headers['user-agent'] || '';
    const tokenRaw = urlObj.searchParams.get('token') || '';
    const tokenHash = tokenRaw ? sha256(tokenRaw) : '';
    const remoteAddr = stripPort(req.socket.remoteAddress || '');
    const routeOrigin = cfg.origins[host] || null;
    const analyticsAllowed = shouldAnalyzePath(routeOrigin, urlObj.pathname);

    const logBase = {
      host,
      path: urlObj.pathname,
      query_token_hash: tokenHash,
      user_agent: userAgent,
      flag,
    };

    const recordAnalytics = ({ origin = null, ipInfo = null, decision, risk_reason = '', clientType = '', riskLevel = null }) => {
      if (!analyticsAllowed) return;
      const suspicious = isRiskSuspicious({ decision, risk_reason });
      analytics?.enqueue({
        ts_ms: start,
        tenant_id: origin?.tenant_id || routeOrigin?.tenant_id || '',
        host,
        origin_base_url: origin?.base_url || routeOrigin?.base_url || '',
        token_raw: tokenRaw,
        token_hash: tokenHash,
        client_ip: ipInfo?.clientIp || ipInfo?.remoteAddr || remoteAddr,
        remote_addr: ipInfo?.remoteAddr || remoteAddr,
        decision,
        risk_reason,
        risk_level: riskLevel ?? riskLevelFor({ decision, risk_reason }),
        is_suspicious: suspicious,
        flag,
        client_type: clientType,
        user_agent: userAgent,
      });
    };

    // 1. 鏂规硶闄愬埗
    if (!cfg.server.allowed_methods.includes(req.method)) {
      logger.access({ ...logBase, decision: 'reject', risk_reason: 'method_not_allowed', method: req.method, status: 405 });
      recordAnalytics({ origin: routeOrigin, decision: 'reject', risk_reason: 'method_not_allowed' });
      sendResponse(res, 405, { 'content-type': 'text/plain', allow: cfg.server.allowed_methods.join(', ') }, 'Method Not Allowed');
      return;
    }

    // 2. 鎻愬彇 client_ip
    const ipInfo = extractClientIp(state, req);
    const logIp = {
      remote_addr: ipInfo.remoteAddr,
      trusted_proxy: ipInfo.trusted,
      client_ip: ipInfo.clientIp,
      x_real_ip: ipInfo.xRealIp,
      x_forwarded_for: ipInfo.xff,
    };

    // 鐩磋繛鎷掔粷
    if (ipInfo.rejected) {
      logger.access({ ...logBase, ...logIp, decision: 'reject', risk_reason: 'direct_access', status: 403 });
      recordAnalytics({ ipInfo, decision: 'reject', risk_reason: 'direct_access' });
      sendResponse(res, 403, { 'content-type': 'text/plain' }, 'Forbidden');
      return;
    }

    // client_ip 鍚堟硶鎬?
    if (!ipInfo.clientIp || !isValidIp(ipInfo.clientIp)) {
      logger.access({ ...logBase, ...logIp, decision: 'reject', risk_reason: 'invalid_client_ip', status: 400 });
      recordAnalytics({ ipInfo, decision: 'reject', risk_reason: 'invalid_client_ip' });
      sendResponse(res, 400, { 'content-type': 'text/plain' }, 'Bad Request');
      return;
    }

    // 3. Host 璺敱锛堟湭鐭?Host -> 404锛?
    const origin = routeOrigin;
    if (!origin) {
      logger.access({ ...logBase, ...logIp, decision: 'reject', risk_reason: 'unknown_host', status: 404 });
      recordAnalytics({ ipInfo, decision: 'reject', risk_reason: 'unknown_host' });
      sendResponse(res, 404, { 'content-type': 'text/plain' }, 'Not Found');
      return;
    }

    // 4. 闄愭祦锛堟寜 client_ip锛?
    if (!state.rateLimiter.allow(ipInfo.clientIp)) {
      logger.access({ ...logBase, ...logIp, decision: 'reject', risk_reason: 'rate_limited', status: 429 });
      recordAnalytics({ origin, ipInfo, decision: 'reject', risk_reason: 'rate_limited' });
      sendResponse(res, 429, { 'content-type': 'text/plain', 'retry-after': '60' }, 'Too Many Requests');
      return;
    }

    // 5. 鍐崇瓥
    let dec;
    if (ipInfo.suspicious) {
      // XFF 鍚涓?IP锛氱洿鎺ュ垽鍙枒
      dec = { decision: 'fake', risk_reason: 'xff_multiple', allowlist_match: '', asn: null, asn_org: '', matched_cidr: '', geoip_error: '' };
    } else {
      dec = decide(state, ipInfo.clientIp);
    }

    const clientType = detectClientType(flag, userAgent);
    const proto = (req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http'));

    // 6a. 鍋囪闃咃紙鑺傜偣鏄亣鐨勶紝浣嗗彲閫夋媺鍙栫湡瀹?subscription-userinfo 璁╁埌鏈?娴侀噺涓虹湡锛?
    if (dec.decision === 'fake') {
      if (origin.decoy_host) {
        const originResp = await forwardToOrigin({
          baseUrl: origin.base_url,
          path: urlObj.pathname,
          search: urlObj.search,
          reqHeaders: req.headers,
          clientIp: ipInfo.clientIp,
          proto,
          timeoutMs: cfg.server.origin_timeout_seconds * 1000,
          maxBytes: cfg.server.max_origin_response_bytes,
          preserveResponseHeaders: 'all',
        });
        const body = rewriteSubscriptionBody(originResp.body, clientType, origin.decoy_host);
        sendResponse(res, originResp.status, originResp.headers, body);
        logger.access({
          ...logBase, ...logIp,
          decision: 'fake_rewrite', risk_reason: dec.risk_reason, allowlist_match: dec.allowlist_match,
          asn: dec.asn, asn_org: dec.asn_org, matched_cidr: dec.matched_cidr, geoip_error: dec.geoip_error,
          client_type: clientType, origin: origin.base_url, origin_status: originResp.status,
          decoy_host: origin.decoy_host, status: originResp.status, latency_ms: Date.now() - start,
        });
        recordAnalytics({ origin, ipInfo, decision: 'fake_rewrite', risk_reason: dec.risk_reason, clientType });
        return;
      }
      const realUi = await fetchRealUserinfo(state, origin, urlObj, logBase.query_token_hash);
      await respondFake(res, cfg, clientType, realUi);
      logger.access({
        ...logBase, ...logIp,
        decision: 'fake', risk_reason: dec.risk_reason, allowlist_match: dec.allowlist_match,
        asn: dec.asn, asn_org: dec.asn_org, matched_cidr: dec.matched_cidr, geoip_error: dec.geoip_error,
        client_type: clientType, real_userinfo: !!realUi, status: 200, latency_ms: Date.now() - start,
      });
      recordAnalytics({ origin, ipInfo, decision: 'fake', risk_reason: dec.risk_reason, clientType });
      return;
    }

    // 6b. 鐪熻闃呭洖婧?
    try {
      const originResp = await forwardToOrigin({
        baseUrl: origin.base_url,
        path: urlObj.pathname,
        search: urlObj.search,
        reqHeaders: req.headers,
        clientIp: ipInfo.clientIp,
        proto,
        timeoutMs: cfg.server.origin_timeout_seconds * 1000,
        maxBytes: cfg.server.max_origin_response_bytes,
      });
      sendResponse(res, originResp.status, originResp.headers, originResp.body);
      logger.access({
        ...logBase, ...logIp,
        decision: 'proxy', risk_reason: dec.risk_reason, allowlist_match: dec.allowlist_match,
        asn: dec.asn, asn_org: dec.asn_org, matched_cidr: '',
        origin: origin.base_url, origin_status: originResp.status,
        status: originResp.status, latency_ms: Date.now() - start,
      });
      recordAnalytics({ origin, ipInfo, decision: 'proxy', risk_reason: dec.risk_reason, clientType });
    } catch (err) {
      const kind = err instanceof OriginError ? err.kind : 'unknown';
      // 鍥炴簮澶辫触鎸?origin_failure_mode 澶勭悊
      if (cfg.origin_failure_mode === 'error') {
        sendResponse(res, 502, { 'content-type': 'text/plain' }, 'Bad Gateway');
        logger.access({ ...logBase, ...logIp, decision: 'proxy', origin: origin.base_url, origin_error: err.message, origin_error_kind: kind, status: 502, latency_ms: Date.now() - start });
        recordAnalytics({ origin, ipInfo, decision: 'proxy', risk_reason: `origin_${kind}`, clientType });
      } else {
        // 婧愮珯宸插け璐ワ紝鎷夸笉鍒扮湡瀹?userinfo锛屽洖閫€闈欐€侀厤缃€?
        await respondFake(res, cfg, clientType, null);
        logger.access({ ...logBase, ...logIp, decision: 'fake', risk_reason: 'origin_failure', origin: origin.base_url, origin_error: err.message, origin_error_kind: kind, client_type: clientType, real_userinfo: false, status: 200, latency_ms: Date.now() - start });
        recordAnalytics({ origin, ipInfo, decision: 'fake', risk_reason: 'origin_failure', clientType });
      }
    }
  };
}

// 鎷夊彇鐪熷疄 subscription-userinfo锛堝甫缂撳瓨锛夈€傛棤 token / 鏈惎鐢?/ 鏃犳簮绔?鏃惰繑鍥?null銆?
// 杩斿洖 { raw, parsed } 鎴?null銆?
async function fetchRealUserinfo(state, origin, urlObj, tokenHash) {
  if (!state.userinfoFetcher || !origin || !tokenHash) return null;
  const key = `${origin.base_url}|${tokenHash}`;
  const raw = await state.userinfoFetcher.get(key, {
    baseUrl: origin.base_url,
    path: urlObj.pathname,
    search: urlObj.search,
  });
  if (!raw) return null;
  return { raw, parsed: parseUserInfo(raw) };
}

// 鐢熸垚鍋囪闃呭苟锛堝彲閫夛級鍔犲叆闅忔満寤惰繜瀵归綈鍥炴簮鏃跺簭銆俽ealUi 涓虹湡瀹?userinfo锛堟垨 null锛夈€?
async function respondFake(res, cfg, clientType, realUi) {
  const fl = cfg.fake_latency || {};
  if (fl.enabled) {
    const min = fl.min_ms ?? 80;
    const max = fl.max_ms ?? 300;
    // 鐢ㄦ椂闂村仛鎶栧姩婧愶紝閬垮厤渚濊禆涓嶅彲鐢ㄧ殑闅忔満锛涜寖鍥村唴鍧囧寑鍋忕Щ
    const span = Math.max(0, max - min);
    const jitter = span > 0 ? Date.now() % (span + 1) : 0;
    await sleep(min + jitter);
  }
  const opts = realUi ? { userinfoRaw: realUi.raw, userinfo: realUi.parsed } : {};
  const fake = buildFakeSubscription(cfg.fake_subscription, cfg._fake_nodes, clientType, opts);
  sendResponse(res, fake.status, fake.headers, fake.body);
}
