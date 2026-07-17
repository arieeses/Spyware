// 杩愯鎬侊細鐢?config 鏋勫缓鎵€鏈?detector锛屼綔涓轰笉鍙彉瀵硅薄鏁翠綋鍘熷瓙鏇挎崲銆?
import { loadConfig } from './config.js';
import { CidrSet, loadCidrFiles } from './detector/cidr.js';
import { Allowlist } from './detector/allowlist.js';
import { GeoIp } from './detector/geoip.js';
import { RateLimiter } from './gateway/ratelimit.js';
import { UserInfoFetcher } from './gateway/userinfo.js';
import { SuspiciousIpRegistry } from './detector/suspiciousRegistry.js';
import { logger } from './logger.js';

// 浠庨厤缃枃浠舵瀯寤轰竴浠藉畬鏁磋繍琛屾€併€備换浣曞姞杞藉け璐ヤ細鎶涢敊銆?
export async function buildState(configPath) {
  const config = loadConfig(configPath);

  // trusted_proxies -> CidrSet锛堝崟 IP 涓?CIDR 娣峰悎锛?
  const trustedProxies = new CidrSet();
  for (const t of config.trusted_proxies) trustedProxies.addIpOrCidr(t);

  // allowlist
  const allowlist = new Allowlist(config.allowlist);

  // geoip
  let geoip = null;
  const geoCfg = config.cloud_detection.geoip || {};
  if (geoCfg.enabled) {
    geoip = await GeoIp.load(geoCfg.db_path, geoCfg.block_asns, geoCfg.block_asn_keywords);
  }

  // cloud cidr
  let cloudCidr = null;
  const cidrCfg = config.cloud_detection.cidr || {};
  if (cidrCfg.enabled) {
    cloudCidr = loadCidrFiles(cidrCfg.files || [], (o) => logger.warn(o));
  }

  // rate limiter锛堥檺娴佺姸鎬佽法閲嶈浇鍙繚鐣欙紝涔熷彲閲嶅缓锛涜繖閲岄噸寤猴紝绠€鍗曪級
  const rateLimiter = new RateLimiter({
    enabled: !!config.rate_limit.enabled,
    requestsPerMinute: config.rate_limit.requests_per_minute || 120,
    burst: config.rate_limit.burst || 40,
  });

  // 鐪熷疄 subscription-userinfo 鎷夊彇鍣紙鍋囪妭鐐?+ 鐪熷埌鏈?娴侀噺锛?
  const userinfoFetcher = new UserInfoFetcher(config.fake_subscription.real_userinfo || {});
  const suspiciousIpRegistry = await SuspiciousIpRegistry.load(config.suspicious_ip || {});

  return Object.freeze({
    config,
    trustedProxies,
    allowlist,
    geoip,
    cloudCidr,
    rateLimiter,
    userinfoFetcher,
    suspiciousIpRegistry,
    loadedAt: Date.now(),
  });
}

// 鍘熷瓙寮曠敤瀹瑰櫒锛氳姹傚鐞嗚鍙?current锛岄噸杞芥椂鏁翠綋鏇挎崲銆?
export class StateHolder {
  constructor(state) {
    this._state = state;
  }
  get current() {
    return this._state;
  }
  swap(next) {
    this._state = next;
  }
}
