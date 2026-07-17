// 真实 subscription-userinfo 拉取器。
// 风险用户命中后，用其 token 向源站拉一次 subscription-userinfo 响应头
// （真实流量/到期），只取头、丢弃节点体，再配合假节点渲染返回。
// 带按 token 缓存 + 超时 + 失败回退，避免高频探测打爆源站、也不泄露真实节点。

// 解析 "upload=1; download=2; total=3; expire=1700000000" -> 对象。
// 值为空视为 null（v2board 对长期有效用户 expired_at 为 null）。
export function parseUserInfo(str) {
  if (!str) return null;
  const out = { upload: null, download: null, total: null, expire: null };
  let any = false;
  for (const part of String(str).split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const raw = part.slice(eq + 1).trim();
    if (key in out) {
      out[key] = raw === '' ? null : Number(raw);
      any = true;
    }
  }
  return any ? out : null;
}

function joinPath(basePath, reqPath) {
  const a = (basePath || '/').replace(/\/+$/, '');
  const b = reqPath || '/';
  return (a + (b.startsWith('/') ? b : '/' + b)) || '/';
}

export class UserInfoFetcher {
  constructor({ enabled = false, cache_ttl_seconds = 300, timeout_seconds = 5 } = {}) {
    this.enabled = !!enabled;
    this.ttlMs = (cache_ttl_seconds || 300) * 1000;
    this.negTtlMs = Math.min(this.ttlMs, 30000); // 失败结果缓存更短，源站抖动时不反复打
    this.timeoutMs = (timeout_seconds || 5) * 1000;
    this.cache = new Map(); // key -> { value: string|null, expiresAt }
    this._sweepAt = Date.now();
  }

  // 返回真实 subscription-userinfo 头字符串；取不到返回 null。带缓存。
  async get(key, target) {
    if (!this.enabled) return null;
    const now = Date.now();
    this._sweep(now);
    const hit = this.cache.get(key);
    if (hit && hit.expiresAt > now) return hit.value;

    let value = null;
    try {
      value = await this._fetch(target);
    } catch {
      value = null;
    }
    this.cache.set(key, { value, expiresAt: now + (value ? this.ttlMs : this.negTtlMs) });
    return value;
  }

  async _fetch({ baseUrl, path, search }) {
    const u = new URL(baseUrl);
    u.pathname = joinPath(u.pathname, path);
    // 强制 flag=clash：确保源站返回 subscription-userinfo 头（General/base64 格式不带该头）
    const params = new URLSearchParams(search || '');
    params.set('flag', 'clash');
    u.search = params.toString();

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const resp = await fetch(u.toString(), { method: 'GET', redirect: 'manual', signal: controller.signal });
      const ui = resp.headers.get('subscription-userinfo');
      try { await resp.body?.cancel(); } catch {} // 立即取消 body，不下载节点
      return ui || null;
    } finally {
      clearTimeout(timer);
    }
  }

  _sweep(now) {
    if (now - this._sweepAt < 60000) return;
    this._sweepAt = now;
    for (const [k, v] of this.cache) if (v.expiresAt <= now) this.cache.delete(k);
  }
}
