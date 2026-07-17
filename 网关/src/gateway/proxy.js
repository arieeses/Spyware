// 真订阅回源转发。使用原生 fetch，带超时与响应体大小限制。
// TLS 证书校验默认由 Node 处理（保持开启）。

// 不透传的 hop-by-hop 头（响应方向）。
const HOP_BY_HOP = new Set([
  'connection',
  'transfer-encoding',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'upgrade',
  'content-length', // 由我们重新计算
]);

// 需要保留回传给用户的重要响应头。
const PRESERVE_RESP_HEADERS = [
  'content-type',
  'subscription-userinfo',
  'profile-update-interval',
  'content-disposition',
  'cache-control',
  'expires',
  'etag',
];

export class OriginError extends Error {
  constructor(message, kind) {
    super(message);
    this.name = 'OriginError';
    this.kind = kind; // 'timeout' | 'network' | 'too_large' | 'status'
  }
}

// 转发到源站，返回 { status, headers, body(Buffer) }。
// 失败抛 OriginError，由上层按 origin_failure_mode 处理。
export async function forwardToOrigin({ baseUrl, path, search, reqHeaders, clientIp, proto, timeoutMs, maxBytes, preserveResponseHeaders = 'safe' }) {
  const target = new URL(baseUrl);
  // 拼接 path + query，保留原始 path 与 query string
  target.pathname = joinPath(target.pathname, path);
  target.search = search || '';

  const outHeaders = {
    host: target.host,
    'x-real-ip': clientIp,
    'x-forwarded-for': clientIp,
    'x-forwarded-proto': proto || 'https',
  };
  // 透传部分客户端头
  for (const h of ['user-agent', 'accept']) {
    if (reqHeaders[h]) outHeaders[h] = reqHeaders[h];
  }
  outHeaders['accept-encoding'] = 'identity';

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let resp;
  try {
    resp = await fetch(target.toString(), {
      method: 'GET',
      headers: outHeaders,
      redirect: 'manual',
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') throw new OriginError('origin timeout', 'timeout');
    throw new OriginError(`origin network error: ${err.message}`, 'network');
  }

  try {
    // 读取响应体，限制最大字节数
    const body = await readLimited(resp, maxBytes);
    const headers = collectResponseHeaders(resp, preserveResponseHeaders);
    // 兜底：其余非 hop-by-hop 头也可保留（可选，这里保守只留白名单）
    return { status: resp.status, headers, body };
  } finally {
    clearTimeout(timer);
  }
}

function collectResponseHeaders(resp, mode) {
  const headers = {};
  if (mode === 'all') {
    for (const [name, value] of resp.headers) {
      const key = name.toLowerCase();
      if (!HOP_BY_HOP.has(key)) headers[name] = value;
    }
    return headers;
  }
  for (const name of PRESERVE_RESP_HEADERS) {
    const v = resp.headers.get(name);
    if (v != null) headers[name] = v;
  }
  return headers;
}

async function readLimited(resp, maxBytes) {
  if (!resp.body) return Buffer.alloc(0);
  const reader = resp.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      try { await reader.cancel(); } catch {}
      throw new OriginError('origin response too large', 'too_large');
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

function joinPath(basePath, reqPath) {
  const a = (basePath || '/').replace(/\/+$/, '');
  const b = reqPath || '/';
  return (a + (b.startsWith('/') ? b : '/' + b)) || '/';
}

export { HOP_BY_HOP };
