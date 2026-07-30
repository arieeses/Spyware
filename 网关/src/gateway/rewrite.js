import yaml from 'js-yaml';

const URI_SCHEMES = new Set(['ss', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls']);
const CLASH_TYPES = new Set(['ss', 'shadowsocks', 'vmess', 'vless', 'trojan', 'tuic', 'anytls', 'hysteria', 'hysteria2']);
const SINGBOX_TYPES = new Set(['shadowsocks', 'vmess', 'vless', 'trojan', 'tuic', 'anytls', 'hysteria', 'hysteria2']);
const QX_PREFIXES = ['shadowsocks', 'vmess', 'vless', 'trojan', 'anytls'];

function b64Decode(text) {
  return Buffer.from(String(text).trim(), 'base64').toString('utf8');
}

function b64Encode(text) {
  return Buffer.from(String(text), 'utf8').toString('base64');
}

function decodeMaybeUrlSafeBase64(text) {
  const normalized = String(text).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(normalized, 'base64').toString('utf8');
}

function encodeMaybeUrlSafeBase64(text, original) {
  let encoded = Buffer.from(String(text), 'utf8').toString('base64');
  if (String(original).includes('-') || String(original).includes('_') || !String(original).includes('=')) {
    encoded = encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }
  return encoded;
}

function splitLinesPreserve(text) {
  return String(text).split(/(\r\n|\n|\r)/);
}

// 协议名归一(改写目标按协议挑域名时用)
function normProto(t) {
  const p = String(t || '').toLowerCase();
  if (p === 'shadowsocks') return 'ss';
  if (p === 'hy2') return 'hysteria2';
  return p;
}
// resolve 可以是: 字符串(所有协议同一域名) 或 函数(proto)=>域名。返回空串=该节点不改写。
function hostFor(resolve, proto) {
  const h = typeof resolve === 'function' ? resolve(normProto(proto)) : resolve;
  return h || '';
}

function rewriteHostPortPrefix(line, prefix, resolve) {
  const start = `${prefix}=`;
  if (!line.startsWith(start)) return line;
  const decoyHost = hostFor(resolve, prefix);
  if (!decoyHost) return line;
  const rest = line.slice(start.length);
  const comma = rest.indexOf(',');
  const endpoint = comma === -1 ? rest : rest.slice(0, comma);
  const suffix = comma === -1 ? '' : rest.slice(comma);
  const idx = endpoint.lastIndexOf(':');
  if (idx <= 0) return line;
  return `${start}${decoyHost}${endpoint.slice(idx)}${suffix}`;
}

function rewriteHostInUrl(raw, resolve) {
  const match = String(raw).match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//);
  if (!match || !URI_SCHEMES.has(match[1].toLowerCase())) return raw;
  const decoyHost = hostFor(resolve, match[1]);
  if (!decoyHost) return raw;

  if (match[1].toLowerCase() === 'vmess') {
    return rewriteVmessUri(raw, decoyHost);
  }

  try {
    const url = new URL(raw);
    url.hostname = decoyHost;
    return url.toString();
  } catch {
    return rewriteAuthorityHost(raw, decoyHost);
  }
}

function rewriteAuthorityHost(raw, decoyHost) {
  return String(raw).replace(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^@\s]+@)(\[[^\]]+\]|[^:?#\s]+)(:\d+)/, `$1${decoyHost}$3`);
}

function rewriteVmessUri(raw, decoyHost) {
  const payload = String(raw).slice('vmess://'.length);
  try {
    const cfg = JSON.parse(decodeMaybeUrlSafeBase64(payload));
    if (cfg && typeof cfg === 'object' && typeof cfg.add === 'string') {
      cfg.add = decoyHost;
      return 'vmess://' + encodeMaybeUrlSafeBase64(JSON.stringify(cfg), payload);
    }
  } catch {}
  return raw;
}

function rewriteLine(line, resolve) {
  for (const prefix of QX_PREFIXES) {
    const next = rewriteHostPortPrefix(line, prefix, resolve);
    if (next !== line) return next;
  }
  return rewriteHostInUrl(line, resolve);
}

function rewriteTextSubscription(text, resolve) {
  return splitLinesPreserve(text)
    .map((part) => (/^\r?\n$|^\r$/.test(part) ? part : rewriteLine(part, resolve)))
    .join('');
}

function rewriteClashYaml(text, resolve) {
  const doc = yaml.load(text);
  if (!doc || typeof doc !== 'object') return text;
  if (Array.isArray(doc.proxies)) {
    for (const proxy of doc.proxies) {
      if (proxy && typeof proxy === 'object' && CLASH_TYPES.has(String(proxy.type || '').toLowerCase()) && proxy.server) {
        const h = hostFor(resolve, proxy.type);
        if (h) proxy.server = h;
      }
    }
  }
  return yaml.dump(doc, { indent: 2, lineWidth: -1, quotingType: '"' });
}

function rewriteSingboxJson(text, resolve) {
  const doc = JSON.parse(text);
  if (doc && Array.isArray(doc.outbounds)) {
    for (const outbound of doc.outbounds) {
      if (outbound && typeof outbound === 'object' && SINGBOX_TYPES.has(String(outbound.type || '').toLowerCase()) && outbound.server) {
        const h = hostFor(resolve, outbound.type);
        if (h) outbound.server = h;
      }
    }
  }
  return JSON.stringify(doc, null, 2);
}

// resolve: 字符串(所有协议同一域名) 或 函数(proto)=>域名(空=该节点不改写)。
export function rewriteSubscriptionBody(body, clientType, resolve) {
  if (!resolve) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body);

  if (clientType === 'clash') {
    return Buffer.from(rewriteClashYaml(text, resolve), 'utf8');
  }
  if (clientType === 'singbox') {
    return Buffer.from(rewriteSingboxJson(text, resolve), 'utf8');
  }
  if (['base64', 'shadowrocket', 'quantumultx'].includes(clientType)) {
    const decoded = b64Decode(text);
    return Buffer.from(b64Encode(rewriteTextSubscription(decoded, resolve)), 'utf8');
  }
  return Buffer.from(rewriteTextSubscription(text, resolve), 'utf8');
}

// 由入口配置 {def, proto:{...}} 生成一个 resolver(协议)=>域名; fallback 为默认兜底域名。
export function makeResolver(entry, fallback) {
  const def = (entry && entry.def) || fallback || '';
  const proto = (entry && entry.proto) || {};
  return (p) => proto[normProto(p)] || def || '';
}
