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

function rewriteHostPortPrefix(line, prefix, decoyHost) {
  const start = `${prefix}=`;
  if (!line.startsWith(start)) return line;
  const rest = line.slice(start.length);
  const comma = rest.indexOf(',');
  const endpoint = comma === -1 ? rest : rest.slice(0, comma);
  const suffix = comma === -1 ? '' : rest.slice(comma);
  const idx = endpoint.lastIndexOf(':');
  if (idx <= 0) return line;
  return `${start}${decoyHost}${endpoint.slice(idx)}${suffix}`;
}

function rewriteHostInUrl(raw, decoyHost) {
  const match = String(raw).match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//);
  if (!match || !URI_SCHEMES.has(match[1].toLowerCase())) return raw;

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

function rewriteLine(line, decoyHost) {
  for (const prefix of QX_PREFIXES) {
    const next = rewriteHostPortPrefix(line, prefix, decoyHost);
    if (next !== line) return next;
  }
  return rewriteHostInUrl(line, decoyHost);
}

function rewriteTextSubscription(text, decoyHost) {
  return splitLinesPreserve(text)
    .map((part) => (/^\r?\n$|^\r$/.test(part) ? part : rewriteLine(part, decoyHost)))
    .join('');
}

function rewriteClashYaml(text, decoyHost) {
  const doc = yaml.load(text);
  if (!doc || typeof doc !== 'object') return text;
  if (Array.isArray(doc.proxies)) {
    for (const proxy of doc.proxies) {
      if (proxy && typeof proxy === 'object' && CLASH_TYPES.has(String(proxy.type || '').toLowerCase()) && proxy.server) {
        proxy.server = decoyHost;
      }
    }
  }
  return yaml.dump(doc, { indent: 2, lineWidth: -1, quotingType: '"' });
}

function rewriteSingboxJson(text, decoyHost) {
  const doc = JSON.parse(text);
  if (doc && Array.isArray(doc.outbounds)) {
    for (const outbound of doc.outbounds) {
      if (outbound && typeof outbound === 'object' && SINGBOX_TYPES.has(String(outbound.type || '').toLowerCase()) && outbound.server) {
        outbound.server = decoyHost;
      }
    }
  }
  return JSON.stringify(doc, null, 2);
}

export function rewriteSubscriptionBody(body, clientType, decoyHost) {
  if (!decoyHost) return body;
  const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body);

  if (clientType === 'clash') {
    return Buffer.from(rewriteClashYaml(text, decoyHost), 'utf8');
  }
  if (clientType === 'singbox') {
    return Buffer.from(rewriteSingboxJson(text, decoyHost), 'utf8');
  }
  if (['base64', 'shadowrocket', 'quantumultx'].includes(clientType)) {
    const decoded = b64Decode(text);
    return Buffer.from(b64Encode(rewriteTextSubscription(decoded, decoyHost)), 'utf8');
  }
  return Buffer.from(rewriteTextSubscription(text, decoyHost), 'utf8');
}
