// Shadowrocket。对齐 v2board Shadowrocket.php。整体 base64，首行 STATUS。
import { b64, rawurlencode, crlfLines, wsHost } from './helpers.js';
import { ssUri } from './base64.js';

const GB = 1024 ** 3;
function toGB(bytes) {
  return parseFloat((Number(bytes || 0) / GB).toFixed(2));
}
function ymd(expire) {
  if (!expire) return '2099-12-31'; // 0 视为长期
  const d = new Date(Number(expire) * 1000);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`;
}

function statusLine(fake) {
  const ui = (fake && fake.userinfo) || {};
  return `STATUS=🚀↑:${toGB(ui.upload)}GB,↓:${toGB(ui.download)}GB,TOT:${toGB(ui.total)}GB💡Expires:${ymd(ui.expire)}`;
}

function query(pairs) {
  return pairs
    .filter(([, v]) => v != null && v !== '')
    .map(([k, v]) => `${k}=${rawurlencode(v)}`)
    .join('&');
}

function vmessUri(n) {
  const userinfo = b64(`auto:${n.uuid}@${n.host}:${n.port}`);
  const pairs = [['tfo', '1'], ['remark', n.name], ['alterId', '0']];
  if (n.tls) {
    pairs.push(['tls', '1'], ['allowInsecure', n.allowInsecure ? 1 : 0]);
    if (n.sni) pairs.push(['peer', n.sni]);
  }
  if (n.network === 'ws') {
    pairs.push(['obfs', 'websocket'], ['path', n.path || '/'], ['obfsParam', wsHost(n)]);
  } else if (n.network === 'grpc') {
    pairs.push(['obfs', 'grpc'], ['path', n.grpcServiceName || '']);
  }
  pairs.push(['host', n.tls ? (n.sni || n.host) : n.host]);
  return `vmess://${userinfo}?${query(pairs)}`;
}

function trojanUri(n) {
  const q = query([
    ['allowInsecure', n.allowInsecure ? 1 : 0],
    ['peer', n.sni || ''],
    ['tfo', '1'],
  ]);
  return `trojan://${n.password}@${n.host}:${n.port}?${q}#${rawurlencode(n.name)}`;
}

function nodeUri(n) {
  switch (n.type) {
    case 'shadowsocks': return ssUri(n);
    case 'vmess': return vmessUri(n);
    case 'trojan': return trojanUri(n);
    default: return null;
  }
}

export function renderShadowrocket(nodes, fake) {
  const lines = [statusLine(fake), ...nodes.map(nodeUri).filter(Boolean)];
  return b64(crlfLines(lines));
}
