// General 通用 base64 订阅（也用于 v2rayn/v2rayng/sagernet/unknown）。
// 对齐 v2board General.php：整体 base64，vmess 用标准 base64(json)，ss urlsafe。
import { b64, urlsafeB64, rawurlencode, crlfLines, wsHost } from './helpers.js';

// 标准 ss URI：ss://urlsafe_b64(cipher:password)@host:port#name
export function ssUri(n) {
  const userinfo = urlsafeB64(`${n.cipher}:${n.password}`);
  return `ss://${userinfo}@${n.host}:${n.port}#${rawurlencode(n.name)}`;
}

// 标准 vmess URI：vmess://base64(json)，字段全为字符串
export function vmessJsonUri(n) {
  const cfg = {
    v: '2',
    ps: n.name,
    add: n.host,
    port: String(n.port),
    id: n.uuid,
    aid: '0',
    net: n.network || 'tcp',
    type: 'none',
    host: '',
    path: '',
    tls: n.tls ? 'tls' : '',
  };
  if (n.tls && n.sni) cfg.sni = n.sni;
  if (n.network === 'ws') {
    cfg.path = n.path || '/';
    cfg.host = wsHost(n);
  } else if (n.network === 'grpc') {
    cfg.path = n.grpcServiceName || '';
  }
  return 'vmess://' + b64(JSON.stringify(cfg));
}

// 标准 trojan URI
export function trojanUri(n) {
  const sni = n.sni || '';
  const q = `allowInsecure=${n.allowInsecure ? 1 : 0}&peer=${rawurlencode(sni)}&sni=${rawurlencode(sni)}`;
  return `trojan://${n.password}@${n.host}:${n.port}?${q}#${rawurlencode(n.name)}`;
}

export function nodeUri(n) {
  switch (n.type) {
    case 'shadowsocks': return ssUri(n);
    case 'vmess': return vmessJsonUri(n);
    case 'trojan': return trojanUri(n);
    default: return null;
  }
}

export function renderBase64(nodes, _fake) {
  return b64(crlfLines(nodes.map(nodeUri).filter(Boolean)));
}
