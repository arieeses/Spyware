// Sing-box。注意：stock v2board 无 SingBox.php（是 Xboard/lotusboard 等 fork 才有）。
// 这里按 sing-box 官方 config schema 渲染 outbounds，保证 sing-box 客户端可解析。
import { wsHost, tlsServerName } from './helpers.js';

function tlsBlock(n) {
  return { enabled: true, server_name: tlsServerName(n), insecure: !!n.allowInsecure };
}

function transportBlock(n) {
  if (n.network === 'ws') {
    return { type: 'ws', path: n.path || '/', headers: { Host: wsHost(n) } };
  }
  if (n.network === 'grpc') {
    return { type: 'grpc', service_name: n.grpcServiceName || '' };
  }
  return null;
}

function outVmess(n) {
  const o = { type: 'vmess', tag: n.name, server: n.host, server_port: n.port, uuid: n.uuid, alter_id: n.alterId || 0, security: 'auto' };
  if (n.tls) o.tls = tlsBlock(n);
  const t = transportBlock(n);
  if (t) o.transport = t;
  return o;
}

function outVless(n) {
  const o = { type: 'vless', tag: n.name, server: n.host, server_port: n.port, uuid: n.uuid };
  if (n.flow) o.flow = n.flow;
  if (n.tls) o.tls = tlsBlock(n);
  const t = transportBlock(n);
  if (t) o.transport = t;
  return o;
}

function outTrojan(n) {
  const o = { type: 'trojan', tag: n.name, server: n.host, server_port: n.port, password: n.password };
  if (n.tls) o.tls = tlsBlock(n);
  const t = transportBlock(n);
  if (t) o.transport = t;
  return o;
}

function outSS(n) {
  return { type: 'shadowsocks', tag: n.name, server: n.host, server_port: n.port, method: n.cipher, password: n.password };
}

function toOutbound(n) {
  switch (n.type) {
    case 'vmess': return outVmess(n);
    case 'vless': return outVless(n);
    case 'trojan': return outTrojan(n);
    case 'shadowsocks': return outSS(n);
    default: return null;
  }
}

export function renderSingbox(nodes, _fake) {
  const outs = nodes.map(toOutbound).filter(Boolean);
  const tags = outs.map((o) => o.tag);
  const config = {
    outbounds: [
      ...outs,
      { type: 'selector', tag: 'PROXY', outbounds: [...tags, 'direct'] },
      { type: 'direct', tag: 'direct' },
    ],
    route: { final: 'PROXY' },
  };
  return JSON.stringify(config, null, 2);
}
