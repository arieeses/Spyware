// Clash / ClashMeta / Stash / Mihomo。对齐 v2board Clash.php + ClashMeta.php。
// 输出 YAML 明文，不 base64。含 vless（ClashMeta 语义）以兼容 mihomo/stash。
import yaml from 'js-yaml';
import { wsHost, tlsServerName } from './helpers.js';

// ss 仅在 AEAD cipher 下由 v2board 输出；这里保持宽松，直接输出配置的 cipher。
function proxySS(n) {
  return { name: n.name, type: 'ss', server: n.host, port: n.port, cipher: n.cipher, password: n.password, udp: true };
}

function applyVmessTransport(p, n) {
  if (n.network === 'ws') {
    p.network = 'ws';
    p['ws-opts'] = { path: n.path || '/', headers: { Host: wsHost(n) } };
  } else if (n.network === 'grpc') {
    p.network = 'grpc';
    p['grpc-opts'] = { 'grpc-service-name': n.grpcServiceName || '' };
  }
}

function proxyVmess(n) {
  const p = {
    name: n.name, type: 'vmess', server: n.host, port: n.port,
    uuid: n.uuid, alterId: n.alterId || 0, cipher: 'auto', udp: true,
  };
  if (n.tls) {
    p.tls = true;
    p['skip-cert-verify'] = !!n.allowInsecure;
    p.servername = tlsServerName(n);
  }
  applyVmessTransport(p, n);
  return p;
}

function proxyVless(n) {
  const p = { name: n.name, type: 'vless', server: n.host, port: n.port, uuid: n.uuid, udp: true };
  if (n.tls) {
    p.tls = true;
    p['skip-cert-verify'] = !!n.allowInsecure;
    p.servername = tlsServerName(n);
    if (n.flow) {
      p.flow = n.flow;
      p['client-fingerprint'] = 'chrome';
    }
  }
  applyVmessTransport(p, n);
  return p;
}

function proxyTrojan(n) {
  const p = { name: n.name, type: 'trojan', server: n.host, port: n.port, password: n.password, udp: true };
  if (n.sni) p.sni = n.sni;
  if (n.allowInsecure) p['skip-cert-verify'] = true;
  return p;
}

function toProxy(n) {
  switch (n.type) {
    case 'shadowsocks': return proxySS(n);
    case 'vmess': return proxyVmess(n);
    case 'vless': return proxyVless(n);
    case 'trojan': return proxyTrojan(n);
    default: return null;
  }
}

export function renderClash(nodes, _fake) {
  const proxies = nodes.map(toProxy).filter(Boolean);
  const names = proxies.map((p) => p.name);
  const config = {
    proxies,
    'proxy-groups': [{ name: 'PROXY', type: 'select', proxies: [...names, 'DIRECT'] }],
    rules: ['MATCH,PROXY'],
  };
  return yaml.dump(config, { indent: 2, lineWidth: -1, quotingType: '"' });
}
