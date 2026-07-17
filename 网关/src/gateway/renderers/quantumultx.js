// Quantumult X。对齐 v2board QuantumultX.php。整体 base64。
// 注意：tls-verification 与 allow_insecure 语义相反；vmess method 硬编码 chacha20-poly1305。
import { b64, crlfLines, wsHost } from './helpers.js';

function ssLine(n) {
  return `shadowsocks=${n.host}:${n.port},method=${n.cipher},password=${n.password},fast-open=true,udp-relay=true,tag=${n.name}`;
}

function vmessLine(n) {
  const parts = [
    `vmess=${n.host}:${n.port}`,
    'method=chacha20-poly1305',
    `password=${n.uuid}`,
  ];
  let obfsHost = '';
  if (n.network === 'ws') {
    parts.push(n.tls ? 'obfs=wss' : 'obfs=ws');
    parts.push(`obfs-uri=${n.path || '/'}`);
    obfsHost = wsHost(n);
  } else if (n.tls) {
    parts.push('obfs=over-tls');
    obfsHost = n.sni || '';
  }
  if (n.tls) parts.push(`tls-verification=${n.allowInsecure ? 'false' : 'true'}`);
  parts.push('fast-open=true', 'udp-relay=true', `tag=${n.name}`);
  if (obfsHost) parts.push(`obfs-host=${obfsHost}`);
  return parts.join(',');
}

function trojanLine(n) {
  const parts = [`trojan=${n.host}:${n.port}`, `password=${n.password}`, 'over-tls=true'];
  if (n.sni) parts.push(`tls-host=${n.sni}`);
  parts.push(`tls-verification=${n.allowInsecure ? 'false' : 'true'}`, 'fast-open=true', 'udp-relay=true', `tag=${n.name}`);
  return parts.join(',');
}

function nodeLine(n) {
  switch (n.type) {
    case 'shadowsocks': return ssLine(n);
    case 'vmess': return vmessLine(n);
    case 'trojan': return trojanLine(n);
    default: return null;
  }
}

export function renderQuantumultX(nodes, _fake) {
  return b64(crlfLines(nodes.map(nodeLine).filter(Boolean)));
}
