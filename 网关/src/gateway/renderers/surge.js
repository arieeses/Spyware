// Surge 与 Surfboard。对齐 v2board Surge.php / Surfboard.php。
// 明文 .conf，不 base64；逗号分隔 key=val；每行 \r\n，空值过滤。
import { crlfLines, tlsServerName, wsHost } from './helpers.js';

function ssLine(n) {
  return `${n.name}=ss,${n.host},${n.port},encrypt-method=${n.cipher},password=${n.password},tfo=true,udp-relay=true`;
}

function vmessLine(n) {
  const parts = [
    `${n.name}=vmess`, n.host, n.port,
    `username=${n.uuid}`, 'vmess-aead=true', 'tfo=true', 'udp-relay=true',
  ];
  if (n.tls) {
    parts.push('tls=true', `skip-cert-verify=${!!n.allowInsecure}`, `sni=${tlsServerName(n)}`);
  }
  if (n.network === 'ws') {
    parts.push('ws=true', `ws-path=${n.path || '/'}`, `ws-headers=Host:${wsHost(n)}`);
  }
  return parts.join(',');
}

function trojanLine(n) {
  const parts = [
    `${n.name}=trojan`, n.host, n.port,
    `password=${n.password}`, `sni=${n.sni || n.host}`, 'tfo=true', 'udp-relay=true',
  ];
  if (n.allowInsecure) parts.push('skip-cert-verify=true');
  return parts.join(',');
}

// vmess/trojan/ss 之外的类型（vless）Surge 不支持，跳过。
function nodeLine(n) {
  switch (n.type) {
    case 'shadowsocks': return ssLine(n);
    case 'vmess': return vmessLine(n);
    case 'trojan': return trojanLine(n);
    default: return null;
  }
}

function build(nodes) {
  const lines = nodes.map(nodeLine).filter(Boolean);
  const names = nodes.filter((n) => nodeLine(n)).map((n) => n.name);
  const group = `PROXY = select, ${[...names, 'DIRECT'].join(', ')}`;
  return { lines, group };
}

export function renderSurge(nodes, _fake) {
  const { lines, group } = build(nodes);
  return `[Proxy]\r\n${crlfLines(lines)}\r\n[Proxy Group]\r\n${group}\r\n\r\n[Rule]\r\nFINAL,PROXY\r\n`;
}

export function renderSurfboard(nodes, _fake) {
  const { lines, group } = build(nodes);
  return (
    `[General]\r\nloglevel = notify\r\n\r\n` +
    `[Proxy]\r\n${crlfLines(lines)}\r\n` +
    `[Proxy Group]\r\n${group}\r\n\r\n` +
    `[Rule]\r\nFINAL,PROXY\r\n`
  );
}
