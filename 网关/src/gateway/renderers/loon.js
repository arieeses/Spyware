// Loon。对齐 v2board Loon.php。明文，不 base64；位置参数风格。
import { crlfLines, tlsServerName, wsHost } from './helpers.js';

function ssLine(n) {
  // 位置参数：cipher, password 直接摆放，无 key=
  return `${n.name}=Shadowsocks,${n.host},${n.port},${n.cipher},${n.password},fast-open=false,udp=true`;
}

function vmessLine(n) {
  const parts = [`${n.name}=vmess`, n.host, n.port, 'auto', n.uuid, 'fast-open=false', 'udp=true', 'alterId=0'];
  if (n.network === 'ws') {
    parts.push('transport=ws', `path=${n.path || '/'}`, `host=${wsHost(n)}`);
  } else {
    parts.push('transport=tcp');
    if (n.tls) parts.push('over-tls=true'); // 仅 tcp 追加 over-tls
  }
  if (n.tls) {
    parts.push(`skip-cert-verify=${!!n.allowInsecure}`, `tls-name=${tlsServerName(n)}`);
  }
  return parts.join(',');
}

function trojanLine(n) {
  const parts = [`${n.name}=trojan`, n.host, n.port, n.password];
  if (n.sni) parts.push(`tls-name=${n.sni}`);
  parts.push('fast-open=false', 'udp=true');
  if (n.allowInsecure) parts.push('skip-cert-verify=true');
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

export function renderLoon(nodes, _fake) {
  return crlfLines(nodes.map(nodeLine).filter(Boolean));
}
