// 渲染器共享工具。对齐 v2board 各 Protocol 的编码习惯。

export function b64(str) {
  return Buffer.from(String(str), 'utf8').toString('base64');
}

// URL-safe base64（去 padding），对齐 v2board 的 ss:// 用户信息编码：
// base64 后 str_replace(['+','/','='], ['-','_',''])
export function urlsafeB64(str) {
  return b64(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// 对齐 PHP rawurlencode（RFC3986）：encodeURIComponent 额外编码 !*'()
export function rawurlencode(str) {
  return encodeURIComponent(String(str)).replace(
    /[!*'()]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase(),
  );
}

// 多行拼接：过滤空值，每行以 \r\n 结尾（对齐 v2board array_filter + "\r\n" 拼接）。
export function crlfLines(lines) {
  return lines.filter((l) => l != null && l !== '').map((l) => l + '\r\n').join('');
}

// ws 的 Host 头：优先 host_header，回退节点 host。
export function wsHost(node) {
  return node.hostHeader || node.host;
}

// tls 的 servername/sni：优先 sni，回退节点 host。
export function tlsServerName(node) {
  return node.sni || node.host;
}
