// fake_nodes 节点模型：归一化 + 校验（对应需求文档第 8 节）。
// 供 config.js 启动校验与各渲染器共用同一份规范化结构。

// 类型别名归一：ss -> shadowsocks
const TYPE_ALIASES = {
  ss: 'shadowsocks',
  shadowsocks: 'shadowsocks',
  vmess: 'vmess',
  vless: 'vless',
  trojan: 'trojan',
};

// 把一条原始配置节点归一化为统一结构（带默认值）。
export function normalizeNode(n) {
  const type = TYPE_ALIASES[String(n.type || '').toLowerCase()] || String(n.type || '').toLowerCase();
  return {
    name: n.name,
    type,
    host: n.host,
    port: Number(n.port),
    // 凭据
    uuid: n.uuid,
    password: n.password,
    cipher: n.cipher,
    // 传输
    network: (n.network || 'tcp').toLowerCase(),
    tls: n.tls === true,
    sni: n.sni || '',
    path: n.path || '',
    hostHeader: n.host_header || '',
    grpcServiceName: n.grpc_service_name || n.path || '',
    allowInsecure: n.allow_insecure === true,
    // vmess 特有
    alterId: n.alter_id != null ? Number(n.alter_id) : 0,
    flow: n.flow || '', // vless 预留
  };
}

// 校验并归一化整组节点。非法则抛错（config 启动 fail-fast）。
export function validateAndNormalizeNodes(fakeNodes) {
  if (!Array.isArray(fakeNodes)) throw new Error('fake_nodes must be an array');
  if (fakeNodes.length < 1) throw new Error('fake_nodes must contain at least 1 node');

  const out = [];
  fakeNodes.forEach((raw, i) => {
    const ctx = `fake_nodes[${i}]`;
    if (!raw || typeof raw !== 'object') throw new Error(`${ctx}: must be an object`);
    for (const f of ['name', 'type', 'host', 'port']) {
      if (raw[f] == null || raw[f] === '') throw new Error(`${ctx}: missing required field '${f}'`);
    }
    const node = normalizeNode(raw);
    if (!Number.isInteger(node.port) || node.port < 1 || node.port > 65535) {
      throw new Error(`${ctx}: invalid port: ${raw.port}`);
    }
    switch (node.type) {
      case 'vmess':
      case 'vless':
        if (!node.uuid) throw new Error(`${ctx}: type=${node.type} requires 'uuid'`);
        break;
      case 'trojan':
        if (!node.password) throw new Error(`${ctx}: type=trojan requires 'password'`);
        break;
      case 'shadowsocks':
        if (!node.cipher) throw new Error(`${ctx}: type=shadowsocks requires 'cipher'`);
        if (!node.password) throw new Error(`${ctx}: type=shadowsocks requires 'password'`);
        break;
      default:
        throw new Error(`${ctx}: unsupported type '${node.type}' (vmess/vless/trojan/shadowsocks)`);
    }
    out.push(node);
  });
  return out;
}
