// 假订阅渲染测试。覆盖需求文档第 10 节测试要求。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectClientType, buildFakeSubscription } from '../src/gateway/fake.js';
import { validateAndNormalizeNodes } from '../src/gateway/nodes.js';
import { parseUserInfo } from '../src/gateway/userinfo.js';
import yaml from 'js-yaml';

const RAW_NODES = [
  { name: '香港 01', type: 'vmess', host: 'hk1.example.com', port: 443, uuid: '00000000-0000-0000-0000-000000000000', network: 'ws', tls: true, sni: 'hk1.example.com', path: '/ws', host_header: 'hk1.example.com' },
  { name: '日本 01', type: 'trojan', host: 'jp1.example.com', port: 443, password: 'fake-password', network: 'tcp', tls: true, sni: 'jp1.example.com', allow_insecure: false },
  { name: '新加坡 01', type: 'shadowsocks', host: 'sg1.example.com', port: 443, cipher: 'aes-128-gcm', password: 'fake-password', network: 'tcp' },
];
const NODES = validateAndNormalizeNodes(RAW_NODES);
const FAKE = { userinfo: { upload: 123456789, download: 987654321, total: 107374182400, expire: 0 }, profile_update_interval: 24, filename: 'subscribe' };

function build(type) {
  return buildFakeSubscription(FAKE, NODES, type);
}
function decode(b64) {
  return Buffer.from(b64, 'base64').toString('utf8');
}

// ---- 1) detectClientType 识别各客户端 ----
test('detectClientType 识别所有客户端类型', () => {
  const cases = {
    clash: 'clash', stash: 'clash', mihomo: 'clash', verge: 'clash',
    'sing-box': 'singbox', sing: 'singbox',
    surge: 'surge', surfboard: 'surfboard', loon: 'loon',
    'quantumult x': 'quantumultx', 'quantumult%20x': 'quantumultx', quantumultx: 'quantumultx',
    shadowrocket: 'shadowrocket',
    v2rayn: 'base64', v2rayng: 'base64', sagernet: 'base64',
    'unknown-client': 'base64',
  };
  for (const [flag, expected] of Object.entries(cases)) {
    assert.equal(detectClientType(flag, ''), expected, `flag=${flag}`);
  }
});

// ---- 2) flag 优先于 UA ----
test('flag 优先于 User-Agent', () => {
  assert.equal(detectClientType('surge', 'clash-verge/1.0'), 'surge');
  assert.equal(detectClientType('', 'clash-verge/1.0'), 'clash'); // 无 flag 才看 UA
});

// ---- 大小写不敏感 ----
test('识别大小写不敏感', () => {
  assert.equal(detectClientType('Shadowrocket', ''), 'shadowrocket');
  assert.equal(detectClientType('', 'Quantumult%20X/1.0'), 'quantumultx');
});

// ---- 3) 每种客户端基于同一组 fake_nodes 输出 ----
test('每种客户端都能基于同一组 fake_nodes 输出', () => {
  for (const type of ['clash', 'singbox', 'surge', 'surfboard', 'loon', 'quantumultx', 'shadowrocket', 'base64']) {
    const r = build(type);
    assert.equal(r.status, 200, type);
    assert.ok(r.body.length > 0, `${type} 有内容`);
  }
});

// ---- 4) base64 / shadowrocket / quantumultx 可 base64 decode ----
test('base64 / shadowrocket / quantumultx 输出可 base64 解码', () => {
  const b64 = decode(build('base64').body.toString());
  assert.match(b64, /vmess:\/\//);
  assert.match(b64, /trojan:\/\//);
  assert.match(b64, /ss:\/\//);

  const sr = decode(build('shadowrocket').body.toString());
  assert.match(sr, /^STATUS=/);
  assert.match(sr, /Expires:2099-12-31/); // expire=0 视为长期

  const qx = decode(build('quantumultx').body.toString());
  assert.match(qx, /vmess=hk1\.example\.com:443,method=chacha20-poly1305/);
  assert.match(qx, /trojan=jp1\.example\.com:443/);
  assert.match(qx, /shadowsocks=sg1\.example\.com:443,method=aes-128-gcm/);
});

// ---- 5) clash 输出包含所有 fake node 名称，且 YAML 合法 ----
test('clash 输出包含所有节点名且为合法 YAML', () => {
  const r = build('clash');
  const doc = yaml.load(r.body.toString());
  const names = doc.proxies.map((p) => p.name);
  assert.deepEqual(names, ['香港 01', '日本 01', '新加坡 01']);
  // vmess ws 结构
  const vmess = doc.proxies[0];
  assert.equal(vmess.type, 'vmess');
  assert.equal(vmess.network, 'ws');
  assert.equal(vmess['ws-opts'].headers.Host, 'hk1.example.com');
  assert.equal(vmess.servername, 'hk1.example.com');
  // trojan
  assert.equal(doc.proxies[1].type, 'trojan');
  assert.equal(doc.proxies[1].sni, 'jp1.example.com');
  // ss
  assert.equal(doc.proxies[2].type, 'ss');
  assert.equal(doc.proxies[2].cipher, 'aes-128-gcm');
  // group
  assert.deepEqual(doc['proxy-groups'][0].proxies, ['香港 01', '日本 01', '新加坡 01', 'DIRECT']);
});

// ---- singbox 输出合法 JSON，含 outbounds ----
test('singbox 输出合法 JSON 且含各节点 outbound', () => {
  const r = build('singbox');
  assert.match(r.headers['content-type'], /json/);
  const doc = JSON.parse(r.body.toString());
  const tags = doc.outbounds.map((o) => o.tag);
  assert.ok(tags.includes('香港 01') && tags.includes('日本 01') && tags.includes('新加坡 01'));
  const vmess = doc.outbounds.find((o) => o.type === 'vmess');
  assert.equal(vmess.transport.type, 'ws');
  assert.equal(vmess.tls.server_name, 'hk1.example.com');
});

// ---- 6) surfboard / loon / surge 不是 base64（明文可读）----
test('surfboard / loon / surge 输出为明文而非 base64', () => {
  const surge = build('surge').body.toString();
  assert.match(surge, /\[Proxy\]/);
  assert.match(surge, /香港 01=vmess,hk1\.example\.com,443,username=/);

  const surfboard = build('surfboard').body.toString();
  assert.match(surfboard, /\[General\]/);
  assert.match(surfboard, /新加坡 01=ss,sg1\.example\.com,443,encrypt-method=aes-128-gcm/);

  const loon = build('loon').body.toString();
  assert.match(loon, /香港 01=vmess,hk1\.example\.com,443,auto,/);
  assert.match(loon, /新加坡 01=Shadowsocks,sg1\.example\.com,443,aes-128-gcm,/);
});

// ---- 7) 响应头包含三件套 ----
test('所有假订阅响应头包含 userinfo / update-interval / disposition', () => {
  for (const type of ['clash', 'singbox', 'surge', 'surfboard', 'loon', 'quantumultx', 'shadowrocket', 'base64']) {
    const r = build(type);
    assert.equal(r.headers['subscription-userinfo'], 'upload=123456789; download=987654321; total=107374182400; expire=0', type);
    assert.equal(r.headers['profile-update-interval'], '24', type);
    assert.match(r.headers['content-disposition'], /attachment; filename=/, type);
  }
  // surfboard 文件名带 .conf
  assert.match(build('surfboard').headers['content-disposition'], /filename="subscribe\.conf"/);
  assert.match(build('clash').headers['content-disposition'], /filename="subscribe"/);
});

// ---- 8) 缺少必填字段时配置校验失败 ----
test('缺少必填字段时校验失败', () => {
  assert.throws(() => validateAndNormalizeNodes([]), /at least 1/);
  assert.throws(() => validateAndNormalizeNodes([{ type: 'vmess', host: 'h', port: 443 }]), /missing required field 'name'/);
  assert.throws(() => validateAndNormalizeNodes([{ name: 'a', type: 'vmess', host: 'h', port: 443 }]), /requires 'uuid'/);
  assert.throws(() => validateAndNormalizeNodes([{ name: 'a', type: 'trojan', host: 'h', port: 443 }]), /requires 'password'/);
  assert.throws(() => validateAndNormalizeNodes([{ name: 'a', type: 'shadowsocks', host: 'h', port: 443, password: 'p' }]), /requires 'cipher'/);
  assert.throws(() => validateAndNormalizeNodes([{ name: 'a', type: 'wut', host: 'h', port: 443 }]), /unsupported type/);
});

// ---- 真实 userinfo：解析 + 覆盖 header 与 Shadowrocket STATUS ----
test('parseUserInfo 解析 subscription-userinfo 头', () => {
  assert.deepEqual(
    parseUserInfo('upload=10; download=20; total=30; expire=1700000000'),
    { upload: 10, download: 20, total: 30, expire: 1700000000 },
  );
  // 空 expire（长期有效）-> null
  assert.deepEqual(parseUserInfo('upload=1; download=2; total=3; expire='), { upload: 1, download: 2, total: 3, expire: null });
  assert.equal(parseUserInfo(''), null);
});

test('真实 userinfo 覆盖响应头（原样透传）与 Shadowrocket STATUS', () => {
  const raw = 'upload=1073741824; download=2147483648; total=107374182400; expire=4102444800';
  const parsed = parseUserInfo(raw);
  // clash：header 原样透传真实值
  const clash = buildFakeSubscription(FAKE, NODES, 'clash', { userinfoRaw: raw, userinfo: parsed });
  assert.equal(clash.headers['subscription-userinfo'], raw);
  // shadowrocket：STATUS 行用真实到期（4102444800 = 2100-01-01 UTC）
  const sr = buildFakeSubscription(FAKE, NODES, 'shadowrocket', { userinfoRaw: raw, userinfo: parsed });
  assert.equal(sr.headers['subscription-userinfo'], raw);
  const body = Buffer.from(sr.body.toString(), 'base64').toString();
  assert.match(body, /STATUS=🚀↑:1GB,↓:2GB,TOT:100GB💡Expires:2100-01-01/);
});

// ---- vless 预留 ----
test('vless 节点可渲染（clash / singbox / base64）', () => {
  const vlessNodes = validateAndNormalizeNodes([
    { name: 'VL 01', type: 'vless', host: 'v.example.com', port: 443, uuid: '00000000-0000-0000-0000-000000000000', network: 'ws', tls: true, sni: 'v.example.com', path: '/v', flow: '' },
  ]);
  const clash = yaml.load(buildFakeSubscription(FAKE, vlessNodes, 'clash').body.toString());
  assert.equal(clash.proxies[0].type, 'vless');
  const sb = JSON.parse(buildFakeSubscription(FAKE, vlessNodes, 'singbox').body.toString());
  assert.equal(sb.outbounds[0].type, 'vless');
});
