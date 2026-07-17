// 端到端集成测试：起一个 stub 源站 + 网关，验证真/假订阅、路由、拒绝直连等。
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildState, StateHolder } from '../src/state.js';
import { createHandler } from '../src/gateway/handler.js';

let originServer, originPort;
let gwServer, gwPort, holder;
let directGwServer, directGwPort;
let realUiGwServer, realUiGwPort;
let tmpDir, cidrFile, cfgFile, directCfgFile;

function listen(server) {
  return new Promise((res) => server.listen(0, '127.0.0.1', () => res(server.address().port)));
}

// 简单 HTTP 客户端
function request(port, { pathUrl = '/api/v1/client/subscribe?token=abc&flag=clash', headers = {}, method = 'GET' } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: pathUrl, method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end();
  });
}

before(async () => {
  // stub 源站：返回真订阅内容 + subscription-userinfo
  originServer = http.createServer((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/yaml; charset=utf-8',
      'subscription-userinfo': 'upload=100; download=200; total=300; expire=0',
      'profile-update-interval': '12',
    });
    res.end('REAL_SUBSCRIPTION_BODY');
  });
  originPort = await listen(originServer);

  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'subgw-'));
  cidrFile = path.join(tmpDir, 'cloud.txt');
  fs.writeFileSync(cidrFile, '# test\n8.8.8.0/24\n');

  // 主配置：127.0.0.1 可信，geoip 关闭，cidr 开启
  const cfg = `
server:
  listen: "127.0.0.1:0"
  reject_direct_access: true
  allowed_methods: ["GET", "HEAD"]
  tls:
    enabled: false
trusted_proxies:
  - "127.0.0.1"
origin_failure_mode: "fake"
rate_limit:
  enabled: false
fake_latency:
  enabled: false
private_ip_decision: "fake"
origins:
  site1.example.com:
    base_url: "http://127.0.0.1:${originPort}"
allowlist:
  ips:
    - "9.9.9.9"
  cidrs: []
  asns: []
cloud_detection:
  geoip:
    enabled: false
  cidr:
    enabled: true
    files:
      - "${cidrFile}"
fake_subscription:
  userinfo:
    upload: 1
    download: 2
    total: 3
    expire: 0
  profile_update_interval: 24
  filename: "subscribe"
fake_nodes:
  - name: "香港 01"
    type: "vmess"
    host: "hk1.example.com"
    port: 443
    uuid: "00000000-0000-0000-0000-000000000000"
    network: "ws"
    tls: true
    sni: "hk1.example.com"
    path: "/ws"
    host_header: "hk1.example.com"
  - name: "新加坡 01"
    type: "shadowsocks"
    host: "sg1.example.com"
    port: 443
    cipher: "aes-128-gcm"
    password: "fake-password"
`;
  cfgFile = path.join(tmpDir, 'config.yaml');
  fs.writeFileSync(cfgFile, cfg);

  const state = await buildState(cfgFile);
  holder = new StateHolder(state);
  gwServer = http.createServer(createHandler(holder));
  gwPort = await listen(gwServer);

  // 直连拒绝测试：trusted 设为 10.0.0.1，本机 127.0.0.1 变为不可信
  const directCfg = cfg.replace('- "127.0.0.1"', '- "10.0.0.1"');
  directCfgFile = path.join(tmpDir, 'config-direct.yaml');
  fs.writeFileSync(directCfgFile, directCfg);
  const dstate = await buildState(directCfgFile);
  directGwServer = http.createServer(createHandler(new StateHolder(dstate)));
  directGwPort = await listen(directGwServer);

  // 开启 real_userinfo 的实例：假节点 + 真到期
  const realUiCfg = cfg.replace(
    'fake_subscription:\n  userinfo:',
    'fake_subscription:\n  real_userinfo:\n    enabled: true\n    cache_ttl_seconds: 300\n    timeout_seconds: 5\n  userinfo:',
  );
  const realUiCfgFile = path.join(tmpDir, 'config-realui.yaml');
  fs.writeFileSync(realUiCfgFile, realUiCfg);
  const rstate = await buildState(realUiCfgFile);
  realUiGwServer = http.createServer(createHandler(new StateHolder(rstate)));
  realUiGwPort = await listen(realUiGwServer);
});

after(() => {
  originServer?.close();
  gwServer?.close();
  directGwServer?.close();
  realUiGwServer?.close();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
});

test('real_userinfo: fake nodes but REAL subscription-userinfo from origin', async () => {
  const r = await request(realUiGwPort, {
    headers: { host: 'site1.example.com', 'x-real-ip': '8.8.8.5' }, // 云 IP -> fake 决策
    pathUrl: '/api/v1/client/subscribe?token=abc&flag=clash',
  });
  assert.equal(r.status, 200);
  // 节点是假的
  assert.match(r.body, /香港 01/);
  assert.doesNotMatch(r.body, /REAL_SUBSCRIPTION_BODY/);
  // 但 subscription-userinfo 是源站返回的真实值（stub: upload=100; download=200; total=300; expire=0）
  assert.equal(r.headers['subscription-userinfo'], 'upload=100; download=200; total=300; expire=0');
});

test('trusted proxy + residential X-Real-IP -> real subscription forwarded', async () => {
  const r = await request(gwPort, {
    headers: { host: 'site1.example.com', 'x-real-ip': '1.1.1.1' },
  });
  assert.equal(r.status, 200);
  assert.equal(r.body, 'REAL_SUBSCRIPTION_BODY');
  assert.equal(r.headers['subscription-userinfo'], 'upload=100; download=200; total=300; expire=0');
});

test('X-Real-IP empty -> fallback to X-Forwarded-For', async () => {
  const r = await request(gwPort, {
    headers: { host: 'site1.example.com', 'x-forwarded-for': '1.1.1.1' },
  });
  assert.equal(r.body, 'REAL_SUBSCRIPTION_BODY');
});

test('cloud IP (in CIDR) -> fake subscription, indistinguishable headers', async () => {
  const r = await request(gwPort, {
    headers: { host: 'site1.example.com', 'x-real-ip': '8.8.8.5' },
  });
  assert.equal(r.status, 200);
  assert.match(r.headers['content-type'], /yaml/);
  assert.equal(r.headers['subscription-userinfo'], 'upload=1; download=2; total=3; expire=0');
  assert.ok(r.headers['content-disposition']);
  assert.match(r.body, /proxies:/);
  assert.notEqual(r.body, 'REAL_SUBSCRIPTION_BODY');
});

test('allowlist IP overrides CIDR block', async () => {
  // 9.9.9.9 在白名单——白名单优先于任何阻断。
  const r = await request(gwPort, {
    headers: { host: 'site1.example.com', 'x-real-ip': '9.9.9.9' },
  });
  assert.equal(r.body, 'REAL_SUBSCRIPTION_BODY');
});

test('multiple IPs in XFF -> suspicious -> fake', async () => {
  const r = await request(gwPort, {
    headers: { host: 'site1.example.com', 'x-forwarded-for': '1.1.1.1, 2.2.2.2' },
  });
  assert.notEqual(r.body, 'REAL_SUBSCRIPTION_BODY');
  assert.match(r.body, /proxies:/);
});

test('unknown host -> 404', async () => {
  const r = await request(gwPort, {
    headers: { host: 'nope.example.com', 'x-real-ip': '1.1.1.1' },
  });
  assert.equal(r.status, 404);
});

test('disallowed method -> 405', async () => {
  const r = await request(gwPort, {
    method: 'POST',
    headers: { host: 'site1.example.com', 'x-real-ip': '1.1.1.1' },
  });
  assert.equal(r.status, 405);
});

test('private client ip -> fake', async () => {
  const r = await request(gwPort, {
    headers: { host: 'site1.example.com', 'x-real-ip': '10.0.0.5' },
  });
  assert.notEqual(r.body, 'REAL_SUBSCRIPTION_BODY');
});

test('direct access from untrusted source -> 403', async () => {
  const r = await request(directGwPort, {
    headers: { host: 'site1.example.com', 'x-real-ip': '1.1.1.1' },
  });
  assert.equal(r.status, 403);
});

test('token is not logged in plaintext (hash only) — smoke via handler success', async () => {
  // 已在其它用例覆盖响应；此处仅确认带 token 请求正常返回。
  const r = await request(gwPort, {
    headers: { host: 'site1.example.com', 'x-real-ip': '1.1.1.1' },
    pathUrl: '/api/v1/client/subscribe?token=secret123&flag=clash',
  });
  assert.equal(r.body, 'REAL_SUBSCRIPTION_BODY');
});

test('singbox fake type renders fake_nodes outbounds', async () => {
  const r = await request(gwPort, {
    headers: { host: 'site1.example.com', 'x-real-ip': '8.8.8.5' },
    pathUrl: '/api/v1/client/subscribe?token=abc&flag=sing-box',
  });
  assert.match(r.headers['content-type'], /json/);
  const parsed = JSON.parse(r.body);
  const tags = parsed.outbounds.map((o) => o.tag);
  assert.ok(tags.includes('香港 01'));
  assert.equal(parsed.route.final, 'PROXY');
});

test('cloud IP fake subscription renders fake_nodes (not hardcoded 127.0.0.1)', async () => {
  const r = await request(gwPort, {
    headers: { host: 'site1.example.com', 'x-real-ip': '8.8.8.5' },
    pathUrl: '/api/v1/client/subscribe?token=abc&flag=clash',
  });
  assert.match(r.body, /香港 01/);
  assert.match(r.body, /新加坡 01/);
  assert.doesNotMatch(r.body, /127\.0\.0\.1/); // 不再硬编码本地节点
});
