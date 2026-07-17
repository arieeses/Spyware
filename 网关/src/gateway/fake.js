// 假订阅编排：客户端识别 + 按类型渲染 fake_nodes + 组装响应头。
// 渲染格式对齐 v2board 各 Protocol（见 renderers/）。响应头统一带
// subscription-userinfo / profile-update-interval / content-disposition（抗探测）。
import { renderClash } from './renderers/clash.js';
import { renderSingbox } from './renderers/singbox.js';
import { renderSurge, renderSurfboard } from './renderers/surge.js';
import { renderLoon } from './renderers/loon.js';
import { renderQuantumultX } from './renderers/quantumultx.js';
import { renderShadowrocket } from './renderers/shadowrocket.js';
import { renderBase64 } from './renderers/base64.js';

// 客户端识别。对齐 v2board：flag(query) 优先于 UA；整体小写；子串包含匹配。
// 顺序很重要（先匹配先返回）。
const RULES = [
  { type: 'singbox', keys: ['sing'] }, // sing / sing-box
  { type: 'clash', keys: ['clash', 'stash', 'verge', 'mihomo'] }, // clash.meta 含 clash
  { type: 'surge', keys: ['surge'] },
  { type: 'surfboard', keys: ['surfboard'] },
  { type: 'loon', keys: ['loon'] },
  { type: 'quantumultx', keys: ['quantumult%20x', 'quantumult x', 'quantumultx', 'quantumult'] },
  { type: 'shadowrocket', keys: ['shadowrocket'] },
  { type: 'base64', keys: ['v2rayn', 'v2rayng', 'sagernet'] },
];

export function detectClientType(flag, userAgent) {
  // v2board: $flag = input('flag') ?? UA; strtolower。flag 存在则只用 flag。
  const source = (flag && String(flag).trim()) ? flag : (userAgent || '');
  const hay = String(source).toLowerCase();
  for (const rule of RULES) {
    if (rule.keys.some((k) => hay.includes(k))) return rule.type;
  }
  return 'base64';
}

// 各类型：渲染器 + Content-Type + 文件名后缀。
const DISPATCH = {
  clash: { render: renderClash, contentType: 'text/yaml; charset=utf-8' },
  singbox: { render: renderSingbox, contentType: 'application/json; charset=utf-8' },
  surge: { render: renderSurge, contentType: 'text/plain; charset=utf-8' },
  surfboard: { render: renderSurfboard, contentType: 'text/plain; charset=utf-8', ext: '.conf' },
  loon: { render: renderLoon, contentType: 'text/plain; charset=utf-8' },
  quantumultx: { render: renderQuantumultX, contentType: 'text/plain; charset=utf-8' },
  shadowrocket: { render: renderShadowrocket, contentType: 'text/plain; charset=utf-8' },
  base64: { render: renderBase64, contentType: 'text/plain; charset=utf-8' },
};

function userinfoHeader(ui) {
  const u = ui || {};
  const val = (x) => (x == null ? '' : x);
  return `upload=${val(u.upload)}; download=${val(u.download)}; total=${val(u.total)}; expire=${val(u.expire)}`;
}

// 统一入口：返回 { status, headers, body(Buffer) }。
// opts:
//   filename       content-disposition 文件名（默认 fake.filename || 'subscribe'）
//   userinfo       真实 userinfo 对象 {upload,download,total,expire}（覆盖 fake.userinfo，
//                  用于 Shadowrocket STATUS 行等 body 内嵌信息）
//   userinfoRaw    真实 subscription-userinfo 头原始字符串（原样透传该响应头，保真度最高）
export function buildFakeSubscription(fakeConfig, fakeNodes, clientType, opts = {}) {
  const fake = fakeConfig || {};
  const nodes = fakeNodes || [];
  const disp = DISPATCH[clientType] || DISPATCH.base64;

  // 有效 userinfo：优先真实值，回退配置里的静态值。渲染器（如 Shadowrocket STATUS）会用它。
  const effectiveUserinfo = opts.userinfo || fake.userinfo || {};
  const effFake = { ...fake, userinfo: effectiveUserinfo };

  const body = disp.render(nodes, effFake);

  const baseName = opts.filename || fake.filename || 'subscribe';
  const fileName = baseName + (disp.ext || '');

  const headers = {
    'content-type': disp.contentType,
    // 真实头存在则原样透传（保真），否则由有效 userinfo 拼装
    'subscription-userinfo': opts.userinfoRaw || userinfoHeader(effectiveUserinfo),
    'content-disposition': `attachment; filename="${fileName}"`,
  };
  if (fake.profile_update_interval != null) {
    headers['profile-update-interval'] = String(fake.profile_update_interval);
  }

  return { status: 200, headers, body: Buffer.from(body, 'utf8') };
}
