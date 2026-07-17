# 假订阅渲染器 vs v2board 源码 比对说明

本文件记录 `sub-gateway` 的假订阅渲染器与 v2board 官方源码
(`github.com/v2board/v2board`,**`dev` 分支**,协议目录 `app/Protocols/`)的对齐情况与**有意的差异**。

> 说明：v2board 的 `app/Protocols/` 目录只存在于 `dev` 分支;`master` 是重构前的旧结构。
> 客户端识别在 `app/Http/Controllers/V1/Client/ClientController.php`。

## 客户端识别（对齐）

v2board 逻辑：`flag = input('flag') ?? User-Agent` → `strtolower` → 遍历协议类做**子串包含**匹配。

我们的 [detectClientType](src/gateway/fake.js) 完全对齐：

- `flag`(query)优先，无则用 `User-Agent`。
- 整体转小写，子串包含匹配，大小写不敏感。
- `clash.meta` / `mihomo` / `stash` / `verge` 归入 clash。
- QuantumultX 识别 `quantumult%20x` / `quantumult x` / `quantumultx`。

## 逐协议还原度

| 协议 | 文件 | base64 | 还原度 | 关键点（与 v2board 一致） |
|---|---|---|---|---|
| Clash / Meta / Stash / Mihomo | [clash.js](src/gateway/renderers/clash.js) | 否(YAML) | ✅ 高 | `type: ss`、vmess `cipher: auto`+`alterId:0`、`ws-opts`、`grpc-opts.grpc-service-name`、trojan `sni`/`skip-cert-verify`、含 vless |
| Surge | [surge.js](src/gateway/renderers/surge.js) | 否 | ✅ 高 | vmess `username=`+`vmess-aead=true`、`ws-path`/`ws-headers=Host:`、`encrypt-method=`、`tfo=true` |
| Surfboard | [surge.js](src/gateway/renderers/surge.js) | 否 | ✅ 高 | 同 Surge 行格式 + `[General]` 头，文件名 `subscribe.conf` |
| Loon | [loon.js](src/gateway/renderers/loon.js) | 否(明文) | ✅ 高 | 位置参数、vmess `auto`+`alterId=0`、ws `transport=ws`、tcp+tls 才 `over-tls=true`、`tls-name=` |
| QuantumultX | [quantumultx.js](src/gateway/renderers/quantumultx.js) | **是** | ✅ 高 | vmess `method=chacha20-poly1305`(硬编码)、`tls-verification` 与 allow_insecure **反转**、`obfs=wss/ws`、`obfs-host=` |
| Shadowrocket | [shadowrocket.js](src/gateway/renderers/shadowrocket.js) | **是** | ✅ 高 | 首行 `STATUS=🚀↑:..GB,↓:..GB,TOT:..GB💡Expires:Y-m-d`、vmess `base64(auto:uuid@host:port)?query`、布尔用 `1`/int |
| General(base64) | [base64.js](src/gateway/renderers/base64.js) | **是** | ✅ 高 | vmess 标准 `base64(json)` 全字符串字段、ss urlsafe `base64(cipher:password)`、trojan `?allowInsecure=&peer=&sni=` |
| Sing-box | [singbox.js](src/gateway/renderers/singbox.js) | 否(JSON) | ⚠️ 见下 | — |

## 有意的差异（重要）

### 1. Sing-box —— stock v2board 没有此渲染器

**stock `v2board/v2board` 不含 `SingBox.php`**（sing-box 订阅是 Xboard / lotusboard 等 fork 才加的；v2board 里的 `SagerNet.php` 输出的是 base64 URI，不是 sing-box JSON）。

因此本项目的 sing-box 渲染**不以 v2board 为基准**，而是按 **sing-box 官方 config schema** 生成 `outbounds`（vmess/vless/trojan/shadowsocks + `tls`/`transport{ws|grpc}` + `selector`），保证 sing-box 客户端能解析。若要严格对齐某个 fork，可再按其 `SingBox.php` 调整。

### 2. 响应头统一化 —— 比 v2board 更严格（为抗探测）

v2board 各协议响应头不一致：Shadowrocket / General **不设** `subscription-userinfo`；Loon 用 `Subscription-Userinfo`（首字母大写）；Clash 才有完整头。

本项目**所有假订阅统一返回** `subscription-userinfo` + `profile-update-interval` + `content-disposition`（需求文档第 7、9 节）。这是**有意为之**：目的是让假订阅与真订阅在响应头层面不可区分，抗探测性优于 v2board 原版。

### 2.1 真实 subscription-userinfo（假节点 + 真到期/流量）

v2board 的 `subscription-userinfo` 值来自用户 DB（`u` / `d` / `transfer_enable` / `expired_at`）。
不同客户端读取方式：Clash/Meta/Stash/Surge/Loon/QuantumultX 读 **HTTP 响应头**（Loon 大写 `Subscription-Userinfo`）；
Shadowrocket 额外读 body 首行 `STATUS=...`；General/base64 类不显示。

本网关本地无 DB，为让**到期/流量为真**，提供开关 `fake_subscription.real_userinfo`：

- 风险用户命中后，网关用其 token 向源站拉一次 `subscription-userinfo` 头（强制 `flag=clash` 以确保源站返回该头），
  **只取头、立即取消 body**，因此**真实节点不会下载、更不会泄露给扫描器**。
- 真实头**原样透传**到响应头；Shadowrocket 的 STATUS 行、以及所有客户端的头显示，均使用真实的 upload/download/total/expire。
- 按 token 缓存（`cache_ttl_seconds`）+ 超时（`timeout_seconds`）+ 失败回退到静态 `userinfo`，避免高频探测打爆源站。

效果：扫描器即便持有真实账号，对比"干净 IP"与"云 IP"两次订阅时，到期时间一致（都是真的），假节点线更可信，更难被识别为"被区别对待"。实现见 [src/gateway/userinfo.js](src/gateway/userinfo.js)。

### 3. ss 的 password 字段

v2board 里 shadowsocks 的 `password` 复用用户 uuid。本项目 fake_nodes 为 ss 提供**独立的 `password` 字段**（假凭据），语义更直观，格式不受影响。

### 4. 简化项

- Clash 未输出 v2board 保留的**冗余旧字段** `ws-path`/`ws-headers`（新客户端用 `ws-opts`，不影响解析）。
- 未实现 v2board Meta 的 `2022-blake3-*` ss 特殊 password 派生、vless Reality 的 `reality-opts`（假节点用不到，如需可补）。
- 未实现 v2board 从模板文件(`resources/rules/*.clash.yaml`)注入规则集，改用最小 `MATCH,PROXY` 规则。

## 验证

- 单元 + 集成测试见 [test/fake.test.js](test/fake.test.js)、[test/integration.test.js](test/integration.test.js)，覆盖需求文档第 10 节全部用例。
- 已实跑确认 8 种客户端基于同一组 `fake_nodes` 输出对应原生格式，base64/shadowrocket/quantumultx 可解码，clash/singbox 结构正确，surge/surfboard/loon 为明文。
