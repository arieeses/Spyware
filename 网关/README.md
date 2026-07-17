# sub-gateway 订阅网关

防探测订阅反向代理。正常用户返回真订阅（回源），风险用户（云厂商 / 机房 / 扫描器 / 私有地址）返回与真订阅**难以区分**的假订阅。所有 IP 判断本地完成。

请求链路：

```text
用户 -> 阿里云国内反代(HTTPS) -> sub-gateway(HTTPS, IP 证书) -> v2b 源站(HTTPS)
```

详细设计见仓库根目录 `SUB_GATEWAY_DEVELOPMENT_CN.md`。

## 依赖

- Node.js >= 18（开发使用 Node 25）
- `js-yaml` / `maxmind` / `ipaddr.js`

```bash
npm install
```

## 运行

```bash
# 本地开发（config.yaml，TLS/GeoLite2 关闭，可直接运行）
npm start

# 指定配置文件
SUB_GATEWAY_CONFIG=./config.yaml npm start
```

- 对外服务监听 `server.listen`。
- 内部服务监听 `server.internal_listen`（仅本机）。

## 测试

```bash
npm test        # node --test，含单元 + 端到端集成测试
```

## 生产部署

1. 复制 `config.example.yaml` 为 `config.yaml` 并修改：
   - `server.tls.enabled: true`，配置 IP 证书 `cert_path` / `key_path`。
   - `server.reject_direct_access: true`。
   - `trusted_proxies` 填阿里云反代公网 IP 或出口 CIDR。
   - `server.reload_token` 换成长随机串。
   - `origins` 配置各站点 Host -> base_url 映射。
2. 放置 GeoLite2 数据：`data/GeoLite2-ASN.mmdb`（MaxMind 账号 + `geoipupdate`），并设 `cloud_detection.geoip.enabled: true`。
3. 按需补全 `data/cloud_ipv4.txt` / `data/cloud_ipv6.txt` 云厂商网段。
4. 阿里云反代 Nginx 需用 `$remote_addr` 覆盖 `X-Real-IP` / `X-Forwarded-For`（见开发文档第 4 节），并 HTTPS 回源、校验网关 IP 证书。

### 生成自签 IP 证书示例

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=YOUR_GATEWAY_IP" \
  -addext "subjectAltName=IP:YOUR_GATEWAY_IP"
```

反代侧用该 `server.crt` 作为 `proxy_ssl_trusted_certificate` 校验。

## 内部接口（仅本机）

```bash
curl http://127.0.0.1:8081/-/health          # {"ok":true}
curl http://127.0.0.1:8081/-/ready           # 就绪检查
curl -X POST -H "Authorization: Bearer <reload_token>" \
     http://127.0.0.1:8081/-/reload          # 热重载配置/数据
```

也可 `kill -HUP <pid>` 触发热重载。`SIGTERM` / `SIGINT` 优雅关闭。

## 决策顺序

方法限制 → 提取 client_ip（可信代理头）→ 校验 → 限流 → 私有/保留地址 → 白名单(ip/cidr/asn) → GeoLite2 ASN → CIDR 兜底 → 默认放行。白名单优先级最高。

## 抗探测要点

- 假订阅返回与真订阅一致的 `subscription-userinfo` / `profile-update-interval` / `content-disposition`，状态码统一 200。
- `fake_latency` 可加入随机延迟对齐回源时序。
- 回源失败默认返回假订阅（`origin_failure_mode: fake`），不暴露网关存在。
- 日志只记录 `sha256(token)`，不记录明文 token。
