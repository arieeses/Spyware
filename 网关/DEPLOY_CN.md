# sub-gateway 部署清单（pm2 + 前置 nginx）

架构：

```text
用户 → 阿里云国内反代(HTTPS) → 网关机 nginx(443, IP白名单) → 127.0.0.1:8080 (node, pm2) → v2b 源站
```

- Node 网关只监听 **127.0.0.1:8080**（明文 HTTP，不对外）。
- 对外的 HTTPS 和访问控制交给前置 nginx。
- aaPanel / 1Panel 都能装；下面命令行步骤通用，面板只是给你图形化的「Node 环境安装 / 站点 / SSL」入口。

---

## 0. 前置条件

- 一台网关服务器（国外，能直连 v2b 源站）。
- 一个解析到网关服务器的域名，如 `gateway.example.com`。
- Node.js ≥ 18（`node -v` 确认；aaPanel 在「软件商店 → Node.js 版本管理器」安装，1Panel 在「运行环境」）。
- 阿里云反代已按开发文档第 4 节配置好（用 `$remote_addr` 覆盖 `X-Real-IP`/`X-Forwarded-For`），并把请求转发到 `https://gateway.example.com`。

---

## 1. 上传代码并安装依赖

```bash
# 假设放在 /www/wwwroot/sub-gateway（aaPanel 站点根目录习惯路径，可自定义）
cd /www/wwwroot/sub-gateway
npm install --omit=dev          # 只装生产依赖
npm install -g pm2              # 若未装 pm2
```

---

## 2. 准备 GeoLite2 数据（可选但强烈建议）

```bash
# 把 GeoLite2-ASN.mmdb 放到 data/
ls data/GeoLite2-ASN.mmdb
```

没有 mmdb 就在 `config.yaml` 里设 `cloud_detection.geoip.enabled: false`，仅靠 CIDR 兜底。
获取方式：MaxMind 免费账号 + `geoipupdate`，或从可信来源下载 `GeoLite2-ASN.mmdb`。

---

## 3. 写生产配置 config.yaml

关键项（其余照 `config.example.yaml`）：

```yaml
server:
  listen: "127.0.0.1:8080"        # 只监听本机，由前置 nginx 反代
  reject_direct_access: true      # 生产必开
  tls:
    enabled: false                # TLS 交给前置 nginx
  internal_listen: "127.0.0.1:8081"
  reload_token: "换成长随机串"     # openssl rand -hex 32

# 【关键】node 的上游是本机 nginx，remote_addr 是 127.0.0.1，不是阿里云反代 IP！
trusted_proxies:
  - "127.0.0.1"
  - "::1"

origins:
  你的订阅域名.com:
    base_url: "https://真实v2b源站"

cloud_detection:
  geoip:
    enabled: true                 # 有 mmdb 就开
    db_path: "./data/GeoLite2-ASN.mmdb"
  cidr:
    enabled: true
    files:
      - "./data/cloud_ipv4.txt"
      - "./data/cloud_ipv6.txt"
```

> 注意 `origins` 的 key 是**用户订阅时用的 Host**（阿里云反代透传过来的 `$host`），不是网关域名。

---

## 4. 用 pm2 启动

```bash
cd /www/wwwroot/sub-gateway
pm2 start ecosystem.config.cjs     # 读取 ecosystem 里的 cwd 和配置路径
pm2 save                           # 保存进程列表
pm2 startup                        # 按提示执行输出的命令，实现开机自启
```

常用命令：

```bash
pm2 status
pm2 logs sub-gateway               # 看结构化 JSON 日志
pm2 restart sub-gateway            # 重启
pm2 reload sub-gateway             # 平滑重启
```

验证本机通了：

```bash
curl http://127.0.0.1:8081/-/health     # {"ok":true}
curl http://127.0.0.1:8081/-/ready      # 就绪检查
```

---

## 5. 前置 nginx（HTTPS + IP 白名单）

在面板「网站」里新建站点 `gateway.example.com`，申请/上传 SSL 证书，然后把站点 nginx 配置改成：

```nginx
server {
    listen 443 ssl;
    server_name gateway.example.com;

    ssl_certificate     /path/fullchain.pem;
    ssl_certificate_key /path/privkey.pem;

    # 只允许阿里云反代访问，其余全拒（可写多行 allow）
    allow 阿里云反代公网IP1;
    # allow 阿里云反代公网IP2;
    deny all;

    location / {
        proxy_pass http://127.0.0.1:8080;

        proxy_set_header Host $host;

        # 不要用 $remote_addr 覆盖！透传阿里云反代已写好的真实用户 IP
        proxy_set_header X-Real-IP $http_x_real_ip;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

改完 `nginx -t && nginx -s reload`（或面板里点「重载/保存」）。

---

## 6. 防火墙 / 安全组

- **对外只放 443**（给阿里云反代）。
- **8080 / 8081 保持只监听 127.0.0.1**，绝不对外暴露（配置里已是 127.0.0.1，别改成 0.0.0.0）。
- aaPanel/1Panel 的「安全 / 防火墙」里确认没有把 8080/8081 放通。

---

## 7. 端到端验证

从阿里云反代侧（或模拟其公网 IP）访问：

```bash
# 正常住宅 IP → 真订阅
curl -H "X-Real-IP: 1.2.3.4" "https://gateway.example.com/api/v1/client/subscribe?token=xxx&flag=clash"

# 云厂商 IP → 假订阅（内容为「节点维护中」占位，但响应头与真订阅一致）
curl -H "X-Real-IP: 13.32.0.5" "https://gateway.example.com/api/v1/client/subscribe?token=xxx&flag=clash"
```

`pm2 logs sub-gateway` 里应看到对应的 `decision: proxy` / `decision: fake` 日志，且 `client_ip` 是真实用户 IP（不是 127.0.0.1、也不是阿里云 IP）。

---

## 更新 / 热重载

- 改了 `config.yaml` 或换了 CIDR/mmdb：
  ```bash
  curl -X POST -H "Authorization: Bearer <reload_token>" http://127.0.0.1:8081/-/reload
  # 或
  pm2 sendSignal SIGHUP sub-gateway
  ```
- 改了代码：`git pull`（或重新上传）后 `pm2 reload sub-gateway`。

---

## 常见坑

| 现象 | 原因 | 解决 |
|---|---|---|
| 日志里 `client_ip` 全是 `127.0.0.1` | `trusted_proxies` 没填 127.0.0.1，或 nginx 没透传 X-Real-IP | 填 `127.0.0.1`/`::1`，检查 nginx `proxy_set_header X-Real-IP` |
| 所有请求都被判 `fake` | GeoLite2/CIDR 把真实用户误伤，或 client_ip 取错 | 看日志 `risk_reason`，核对 trusted_proxies |
| 启动报 `tls cert not found` | 生产配置误开了 node 的 tls | node 侧 `tls.enabled: false`，TLS 只在前置 nginx |
| 502 | node 没起来 / 端口不对 | `pm2 status`、`curl 127.0.0.1:8081/-/health` |
| 直接 curl 网关域名被拒 | `allow/deny` 生效（正常） | 只有阿里云反代 IP 能访问 |
