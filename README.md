# 内鬼系统

面向 v2board 机场的内鬼识别与风控中央面板。识别「拉取订阅后攻击/侦察节点」的内鬼。

- 立项与信号设计:[内鬼识别方案.md](内鬼识别方案.md)
- 架构与路线:[架构设计.md](架构设计.md)

## 当前进度

**增量 1 · 检测核心**(本目录 `neigui/`)——纯 Python 标准库,零外部依赖。
从订阅拉取日志 + v2board 用户画像,产出**可解释的风险名单**。

已实现信号:机房ASN、工具UA、UA伪造、机器规整拉取、流量背离、注册即侦察 + 自有IP排除层。
待接入(需节点侧日志 / JA3):拉取后IP静默、扫描式短连、TLS指纹、跨token关联。

## 生产部署

完整步骤见 [部署文档.md](部署文档.md)。速览:

```bash
# 中央主控(一台 VPS, Python 3.8+)
git clone https://github.com/arieeses/Spyware.git /opt/spyware && cd /opt/spyware
pip3 install pymysql
python3 -m neigui.web --host 127.0.0.1 --port 8787   # 前面套 Nginx HTTPS 反代
```
- 首次打开注册管理员 → 加 v2board 面板(只读同步)→ 加探针源、在各面板机一键装探针。
- 面板机 Nginx 配 `neigui` 日志格式 + `real_ip`;订阅网关按 `/api/decision` 分级下发。

## 本地试用 / 可视化控制后台

```bash
python3 -m neigui.web            # 打开 http://127.0.0.1:8787
```

**首次打开**会跳到 `/register` 创建管理员账号,之后用账号密码登录。

- **登录 / 注册 / 忘记密码**:忘记密码时,重置链接**输出到服务器控制台**(自托管安全方式);也可运行 `python3 -m neigui.web resetpw <用户名>` 直接改密。
- **数据库迁移**:单文件 SQLite,系统设置页可**备份下载**;迁移只需拷 `neigui.db`,或设 `NEIGUI_DB=/路径/neigui.db` / config.json 的 `db_path`。
- **自动升级**:系统设置 › 检查更新,git 部署可**点击 `git pull` 并自动重启**。

侧边栏分类导航(aaPanel 风格):仪表盘 / 接入管理(v2board·1Panel·aaPanel)/ 风险管理 / 运行 / 系统。面板功能:

- **数据源管理**:增 / 删 / 启停 日志源(Nginx neigui 日志)和 v2board(MySQL 只读)
- **手动运行**:单源「运行」或「▶ 手动运行全部」
- **自动运行**:勾选 + 设间隔(秒),后台调度定时导入日志 + 同步 v2board
- **风险名单**:可疑 token 评分 + 可解释命中信号,刷新即重算
- **JSON API**:`/api/risks`

> ⚠️ 面板无鉴权,仅绑定 127.0.0.1,**勿直接暴露公网**(v2board 密码存在本地库)。
> 换端口:`--port 9000`;停止:`pkill -f neigui.web`。

## 命令行(等价能力, 便于 cron)

```bash
python3 -m neigui.cli ingest --log sample/sub.log   # 增量导入(cron 安全)
python3 -m neigui.cli load-users --users sample/users.json
python3 -m neigui.cli sync-v2board                  # 需 config.json
python3 -m neigui.cli analyze                        # --all / --level 高 中
```

> 重置:`rm -f neigui.db`。

示例结果:`tok_spoof`(高85)`tok_insider1`(高80)被抓;`tok_normal`(住宅+客户端+有流量)放行;
`tok_selfsvc`(自有IP)排除;`tok_newscout`(仅注册轨迹弱信号)不误报——正是设计的抗误杀行为。

## Nginx 日志格式

在 1Panel/aaPanel 的站点配置里,给订阅路由单独记一份日志:

```nginx
log_format neigui '$time_iso8601|$http_x_forwarded_for|$remote_addr|'
                  '$status|$request_time|$http_user_agent|'
                  '$arg_token|$request_uri';

location /api/v1/client/subscribe {
    access_log /www/wwwlogs/neigui_sub.log neigui;
    proxy_pass http://v2board_backend;
}
```

CDN/反代场景必配 `real_ip` 还原真实 IP,否则 IP/ASN 信号失效。

## 配置

- `neigui/config.py` —— 权重与阈值(按真实数据校准)
- `data/self_ips.txt` —— 自有基础设施 IP(命中即排除;只填自己的具体IP,别填整个机房ASN)
- `data/hosting_cidrs.txt` —— 机房网段(**生产强烈建议替换为 MaxMind GeoLite2-ASN**)
- `data/ua_clients.txt` —— 客户端 UA 白名单(正则)

## 下一步

增量 2:v2board MySQL 只读 connector(自动补全用户画像)+ 日志推送落库。
详见[架构设计.md](架构设计.md) §4 路线。
