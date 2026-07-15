#!/bin/bash
# 内鬼系统(Spyware)中央主控 · 一键安装
# 用法: 在项目目录内执行   sudo bash install.sh
# 可选: PORT=8787 sudo bash install.sh
set -e

PORT="${PORT:-8787}"
DIR="$(cd "$(dirname "$0")" && pwd)"
SVC="spyware"

echo "==================================="
echo "  内鬼系统 (Spyware) 一键安装"
echo "==================================="
echo "  安装目录: $DIR"
echo "  监听端口: 127.0.0.1:$PORT"
echo

# root 检查(systemd 需要)
if [ "$(id -u)" != "0" ]; then
  echo "✗ 请用 root 运行:  sudo bash install.sh"
  exit 1
fi

# Python 检查
if ! command -v python3 >/dev/null 2>&1; then
  echo "✗ 未找到 python3, 请先安装 Python 3.8+"
  exit 1
fi
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
echo "✓ Python $PYV"

# 依赖(pymysql 仅 v2board 连接器需要, 装不上不阻断)
if python3 -m pip install --quiet pymysql 2>/dev/null || pip3 install --quiet pymysql 2>/dev/null; then
  echo "✓ pymysql 已就绪"
else
  echo "! pymysql 未装成功; 接 v2board 前手动执行: pip3 install pymysql"
fi

# systemd 服务
cat > /etc/systemd/system/${SVC}.service <<EOF
[Unit]
Description=内鬼系统 (Spyware) 中央主控
After=network.target

[Service]
WorkingDirectory=$DIR
ExecStart=$(command -v python3) -m spyware.web --host 127.0.0.1 --port $PORT
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${SVC}
sleep 1

echo
if systemctl is-active --quiet ${SVC}; then
  echo "✓ 服务已启动并设为开机自启"
else
  echo "✗ 服务未能启动, 查看: journalctl -u ${SVC} -n 30"
  exit 1
fi

echo
echo "==================================="
echo "  安装完成"
echo "==================================="
echo "  本地地址: http://127.0.0.1:$PORT  (仅本机, 需反代对外)"
echo
echo "  下一步(aaPanel/宝塔):"
echo "   1) 网站 → 加站点(绑域名) → SSL 申请 Let's Encrypt → 开强制 HTTPS"
echo "   2) 站点 → 反向代理 → 目标 http://127.0.0.1:$PORT"
echo "   3) 反代配置里加一行:  proxy_set_header X-Forwarded-Proto \$scheme;"
echo "   4) 打开 https://你的域名/register 注册管理员"
echo
echo "  服务管理:  systemctl {start|stop|restart|status} ${SVC}"
echo "  查看日志:  journalctl -u ${SVC} -f"
echo "  卸载:      systemctl disable --now ${SVC} && rm /etc/systemd/system/${SVC}.service"
