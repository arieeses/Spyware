"""命令行入口。

  python3 -m neigui.cli ingest --log sample/sub.log
  python3 -m neigui.cli load-users --users sample/users.json
  python3 -m neigui.cli analyze [--level 高 中] [--all]
"""
from __future__ import annotations

import argparse
import json

from .config import CONFIG
from .pipeline import analyze
from .runner import ingest_logfile
from .store import Store

LEVEL_ICON = {"高": "🔴", "中": "🟠", "低": "🟡", "正常": "⚪"}


def cmd_ingest(args) -> None:
    """增量导入: 记录读取 offset, 重跑/定时只读新增行(cron 安全)。--reset 强制重读。"""
    store = Store()
    n, nf, _ = ingest_logfile(store, args.log, reset=args.reset)
    print(f"已导入 {n} 条新记录(匹配 {nf} 个文件) → {CONFIG.db_path}")


def cmd_sync_v2board(args) -> None:
    from .connectors.v2board import V2BoardConnector
    from .settings import load_settings

    cfg = load_settings().get("v2board")
    if not cfg:
        raise SystemExit("未找到 v2board 配置: 请复制 config.example.json 为 config.json 并填写")
    store = Store()
    n = V2BoardConnector(cfg).sync_users(store)
    print(f"已从 v2board 同步 {n} 个用户画像")


def cmd_load_users(args) -> None:
    store = Store()
    with open(args.users, encoding="utf-8") as f:
        data = json.load(f)
    for u in data:
        store.upsert_user(
            token=u["token"], user_id=u.get("user_id"), email=u.get("email"),
            plan=u.get("plan"), group_id=u.get("group_id"),
            created_at=u.get("created_at"), traffic_bytes=u.get("traffic_bytes", 0),
            banned=u.get("banned", 0),
        )
    print(f"已载入 {len(data)} 个用户画像")


def cmd_analyze(args) -> None:
    store = Store()
    results = analyze(store)
    shown = 0
    for r in results:
        if args.level and r.level not in args.level:
            continue
        if not args.all and (r.excluded or r.level == "正常"):
            continue
        print(f"\n{LEVEL_ICON.get(r.level, '')} [{r.level}] {r.token}  评分 {r.score}")
        if r.excluded:
            print(f"    排除: {r.note}")
        for s in r.signals:
            print(f"    +{s.points:<5} {s.name}: {s.detail}")
        shown += 1
    if shown == 0:
        print("无命中(试试 --all 查看全部)")
    else:
        print(f"\n共 {shown} 个命中。")


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="neigui", description="内鬼识别系统 · 检测核心(MVP)")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_ing = sub.add_parser("ingest", help="增量导入订阅拉取日志(cron 安全)")
    p_ing.add_argument("--log", required=True)
    p_ing.add_argument("--reset", action="store_true", help="忽略已记录 offset, 从头重读")
    p_ing.set_defaults(func=cmd_ingest)

    p_v2b = sub.add_parser("sync-v2board", help="从 v2board MySQL 同步用户画像")
    p_v2b.set_defaults(func=cmd_sync_v2board)

    p_usr = sub.add_parser("load-users", help="载入 v2board 用户画像(JSON)")
    p_usr.add_argument("--users", required=True)
    p_usr.set_defaults(func=cmd_load_users)

    p_an = sub.add_parser("analyze", help="分析并输出风险名单")
    p_an.add_argument("--level", nargs="*", help="只看指定档位, 如: --level 高 中")
    p_an.add_argument("--all", action="store_true", help="显示全部(含正常/排除)")
    p_an.set_defaults(func=cmd_analyze)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
