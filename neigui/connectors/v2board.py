"""v2board MySQL 只读连接器: 把 token → 用户画像(注册时间/流量/分组)同步进本地库。

需要 pymysql: pip install pymysql
强烈建议为它单独建一个**只读**数据库账号。
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ..store import Store


def _epoch_to_iso(ts) -> str | None:
    """v2board 的 created_at 是 unix 时间戳(整数)。"""
    if ts in (None, "", 0):
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except (ValueError, OSError, TypeError):
        return None


class V2BoardConnector:
    def __init__(self, cfg: dict):
        self.cfg = cfg

    def _connect(self, read_timeout=None):
        """read_timeout=None: 不限(批量同步用); 详情页订单查询传小值快速失败。
        connect_timeout 固定 5s(仅约束建连, 库不可达时不长时间卡住)。"""
        try:
            import pymysql
        except ImportError as e:
            raise SystemExit("缺少依赖: 请先 `pip install pymysql`") from e
        c = self.cfg
        return pymysql.connect(
            host=c.get("host", "127.0.0.1"),
            port=int(c.get("port", 3306)),
            user=c["user"],
            password=c["password"],
            database=c["database"],
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5,
            read_timeout=read_timeout,
            write_timeout=30,
        )

    # v2board/Xboard 的 v2_user 列名(可在面板"字段映射"里覆盖)
    COLS_DEFAULT = {"id": "id", "token": "token", "email": "email", "plan": "plan_id",
                    "group": "group_id", "created": "created_at", "expired": "expired_at",
                    "banned": "banned", "u": "u", "d": "d"}

    def sync_users(self, store: Store, panel: str = None, paid_only: bool = False) -> int:
        """读 v2_user, upsert 到本地 users 表。流量 = u + d。panel=归属机场名。
        paid_only=True: 只同步购买过的(有套餐或有到期时间), 跳过从未购买的免费注册。"""
        prefix = self.cfg.get("prefix", "v2_")
        c = {**self.COLS_DEFAULT, **(self.cfg.get("cols") or {})}
        where = ""
        if paid_only:
            # 有套餐(plan 非空非0)或有到期时间 = 购买过; 二者皆无 = 从未购买
            where = (f" WHERE ({c['plan']} IS NOT NULL AND {c['plan']}<>0) "
                     f"OR {c['expired']} IS NOT NULL")
        sql = (
            f"SELECT {c['id']} AS id, {c['token']} AS token, {c['email']} AS email, "
            f"{c['plan']} AS plan_id, {c['group']} AS group_id, {c['created']} AS created_at, "
            f"{c['expired']} AS expired_at, "
            f"(COALESCE({c['u']},0) + COALESCE({c['d']},0)) AS traffic, {c['banned']} AS banned "
            f"FROM {prefix}user{where}"
        )
        conn = self._connect()
        n = 0
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
                for row in cur.fetchall():
                    if not row.get("token"):
                        continue
                    store.upsert_user(
                        token=row["token"],
                        user_id=row.get("id"),
                        email=row.get("email"),
                        plan=str(row.get("plan_id") or ""),
                        group_id=row.get("group_id"),
                        created_at=_epoch_to_iso(row.get("created_at")),
                        expired_at=_epoch_to_iso(row.get("expired_at")),
                        traffic_bytes=int(row.get("traffic") or 0),
                        banned=int(row.get("banned") or 0),
                        panel=panel,
                        commit=False,   # 批量, 结束统一提交(大幅提速)
                    )
                    n += 1
            store.commit()
            store.bump_data_version()   # 同步改了用户数据, 让风险分析缓存失效
        finally:
            conn.close()
        return n

    def sync_traffic30(self, store: Store, panel: str = None, days: int = 30) -> int:
        """从 v2_stat_user 汇总近 days 天每用户上下行, 写入本地 up30/down30。返回覆盖用户数。
        v2_stat_user: user_id / u / d / record_type('d'=按天) / record_at(unix)。失败静默(不影响同步)。"""
        import time as _t
        prefix = self.cfg.get("prefix", "v2_")
        since = int(_t.time()) - days * 86400
        conn = self._connect(read_timeout=60)
        by_uid = {}
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT user_id, SUM(u) u30, SUM(d) d30 FROM {prefix}stat_user "
                    f"WHERE record_type='d' AND record_at>=%s GROUP BY user_id", (since,))
                for row in cur.fetchall():
                    by_uid[row["user_id"]] = (row.get("u30") or 0, row.get("d30") or 0)
        finally:
            conn.close()
        if by_uid:
            store.update_traffic30(panel, by_uid)
        return len(by_uid)

    _ORDER_STATUS = {0: "待支付", 1: "开通中", 2: "已取消", 3: "已完成", 4: "已折抵"}

    def query_orders(self, user_id, limit: int = 20):
        """实时查该用户订单(v2_order)。金额单位分→元。"""
        prefix = self.cfg.get("prefix", "v2_")
        conn = self._connect(read_timeout=8)  # 详情页要快, 慢就放弃
        out = []
        try:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT trade_no, total_amount, status, created_at "
                    f"FROM {prefix}order WHERE user_id=%s ORDER BY id DESC LIMIT %s",
                    (user_id, limit))
                for row in cur.fetchall():
                    ca = _epoch_to_iso(row.get("created_at"))
                    out.append({
                        "trade_no": row.get("trade_no"),
                        "amount": round((row.get("total_amount") or 0) / 100, 2),
                        "status": self._ORDER_STATUS.get(row.get("status"), row.get("status")),
                        "created_at": ca[:10] if ca else "",
                    })
        finally:
            conn.close()
        return out

    # 非协议节点的 v2_server_* 表(排除)
    NON_NODE_SUFFIX = {"group", "route"}

    def detect_nodes(self, store, panel: str):
        """探测该面板用到的协议 + 节点统计。返回 (协议列表, 节点数, 中转数)。

        - 自动发现所有 v2_server_* 表(排除 group/route), 新增自定义协议表也能读到;
        - 若表有 `protocol` 列(如 v2node 统一表), 用每行的 protocol 值当真实协议
          (v2node 集成的 vless/vmess/hysteria/自定义 都能读出); 否则用表名后缀。
        """
        prefix = self.cfg.get("prefix", "v2_")
        base = prefix + "server_"
        conn = self._connect()
        protos, total, relay, nodes = set(), 0, 0, []
        try:
            with conn.cursor() as cur:
                cur.execute("SHOW TABLES")
                all_tables = [list(r.values())[0] for r in cur.fetchall()]
                tables = [t for t in all_tables
                          if t.startswith(base) and t[len(base):] not in self.NON_NODE_SUFFIX]
                for tbl in tables:
                    suffix = tbl[len(base):]
                    try:
                        cur.execute(f"SHOW COLUMNS FROM `{tbl}`")
                        cols = {r["Field"] for r in cur.fetchall()}
                        sel = "id, name, parent_id, host, `show`, group_id"
                        if "protocol" in cols:
                            sel += ", protocol"
                        cur.execute(f"SELECT {sel} FROM `{tbl}`")
                        rows = cur.fetchall()
                    except Exception:  # noqa: BLE001
                        continue
                    for r in rows:
                        proto = (r.get("protocol") or suffix) if "protocol" in cols else suffix
                        shown = int(r.get("show") or 0)
                        is_relay = r.get("parent_id") is not None
                        # 协议列表只统计"可见节点"(show=1, 即订阅里真正下发的)
                        if shown:
                            protos.add(proto)
                            total += 1
                            relay += 1 if is_relay else 0
                        nodes.append({
                            "proto": proto, "table": suffix, "id": r.get("id"),
                            "name": r.get("name"), "relay": is_relay,
                            "show": shown, "host": r.get("host"),
                            "group_id": r.get("group_id"),
                        })
        finally:
            conn.close()
        proto_list = sorted(protos)
        if panel is not None:
            store.set_kv(f"protocols::{panel}", ",".join(proto_list))
            store.set_kv(f"nodes::{panel}", json.dumps(nodes, ensure_ascii=False))
        return proto_list, total, relay
