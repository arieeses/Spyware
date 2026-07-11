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

    def _connect(self):
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
        )

    def sync_users(self, store: Store, panel: str = None) -> int:
        """读 v2_user, upsert 到本地 users 表。流量 = u + d(上下行累计)。panel=归属机场名。"""
        prefix = self.cfg.get("prefix", "v2_")
        sql = (
            "SELECT id, email, token, plan_id, group_id, created_at, "
            "(COALESCE(u,0) + COALESCE(d,0)) AS traffic, banned "
            f"FROM {prefix}user"
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
                        traffic_bytes=int(row.get("traffic") or 0),
                        banned=int(row.get("banned") or 0),
                        panel=panel,
                    )
                    n += 1
        finally:
            conn.close()
        return n

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
                        protos.add(proto)
                        total += 1
                        is_relay = r.get("parent_id") is not None
                        relay += 1 if is_relay else 0
                        nodes.append({
                            "proto": proto, "table": suffix, "id": r.get("id"),
                            "name": r.get("name"), "relay": is_relay,
                            "show": int(r.get("show") or 0), "host": r.get("host"),
                            "group_id": r.get("group_id"),
                        })
        finally:
            conn.close()
        proto_list = sorted(protos)
        if panel is not None:
            store.set_kv(f"protocols::{panel}", ",".join(proto_list))
            store.set_kv(f"nodes::{panel}", json.dumps(nodes, ensure_ascii=False))
        return proto_list, total, relay
