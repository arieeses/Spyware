"""SQLite 存储: 订阅拉取记录 + v2board 用户画像快照。"""
from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Iterable, List, Optional

from .config import CONFIG
from .log_parser import PullRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS pulls (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  token        TEXT NOT NULL,
  ts           TEXT NOT NULL,
  ip           TEXT,
  status       INTEGER,
  request_time REAL,
  ua           TEXT,
  uri          TEXT
);
CREATE INDEX IF NOT EXISTS idx_pulls_token ON pulls(token);

CREATE TABLE IF NOT EXISTS users (
  token         TEXT PRIMARY KEY,
  user_id       INTEGER,
  email         TEXT,
  plan          TEXT,
  group_id      INTEGER,
  created_at    TEXT,
  traffic_bytes INTEGER,
  banned        INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ingest_state (
  path   TEXT PRIMARY KEY,
  offset INTEGER,
  inode  INTEGER
);

CREATE TABLE IF NOT EXISTS sources (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  type       TEXT,            -- logfile | v2board
  name       TEXT,
  config     TEXT,            -- JSON
  enabled    INTEGER DEFAULT 1,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS kv (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS runlog (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  ts   TEXT,
  kind TEXT,
  name TEXT,
  ok   INTEGER,
  msg  TEXT
);

CREATE TABLE IF NOT EXISTS admins (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT UNIQUE,
  email      TEXT,
  salt       TEXT,
  pwd_hash   TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  token    TEXT PRIMARY KEY,
  admin_id INTEGER,
  expires  TEXT
);

CREATE TABLE IF NOT EXISTS resets (
  token    TEXT PRIMARY KEY,
  admin_id INTEGER,
  expires  TEXT,
  used     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS entities (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT,           -- backend | relay | template
  name       TEXT,
  detail     TEXT,
  config     TEXT,
  created_at TEXT
);
"""

# 增量列(老库升级用, 新库 CREATE 后补齐)
_MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN panel TEXT",
    "ALTER TABLE users ADD COLUMN expired_at TEXT",
    "ALTER TABLE sources ADD COLUMN auto INTEGER DEFAULT 0",
    "ALTER TABLE sources ADD COLUMN interval INTEGER DEFAULT 300",
    "ALTER TABLE sources ADD COLUMN sort_order INTEGER DEFAULT 0",
    "ALTER TABLE pulls ADD COLUMN src TEXT",
]


class Store:
    def __init__(self, path: Optional[str] = None):
        self.conn = sqlite3.connect(path or CONFIG.db_path, timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=8000")
        self.conn.executescript(SCHEMA)
        for stmt in _MIGRATIONS:
            try:
                self.conn.execute(stmt)
            except sqlite3.OperationalError:
                pass  # 列已存在
        self._dedup_pulls_index()
        self.conn.commit()

    def _dedup_pulls_index(self) -> None:
        """给 pulls 建唯一索引, 让重复读同一行日志幂等(重读整个文件不产生重复)。
        老库若已有重复行, 先删重再建索引。"""
        try:
            self.conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_pulls_uniq "
                "ON pulls(token, ts, ip, uri)")
        except sqlite3.IntegrityError:
            self.conn.execute(
                "DELETE FROM pulls WHERE id NOT IN "
                "(SELECT MIN(id) FROM pulls GROUP BY token, ts, ip, uri)")
            self.conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_pulls_uniq "
                "ON pulls(token, ts, ip, uri)")

    def purge_unpaid_users(self, panel: Optional[str] = None) -> int:
        """删除本地"从未购买"用户(无套餐 且 无到期时间)。panel 限定某机场; 返回删除数。
        有拉取记录的 token 仍会通过 pulls 出现在风险名单, 不受影响。"""
        cond = "(plan IS NULL OR plan IN ('','0')) AND (expired_at IS NULL OR expired_at='')"
        args = []
        if panel is not None:
            cond += " AND panel=?"
            args.append(panel)
        cur = self.conn.execute(f"DELETE FROM users WHERE {cond}", args)
        self.conn.commit()
        if cur.rowcount:
            self.bump_data_version()
        return cur.rowcount

    def bump_data_version(self) -> None:
        """数据变更计数, 供分析结果缓存判断是否需要重算。"""
        self.conn.execute(
            "INSERT INTO kv(key,value) VALUES('data_version','1') "
            "ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)")
        self.conn.commit()

    def data_version(self) -> str:
        row = self.conn.execute("SELECT value FROM kv WHERE key='data_version'").fetchone()
        return row[0] if row else "0"

    def add_pulls(self, recs: Iterable[PullRecord], src: Optional[str] = None) -> int:
        n = 0
        cur = self.conn.cursor()
        for r in recs:
            cur.execute(
                "INSERT OR IGNORE INTO pulls(token, ts, ip, status, request_time, ua, uri, src) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (r.token, r.ts.isoformat(), r.ip, r.status, r.request_time, r.ua, r.uri, src),
            )
            n += cur.rowcount  # 被 IGNORE 的重复行 rowcount=0
        self.conn.commit()
        if n:
            self.bump_data_version()
        return n

    def list_pulls(self, limit: int = 200, offset: int = 0, src: Optional[str] = None):
        """日志库: 按时间倒序列出拉取记录, 可按来源(数据源名)过滤。"""
        sql = "SELECT token, ts, ip, status, request_time, ua, uri, src FROM pulls"
        args: list = []
        if src:
            sql += " WHERE src=?"
            args.append(src)
        sql += " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        return self.conn.execute(sql, args).fetchall()

    def count_pulls_by_src(self, src: Optional[str] = None) -> int:
        if src:
            row = self.conn.execute("SELECT COUNT(*) FROM pulls WHERE src=?", (src,)).fetchone()
        else:
            row = self.conn.execute("SELECT COUNT(*) FROM pulls").fetchone()
        return row[0] if row else 0

    def clear_pulls(self, src: Optional[str] = None) -> int:
        """清空日志库: src 指定则只删该来源, 否则全清。返回删除条数。"""
        cur = self.conn.cursor()
        if src:
            cur.execute("DELETE FROM pulls WHERE src=?", (src,))
        else:
            cur.execute("DELETE FROM pulls")
        self.conn.commit()
        self.bump_data_version()
        return cur.rowcount

    def ip_user_counts(self, since_iso: Optional[str] = None) -> dict:
        """每个 IP 被多少个不同账号(token)使用。since_iso 限定时间窗口(在线判定)。
        返回 {ip: distinct_token_count}, 供「IP共用账号」信号用。"""
        sql = "SELECT ip, COUNT(DISTINCT token) c FROM pulls"
        args: list = []
        if since_iso:
            sql += " WHERE ts>=?"
            args.append(since_iso)
        sql += " GROUP BY ip"
        return {r["ip"]: r["c"] for r in self.conn.execute(sql, args).fetchall() if r["ip"]}

    def ip_user_counts_for_token(self, token: str, since_iso: Optional[str] = None) -> dict:
        """只统计某 token 用过的 IP 各自被多少账号共用(详情页用, 避免全表扫描)。"""
        sql = ("SELECT ip, COUNT(DISTINCT token) c FROM pulls WHERE ip IN "
               "(SELECT DISTINCT ip FROM pulls WHERE token=?")
        args: list = [token]
        if since_iso:
            sql += " AND ts>=?"
            args.append(since_iso)
        sql += ")"
        if since_iso:
            sql += " AND ts>=?"
            args.append(since_iso)
        sql += " GROUP BY ip"
        return {r["ip"]: r["c"] for r in self.conn.execute(sql, args).fetchall() if r["ip"]}

    def pull_srcs(self):
        """日志库里出现过的来源名(去重), 用于分类子标签。"""
        rows = self.conn.execute(
            "SELECT DISTINCT src FROM pulls WHERE src IS NOT NULL AND src<>'' "
            "ORDER BY src").fetchall()
        return [r[0] for r in rows]

    def upsert_user(self, token, user_id=None, email=None, plan=None, group_id=None,
                    created_at=None, traffic_bytes=0, banned=0, panel=None,
                    expired_at=None, commit=True) -> None:
        self.conn.execute(
            """INSERT INTO users(token, user_id, email, plan, group_id,
                                 created_at, traffic_bytes, banned, panel, expired_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(token) DO UPDATE SET
                 user_id=excluded.user_id, email=excluded.email, plan=excluded.plan,
                 group_id=excluded.group_id, created_at=excluded.created_at,
                 traffic_bytes=excluded.traffic_bytes, banned=excluded.banned,
                 panel=COALESCE(excluded.panel, users.panel), expired_at=excluded.expired_at""",
            (token, user_id, email, plan, group_id, created_at, traffic_bytes, banned, panel, expired_at),
        )
        if commit:
            self.conn.commit()

    def commit(self) -> None:
        self.conn.commit()

    def tokens(self) -> List[str]:
        rows = self.conn.execute("SELECT DISTINCT token FROM pulls").fetchall()
        return [r["token"] for r in rows]

    def pulls_for(self, token: str):
        return self.conn.execute(
            "SELECT * FROM pulls WHERE token=? ORDER BY ts", (token,)
        ).fetchall()

    def user(self, token: str):
        return self.conn.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()

    def all_users(self):
        return self.conn.execute("SELECT * FROM users").fetchall()

    def tokens_by_ip(self, ip_like: str):
        rows = self.conn.execute(
            "SELECT DISTINCT token FROM pulls WHERE ip LIKE ?", (f"%{ip_like}%",)).fetchall()
        return {r["token"] for r in rows}

    def update_source_config(self, sid: int, config: str) -> None:
        self.conn.execute("UPDATE sources SET config=? WHERE id=?", (config, sid))
        self.conn.commit()

    def update_source(self, sid: int, name: str, config: str) -> None:
        self.conn.execute("UPDATE sources SET name=?, config=? WHERE id=?", (name, config, sid))
        self.conn.commit()

    def get_ingest_state(self, path: str):
        return self.conn.execute(
            "SELECT offset, inode FROM ingest_state WHERE path=?", (path,)
        ).fetchone()

    def set_ingest_state(self, path: str, offset: int, inode: int) -> None:
        self.conn.execute(
            "INSERT INTO ingest_state(path, offset, inode) VALUES(?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET offset=excluded.offset, inode=excluded.inode",
            (path, offset, inode),
        )
        self.conn.commit()

    # —— 数据源管理 ——
    def add_source(self, type: str, name: str, config: str, enabled: int = 1) -> None:
        row = self.conn.execute("SELECT COALESCE(MAX(sort_order),0)+1 FROM sources").fetchone()
        nxt = row[0] if row else 1
        self.conn.execute(
            "INSERT INTO sources(type, name, config, enabled, created_at, sort_order) VALUES(?,?,?,?,?,?)",
            (type, name, config, enabled, datetime.now().isoformat(timespec="seconds"), nxt),
        )
        self.conn.commit()

    def delete_source(self, sid: int) -> int:
        """删除数据源, 并清理它带进来的数据(v2board→其同步用户; 日志源→其入库日志)。
        返回清理的记录数。"""
        s = self.get_source(sid)
        purged = 0
        if s is not None:
            name = s["name"]
            if s["type"] == "v2board":
                cur = self.conn.execute("DELETE FROM users WHERE panel=?", (name,))
                purged += cur.rowcount
                # 该面板协议/节点快照
                self.conn.execute("DELETE FROM kv WHERE key IN (?,?)",
                                  (f"protocols::{name}", f"nodes::{name}"))
            else:  # 日志源: 删除以其名字或其标签为 src 的拉取记录
                import json as _json
                srcs = {name}
                try:
                    cfg = _json.loads(s["config"] or "{}")
                    if cfg.get("panel"):
                        srcs.add(cfg["panel"])
                except (ValueError, TypeError):
                    pass
                for sv in srcs:
                    cur = self.conn.execute("DELETE FROM pulls WHERE src=?", (sv,))
                    purged += cur.rowcount
        self.conn.execute("DELETE FROM sources WHERE id=?", (sid,))
        self.conn.commit()
        if purged:
            self.bump_data_version()
        return purged

    def move_source(self, sid: int, direction: str) -> None:
        """在同类型(前端面板/日志接入)内上移/下移一位。"""
        s = self.get_source(sid)
        if s is None:
            return
        same = [r["id"] for r in self.list_sources() if r["type"] == s["type"]]
        if sid not in same:
            return
        i = same.index(sid)
        j = i - 1 if direction == "up" else i + 1
        if not (0 <= j < len(same)):
            return
        same[i], same[j] = same[j], same[i]
        for pos, rid in enumerate(same):
            self.conn.execute("UPDATE sources SET sort_order=? WHERE id=?", (pos, rid))
        self.conn.commit()

    def toggle_source(self, sid: int) -> None:
        self.conn.execute("UPDATE sources SET enabled=1-enabled WHERE id=?", (sid,))
        self.conn.commit()

    def set_source_auto(self, sid: int, auto: int, interval: int) -> None:
        self.conn.execute("UPDATE sources SET auto=?, interval=? WHERE id=?",
                          (auto, max(30, interval), sid))
        self.conn.commit()

    def list_sources(self):
        return self.conn.execute("SELECT * FROM sources ORDER BY sort_order, id").fetchall()

    def get_source(self, sid: int):
        return self.conn.execute("SELECT * FROM sources WHERE id=?", (sid,)).fetchone()

    # —— 节点管理实体(后端机/中转/协议模板) ——
    def add_entity(self, kind: str, name: str, detail: str = "", config: str = "") -> None:
        self.conn.execute(
            "INSERT INTO entities(kind, name, detail, config, created_at) VALUES(?,?,?,?,?)",
            (kind, name, detail, config, datetime.now().isoformat(timespec="seconds")))
        self.conn.commit()

    def delete_entity(self, eid: int) -> None:
        self.conn.execute("DELETE FROM entities WHERE id=?", (eid,))
        self.conn.commit()

    def list_entities(self, kind: str):
        return self.conn.execute("SELECT * FROM entities WHERE kind=? ORDER BY id", (kind,)).fetchall()

    # —— 键值配置 ——
    def get_kv(self, key: str, default=None):
        r = self.conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default

    def set_kv(self, key: str, value) -> None:
        self.conn.execute(
            "INSERT INTO kv(key, value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        self.conn.commit()

    # —— 管理员 / 会话 / 重置 ——
    def admin_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) c FROM admins").fetchone()["c"]

    def create_admin(self, username, email, salt, pwd_hash) -> None:
        self.conn.execute(
            "INSERT INTO admins(username, email, salt, pwd_hash, created_at) VALUES(?,?,?,?,?)",
            (username, email, salt, pwd_hash, datetime.now().isoformat(timespec="seconds")))
        self.conn.commit()

    def get_admin_by_name(self, username):
        return self.conn.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()

    def get_admin_by_email(self, email):
        if not email:
            return None
        return self.conn.execute("SELECT * FROM admins WHERE email=?", (email,)).fetchone()

    def get_admin_by_id(self, aid):
        return self.conn.execute("SELECT * FROM admins WHERE id=?", (aid,)).fetchone()

    def update_admin_password(self, aid, salt, pwd_hash) -> None:
        self.conn.execute("UPDATE admins SET salt=?, pwd_hash=? WHERE id=?", (salt, pwd_hash, aid))
        self.conn.commit()

    def create_session(self, token, admin_id, expires) -> None:
        self.conn.execute("INSERT INTO sessions(token, admin_id, expires) VALUES(?,?,?)",
                          (token, admin_id, expires))
        self.conn.commit()

    def get_session(self, token):
        return self.conn.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()

    def delete_session(self, token) -> None:
        self.conn.execute("DELETE FROM sessions WHERE token=?", (token,))
        self.conn.commit()

    def create_reset(self, token, admin_id, expires) -> None:
        self.conn.execute("INSERT INTO resets(token, admin_id, expires, used) VALUES(?,?,?,0)",
                          (token, admin_id, expires))
        self.conn.commit()

    def get_reset(self, token):
        return self.conn.execute("SELECT * FROM resets WHERE token=?", (token,)).fetchone()

    def mark_reset_used(self, token) -> None:
        self.conn.execute("UPDATE resets SET used=1 WHERE token=?", (token,))
        self.conn.commit()

    # —— 运行日志 ——
    def add_runlog(self, kind: str, name: str, ok: bool, msg: str) -> None:
        self.conn.execute(
            "INSERT INTO runlog(ts, kind, name, ok, msg) VALUES(?,?,?,?,?)",
            (datetime.now().isoformat(timespec="seconds"), kind, name, 1 if ok else 0, msg))
        self.conn.execute(
            "DELETE FROM runlog WHERE id NOT IN (SELECT id FROM runlog ORDER BY id DESC LIMIT 500)")
        self.conn.commit()

    def list_runlog(self, limit: int = 200, kind: str = None, name: str = None):
        where, params = [], []
        if kind:
            where.append("kind=?"); params.append(kind)
        if name:
            where.append("name=?"); params.append(name)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        params.append(limit)
        return self.conn.execute(
            f"SELECT * FROM runlog{w} ORDER BY id DESC LIMIT ?", params).fetchall()

    def clear_runlog(self, kind: str = None, name: str = None) -> None:
        where, params = [], []
        if kind:
            where.append("kind=?"); params.append(kind)
        if name:
            where.append("name=?"); params.append(name)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        self.conn.execute(f"DELETE FROM runlog{w}", params)
        self.conn.commit()

    # —— 清理演示/示例数据 ——
    def purge_demo(self) -> int:
        demo = ("tok_normal", "tok_insider1", "tok_spoof", "tok_newscout", "tok_selfsvc")
        qs = ",".join("?" * len(demo))
        n = self.conn.execute(f"SELECT COUNT(*) c FROM pulls WHERE token IN ({qs})", demo).fetchone()["c"]
        self.conn.execute(f"DELETE FROM pulls WHERE token IN ({qs})", demo)
        self.conn.execute(f"DELETE FROM users WHERE token IN ({qs})", demo)
        self.conn.execute("DELETE FROM sources WHERE name='示例日志'")
        self.conn.commit()
        return n

    def close(self) -> None:
        self.conn.close()
