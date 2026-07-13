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
    "ALTER TABLE sources ADD COLUMN auto INTEGER DEFAULT 0",
    "ALTER TABLE sources ADD COLUMN interval INTEGER DEFAULT 300",
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
        self.conn.commit()

    def add_pulls(self, recs: Iterable[PullRecord]) -> int:
        n = 0
        cur = self.conn.cursor()
        for r in recs:
            cur.execute(
                "INSERT INTO pulls(token, ts, ip, status, request_time, ua, uri) "
                "VALUES(?,?,?,?,?,?,?)",
                (r.token, r.ts.isoformat(), r.ip, r.status, r.request_time, r.ua, r.uri),
            )
            n += 1
        self.conn.commit()
        return n

    def upsert_user(self, token, user_id=None, email=None, plan=None, group_id=None,
                    created_at=None, traffic_bytes=0, banned=0, panel=None, commit=True) -> None:
        self.conn.execute(
            """INSERT INTO users(token, user_id, email, plan, group_id,
                                 created_at, traffic_bytes, banned, panel)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(token) DO UPDATE SET
                 user_id=excluded.user_id, email=excluded.email, plan=excluded.plan,
                 group_id=excluded.group_id, created_at=excluded.created_at,
                 traffic_bytes=excluded.traffic_bytes, banned=excluded.banned,
                 panel=COALESCE(excluded.panel, users.panel)""",
            (token, user_id, email, plan, group_id, created_at, traffic_bytes, banned, panel),
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
        self.conn.execute(
            "INSERT INTO sources(type, name, config, enabled, created_at) VALUES(?,?,?,?,?)",
            (type, name, config, enabled, datetime.now().isoformat(timespec="seconds")),
        )
        self.conn.commit()

    def delete_source(self, sid: int) -> None:
        self.conn.execute("DELETE FROM sources WHERE id=?", (sid,))
        self.conn.commit()

    def toggle_source(self, sid: int) -> None:
        self.conn.execute("UPDATE sources SET enabled=1-enabled WHERE id=?", (sid,))
        self.conn.commit()

    def set_source_auto(self, sid: int, auto: int, interval: int) -> None:
        self.conn.execute("UPDATE sources SET auto=?, interval=? WHERE id=?",
                          (auto, max(30, interval), sid))
        self.conn.commit()

    def list_sources(self):
        return self.conn.execute("SELECT * FROM sources ORDER BY id").fetchall()

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

    def list_runlog(self, limit: int = 200):
        return self.conn.execute(
            "SELECT * FROM runlog ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

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
