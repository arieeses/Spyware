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

-- 物化的风险评分(后台按数据变化重算; 风险名单/仪表盘直接读它, SQL 分页, 与总用户数解耦)
CREATE TABLE IF NOT EXISTS scores (
  token           TEXT PRIMARY KEY,
  score           REAL DEFAULT 0,
  level           TEXT,
  excluded        INTEGER DEFAULT 0,
  tags            TEXT,
  signals         TEXT,
  email           TEXT,
  user_id         INTEGER,
  panel           TEXT,
  plan            TEXT,
  distinct_ips    INTEGER DEFAULT 0,
  online_ips      INTEGER DEFAULT 0,
  distinct_uas    INTEGER DEFAULT 0,
  ip_shared_users INTEGER DEFAULT 0,
  pull_count      INTEGER DEFAULT 0,
  traffic_bytes   INTEGER DEFAULT 0,
  created_at      TEXT,
  expired_at      TEXT,
  last_pull       TEXT
);
CREATE INDEX IF NOT EXISTS idx_scores_score ON scores(score DESC);
CREATE INDEX IF NOT EXISTS idx_scores_level ON scores(level, score DESC);
CREATE INDEX IF NOT EXISTS idx_scores_panel ON scores(panel);

-- 特征库: 手工登记特征(IP/UA/ASN/邮箱), 命中即加分
CREATE TABLE IF NOT EXISTS signatures (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT,           -- ip | ua | asn | email
  value      TEXT,
  note       TEXT,
  created_at TEXT
);

-- 本地每日流量(同步 v2board 时一并拉入 v2_stat_user): 详情页流量记录直接读本地, 也供流量对称分析
CREATE TABLE IF NOT EXISTS traffic_daily (
  token TEXT,
  panel TEXT,
  day   INTEGER,   -- 当天 unix 时间戳
  u     INTEGER,
  d     INTEGER,
  rate  REAL,
  PRIMARY KEY (token, day)
);
CREATE INDEX IF NOT EXISTS idx_traffic_token ON traffic_daily(token);

-- 内鬼库: 一键移入的已确认内鬼账号(快照其IP/UA/ASN/邮箱, 继续反哺检测); 移入后不再进风险名单
CREATE TABLE IF NOT EXISTS insiders (
  token      TEXT PRIMARY KEY,
  email      TEXT,
  panel      TEXT,
  ips        TEXT,           -- JSON 数组
  uas        TEXT,           -- JSON 数组
  asns       TEXT,           -- JSON 数组(ASN 号)
  note       TEXT,
  added_at   TEXT
);
"""

_SCORE_COLS = ("token", "score", "level", "excluded", "tags", "signals", "email", "user_id",
               "panel", "plan", "distinct_ips", "online_ips", "distinct_uas", "ip_shared_users",
               "pull_count", "traffic_bytes", "created_at", "expired_at", "last_pull", "main_ip")


def _row_to_result(row):
    """scores 表行 → RiskResult(复用现有渲染代码)。"""
    import json as _json
    from datetime import datetime
    from .scoring import RiskResult, Signal

    def pdt(s):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s)
        except (ValueError, TypeError):
            return None
    sigs = []
    try:
        for s in _json.loads(row["signals"] or "[]"):
            sigs.append(Signal(s.get("name", ""), s.get("points", 0),
                               s.get("detail", ""), s.get("tag", "")))
    except (ValueError, TypeError):
        pass
    cols = row.keys()
    return RiskResult(
        row["token"], row["score"], row["level"], bool(row["excluded"]), signals=sigs,
        email=row["email"], user_id=row["user_id"], panel=row["panel"], plan=row["plan"],
        distinct_ips=row["distinct_ips"], distinct_uas=row["distinct_uas"],
        online_ips=row["online_ips"], ip_shared_users=row["ip_shared_users"],
        pull_count=row["pull_count"], traffic_bytes=row["traffic_bytes"],
        created_at=pdt(row["created_at"]), expired_at=pdt(row["expired_at"]),
        last_pull=pdt(row["last_pull"]),
        main_ip=(row["main_ip"] if "main_ip" in cols else None))

# 增量列(老库升级用, 新库 CREATE 后补齐)
_MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN panel TEXT",
    "ALTER TABLE users ADD COLUMN expired_at TEXT",
    "ALTER TABLE sources ADD COLUMN auto INTEGER DEFAULT 0",
    "ALTER TABLE sources ADD COLUMN interval INTEGER DEFAULT 300",
    "ALTER TABLE sources ADD COLUMN sort_order INTEGER DEFAULT 0",
    "ALTER TABLE pulls ADD COLUMN src TEXT",
    "ALTER TABLE users ADD COLUMN up30 INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN down30 INTEGER DEFAULT 0",
    "ALTER TABLE scores ADD COLUMN main_ip TEXT",
    "ALTER TABLE insiders ADD COLUMN tags TEXT",
    "ALTER TABLE users ADD COLUMN active_days90 INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN maxup_day INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN maxdown_day INTEGER DEFAULT 0",
]


class Store:
    def __init__(self, path: Optional[str] = None):
        self.conn = sqlite3.connect(path or CONFIG.db_path, timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=8000")
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")   # 读写并发: 后台算分时页面仍可读
        except sqlite3.OperationalError:
            pass
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

    def checkpoint(self) -> None:
        """把 WAL 合并进主库(备份前调用, 保证 .db 文件完整一致)。"""
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.OperationalError:
            pass

    def vacuum(self) -> None:
        """回收空洞 + 整理碎片(数据不变)。VACUUM 不能在事务内, 临时关自动事务。"""
        self.conn.commit()
        self.checkpoint()
        old = self.conn.isolation_level
        try:
            self.conn.isolation_level = None
            self.conn.execute("VACUUM")
        finally:
            self.conn.isolation_level = old

    def bump_data_version(self) -> None:
        """数据变更计数, 供分析结果缓存判断是否需要重算。"""
        self.conn.execute(
            "INSERT INTO kv(key,value) VALUES('data_version','1') "
            "ON CONFLICT(key) DO UPDATE SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT)")
        self.conn.commit()

    def data_version(self) -> str:
        row = self.conn.execute("SELECT value FROM kv WHERE key='data_version'").fetchone()
        return row[0] if row else "0"

    # —— 物化风险评分: 写(后台重算) + 读(风险名单/仪表盘, SQL 分页) ——
    def replace_scores(self, rows) -> None:
        """整表替换评分(在一个事务里 DELETE + 批量 INSERT)。rows=按 _SCORE_COLS 顺序的元组列表。"""
        ph = ",".join("?" * len(_SCORE_COLS))
        cur = self.conn.cursor()
        cur.execute("BEGIN")
        cur.execute("DELETE FROM scores")
        cur.executemany(f"INSERT INTO scores({','.join(_SCORE_COLS)}) VALUES({ph})", rows)
        self.conn.commit()

    def delete_score(self, token: str) -> None:
        """从物化评分表删除一个 token(移入内鬼库时立即生效, 不等后台重算)。"""
        self.conn.execute("DELETE FROM scores WHERE token=?", (token,))
        self.conn.commit()

    def upsert_score(self, row) -> None:
        """写入/替换单个 token 的评分(移出内鬼库时立即让它回名单)。"""
        ph = ",".join("?" * len(_SCORE_COLS))
        self.conn.execute(
            f"INSERT OR REPLACE INTO scores({','.join(_SCORE_COLS)}) VALUES({ph})", row)
        self.conn.commit()

    def score_counts(self) -> dict:
        out = {"高": 0, "中": 0, "低": 0, "正常": 0, "excluded": 0, "total": 0}
        for r in self.conn.execute("SELECT level, COUNT(*) c FROM scores GROUP BY level").fetchall():
            out[r["level"]] = r["c"]
            out["total"] += r["c"]
        row = self.conn.execute("SELECT COUNT(*) FROM scores WHERE excluded=1").fetchone()
        out["excluded"] = row[0] if row else 0
        return out

    def rename_panel(self, old: str, new: str) -> None:
        """把面板名从 old 改成 new, 同步更新所有已存的用户/评分/日志/流量/内鬼库。"""
        if not old or not new or old == new:
            return
        for tbl, col in (("users", "panel"), ("scores", "panel"), ("pulls", "src"),
                         ("traffic_daily", "panel"), ("insiders", "panel")):
            try:
                self.conn.execute(f"UPDATE {tbl} SET {col}=? WHERE {col}=?", (new, old))
            except sqlite3.OperationalError:
                pass
        self.conn.commit()
        self.bump_data_version()

    def purge_orphan_panels(self, valid) -> int:
        """删除面板不在 valid(当前 v2board 源名集合)里的遗留用户/评分(改名/删源留下的)。"""
        valid = [v for v in valid if v]
        if not valid:
            return 0
        ph = ",".join("?" * len(valid))
        cur = self.conn.execute(
            f"DELETE FROM users WHERE panel IS NOT NULL AND panel<>'' AND panel NOT IN ({ph})", valid)
        n = cur.rowcount
        self.conn.execute(
            f"DELETE FROM scores WHERE panel IS NOT NULL AND panel<>'' AND panel NOT IN ({ph})", valid)
        self.conn.commit()
        self.bump_data_version()
        return n

    def score_panels(self):
        rows = self.conn.execute(
            "SELECT DISTINCT panel FROM scores WHERE panel IS NOT NULL AND panel<>'' "
            "ORDER BY panel").fetchall()
        return [r[0] for r in rows]

    def tokens_by_terms(self, terms, asndb=None):
        """批量搜索: 返回匹配任一 term 的 token 集。term 支持
        token/邮箱(含前缀,子串) · IP(子串) · UA(子串) · ASN(as123 / 123) · 网段(CIDR)。
        最多扫一次 pulls(仅当含 IP/UA/ASN/网段类词时)。"""
        import ipaddress
        out = set()
        cidrs, subs, asn_nums = [], [], set()
        for raw in terms or []:
            t = (raw or "").strip()
            if not t:
                continue
            like = f"%{t}%"        # token/邮箱(前缀) 子串: scores 表, 便宜
            for r in self.conn.execute(
                    "SELECT token FROM scores WHERE token LIKE ? OR email LIKE ?", (like, like)).fetchall():
                out.add(r["token"])
            if "@" in t:           # 邮箱: 上面已覆盖, 不必扫 pulls
                continue
            if "/" in t:
                try:
                    cidrs.append(ipaddress.ip_network(t, strict=False)); continue
                except ValueError:
                    pass
            tl = t.lower()
            if tl.startswith("as") and tl[2:].isdigit():
                asn_nums.add(tl[2:]); continue
            if tl.isdigit():       # 纯数字: 可能是 ASN(邮箱前缀已被上面 LIKE 覆盖)
                asn_nums.add(tl)
            subs.append(tl)        # 其余当 IP/UA 子串
        if cidrs or subs or (asn_nums and asndb is not None):
            for r in self.conn.execute("SELECT token, ip, ua FROM pulls").fetchall():
                ip = r["ip"] or ""
                ua = (r["ua"] or "").lower()
                hit = False
                if ip:
                    ipl = ip.lower()
                    if subs and any(sub in ipl for sub in subs):
                        hit = True
                    elif cidrs:
                        try:
                            addr = ipaddress.ip_address(ip)
                            if any(addr in n for n in cidrs):
                                hit = True
                        except ValueError:
                            pass
                    if not hit and asn_nums and asndb is not None:
                        asn, _ = asndb.lookup(ip)
                        if asn and str(asn) in asn_nums:
                            hit = True
                if not hit and ua and subs and any(sub in ua for sub in subs):
                    hit = True
                if hit:
                    out.add(r["token"])
        return out

    def _scores_where(self, level, panel, search, ip_tokens, levels=None, token_filter=None):
        clauses, args = [], []
        if token_filter is not None:      # 批量搜索: 限定 token 集(空集=无命中)
            if token_filter:
                clauses.append("token IN (%s)" % ",".join("?" * len(token_filter)))
                args += list(token_filter)
            else:
                clauses.append("1=0")
        if levels:   # 导出: 多等级
            ph = ",".join("?" * len(levels))
            clauses.append(f"level IN ({ph})"); args += list(levels)
        elif level == "排除":
            clauses.append("excluded=1")
        elif level in ("高", "中", "低", "正常"):
            clauses.append("level=?"); args.append(level)
        if panel and panel != "all":
            clauses.append("panel=?"); args.append(panel)
        if search:
            like = f"%{search}%"
            sub, a2 = "(token LIKE ? OR email LIKE ?", [like, like]
            if ip_tokens:
                sub += " OR token IN (%s)" % ",".join("?" * len(ip_tokens))
                a2 += list(ip_tokens)
            sub += ")"
            clauses.append(sub); args += a2
        return ((" WHERE " + " AND ".join(clauses)) if clauses else ""), args

    def count_scores(self, level="all", panel="all", search="", ip_tokens=None, levels=None,
                     token_filter=None) -> int:
        where, args = self._scores_where(level, panel, search, ip_tokens or set(), levels, token_filter)
        return self.conn.execute(f"SELECT COUNT(*) FROM scores{where}", args).fetchone()[0]

    _SORT_COLS = {"score": "score", "last": "last_pull", "ips": "distinct_ips",
                  "online": "online_ips", "uas": "distinct_uas", "shared": "ip_shared_users",
                  "pull": "pull_count", "created": "created_at", "expired": "expired_at",
                  "uid": "user_id"}

    def list_scores(self, level="all", panel="all", search="", ip_tokens=None,
                    limit=10, offset=0, levels=None, sort="", sdir="desc", token_filter=None):
        where, args = self._scores_where(level, panel, search, ip_tokens or set(), levels, token_filter)
        col = self._SORT_COLS.get(sort)
        if col:
            direction = "ASC" if sdir == "asc" else "DESC"
            order = f"{col} {direction}, token"
        else:
            order = "score DESC, token"
        q = f"SELECT * FROM scores{where} ORDER BY {order} LIMIT ? OFFSET ?"
        rows = self.conn.execute(q, args + [limit, offset]).fetchall()
        return [_row_to_result(r) for r in rows]

    def accounts_by_ip(self, ip: str, limit: int = 200):
        """同IP下钻: 列出用该 IP 拉取过的账号(token/邮箱/面板)。"""
        rows = self.conn.execute(
            "SELECT DISTINCT p.token, u.email, u.panel FROM pulls p "
            "LEFT JOIN users u ON u.token=p.token WHERE p.ip=? LIMIT ?", (ip, limit)).fetchall()
        return [{"token": r["token"], "email": r["email"] or "", "panel": r["panel"] or ""}
                for r in rows]

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

    def recent_pulls(self, token: str, limit: int = 15):
        """最近 N 条拉取(倒序)。详情页只需最近几条, 不必载入该 token 全部拉取。"""
        return self.conn.execute(
            "SELECT * FROM pulls WHERE token=? ORDER BY ts DESC LIMIT ?", (token, limit)
        ).fetchall()

    def get_score(self, token: str):
        """读单个 token 已物化的评分行(详情页直接用, 免重算)。无则 None。"""
        return self.conn.execute("SELECT * FROM scores WHERE token=?", (token,)).fetchone()

    def user(self, token: str):
        return self.conn.execute("SELECT * FROM users WHERE token=?", (token,)).fetchone()

    def all_users(self):
        return self.conn.execute("SELECT * FROM users").fetchall()

    def tokens_by_ip(self, ip_like: str):
        rows = self.conn.execute(
            "SELECT DISTINCT token FROM pulls WHERE ip LIKE ?", (f"%{ip_like}%",)).fetchall()
        return {r["token"] for r in rows}

    def tokens_by_search(self, q: str, asndb=None):
        """在拉取日志里按 IP / UA 模糊匹配, 并可按 ASN 号或组织名匹配, 返回命中 token 集。"""
        q = (q or "").strip()
        if not q:
            return set()
        like = f"%{q}%"
        toks = {r["token"] for r in self.conn.execute(
            "SELECT DISTINCT token FROM pulls WHERE ip LIKE ? OR ua LIKE ?", (like, like)).fetchall()}
        # ASN 匹配: "AS45090" / "45090" 按号, 其余按组织名子串; 解析各不同 IP(bisect, 很快)
        if asndb is not None:
            ql = q.lower()
            want_num = ql[2:] if ql.startswith("as") and ql[2:].isdigit() else (ql if ql.isdigit() else None)
            match_ips = []
            for r in self.conn.execute(
                    "SELECT DISTINCT ip FROM pulls WHERE ip IS NOT NULL AND ip<>''").fetchall():
                asn, org = asndb.lookup(r["ip"])
                if not asn:
                    continue
                if (want_num and str(asn) == want_num) or (org and ql in org.lower()):
                    match_ips.append(r["ip"])
            for i in range(0, len(match_ips), 400):   # 分批 IN 查询, 避免占位符过多
                chunk = match_ips[i:i + 400]
                ph = ",".join("?" * len(chunk))
                for r in self.conn.execute(
                        f"SELECT DISTINCT token FROM pulls WHERE ip IN ({ph})", chunk).fetchall():
                    toks.add(r["token"])
        return toks

    def pull_ips_for_tokens(self, tokens) -> dict:
        """批量取一组 token 各自的拉取 IP 列表(导出用)。分批 IN 查询。"""
        out: dict = {}
        tl = list(tokens)
        for i in range(0, len(tl), 400):
            chunk = tl[i:i + 400]
            ph = ",".join("?" * len(chunk))
            for r in self.conn.execute(
                    f"SELECT DISTINCT token, ip FROM pulls WHERE token IN ({ph}) "
                    f"AND ip IS NOT NULL AND ip<>''", chunk).fetchall():
                out.setdefault(r["token"], []).append(r["ip"])
        return out

    # —— 内鬼特征库 ——
    def add_signature(self, kind: str, value: str, note: str = "") -> None:
        self.conn.execute(
            "INSERT INTO signatures(kind, value, note, created_at) VALUES(?,?,?,?)",
            (kind, value.strip(), note.strip(), datetime.now().isoformat(timespec="seconds")))
        self.conn.commit()
        self.bump_data_version()   # 影响评分, 触发重算

    def add_signatures_bulk(self, items) -> int:
        """items: [(kind, value, note)]。去重(已存在的 kind+value 跳过), 返回新增条数。一次提交/一次重算。"""
        existing = {(r["kind"], r["value"]) for r in
                    self.conn.execute("SELECT kind, value FROM signatures").fetchall()}
        now = datetime.now().isoformat(timespec="seconds")
        added = 0
        for kind, value, note in items:
            value = (value or "").strip()
            if not value or kind not in ("ip", "ua", "asn", "email"):
                continue
            if (kind, value) in existing:
                continue
            self.conn.execute(
                "INSERT INTO signatures(kind, value, note, created_at) VALUES(?,?,?,?)",
                (kind, value, (note or "").strip(), now))
            existing.add((kind, value))
            added += 1
        if added:
            self.conn.commit()
            self.bump_data_version()
        return added

    def list_signatures(self):
        return self.conn.execute("SELECT * FROM signatures ORDER BY kind, id DESC").fetchall()

    def _sig_where(self, kind, search):
        clauses, args = [], []
        if kind and kind != "all":
            clauses.append("kind=?"); args.append(kind)
        if search:
            like = f"%{search}%"
            clauses.append("(value LIKE ? OR note LIKE ?)"); args += [like, like]
        return ((" WHERE " + " AND ".join(clauses)) if clauses else ""), args

    def count_signatures(self, kind=None, search="") -> int:
        where, args = self._sig_where(kind, search)
        return self.conn.execute(f"SELECT COUNT(*) FROM signatures{where}", args).fetchone()[0]

    def list_signatures_page(self, kind=None, search="", limit=10, offset=0):
        where, args = self._sig_where(kind, search)
        return self.conn.execute(
            f"SELECT * FROM signatures{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            args + [limit, offset]).fetchall()

    def signature_kind_counts(self, search="") -> dict:
        """各类型条数(受 search 影响), 供特征库标签页角标。"""
        where, args = self._sig_where(None, search)
        rows = self.conn.execute(
            f"SELECT kind, COUNT(*) c FROM signatures{where} GROUP BY kind", args).fetchall()
        return {r["kind"]: r["c"] for r in rows}

    def delete_signature(self, sid: int) -> None:
        self.conn.execute("DELETE FROM signatures WHERE id=?", (sid,))
        self.conn.commit()
        self.bump_data_version()

    def delete_all_signatures(self) -> int:
        n = self.conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
        self.conn.execute("DELETE FROM signatures")
        self.conn.commit()
        self.bump_data_version()
        return n

    # —— 内鬼库(已确认账号, 一键移入) ——
    def add_insider(self, token, email=None, panel=None, ips=None, uas=None,
                    asns=None, note="", tags=None) -> None:
        import json as _json
        self.conn.execute(
            "INSERT INTO insiders(token, email, panel, ips, uas, asns, note, added_at, tags) "
            "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(token) DO UPDATE SET "
            "email=excluded.email, panel=excluded.panel, ips=excluded.ips, "
            "uas=excluded.uas, asns=excluded.asns, tags=excluded.tags",
            (token, email, panel, _json.dumps(ips or [], ensure_ascii=False),
             _json.dumps(uas or [], ensure_ascii=False),
             _json.dumps(asns or [], ensure_ascii=False), note,
             datetime.now().isoformat(timespec="seconds"),
             _json.dumps(tags or [], ensure_ascii=False)))
        self.conn.commit()
        self.bump_data_version()

    def score_tags(self, token: str):
        """读某 token 当前物化评分的标签(移入内鬼库时快照其行为标签)。"""
        row = self.conn.execute("SELECT tags FROM scores WHERE token=?", (token,)).fetchone()
        if not row or not row["tags"]:
            return []
        return [t for t in row["tags"].split(",") if t]

    def remove_insider(self, token) -> None:
        self.conn.execute("DELETE FROM insiders WHERE token=?", (token,))
        self.conn.commit()
        self.bump_data_version()

    def list_insiders(self):
        return self.conn.execute("SELECT * FROM insiders ORDER BY added_at DESC").fetchall()

    def insider_pull_times(self, tokens):
        """批量取每个 token 的首次/最后订阅拉取时间。返回 {token: (first_ts, last_ts)}。"""
        if not tokens:
            return {}
        ph = ",".join("?" * len(tokens))
        out = {}
        for r in self.conn.execute(
                f"SELECT token, MIN(ts) AS first_ts, MAX(ts) AS last_ts FROM pulls "
                f"WHERE token IN ({ph}) GROUP BY token", tuple(tokens)).fetchall():
            out[r["token"]] = (r["first_ts"], r["last_ts"])
        return out

    def insider_tokens(self) -> set:
        return {r["token"] for r in self.conn.execute("SELECT token FROM insiders").fetchall()}

    def tokens_by_email_substrings(self, subs) -> set:
        """邮箱前缀/关键词(子串)命中的 token 集合。供网关 feed 把邮箱前缀翻译成 token。"""
        subs = [s.strip().lower() for s in (subs or []) if s and s.strip()]
        out = set()
        for s in subs:
            for r in self.conn.execute(
                    "SELECT token FROM users WHERE email IS NOT NULL AND lower(email) LIKE ?",
                    (f"%{s}%",)):
                out.add(r["token"])
        return out

    def users_matching_email_prefixes(self, subs, limit=3000):
        """邮箱含任一前缀/关键词的账号(排除已在内鬼库的)。返回 [{token,email,panel,hit}]。供前缀审查。"""
        subs = [s.strip().lower() for s in (subs or []) if s and s.strip()]
        if not subs:
            return []
        ins = self.insider_tokens()
        seen, out = set(), []
        for s in subs:
            for r in self.conn.execute(
                    "SELECT token, email, panel FROM users "
                    "WHERE email IS NOT NULL AND lower(email) LIKE ? ORDER BY email LIMIT ?",
                    (f"%{s}%", limit)):
                t = r["token"]
                if t in ins or t in seen:
                    continue
                seen.add(t)
                out.append({"token": t, "email": r["email"], "panel": r["panel"] or "", "hit": s})
        return out

    def ip_panel_map(self) -> dict:
        """每个拉取 IP 出现在哪些面板(src)。用于「跨面板同IP」信号。"""
        out: dict = {}
        for r in self.conn.execute(
                "SELECT DISTINCT ip, src FROM pulls WHERE ip IS NOT NULL AND ip<>''").fetchall():
            out.setdefault(r["ip"], set()).add(r["src"] or "")
        return out

    def email_panel_map(self) -> dict:
        """每个邮箱在哪些面板注册过。用于「同邮箱多面板」信号。"""
        out: dict = {}
        for r in self.conn.execute(
                "SELECT DISTINCT email, panel FROM users "
                "WHERE email IS NOT NULL AND email<>''").fetchall():
            out.setdefault(r["email"], set()).add(r["panel"] or "")
        return out

    def update_traffic30(self, panel: str, by_uid: dict) -> None:
        """按 (panel, user_id) 批量写入近30天上下行。by_uid={user_id:(u30,d30)}。"""
        cur = self.conn.cursor()
        for uid, (u30, d30) in by_uid.items():
            cur.execute("UPDATE users SET up30=?, down30=? WHERE panel=? AND user_id=?",
                        (int(u30 or 0), int(d30 or 0), panel, uid))
        self.conn.commit()

    # —— 本地每日流量 ——
    def tokens_by_uid(self, panel: str) -> dict:
        rows = self.conn.execute(
            "SELECT user_id, token FROM users WHERE panel=? AND user_id IS NOT NULL",
            (panel,)).fetchall()
        return {r["user_id"]: r["token"] for r in rows}

    def clear_traffic_daily(self, panel: str) -> None:
        self.conn.execute("DELETE FROM traffic_daily WHERE panel=?", (panel,))
        self.conn.commit()

    def add_traffic_daily(self, rows) -> None:
        """rows=(token, panel, day, u, d, rate) 列表; 批量写入。"""
        self.conn.executemany(
            "INSERT OR REPLACE INTO traffic_daily(token, panel, day, u, d, rate) "
            "VALUES(?,?,?,?,?,?)", rows)
        self.conn.commit()

    def refresh_traffic30(self, panel: str, since30: int) -> None:
        """从本地每日流量重算近30天上下行, 写回 users.up30/down30。"""
        self.conn.execute(
            "UPDATE users SET "
            "up30=COALESCE((SELECT SUM(u) FROM traffic_daily t WHERE t.token=users.token AND t.day>=?),0), "
            "down30=COALESCE((SELECT SUM(d) FROM traffic_daily t WHERE t.token=users.token AND t.day>=?),0) "
            "WHERE panel=?", (since30, since30, panel))
        self.conn.commit()

    def refresh_daily_stats(self, panel: str, since90: int) -> None:
        """从本地每日流量重算近90天: 活跃天数(有流量的天) + 单日上/下行峰值, 写回 users。
        供「流量背离」判断: 每天都在用(活跃天数多)但每天上下行峰值都很小。"""
        self.conn.execute(
            "UPDATE users SET "
            "active_days90=COALESCE((SELECT COUNT(*) FROM traffic_daily t "
            "  WHERE t.token=users.token AND t.day>=? AND (t.u>0 OR t.d>0)),0), "
            "maxup_day=COALESCE((SELECT MAX(t.u) FROM traffic_daily t WHERE t.token=users.token AND t.day>=?),0), "
            "maxdown_day=COALESCE((SELECT MAX(t.d) FROM traffic_daily t WHERE t.token=users.token AND t.day>=?),0) "
            "WHERE panel=?", (since90, since90, since90, panel))
        self.conn.commit()

    def traffic_daily_for(self, token: str):
        return self.conn.execute(
            "SELECT day, u, d, rate FROM traffic_daily WHERE token=? ORDER BY day DESC",
            (token,)).fetchall()

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

    # —— 面板权限组映射(同步时缓存, 供「检查分组」纯本地判定) ——
    def set_panel_groups(self, panel, mapping) -> None:
        import json as _json
        raw = self.get_kv("panel_groups", "")
        try:
            allg = _json.loads(raw) if raw else {}
        except (ValueError, TypeError):
            allg = {}
        allg[panel or ""] = {str(k): int(v) for k, v in (mapping or {}).items()}
        self.set_kv("panel_groups", _json.dumps(allg, ensure_ascii=False))

    def get_panel_groups(self) -> dict:
        import json as _json
        raw = self.get_kv("panel_groups", "")
        try:
            return _json.loads(raw) if raw else {}
        except (ValueError, TypeError):
            return {}

    # —— 自动入库规则(命中特征库 → 移入内鬼库) ——
    # 规则 = {"id","conds":[类型...],"on":bool}; conds 全命中(AND)才触发, 规则间 OR。
    # 类型取自 {'email','ip','ua','asn'}。存 kv auto_insider_rules(JSON)。
    _VALID_COND = {"email", "ip", "subnet", "ua", "asn"}

    def get_auto_insider_rules(self):
        import json as _json
        raw = self.get_kv("auto_insider_rules", "")
        if raw:
            try:
                rules = _json.loads(raw)
                if isinstance(rules, list):
                    return rules
            except (ValueError, TypeError):
                pass
        # 首次: 从旧开关 auto_prefix_insider 迁移出一条"邮箱"规则
        on = self.get_kv("auto_prefix_insider", "1") != "0"
        return [{"id": "email", "conds": ["email"], "on": on}]

    def set_auto_insider_rules(self, rules) -> None:
        import json as _json
        clean = []
        for r in rules or []:
            conds = [c for c in (r.get("conds") or []) if c in self._VALID_COND]
            conds = sorted(set(conds))
            if not conds:
                continue
            clean.append({"id": r.get("id") or "+".join(conds),
                          "conds": conds, "on": bool(r.get("on"))})
        self.set_kv("auto_insider_rules", _json.dumps(clean, ensure_ascii=False))

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
