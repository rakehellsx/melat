"""数据库访问层：PyMySQL 连接（MySQL 8.0+ / TiDB 兼容）"""
import os
import re
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse, unquote

import pymysql
import pymysql.cursors


def _load_env():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            m = re.match(r"\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$", line)
            if m and m.group(1) not in os.environ:
                os.environ[m.group(1)] = m.group(2)


_load_env()

DATABASE_URL = os.environ.get("DATABASE_URL", "")
if not DATABASE_URL:
    raise RuntimeError("缺少 DATABASE_URL 环境变量（mysql://user:pass@host:port/dbname）")

_u = urlparse(DATABASE_URL)
DB_CONF = dict(
    host=_u.hostname or "127.0.0.1",
    port=_u.port or 3306,
    user=unquote(_u.username or "root"),
    password=unquote(_u.password or ""),
    database=_u.path.lstrip("/"),
    charset="utf8mb4",
    autocommit=True,
    connect_timeout=15,
    read_timeout=120,
)


@contextmanager
def get_conn():
    conn = pymysql.connect(**DB_CONF, cursorclass=pymysql.cursors.DictCursor)
    try:
        yield conn
    finally:
        conn.close()


def query_all(sql: str, params=None) -> list[dict]:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(sql, params or ())
        return cur.fetchall()


def query_one(sql: str, params=None) -> dict | None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(sql, params or ())
        return cur.fetchone()


def execute(sql: str, params=None) -> int:
    with get_conn() as conn, conn.cursor() as cur:
        return cur.execute(sql, params or ())


def insert(sql: str, params=None) -> int:
    """执行 INSERT 并返回自增主键"""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(sql, params or ())
        return cur.lastrowid


def executemany(sql: str, rows: list[tuple]):
    with get_conn() as conn, conn.cursor() as cur:
        cur.executemany(sql, rows)
