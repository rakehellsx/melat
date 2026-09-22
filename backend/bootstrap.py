"""启动引导：数据库为空时自动导入 db/init.sql（建表 + 演示数据）"""
import logging
from pathlib import Path

from .db import query_all, get_conn

log = logging.getLogger("bootstrap")

INIT_SQL = Path(__file__).resolve().parent.parent / "db" / "init.sql"
TABLES = ("sessions", "analysis_runs", "alerts", "ingest_batches", "custom_models")


def _schema_ready() -> bool:
    try:
        rows = query_all("SHOW TABLES")
        names = {list(r.values())[0] for r in rows}
        return set(TABLES) <= names
    except Exception as e:  # 连接失败等，交由请求路径报错
        log.warning("schema check failed: %s", e)
        return True  # 不阻断启动


def ensure_schema() -> None:
    """表不存在时自动执行 init.sql 完成初始化，保证全新数据库开箱可用"""
    if _schema_ready():
        return
    if not INIT_SQL.exists():
        log.warning("init.sql not found, skip auto init")
        return
    log.info("database schema missing, importing %s ...", INIT_SQL)
    text = INIT_SQL.read_text(encoding="utf-8")
    stmts = [s.strip() for s in text.split(";\n") if s.strip() and not s.strip().startswith("--")]
    with get_conn() as conn, conn.cursor() as cur:
        for s in stmts:
            # 去掉语句内的注释行
            lines = [ln for ln in s.splitlines() if not ln.strip().startswith("--")]
            stmt = "\n".join(lines).strip()
            if stmt:
                cur.execute(stmt)
    log.info("database initialized: %d statements executed", len(stmts))
