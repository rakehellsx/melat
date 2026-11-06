"""Idempotent ClickHouse 22.3 schema creation; never reload demo data."""
from pathlib import Path
from .db import command, query_one, DATABASE
from .local_state import host_lock


def ensure_runtime_schema():
    with host_lock('schema', timeout=60):
        command(f'CREATE DATABASE IF NOT EXISTS {DATABASE}', database=False)
        version = query_one('SELECT version() AS version')['version']
        if version != '22.3.10.22':
            raise RuntimeError(f'需要 ClickHouse 22.3.10.22，当前版本 {version}')
        text = (Path(__file__).resolve().parent.parent / 'db/clickhouse.sql').read_text()
        for statement in text.split(';'):
            if statement.strip():
                command(statement)
