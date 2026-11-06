"""Create the ClickHouse schema without injecting demonstration records."""
from .runtime_schema import ensure_runtime_schema


def ensure_schema():
    ensure_runtime_schema()
