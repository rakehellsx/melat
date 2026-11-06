"""Explicit, repeatable installation of the six supplied behavior models."""
import json
from pathlib import Path
from backend.db import insert_rows,query_all
from backend.local_state import host_lock
from backend.runtime_schema import ensure_runtime_schema

ensure_runtime_schema()
models=json.loads((Path(__file__).resolve().parent.parent/'db/builtin-models.json').read_text())
with host_lock('data-write',30):
    existing=query_all('SELECT id,name FROM custom_models')
    ids={row['id'] for row in existing}
    names={row['name'] for row in existing}
    missing=[row for row in models if row['id'] not in ids and row['name'] not in names]
    insert_rows('custom_models',missing)
print('Installed models:',len(missing))
