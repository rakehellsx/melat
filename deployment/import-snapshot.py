"""Import an empty destination, or explicitly resume verified tables after interruption."""
import gzip,hashlib,json,sys
from pathlib import Path
from backend.db import query_one,insert_rows,iter_rows
from backend.runtime_schema import ensure_runtime_schema
from backend.local_state import host_lock

source=Path(sys.argv[1]);manifest=json.loads((source/'manifest.json').read_text())
verify_only='--verify-only' in sys.argv[2:]
resume='--resume' in sys.argv[2:]
ensure_runtime_schema()
for table in manifest['tables']:
    if not verify_only and not resume and query_one(f'SELECT count() c FROM {table}')['c']:
        raise RuntimeError(f'{table} 目标表非空，停止迁移以避免重复数据')
result={'tables':{}}
with host_lock('data-write',30):
    for table,expected in manifest['tables'].items():
        existing=query_one(f'SELECT count() c FROM {table}')['c']
        if resume and existing not in (0,expected['rows']):
            raise RuntimeError(f'{table} 部分写入，需要人工检查后恢复')
        if not verify_only and not (resume and existing):
            batch=[]
            with gzip.open(source/(table+'.jsonl.gz'),'rt',encoding='utf-8') as stream:
                for line in stream:
                    batch.append(json.loads(line))
                    if len(batch)>=5000:insert_rows(table,batch);batch.clear()
                if batch:insert_rows(table,batch)
        digest=hashlib.sha256();count=0
        for row in iter_rows(f'SELECT * FROM {table} ORDER BY id'):
            text=json.dumps(row,ensure_ascii=False,sort_keys=True,separators=(',',':'),default=str)
            digest.update((text+'\n').encode());count+=1
        actual={'rows':count,'sha256':digest.hexdigest()}
        if actual!=expected:raise RuntimeError(f'{table} 数据核验失败: {actual} != {expected}')
        result['tables'][table]=actual
        print(table,count,'row hashes verified',flush=True)
(source/'clickhouse-verified.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
print('All IDs and row contents preserved',flush=True)
