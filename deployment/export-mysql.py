"""One-time legacy export. Run with the old Python environment, before stopping MySQL."""
import gzip,hashlib,json,sys
from pathlib import Path
from datetime import date,datetime
import pymysql
from backend.db import get_conn

output=Path(sys.argv[1]);output.mkdir(parents=True,exist_ok=True)
tables=('sessions','alerts','analysis_runs','custom_models','ingest_batches','ingest_jobs')
manifest={'tables':{}}
def canonical(row):
    return json.dumps(row,ensure_ascii=False,sort_keys=True,separators=(',',':'),default=str)
with get_conn() as conn:
    conn.begin()
    try:
        for table in tables:
            count=0;digest=hashlib.sha256()
            with conn.cursor(pymysql.cursors.SSDictCursor) as cur,gzip.open(output/(table+'.jsonl.gz'),'wt',encoding='utf-8') as stream:
                cur.execute(f'SELECT * FROM {table} ORDER BY id')
                for row in cur:
                    text=canonical(row);digest.update((text+'\n').encode());stream.write(text+'\n');count+=1
            manifest['tables'][table]={'rows':count,'sha256':digest.hexdigest()}
            print(table,count,flush=True)
        conn.commit()
    except BaseException:
        conn.rollback();raise
(output/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
print('Snapshot export complete',flush=True)
