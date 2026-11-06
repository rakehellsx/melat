"""Single persistent queue worker, isolated from the web server's memory."""
import json
import threading
import time
import traceback
from .bootstrap import ensure_schema
from .runtime_schema import ensure_runtime_schema
from .db import execute, insert, query_all, query_one
from .data_management import data_write_connection
from .ingest_jobs import WORK_DIR
from .pcap_parser import parse_pcap_file
from .pcap_importer import import_flow_stream
from .local_state import host_lock, next_id


def clean_job_files(job_id):
    for suffix in ('.pcap', '.part', '.flows.sqlite', '.timestamps.pcap'):
        (WORK_DIR / f'{job_id}{suffix}').unlink(missing_ok=True)


def fail_job(job, error):
    # Compensating cleanup is repeatable after a crash; ClickHouse has no OLTP transaction.
    batch_id = job.get('batch_id')
    if batch_id:
        execute('DELETE FROM sessions WHERE ingest_batch_id=%s', (batch_id,))
        execute('DELETE FROM ingest_batches WHERE id=%s', (batch_id,))
    execute("UPDATE ingest_jobs SET status='failed', error=%s WHERE id=%s", (str(error)[:4000], job['id']))
    clean_job_files(job['id'])


def process_job(job):
    start = time.monotonic()
    source = WORK_DIR / f"{job['id']}.pcap"
    execute("UPDATE ingest_jobs SET status='processing',error=NULL WHERE id=%s", (job['id'],))
    last_progress = 0
    def packets_progress(count):
        nonlocal last_progress
        now = time.monotonic()
        if now - last_progress > 1:
            execute('UPDATE ingest_jobs SET packets=%s WHERE id=%s', (count, job['id']))
            last_progress = now
    def rows_progress(count):
        execute('UPDATE ingest_jobs SET imported=%s WHERE id=%s', (count, job['id']))
    try:
        with data_write_connection(timeout=30):
            with parse_pcap_file(source, progress=packets_progress) as parsed:
                if parsed['flowCount'] == 0:
                    raise ValueError(f"未识别到 TCP/UDP 会话（共 {parsed['packets']} 个报文）")
                job['batch_id'] = next_id()
                # Persist ownership first: an interruption before/after batch creation
                # can always be cleaned without losing track of imported sessions.
                execute('UPDATE ingest_jobs SET batch_id=%s,packets=%s WHERE id=%s',
                        (job['batch_id'], parsed['packets'], job['id']))
                insert('INSERT INTO ingest_batches (id,filename,size_bytes,packets,flows,skipped,duration_ms) '
                       'VALUES (%s,%s,%s,%s,0,%s,0)',
                       (job['batch_id'], job['filename'], job['size_bytes'], parsed['packets'], parsed['skipped']))
                imported = import_flow_stream(parsed['flows'], job['batch_id'], rows_progress)
                duration = round((time.monotonic() - start) * 1000)
                result = {'ok': True, 'batchId': job['batch_id'], 'filename': job['filename'],
                          'sizeBytes': job['size_bytes'], 'packets': parsed['packets'],
                          'skipped': parsed['skipped'], 'flows': imported['imported'],
                          'normalizedTimestamps': parsed['normalizedTimestamps'],
                          **imported, 'durationMs': duration}
                execute('UPDATE ingest_batches SET flows=%s,duration_ms=%s WHERE id=%s',
                        (imported['imported'], duration, job['batch_id']))
                execute("UPDATE ingest_jobs SET status='success',result=%s,packets=%s,imported=%s WHERE id=%s",
                        (json.dumps(result, ensure_ascii=False), parsed['packets'], imported['imported'], job['id']))
        clean_job_files(job['id'])
        print(f"Import {job['id']} complete: {result['packets']} packets, {result['imported']} sessions", flush=True)
    except Exception as error:
        traceback.print_exc()
        fail_job(job, error)


def _heartbeat():
    while True:
        (WORK_DIR / 'worker-heartbeat').touch()
        time.sleep(10)


def main():
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    ensure_schema()
    # The app and worker share a persistent, host-local lock directory.
    with host_lock('import-worker'):
        threading.Thread(target=_heartbeat, daemon=True).start()
        for stale in query_all("SELECT * FROM ingest_jobs WHERE status='processing'"):
            fail_job(stale, '导入进程已重启，本次导入已回滚，请重新上传')
        print('Import worker ready', flush=True)
        while True:
            job = query_one("SELECT * FROM ingest_jobs WHERE status='queued' ORDER BY created_at,id LIMIT 1")
            if job:
                process_job(job)
            else:
                time.sleep(1)


if __name__ == '__main__':
    main()
