"""Stream uploads to disk; parsing is performed by the dedicated import worker."""
import asyncio
import json
import os
import shutil
import uuid
from pathlib import Path
from urllib.parse import unquote

import anyio
from fastapi.responses import JSONResponse
from .db import execute, query_one
from .pcap_parser import validate_capture_header

PCAP_MAX_BYTES = 2 * 1024 * 1024 * 1024
WORK_DIR = Path(os.environ.get('PCAP_WORK_DIR', '/tmp/melat-imports'))
UPLOAD_LIMIT = asyncio.Semaphore(1)
DISK_RESERVE = 512 * 1024 * 1024


async def receive_upload(request):
    length = request.headers.get('content-length')
    try:
        declared = int(length) if length is not None else None
    except ValueError:
        return JSONResponse({'detail': '无效的文件长度'}, status_code=400)
    if declared is not None and (declared < 0 or declared > PCAP_MAX_BYTES):
        return JSONResponse({'detail': '单文件不能超过 2 GB'}, status_code=413)
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    job_id = uuid.uuid4().hex
    part, source = WORK_DIR / f'{job_id}.part', WORK_DIR / f'{job_id}.pcap'
    async with UPLOAD_LIMIT:
        size, header, last_disk_check = 0, b'', 0
        try:
            if shutil.disk_usage(WORK_DIR).free < (declared or 0) + DISK_RESERVE:
                return JSONResponse({'detail': '磁盘可用空间不足，请清理导入文件后重试'}, status_code=507)
            async with await anyio.open_file(part, 'wb') as stream:
                part.chmod(0o600)
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > PCAP_MAX_BYTES:
                        return JSONResponse({'detail': '单文件不能超过 2 GB'}, status_code=413)
                    if len(header) < 24:
                        header = (header + chunk)[:24]
                        if len(header) >= 24:
                            validate_capture_header(header)
                    if size - last_disk_check >= 64 * 1024 * 1024:
                        if shutil.disk_usage(WORK_DIR).free < len(chunk) + DISK_RESERVE:
                            return JSONResponse({'detail': '磁盘可用空间不足'}, status_code=507)
                        last_disk_check = size
                    await stream.write(chunk)
            validate_capture_header(header)
            part.replace(source)
            filename = Path(unquote(request.headers.get('x-filename', 'upload.pcap'))).name[:255]
            await anyio.to_thread.run_sync(lambda: execute(
                'INSERT INTO ingest_jobs (id,filename,size_bytes,status) VALUES (%s,%s,%s,%s)',
                (job_id, filename or 'upload.pcap', size, 'queued')))
            return JSONResponse({'ok': True, 'jobId': job_id, 'status': 'queued', 'sizeBytes': size}, status_code=202)
        except ValueError as error:
            return JSONResponse({'detail': str(error)}, status_code=400)
        except OSError as error:
            return JSONResponse({'detail': '文件写入失败，请检查磁盘空间'}, status_code=507)
        finally:
            part.unlink(missing_ok=True)
            # Only successful queue entries retain their files.
            if source.exists():
                row = await anyio.to_thread.run_sync(lambda: query_one('SELECT id FROM ingest_jobs WHERE id=%s', (job_id,)))
                if not row:
                    source.unlink(missing_ok=True)


def get_job(job_id):
    row = query_one('SELECT * FROM ingest_jobs WHERE id=%s', (str(job_id),))
    if not row:
        return None
    result = row['result']
    if isinstance(result, str):
        result = json.loads(result)
    return {'id': row['id'], 'filename': row['filename'], 'sizeBytes': int(row['size_bytes']),
            'status': row['status'], 'packets': int(row['packets']), 'imported': int(row['imported']),
            'result': result, 'error': row['error']}
