"""Synchronous ClickHouse mutations serialized with imports on this host."""
from contextlib import contextmanager
from .db import execute, query_all, query_one
from .local_state import host_lock, LockBusyError


class DataBusyError(ValueError):
    pass


@contextmanager
def data_write_connection(timeout=0):
    try:
        with host_lock('data-write', timeout):
            yield
    except LockBusyError as error:
        raise DataBusyError(str(error)) from error


def delete_records(entity: str, body: dict, all_rows=False):
    if not isinstance(body, dict):
        raise ValueError('删除参数必须为对象')
    if entity not in ('sessions', 'alerts'):
        raise ValueError('不支持的数据类型')
    if all_rows:
        if body.get('confirm') != 'DELETE_ALL':
            raise ValueError('请确认删除全部数据')
        where, params = '', []
    else:
        ids = body.get('ids')
        if not isinstance(ids, list) or not ids or len(ids) > 10000:
            raise ValueError('请选择 1 至 10000 条记录')
        if any(type(value) is not int or value <= 0 for value in ids):
            raise ValueError('记录 ID 必须为正整数')
        ids = list(dict.fromkeys(ids))
        where, params = ' WHERE id IN (' + ','.join(['%s'] * len(ids)) + ')', ids
    with data_write_connection():
        batches = []
        if entity == 'sessions' and not all_rows:
            batches = [row['id'] for row in query_all('SELECT DISTINCT ingest_batch_id AS id FROM sessions' + where, params)
                       if row['id'] is not None]
        deleted = execute(f'DELETE FROM {entity}{where}', params)
        if entity == 'sessions':
            if all_rows:
                execute('UPDATE ingest_batches SET flows=0')
            else:
                for batch in batches:
                    count = query_one('SELECT count() AS c FROM sessions WHERE ingest_batch_id=%s', (batch,))['c']
                    execute('UPDATE ingest_batches SET flows=%s WHERE id=%s', (count, batch))
    return {'ok': True, 'deleted': deleted}


def delete_batch(batch_id: int):
    with data_write_connection():
        execute('DELETE FROM sessions WHERE ingest_batch_id=%s', (batch_id,))
        execute('DELETE FROM ingest_batches WHERE id=%s', (batch_id,))
    return {'ok': True}
