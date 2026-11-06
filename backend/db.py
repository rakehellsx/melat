"""ClickHouse 22.3 HTTP/native access, typed results and bounded bulk inserts."""
import json
import math
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path


def _load_env():
    path = Path(os.environ.get('MELAT_ENV_FILE', Path(__file__).resolve().parent.parent / '.env'))
    if path.exists():
        for line in path.read_text().splitlines():
            match = re.match(r'\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$', line)
            if match:
                os.environ.setdefault(match[1], match[2])


_load_env()
DATABASE_URL = os.environ.get('DATABASE_URL', 'clickhouse://default@127.0.0.1:8123/netmeta')
_url = urllib.parse.urlparse(DATABASE_URL)
if _url.scheme not in ('clickhouse', 'clickhouse+native'):
    raise RuntimeError('DATABASE_URL 必须使用 clickhouse://（HTTP）或 clickhouse+native://（原生协议）')
_native = _url.scheme == 'clickhouse+native'
DATABASE = _url.path.lstrip('/') or 'netmeta'
if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', DATABASE):
    raise RuntimeError('无效的 ClickHouse 数据库名称')
_endpoint = f'http://{_url.hostname or "127.0.0.1"}:{_url.port or 8123}/'
_headers = {'X-ClickHouse-User': urllib.parse.unquote(_url.username or 'default'),
            'X-ClickHouse-Key': urllib.parse.unquote(_url.password or '')}
DATE_COLUMNS = {'start_time', 'created_at', 'started_at', 'finished_at', 'updated_at'}
NUMERIC_IDS = {'sessions', 'alerts', 'analysis_runs', 'custom_models', 'ingest_batches'}


def literal(value):
    if value is None:
        return 'NULL'
    if isinstance(value, bool):
        return '1' if value else '0'
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError('数值必须为有限数')
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo:
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        value = value.isoformat(sep=' ')
    elif isinstance(value, date):
        value = value.isoformat()
    if not isinstance(value, str):
        raise ValueError(f'不支持的查询参数类型: {type(value).__name__}')
    return "'" + value.replace('\\', '\\\\').replace("'", "\\'").replace('\0', '\\0').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t') + "'"


def bind(sql, params=None):
    if params is None:
        return sql
    parts = sql.split('%s')
    if len(parts) != len(params) + 1:
        raise ValueError('SQL 参数数量不匹配')
    return ''.join(part + literal(value) for part, value in zip(parts, params)) + parts[-1]


def _request(sql, data=None, database=True, **settings):
    options = {'output_format_json_quote_64bit_integers': 0, 'date_time_input_format': 'best_effort',
               'max_execution_time': 120, 'max_threads': 2,
               'max_bytes_before_external_sort': 67108864,
               'max_bytes_before_external_group_by': 67108864, **settings}
    if database:
        options['database'] = DATABASE
    if data is None:
        body = sql.encode()
    else:
        options['query'] = sql
        body = data
    request = urllib.request.Request(_endpoint + '?' + urllib.parse.urlencode(options), data=body, headers=_headers)
    try:
        return urllib.request.urlopen(request, timeout=180)
    except urllib.error.HTTPError as error:
        message = error.read(8000).decode(errors='replace')
        raise RuntimeError(f'ClickHouse 查询失败: {message}') from None


def _typed(row):
    for name in DATE_COLUMNS & row.keys():
        if isinstance(row[name], str) and row[name]:
            row[name] = datetime.fromisoformat(row[name])
        if isinstance(row[name], datetime) and row[name].tzinfo:
            row[name] = row[name].astimezone(timezone.utc).replace(tzinfo=None)
    return row


def _native_client(database=True, **settings):
    from clickhouse_driver import Client
    return Client(host=_url.hostname or '127.0.0.1', port=_url.port or 9000,
                  user=urllib.parse.unquote(_url.username or 'default'),
                  password=urllib.parse.unquote(_url.password or ''),
                  database=DATABASE if database else 'default',
                  connect_timeout=15, send_receive_timeout=180,
                  settings={'max_execution_time':120, 'max_threads':2,
                            'max_bytes_before_external_sort':67108864,
                            'max_bytes_before_external_group_by':67108864, **settings})


def iter_rows(sql, params=None):
    if _native:
        client = _native_client()
        try:
            iterator = client.execute_iter(bind(sql, params), with_column_types=True)
            columns = next(iterator)
            names = [name for name, _ in columns]
            for values in iterator:
                yield _typed(dict(zip(names, values)))
        finally:
            client.disconnect()
        return
    with _request(bind(sql, params).rstrip().rstrip(';') + ' FORMAT JSONEachRow') as response:
        for line in response:
            if line.strip():
                yield _typed(json.loads(line))


def query_all(sql, params=None):
    return list(iter_rows(sql, params))


def query_one(sql, params=None):
    rows = query_all(sql, params)
    return rows[0] if rows else None


def command(sql, params=None, **settings):
    if _native:
        client = _native_client(**settings)
        try:
            client.execute(bind(sql, params))
        finally:
            client.disconnect()
        return
    with _request(bind(sql, params), **settings) as response:
        response.read()


def insert_rows(table, rows):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', table):
        raise ValueError('无效表名')
    if not rows:
        return
    if _native:
        columns = list(rows[0])
        if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) for name in columns):
            raise ValueError('无效字段名')
        values = []
        for row in rows:
            record = dict(row)
            for name in DATE_COLUMNS & record.keys():
                if isinstance(record[name], str):
                    record[name] = datetime.fromisoformat(record[name])
            values.append(tuple(record[name] for name in columns))
        client = _native_client()
        try:
            client.execute(f'INSERT INTO {table} ({",".join(columns)}) VALUES', values)
        finally:
            client.disconnect()
        return
    def serialize(value):
        if isinstance(value, datetime):
            return value.isoformat(sep=' ')
        if isinstance(value, date):
            return value.isoformat()
        raise TypeError(type(value).__name__)
    data = ''.join(json.dumps(row, ensure_ascii=False, default=serialize, allow_nan=False) + '\n' for row in rows).encode()
    with _request(f'INSERT INTO {table} FORMAT JSONEachRow', data, input_format_defaults_for_omitted_fields=1) as response:
        response.read()


def _insert_values(sql, params):
    match = re.fullmatch(r'\s*INSERT INTO (\w+)\s*\(([^)]+)\)\s*VALUES\s*\((.*)\)\s*', sql, re.I | re.S)
    if not match:
        raise ValueError('INSERT 必须显式列出字段')
    table, columns, expressions = match.groups()
    columns = [column.strip() for column in columns.split(',')]
    expressions = [expression.strip() for expression in expressions.split(',')]
    values, parameters = [], iter(params or ())
    for expr in expressions:
        if expr == '%s':
            values.append(next(parameters))
        elif expr.upper() == 'NULL':
            values.append(None)
        elif expr.startswith("'") and expr.endswith("'"):
            values.append(expr[1:-1])
        else:
            values.append(int(expr))
    if len(columns) != len(values):
        raise ValueError('INSERT 字段数量不匹配')
    return table, dict(zip(columns, values))


def execute(sql, params=None):
    if re.match(r'\s*INSERT\s', sql, re.I):
        insert(sql, params)
        return 1
    delete = re.fullmatch(r'\s*DELETE FROM (\w+)(?: WHERE (.*))?\s*', sql, re.I | re.S)
    if delete:
        table, where = delete.groups()
        where = where or '1'
        count = query_one(f'SELECT count() AS c FROM {table} WHERE {where}', params)['c']
        command(f'ALTER TABLE {table} DELETE WHERE {where}', params, mutations_sync=2)
        return count
    update = re.fullmatch(r'\s*UPDATE (\w+) SET (.+?)(?: WHERE (.+))?\s*', sql, re.I | re.S)
    if update:
        table, changes, where = update.groups()
        if table == 'ingest_jobs' and 'updated_at' not in changes:
            changes += ',updated_at=now64(3)'
        command(f'ALTER TABLE {table} UPDATE {changes} WHERE {where or "1"}', params, mutations_sync=2)
        return 0
    command(sql, params)
    return 0


def insert(sql, params=None):
    from .local_state import next_id
    table, row = _insert_values(sql, params)
    if table in NUMERIC_IDS and 'id' not in row:
        row['id'] = next_id()
    insert_rows(table, [row])
    return row.get('id')


def executemany(sql, rows):
    from .local_state import reserve_ids
    if not rows:
        return
    parsed = [_insert_values(sql, row) for row in rows]
    table = parsed[0][0]
    identifiers = iter(reserve_ids(len(rows))) if table in NUMERIC_IDS else None
    values = []
    for _, row in parsed:
        if identifiers is not None:
            row.setdefault('id', next(identifiers))
        values.append(row)
    insert_rows(table, values)
