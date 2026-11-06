"""通用模型执行引擎（Python 版）
按白名单把模型定义（维度/度量/过滤/阈值）编译为参数化聚合查询并执行。
"""
import time

from .db import query_all
from .contracts import DIMENSIONS, METRIC_FIELDS

# ---------- 字段 → SQL 表达式（白名单，杜绝注入） ----------

COLUMN_EXPR = {
    "sessionId": "session_id", "startTime": "start_time",
    "srcIp": "src_ip", "dstIp": "dst_ip",
    "srcPort": "src_port", "dstPort": "dst_port",
    "protocol": "protocol", "appProtocol": "app_protocol",
    "direction": "direction", "dstCountry": "dst_country",
    "upBytes": "up_bytes", "downBytes": "down_bytes",
    "upPackets": "up_packets", "downPackets": "down_packets",
    "duration": "duration", "threatScore": "threat_score",
    "totalBytes": "(up_bytes + down_bytes)",
    "totalPackets": "(up_packets + down_packets)",
}


def _meta_text(key: str) -> str:
    return f"nullIf(nullIf(if(JSONType(meta, '{key}')='String',JSONExtractString(meta, '{key}'),JSONExtractRaw(meta, '{key}')), ''), 'null')"


def _meta_num(key: str) -> str:
    raw = f"nullIf(JSONExtractRaw(meta, '{key}'), 'null')"
    field = next((f for f in DIMENSIONS if f['key'] == key), {})
    if field.get('type') == 'boolean':
        return f"multiIf({raw}='true',1.,{raw}='false',0.,toFloat64OrNull({raw}))"
    return f"toFloat64OrNull({raw})"



def _field_expr(key: str, numeric: bool = False) -> str:
    if key in COLUMN_EXPR:
        return COLUMN_EXPR[key]
    # meta 字段 key 仅允许字母数字与下划线（白名单前置校验已保证，双保险）
    if not key.replace("_", "").isalnum():
        raise ValueError(f"非法字段: {key}")
    return _meta_num(key) if numeric else _meta_text(key)


def _dim_expr(key: str) -> str:
    dim = next((d for d in DIMENSIONS if d["key"] == key), None)
    if not dim:
        raise ValueError(f"非法维度字段: {key}")
    return _field_expr(key, bool(dim.get("numeric")))


def _metric_expr(field: str, agg: str) -> str:
    mdef = next((m for m in METRIC_FIELDS if m["key"] == field), None)
    if not mdef:
        raise ValueError(f"非法度量字段: {field}")
    if agg not in mdef["aggs"]:
        raise ValueError(f"字段 {field} 不支持聚合 {agg}")
    if agg == "count":
        return "COUNT(*)"
    # meta 文本字段（如 dnsQueryName）做 countDistinct 时不能数值化，
    # 否则 CAST(... AS DOUBLE) 会把所有字符串折叠为 0，去重计数恒为 1
    numeric = mdef.get("numeric", False) and agg != "countDistinct"
    expr = _field_expr(field, numeric)
    fn = {"sum": "SUM", "avg": "AVG", "max": "MAX", "min": "MIN"}[agg] if agg != "countDistinct" else None
    return f"COUNT(DISTINCT {expr})" if fn is None else f"{fn}({expr})"


OP_SQL = {"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}


def _filter_conds(model_def: dict) -> tuple[list[str], list]:
    conds, params = [], []
    for f in model_def["filters"]:
        dim = next((d for d in DIMENSIONS if d["key"] == f["field"]), None)
        mfield = next((m for m in METRIC_FIELDS if m["key"] == f["field"]), None)
        if not dim and (not mfield or f["field"] == "*"):
            raise ValueError(f"非法过滤字段: {f['field']}")
        numeric = bool(dim.get("numeric")) if dim else (
            mfield["key"] not in ("srcIp", "dstIp", "dnsQueryName"))
        expr = _field_expr(f["field"], numeric)
        value = f["value"]
        if dim and dim.get("type") == "boolean":
            text = str(value).strip().lower()
            if text not in ("true", "false", "1", "0", "是", "否"):
                raise ValueError("布尔字段请使用 true/false、是/否或 1/0")
            value = 1 if text in ("true", "1", "是") else 0
        if f["op"] == "like":
            conds.append(f"{expr} LIKE %s")
            params.append(f"%{f['value']}%")
        else:
            op = OP_SQL.get(f["op"])
            if not op:
                raise ValueError(f"非法算子: {f['op']}")
            conds.append(f"{expr} {op} %s")
            params.append(float(value) if numeric else str(value))
    return conds, params


def _model_sql(model_def: dict):
    dims = model_def["dimensions"]
    mets = model_def["metrics"]
    if not dims:
        raise ValueError("至少选择一个维度")
    if not mets:
        raise ValueError("至少配置一个度量")

    dim_exprs = [_dim_expr(d) for d in dims]
    met_exprs = [_metric_expr(m["field"], m["agg"]) for m in mets]

    select_parts = [f"{e} AS d{i}" for i, e in enumerate(dim_exprs)]
    select_parts += [f"{e} AS m{i}" for i, e in enumerate(met_exprs)]

    conds, params = _filter_conds(model_def)
    sql = f"SELECT {', '.join(select_parts)} FROM sessions"
    if conds:
        sql += " WHERE " + " AND ".join(f"({c})" for c in conds)
    # 同一表达式同时用于 SELECT 与 GROUP BY，兼容 ONLY_FULL_GROUP_BY
    sql += " GROUP BY " + ", ".join(dim_exprs)

    having = model_def.get("having")
    if having:
        idx = having["metricIndex"]
        if idx < 0 or idx >= len(met_exprs):
            raise ValueError("阈值引用的度量不存在")
        op = OP_SQL.get(having["op"])
        if not op or having["op"] == "like":
            raise ValueError("阈值仅支持数值比较")
        sql += f" HAVING {met_exprs[idx]} {op} %s"
        params.append(float(having["value"]))

    return sql, params


def run_model(model_def: dict, page=None) -> dict:
    t0 = time.time()
    dims, mets = model_def["dimensions"], model_def["metrics"]
    sql, params = _model_sql(model_def)
    total = int(query_all(f"SELECT COUNT(*) AS c FROM ({sql}) AS groups_count", params)[0]["c"])
    order = " ORDER BY " + ", ".join(f"d{i}" for i in range(len(dims)))
    if page is not None:
        page = min(max(1, int(page)), max(1, (total + 9) // 10))
        raw = query_all(sql + order + " LIMIT %s OFFSET %s", [*params, 10, (page - 1) * 10])
    else:
        raw = query_all(sql + order, params)

    columns = [
        *[next((x["label"] for x in DIMENSIONS if x["key"] == d), d) for d in dims],
        *[m["alias"] for m in mets],
    ]
    rows = []
    for r in raw:
        row = {}
        for i in range(len(dims)):
            row[f"d{i}"] = r[f"d{i}"]
        for i in range(len(mets)):
            v = r[f"m{i}"]
            row[f"m{i}"] = float(v) if v is not None and isinstance(v, (int, float)) or (isinstance(v, str) and v.replace(".", "").replace("-", "").isdigit()) else v
            # Decimal 兼容
            if hasattr(r[f"m{i}"], "__float__") and not isinstance(r[f"m{i}"], (int, float)):
                row[f"m{i}"] = float(r[f"m{i}"])
        rows.append(row)

    return {
        "columns": columns, "rows": rows,
        "matched": total, "total": total, "page": page or 1, "pageSize": 10,
        "durationMs": int((time.time() - t0) * 1000),
    }


def match_sessions_for_model(model_def: dict, page=1, groups_page=1) -> dict:
    """Match all qualifying groups, with independent group/session pages."""
    run = run_model(model_def, page=groups_page)
    group_sql, group_params = _model_sql(model_def)
    dim_exprs = [_dim_expr(d) for d in model_def["dimensions"]]
    # Tuple keys distinguish a missing value from an empty string/zero.
    def key(expr):
        return f"tuple(isNull({expr}),ifNull(toString({expr}),''))"
    source_key = 'tuple(' + ','.join(key(expr) for expr in dim_exprs) + ')'
    hit_key = 'tuple(' + ','.join(key(f'd{i}') for i in range(len(dim_exprs))) + ')'
    conds, filter_params = _filter_conds(model_def)
    group_match = f"{source_key} IN (SELECT {hit_key} FROM ({group_sql}) AS hits)"
    where = ' WHERE ' + ' AND '.join([group_match, *[f'({c})' for c in conds]])
    source = f"FROM sessions{where}"
    params = [*group_params, *filter_params]
    cnt = int(query_all(f"SELECT COUNT(*) AS c {source}", params)[0]["c"])
    page = min(max(1, int(page)), max(1, (cnt + 9) // 10))
    cols = ("id, session_id, src_ip, src_port, dst_ip, dst_port, protocol, app_protocol, "
            "direction, start_time, duration, up_packets, down_packets, up_bytes, down_bytes, "
            "dst_country, threat_score")
    rows = query_all(f"SELECT {cols} {source} ORDER BY start_time DESC, id DESC LIMIT %s OFFSET %s",
                     [*params, 10, (page - 1) * 10])

    sessions = [{
        "id": r["id"], "sessionId": r["session_id"], "srcIp": r["src_ip"],
        "srcPort": r["src_port"], "dstIp": r["dst_ip"], "dstPort": r["dst_port"],
        "protocol": r["protocol"], "appProtocol": r["app_protocol"],
        "direction": r["direction"],
        "startTime": r["start_time"].isoformat() if r["start_time"] else None,
        "duration": r["duration"], "upPackets": r["up_packets"],
        "downPackets": r["down_packets"], "upBytes": int(r["up_bytes"]),
        "downBytes": int(r["down_bytes"]), "dstCountry": r["dst_country"],
        "threatScore": r["threat_score"],
    } for r in rows]

    return {"run": run, "sessions": sessions, "sessionTotal": cnt, "page": page, "pageSize": 10}
