"""通用模型执行引擎（Python 版）
按白名单把模型定义（维度/度量/过滤/阈值）编译为参数化聚合查询并执行。
"""
import time

from .db import query_all
from .contracts import DIMENSIONS, METRIC_FIELDS

# ---------- 字段 → SQL 表达式（白名单，杜绝注入） ----------

COLUMN_EXPR = {
    "srcIp": "src_ip", "dstIp": "dst_ip",
    "srcPort": "src_port", "dstPort": "dst_port",
    "protocol": "protocol", "appProtocol": "app_protocol",
    "direction": "direction", "dstCountry": "dst_country",
    "upBytes": "up_bytes", "downBytes": "down_bytes",
    "upPackets": "up_packets", "downPackets": "down_packets",
    "duration": "duration", "threatScore": "threat_score",
    "totalBytes": "(up_bytes + down_bytes)",
}


def _meta_text(key: str) -> str:
    return f"JSON_UNQUOTE(JSON_EXTRACT(meta, '$.{key}'))"


def _meta_num(key: str) -> str:
    return f"CAST(JSON_UNQUOTE(JSON_EXTRACT(meta, '$.{key}')) AS DOUBLE)"


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
    numeric = mdef.get("source") == "meta" and agg != "countDistinct"
    expr = _field_expr(field, numeric)
    fn = {"sum": "SUM", "avg": "AVG", "max": "MAX", "min": "MIN"}[agg] if agg != "countDistinct" else None
    return f"COUNT(DISTINCT {expr})" if fn is None else f"{fn}({expr})"


OP_SQL = {"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}


def _filter_conds(model_def: dict) -> tuple[list[str], list]:
    conds, params = [], []
    for f in model_def["filters"]:
        dim = next((d for d in DIMENSIONS if d["key"] == f["field"]), None)
        mfield = next((m for m in METRIC_FIELDS if m["key"] == f["field"]), None)
        if not dim and not mfield:
            raise ValueError(f"非法过滤字段: {f['field']}")
        numeric = bool(dim.get("numeric")) if dim else (
            mfield["key"] not in ("srcIp", "dstIp", "dnsQueryName"))
        expr = _field_expr(f["field"], numeric)
        if f["op"] == "like":
            conds.append(f"{expr} LIKE %s")
            params.append(f"%{f['value']}%")
        else:
            op = OP_SQL.get(f["op"])
            if not op:
                raise ValueError(f"非法算子: {f['op']}")
            conds.append(f"{expr} {op} %s")
            params.append(float(f["value"]) if numeric else str(f["value"]))
    return conds, params


def run_model(model_def: dict) -> dict:
    t0 = time.time()
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

    sql += " LIMIT 500"
    raw = query_all(sql, params)

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
        "matched": len(rows), "total": len(rows),
        "durationMs": int((time.time() - t0) * 1000),
    }


def match_sessions_for_model(model_def: dict, limit: int = 300) -> dict:
    """运行模型并反查命中分组对应的会话明细"""
    run = run_model(model_def)
    if not run["rows"]:
        return {"run": run, "sessions": [], "sessionTotal": 0}

    dims = model_def["dimensions"]
    dim_exprs = [_dim_expr(d) for d in dims]

    # 每个命中分组 = 各维度值全等；分组之间 OR
    group_conds, params = [], []
    for row in run["rows"][:50]:
        parts = []
        for i, expr in enumerate(dim_exprs):
            v = row[f"d{i}"]
            if v is None:
                parts.append(f"{expr} IS NULL")
            else:
                parts.append(f"{expr} = %s")
                params.append(v)
        group_conds.append("(" + " AND ".join(parts) + ")")
    hit_where = "(" + " OR ".join(group_conds) + ")"

    conds, fparams = _filter_conds(model_def)
    where = f"{hit_where} AND " + " AND ".join(f"({c})" for c in conds) if conds else hit_where
    params += fparams

    cols = ("id, session_id, src_ip, src_port, dst_ip, dst_port, protocol, app_protocol, "
            "direction, start_time, duration, up_packets, down_packets, up_bytes, down_bytes, "
            "dst_country, threat_score")
    rows = query_all(
        f"SELECT {cols} FROM sessions WHERE {where} ORDER BY start_time DESC LIMIT %s",
        [*params, limit])
    cnt = query_all(f"SELECT COUNT(*) AS c FROM sessions WHERE {where}", params)[0]["c"]

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

    return {"run": run, "sessions": sessions, "sessionTotal": int(cnt)}
