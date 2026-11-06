"""FastAPI 主程序：REST API + 前端静态托管 + pcap 上传
运行：uvicorn backend.main:app --host 0.0.0.0 --port 3000
"""
import json
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse
from starlette.concurrency import run_in_threadpool

from .db import query_all, query_one, execute, insert
from .contracts import (
    FIELD_CATEGORIES, FIELD_COUNT, ANALYSIS_RULES, RULE_CATEGORY_META,
    DIMENSIONS, AGG_LABEL, OP_LABEL,
)
from .analysis_engine import run_analysis, run_all_analyses
from .model_engine import run_model, match_sessions_for_model
from .ingest_jobs import receive_upload, get_job
from .data_management import delete_records, delete_batch, DataBusyError
from .runtime_schema import ensure_runtime_schema
from .bootstrap import ensure_schema

ensure_schema()

app = FastAPI(title="网络安全元数据建模分析平台")
DIST = Path(__file__).resolve().parent.parent / "dist" / "public"


@app.get('/api/health')
def health():
    try:
        query_one('SELECT 1 AS ok')
    except Exception:
        return JSONResponse({'ok': False}, status_code=503)
    return {'ok': True}


def _err(e: Exception, code: int = 400) -> JSONResponse:
    return JSONResponse({"detail": str(e)}, status_code=code)


def _dt(v):
    return v.isoformat() if isinstance(v, datetime) else v


def _j(v):
    """JSON 列 → Python 对象"""
    if isinstance(v, str):
        try:
            return json.loads(v)
        except (ValueError, TypeError):
            return v
    return v


def _input(request: Request) -> dict:
    raw = request.query_params.get("input")
    return json.loads(raw) if raw else {}


def _paged_query(sql: str, params, inp: dict) -> dict:
    """Page a deterministic query, including counts and empty/deleted last pages."""
    total = int(query_one(f"SELECT COUNT(*) AS c FROM ({sql}) AS page_source", params)["c"])
    page = min(max(1, int(inp.get("page", 1))), max(1, (total + 9) // 10))
    rows = query_all(sql + " LIMIT %s OFFSET %s", [*(params or ()), 10, (page - 1) * 10])
    return {"rows": rows, "total": total, "page": page, "pageSize": 10}


# ---------- 会话行序列化 ----------

def _session_row(r: dict) -> dict:
    return {
        "id": r["id"], "sessionId": r["session_id"], "srcIp": r["src_ip"],
        "srcPort": r["src_port"], "dstIp": r["dst_ip"], "dstPort": r["dst_port"],
        "protocol": r["protocol"], "appProtocol": r["app_protocol"],
        "direction": r["direction"], "startTime": _dt(r["start_time"]),
        "duration": r["duration"], "upPackets": r["up_packets"],
        "downPackets": r["down_packets"], "upBytes": int(r["up_bytes"]),
        "downBytes": int(r["down_bytes"]), "dstCountry": r["dst_country"],
        "threatScore": r["threat_score"], "meta": _j(r["meta"]),
    }


def _alert_row(r: dict) -> dict:
    return {
        "id": r["id"], "ruleCode": r["rule_code"], "ruleName": r["rule_name"],
        "category": r["category"], "severity": r["severity"], "title": r["title"],
        "srcIp": r["src_ip"], "dstIp": r["dst_ip"], "score": r["score"],
        "evidence": _j(r["evidence"]), "relatedSessions": _j(r["related_sessions"]),
        "status": r["status"], "runId": r["run_id"], "createdAt": _dt(r["created_at"]),
    }


# ---------- 元数据建模字段 ----------

@app.get("/api/rpc/meta.fieldCatalog")
def meta_field_catalog():
    return {
        "categories": [
            {"code": c["code"], "label": c["label"], "en": c["en"],
             "desc": c["desc"], "count": len(c["fields"]), "fields": c["fields"]}
            for c in FIELD_CATEGORIES
        ],
        "total": FIELD_COUNT,
    }


# ---------- 会话检索 ----------

@app.get("/api/rpc/session.list")
def session_list(request: Request):
    inp = _input(request)
    conds, params = [], []
    if inp.get("srcIp"):
        conds.append("src_ip LIKE %s"); params.append(f"%{inp['srcIp']}%")
    if inp.get("dstIp"):
        conds.append("dst_ip LIKE %s"); params.append(f"%{inp['dstIp']}%")
    if inp.get("appProtocol"):
        conds.append("app_protocol = %s"); params.append(inp["appProtocol"])
    if inp.get("protocol"):
        conds.append("protocol = %s"); params.append(inp["protocol"])
    if inp.get("direction"):
        conds.append("direction = %s"); params.append(inp["direction"])
    if inp.get("minThreat"):
        conds.append("threat_score >= %s"); params.append(int(inp["minThreat"]))
    if inp.get("keyword"):
        kw = f"%{inp['keyword']}%"
        conds.append("(src_ip LIKE %s OR dst_ip LIKE %s OR session_id LIKE %s OR "
                     "JSONExtractString(meta, 'dnsQueryName') LIKE %s OR "
                     "JSONExtractString(meta, 'tlsSni') LIKE %s)")
        params += [kw, kw, kw, kw, kw]
    where = (" WHERE " + " AND ".join(conds)) if conds else ""

    result = _paged_query(f"SELECT * FROM sessions{where} ORDER BY start_time DESC, id DESC", params, inp)
    result["rows"] = [_session_row(r) for r in result["rows"]]
    return result


@app.get("/api/rpc/session.bySessionId")
def session_by_id(request: Request):
    sid = _input(request).get("sessionId", "")
    r = query_one("SELECT * FROM sessions WHERE session_id = %s LIMIT 1", (sid,))
    return _session_row(r) if r else None


@app.get("/api/rpc/session.protocols")
def session_protocols():
    rows = query_all("SELECT app_protocol AS n, COUNT(*) AS c FROM sessions "
                     "GROUP BY app_protocol ORDER BY c DESC")
    return [{"name": r["n"], "count": int(r["c"])} for r in rows]


# ---------- 行为关联分析 ----------

@app.get("/api/rpc/analysis.rules")
def analysis_rules():
    last_runs = query_all("SELECT rule_code, MAX(started_at) AS last_at, COUNT(*) AS runs "
                          "FROM analysis_runs GROUP BY rule_code")
    alert_counts = query_all("SELECT rule_code, COUNT(*) AS c FROM alerts GROUP BY rule_code")
    run_map = {r["rule_code"]: r for r in last_runs}
    alert_map = {r["rule_code"]: int(r["c"]) for r in alert_counts}
    return {
        "categories": RULE_CATEGORY_META,
        "rules": [{
            **r,
            "lastRunAt": _dt(run_map[r["code"]]["last_at"]) if r["code"] in run_map else None,
            "runCount": int(run_map[r["code"]]["runs"]) if r["code"] in run_map else 0,
            "alertCount": alert_map.get(r["code"], 0),
        } for r in ANALYSIS_RULES],
    }


@app.post("/api/rpc/analysis.run")
async def analysis_run(request: Request):
    body = await request.json()
    try:
        return run_analysis(body["ruleCode"])
    except ValueError as e:
        return _err(e)


@app.post("/api/rpc/analysis.runAll")
def analysis_run_all():
    return run_all_analyses()


@app.get("/api/rpc/analysis.runs")
def analysis_runs(request: Request):
    inp = _input(request)
    result = _paged_query("SELECT * FROM analysis_runs ORDER BY started_at DESC, id DESC", [], inp)
    rows = result["rows"] if inp else query_all("SELECT * FROM analysis_runs ORDER BY started_at DESC, id DESC")
    result["rows"] = [{
        "id": r["id"], "ruleCode": r["rule_code"], "status": r["status"],
        "sessionsScanned": r["sessions_scanned"], "alertsGenerated": r["alerts_generated"],
        "durationMs": r["duration_ms"], "startedAt": _dt(r["started_at"]),
        "finishedAt": _dt(r["finished_at"]),
    } for r in rows]
    return result if inp else result["rows"]


# ---------- 告警 ----------

@app.get("/api/rpc/alert.list")
def alert_list(request: Request):
    inp = _input(request)
    conds, params = [], []
    for key, col in (("severity", "severity"), ("category", "category"),
                     ("status", "status"), ("ruleCode", "rule_code")):
        if inp.get(key):
            conds.append(f"{col} = %s"); params.append(inp[key])
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    result = _paged_query(f"SELECT * FROM alerts{where} ORDER BY created_at DESC, id DESC", params, inp)
    result["rows"] = [_alert_row(r) for r in result["rows"]]
    return result


@app.post("/api/rpc/alert.updateStatus")
async def alert_update_status(request: Request):
    body = await request.json()
    if body.get("status") not in ("open", "confirmed", "dismissed"):
        return _err(ValueError("非法状态"))
    execute("UPDATE alerts SET status = %s WHERE id = %s", (body["status"], body["id"]))
    return {"ok": True}


async def _delete_data(request: Request, entity: str, all_rows=False):
    try:
        return await run_in_threadpool(delete_records, entity, await request.json(), all_rows)
    except DataBusyError as e:
        return _err(e, 409)
    except ValueError as e:
        return _err(e)


@app.post("/api/rpc/session.deleteMany")
async def session_delete_many(request: Request):
    return await _delete_data(request, 'sessions')


@app.post("/api/rpc/session.deleteAll")
async def session_delete_all(request: Request):
    return await _delete_data(request, 'sessions', True)


@app.post("/api/rpc/alert.deleteMany")
async def alert_delete_many(request: Request):
    return await _delete_data(request, 'alerts')


@app.post("/api/rpc/alert.deleteAll")
async def alert_delete_all(request: Request):
    return await _delete_data(request, 'alerts', True)


# ---------- 数据接入 ----------

@app.get("/api/rpc/ingest.batches")
def ingest_batches(request: Request):
    inp = _input(request)
    result = _paged_query("SELECT * FROM ingest_batches ORDER BY created_at DESC, id DESC", [], inp)
    rows = result["rows"] if inp else query_all("SELECT * FROM ingest_batches ORDER BY created_at DESC, id DESC")
    result["rows"] = [{
        "id": r["id"], "filename": r["filename"], "sizeBytes": int(r["size_bytes"]),
        "packets": r["packets"], "flows": r["flows"], "skipped": r["skipped"],
        "durationMs": r["duration_ms"], "createdAt": _dt(r["created_at"]),
    } for r in rows]
    return result if inp else result["rows"]


@app.post("/api/rpc/ingest.deleteBatch")
async def ingest_delete_batch(request: Request):
    body = await request.json()
    try:
        return await run_in_threadpool(delete_batch, int(body["id"]))
    except DataBusyError as e:
        return _err(e, 409)
    except ValueError as e:
        return _err(e)


@app.post("/api/upload/pcap")
async def upload_pcap(request: Request):
    return await receive_upload(request)


@app.get("/api/rpc/ingest.job")
def ingest_job(request: Request):
    job = get_job(_input(request).get('id', ''))
    return job if job else _err(ValueError('导入任务不存在'), 404)


# ---------- 可视化建模 ----------

SEVERITIES = ("critical", "high", "medium", "low")


def _validate_model(body: dict) -> dict | JSONResponse:
    name = str(body.get("name", "")).strip()
    if not name or len(name) > 128:
        return _err(ValueError("模型名称必填且不超过 128 字"))
    if body.get("severity") not in SEVERITIES:
        return _err(ValueError("非法告警级别"))
    dims = body.get("dimensions") or []
    mets = body.get("metrics") or []
    if not dims:
        return _err(ValueError("至少选择一个维度"))
    if not mets:
        return _err(ValueError("至少配置一个度量"))
    return {
        "name": name, "description": str(body.get("description", ""))[:512],
        "severity": body["severity"], "dimensions": dims, "metrics": mets,
        "filters": body.get("filters") or [], "having": body.get("having"),
    }


def _model_row(r: dict) -> dict:
    return {
        "id": r["id"], "name": r["name"], "description": r["description"],
        "severity": r["severity"], "dimensions": _j(r["dimensions"]),
        "metrics": _j(r["metrics"]), "filters": _j(r["filters"]),
        "having": _j(r["having_def"]), "createdAt": _dt(r["created_at"]),
    }


@app.get("/api/rpc/model.list")
def model_list(request: Request):
    inp = _input(request)
    sql = "SELECT * FROM custom_models ORDER BY created_at DESC, id DESC"
    if not inp:
        return [_model_row(r) for r in query_all(sql)]
    result = _paged_query(sql, [], inp)
    result["rows"] = [_model_row(r) for r in result["rows"]]
    return result


@app.post("/api/rpc/model.create")
async def model_create(request: Request):
    body = await request.json()
    model_def = _validate_model(body)
    if isinstance(model_def, JSONResponse):
        return model_def
    try:
        run_model(model_def)  # 保存前先验证模型可执行
    except ValueError as e:
        return _err(e)
    mid = insert(
        "INSERT INTO custom_models (name, description, severity, dimensions, metrics, filters, having_def) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (model_def["name"], model_def["description"], model_def["severity"],
         json.dumps(model_def["dimensions"]), json.dumps(model_def["metrics"]),
         json.dumps(model_def["filters"], ensure_ascii=False),
         json.dumps(model_def["having"]) if model_def["having"] else None),
    )
    return {"id": mid}


@app.post("/api/rpc/model.delete")
async def model_delete(request: Request):
    body = await request.json()
    execute("DELETE FROM custom_models WHERE id = %s", (body["id"],))
    execute("DELETE FROM alerts WHERE rule_code = %s", (f"CUSTOM_{body['id']}",))
    return {"ok": True}


@app.post("/api/rpc/model.run")
async def model_run(request: Request):
    body = await request.json()
    model_def = _validate_model(body)
    if isinstance(model_def, JSONResponse):
        return model_def
    try:
        return run_model(model_def, page=body.get("page", 1))
    except ValueError as e:
        return _err(e)


def _load_model(mid: int) -> dict:
    r = query_one("SELECT * FROM custom_models WHERE id = %s LIMIT 1", (mid,))
    if not r:
        raise ValueError("模型不存在")
    return {
        "name": r["name"], "description": r["description"], "severity": r["severity"],
        "dimensions": _j(r["dimensions"]), "metrics": _j(r["metrics"]),
        "filters": _j(r["filters"]), "having": _j(r["having_def"]),
    }


@app.post("/api/rpc/model.runSaved")
async def model_run_saved(request: Request):
    body = await request.json()
    try:
        return run_model(_load_model(body["id"]), page=body.get("page", 1))
    except ValueError as e:
        return _err(e)


@app.get("/api/rpc/model.matchSessions")
def model_match_sessions(request: Request):
    try:
        inp = _input(request)
        return match_sessions_for_model(_load_model(int(inp.get("id", 0))),
                                        page=inp.get("page", 1), groups_page=inp.get("groupsPage", 1))
    except ValueError as e:
        return _err(e)


@app.post("/api/rpc/model.createAlerts")
async def model_create_alerts(request: Request):
    body = await request.json()
    try:
        m = _load_model(body["id"])
        result = run_model(m)
    except ValueError as e:
        return _err(e)
    rule_code = f"CUSTOM_{body['id']}"
    execute("DELETE FROM alerts WHERE rule_code = %s", (rule_code,))
    dim_labels = [next((x["label"] for x in DIMENSIONS if x["key"] == d), d) for d in m["dimensions"]]
    for row in result["rows"][:50]:
        dim_text = "，".join(f"{dim_labels[i]}={row[f'd{i}'] if row[f'd{i}'] is not None else '-'}"
                             for i in range(len(m["dimensions"])))
        evidence = {}
        for i, mt in enumerate(m["metrics"]):
            evidence[f"{mt['alias']}（{AGG_LABEL[mt['agg']]}）"] = row[f"m{i}"]
        if m["having"]:
            hv = m["having"]
            evidence["触发阈值"] = (f"{m['metrics'][hv['metricIndex']]['alias']} "
                                   f"{OP_LABEL[hv['op']]} {hv['value']}")
        insert(
            "INSERT INTO alerts (rule_code, rule_name, category, severity, title, src_ip, dst_ip, "
            "score, evidence, related_sessions) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (rule_code, m["name"], "custom", m["severity"],
             f"[自定义模型] {m['name']}：{dim_text}",
             str(row[f"d{m['dimensions'].index('srcIp')}"] or "") if "srcIp" in m["dimensions"] else None,
             str(row[f"d{m['dimensions'].index('dstIp')}"] or "") if "dstIp" in m["dimensions"] else None,
             min(100, 50 + len(result["rows"])),
             json.dumps(evidence, ensure_ascii=False), "[]"),
        )
    return {"alerts": len(result["rows"])}


# ---------- 总览 ----------

@app.get("/api/rpc/dashboard.overview")
def dashboard_overview(request: Request):
    inp = _input(request)
    counts = query_one(
        "SELECT (SELECT COUNT(*) FROM sessions) AS sc, "
        "(SELECT COUNT(*) FROM alerts) AS ac, "
        "(SELECT COUNT(*) FROM alerts WHERE status='open') AS oc, "
        "(SELECT COUNT(DISTINCT src_ip) FROM sessions) AS hc")

    sev = query_all("SELECT severity AS n, COUNT(*) AS c FROM alerts GROUP BY severity")
    cat = query_all("SELECT category AS n, COUNT(*) AS c FROM alerts GROUP BY category")
    proto = query_all("SELECT app_protocol AS n, COUNT(*) AS c FROM sessions "
                      "GROUP BY app_protocol ORDER BY c DESC, n")
    direc = query_all("SELECT direction AS n, COUNT(*) AS c FROM sessions GROUP BY direction")

    trend_rows = query_all("SELECT toString(toDate(start_time)) AS day,count() AS count,"
                           "sum(up_bytes+down_bytes) AS bytes FROM sessions GROUP BY day ORDER BY day")
    trend = [{'day': r['day'], 'count': r['count'], 'bytes': r['bytes']} for r in trend_rows]

    top_result = _paged_query(
        "SELECT src_ip, COUNT(*) AS sc, SUM(up_bytes + down_bytes) AS b, "
        "MAX(threat_score) AS mt FROM sessions GROUP BY src_ip ORDER BY b DESC, src_ip",
        [], {"page": inp.get("hostPage", 1)})
    top, top_total = top_result["rows"], top_result["total"]
    latest_page = _paged_query("SELECT * FROM alerts ORDER BY created_at DESC, id DESC", [], {"page": inp.get("alertPage", 1)})
    latest = latest_page["rows"]

    return {
        "sessionCount": int(counts["sc"]), "alertCount": int(counts["ac"]),
        "openAlerts": int(counts["oc"]), "hostCount": int(counts["hc"]),
        "ruleCount": len(ANALYSIS_RULES), "fieldCount": FIELD_COUNT,
        "severityDist": [{"name": r["n"], "count": int(r["c"])} for r in sev],
        "categoryDist": [{"name": r["n"], "count": int(r["c"])} for r in cat],
        "protocolDist": [{"name": r["n"], "count": int(r["c"])} for r in proto],
        "directionDist": [{"name": r["n"], "count": int(r["c"])} for r in direc],
        "trend": trend,
        "topTalkers": [{"srcIp": r["src_ip"], "sessions": int(r["sc"]),
                        "bytes": int(r["b"]), "maxThreat": int(r["mt"])} for r in top],
        "latestAlerts": [_alert_row(r) for r in latest],
        "latestAlertTotal": latest_page["total"], "topTalkerTotal": top_total,
    }


# ---------- 前端静态托管（SPA） ----------

@app.get("/{full_path:path}")
def spa(full_path: str):
    if full_path.startswith("api/"):
        return _err(ValueError("Not Found"), 404)
    target = (DIST / full_path).resolve()
    if full_path and target.is_file() and str(target).startswith(str(DIST.resolve())):
        return FileResponse(target)
    return FileResponse(DIST / "index.html")
