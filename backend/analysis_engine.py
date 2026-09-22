"""行为关联分析引擎（Python 版）
从数据库加载会话元数据，按规则做跨会话聚合关联，产出告警。
"""
import json
import math
import time
from datetime import datetime, timezone

from .db import query_all, execute, insert
from .contracts import ANALYSIS_RULES


def _meta(row: dict) -> dict:
    m = row.get("meta")
    if isinstance(m, str):
        return json.loads(m)
    return m or {}


def _num(m: dict, k: str) -> float:
    v = m.get(k)
    if v is None or v is True or v is False:
        return 0
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0


def _str(m: dict, k: str) -> str:
    v = m.get(k)
    return "" if v is None else str(v)


def _bool(m: dict, k: str) -> bool:
    return m.get(k) is True


def _group_by(rows: list[dict], key) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for r in rows:
        out.setdefault(key(r), []).append(r)
    return out


def _ts_ms(v) -> float:
    if isinstance(v, datetime):
        return v.timestamp() * 1000
    return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() * 1000


def _draft(rule_code, rule_name, category, severity, title, src_ip, dst_ip, score, evidence, related):
    return {
        "ruleCode": rule_code, "ruleName": rule_name, "category": category,
        "severity": severity, "title": title, "srcIp": src_ip, "dstIp": dst_ip,
        "score": min(100, score), "evidence": evidence, "relatedSessions": related,
    }


# ---------- 各规则分析器 ----------

def port_scan(rows):
    out = []
    for src, lst in _group_by(rows, lambda r: r["srcIp"]).items():
        ports = {r["dstPort"] for r in lst}
        fails = [r for r in lst
                 if _bool(_meta(r), "handshakeSuccess") is False or _num(_meta(r), "rstCount") > 0]
        # 注：handshakeSuccess 缺省视为 False 仅对 pcap 导入数据成立；生成数据恒为 True
        fails = [r for r in lst if not _meta(r).get("handshakeSuccess", True) or _num(_meta(r), "rstCount") > 0]
        fail_ratio = len(fails) / len(lst)
        if len(ports) >= 30 and fail_ratio > 0.6:
            out.append(_draft(
                "PORT_SCAN", "端口扫描检测", "attack", "high",
                f"{src} 在窗口内触达 {len(ports)} 个不同端口（失败率 {fail_ratio * 100:.0f}%）",
                src, None, 60 + len(ports) / 10,
                {
                    "独立目的端口数": len(ports), "触达主机数": len({r["dstIp"] for r in lst}),
                    "连接失败率": f"{fail_ratio * 100:.1f}%", "会话数": len(lst),
                    "小包占比": _str(_meta(lst[0]), "smallPktRatio"), "判定": "SYN 扫描特征（小包 + RST 关闭）",
                },
                [r["sessionId"] for r in lst[:20]],
            ))
    return out


def lateral_move(rows):
    out = []
    mgmt = {22, 135, 139, 445, 3389, 5985}
    internal = [r for r in rows if r["direction"] == "内到内" and r["dstPort"] in mgmt]
    for src, lst in _group_by(internal, lambda r: r["srcIp"]).items():
        targets = {r["dstIp"] for r in lst}
        if len(targets) >= 12:
            port_dist: dict[str, int] = {}
            for r in lst:
                port_dist[r["appProtocol"]] = port_dist.get(r["appProtocol"], 0) + 1
            out.append(_draft(
                "LATERAL_MOVE", "横向移动检测", "attack", "critical",
                f"{src} 通过管理服务触达 {len(targets)} 台内网主机",
                src, None, 70 + len(targets),
                {
                    "扇出度": len(targets), "协议分布": port_dist, "会话数": len(lst),
                    "目标样例": sorted(targets)[:8], "涉及端口": sorted({r["dstPort"] for r in lst}),
                },
                [r["sessionId"] for r in lst[:20]],
            ))
    return out


def brute_force(rows):
    out = []
    auth_rows = [r for r in rows if _num(_meta(r), "authAttempts") > 0]
    for key, lst in _group_by(auth_rows, lambda r: f"{r['srcIp']}|{r['dstIp']}|{r['dstPort']}").items():
        attempts = sum(_num(_meta(r), "authAttempts") for r in lst)
        success = len([r for r in lst if _bool(_meta(r), "authSuccess")])
        if attempts >= 20 and success / len(lst) < 0.1:
            src, dst, port = key.split("|")
            out.append(_draft(
                "BRUTE_FORCE", "暴力破解检测", "attack", "high",
                f"{src} 对 {dst}:{port} 发起 {attempts:.0f} 次认证尝试，全部失败",
                src, dst, 55 + attempts / 2,
                {
                    "认证尝试次数": int(attempts), "成功次数": success, "会话数": len(lst),
                    "目标服务": _str(_meta(lst[0]), "appProtocol"),
                    "关闭方式": "RST 为主",
                    "平均会话时长": f"{sum(r['duration'] for r in lst) // len(lst)}ms",
                },
                [r["sessionId"] for r in lst[:20]],
            ))
    return out


def web_attack(rows):
    out = []
    hits = [r for r in rows if _bool(_meta(r), "httpHasSqlPattern")
            or _bool(_meta(r), "httpHasXssPattern") or _bool(_meta(r), "httpHasPathTraversal")]
    for src, lst in _group_by(hits, lambda r: r["srcIp"]).items():
        if len(lst) >= 3:
            types = {
                "SQL注入": len([r for r in lst if _bool(_meta(r), "httpHasSqlPattern")]),
                "XSS": len([r for r in lst if _bool(_meta(r), "httpHasXssPattern")]),
                "路径穿越": len([r for r in lst if _bool(_meta(r), "httpHasPathTraversal")]),
            }
            out.append(_draft(
                "WEB_ATTACK", "Web 攻击探测", "attack", "high",
                f"{src} 发起 {len(lst)} 次 Web 攻击探测（SQLi/XSS/路径穿越）",
                src, lst[0]["dstIp"], 50 + len(lst),
                {
                    "攻击类型分布": types, "目标": lst[0]["dstIp"],
                    "攻击载荷样例": [_str(_meta(r), "httpUri") for r in lst[:4]],
                    "UserAgent": _str(_meta(lst[0]), "httpUserAgent"),
                },
                [r["sessionId"] for r in lst[:20]],
            ))
    return out


def c2_beacon(rows):
    out = []
    for key, lst in _group_by(rows, lambda r: f"{r['srcIp']}|{r['dstIp']}").items():
        if len(lst) < 10:
            continue
        times = sorted(_ts_ms(r["startTime"]) for r in lst)
        intervals = [(times[i + 1] - times[i]) / 1000 for i in range(len(times) - 1)]
        mean = sum(intervals) / len(intervals)
        std = math.sqrt(sum((v - mean) ** 2 for v in intervals) / len(intervals))
        cv = std / mean if mean > 0 else 1
        avg_pkt = sum(_num(_meta(r), "avgPktLenUp") for r in lst) / len(lst)

        def _sym(r):
            m = _meta(r)
            ms = _num(m, "pairByteSymmetry")
            if ms > 0:
                return ms
            mx = max(int(r["upBytes"]), int(r["downBytes"]))
            return min(int(r["upBytes"]), int(r["downBytes"])) / mx if mx > 0 else 0

        sym = sum(_sym(r) for r in lst) / len(lst)
        if cv < 0.15 and avg_pkt < 300 and sym > 0.5:
            src, dst = key.split("|")
            m0 = _meta(lst[0])
            out.append(_draft(
                "C2_BEACON", "C&C 心跳检测", "c2", "critical",
                f"{src} → {dst} 存在固定周期心跳（间隔 {mean / 60:.1f} 分钟，CV={cv:.3f}）",
                src, dst, 80 + (0.15 - cv) * 100,
                {
                    "会话条数": len(lst), "平均间隔": f"{mean:.0f}s", "间隔标准差": f"{std:.1f}s",
                    "变异系数": f"{cv:.4f}", "上行平均包长": f"{avg_pkt:.0f}B",
                    "字节对称度": f"{sym:.2f}", "周期性得分": _str(m0, "periodicityScore"),
                    "威胁情报": "命中已知 C2" if _bool(m0, "dstIsKnownC2") else "未命中",
                },
                [r["sessionId"] for r in lst[:20]],
            ))
    return out


def dns_tunnel(rows):
    out = []
    dns = [r for r in rows if r["appProtocol"] == "DNS"]
    for src, lst in _group_by(dns, lambda r: r["srcIp"]).items():
        long_q = sum(_num(_meta(r), "dnsLongQueryCount") for r in lst)
        txt = sum(_num(_meta(r), "dnsTxtCount") for r in lst)
        ents = [e for e in (_num(_meta(r), "dnsNameEntropy") for r in lst) if e > 0]
        avg_ent = sum(ents) / len(ents) if ents else 0
        avg_resp = sum(_num(_meta(r), "dnsResponseSize") for r in lst) / len(lst)
        if (long_q >= 20 or txt / len(lst) > 0.3) and avg_ent > 4.2 and avg_resp > 300:
            out.append(_draft(
                "DNS_TUNNEL", "DNS 隧道检测", "c2", "critical",
                f"{src} 疑似 DNS 隧道：{long_q:.0f} 次超长 TXT 查询，平均熵 {avg_ent:.2f}bit",
                src, None, 75 + long_q / 4,
                {
                    "超长查询次数": int(long_q), "TXT查询占比": f"{txt / len(lst) * 100:.0f}%",
                    "域名平均熵": f"{avg_ent:.2f}bit", "平均响应大小": f"{avg_resp:.0f}B",
                    "查询样例": [_str(_meta(r), "dnsQueryName") for r in lst if _num(_meta(r), "dnsLongQueryCount") > 0][:3],
                },
                [r["sessionId"] for r in lst[:20]],
            ))
    return out


def dga_domain(rows):
    out = []
    dns = [r for r in rows if r["appProtocol"] == "DNS"]
    for src, lst in _group_by(dns, lambda r: r["srcIp"]).items():
        nx = len([r for r in lst if _bool(_meta(r), "dnsIsNxdomain")])
        domains = {s for s in (_str(_meta(r), "dnsQueryName") for r in lst) if s}
        ents = [e for e in (_num(_meta(r), "dnsNameEntropy") for r in lst) if e > 0]
        avg_ent = sum(ents) / len(ents) if ents else 0
        if nx / len(lst) > 0.5 and len(domains) >= 50 and avg_ent > 3.8:
            out.append(_draft(
                "DGA_DOMAIN", "DGA 域名检测", "c2", "high",
                f"{src} 查询 {len(domains)} 个高熵域名，NXDOMAIN 率 {nx / len(lst) * 100:.0f}%",
                src, None, 60 + len(domains) / 4,
                {
                    "独立域名数": len(domains), "NXDOMAIN率": f"{nx / len(lst) * 100:.1f}%",
                    "域名平均熵": f"{avg_ent:.2f}bit", "可疑域名样例": sorted(domains)[:5],
                },
                [r["sessionId"] for r in lst[:20]],
            ))
    return out


def covert_channel(rows):
    out = []

    def _hit(r):
        m = _meta(r)
        if r["appProtocol"] == "HTTPS" and r["dstPort"] != 443:
            return True
        if r["appProtocol"] == "HTTP" and r["dstPort"] > 1024:
            return True
        if r["appProtocol"] == "HTTPS" and m.get("tlsCertSnMatch") is False and _bool(m, "tlsCertSelfSigned"):
            return True
        return False

    hits = [r for r in rows if _hit(r)]
    for key, lst in _group_by(hits, lambda r: f"{r['srcIp']}|{r['dstIp']}|{r['dstPort']}").items():
        if len(lst) >= 2:
            src, dst, port = key.split("|")
            m0 = _meta(lst[0])
            out.append(_draft(
                "COVERT_CHANNEL", "隐蔽通道检测", "c2", "medium",
                f"{src} → {dst}:{port} 协议-端口不匹配 / 证书异常（{len(lst)} 次）",
                src, dst, 45 + len(lst) * 3,
                {
                    "命中次数": len(lst), "应用协议": _str(m0, "appProtocol"),
                    "目的端口": port, "SNI": _str(m0, "tlsSni") or "-",
                    "证书自签名": "是" if _bool(m0, "tlsCertSelfSigned") else "否",
                    "SNI证书匹配": "是" if _bool(m0, "tlsCertSnMatch") else "否",
                },
                [r["sessionId"] for r in lst[:20]],
            ))
    return out


def data_exfil(rows):
    out = []
    ext = [r for r in rows if r["direction"] == "内到外"]
    for key, lst in _group_by(ext, lambda r: f"{r['srcIp']}|{r['dstIp']}").items():
        up_total = sum(int(r["upBytes"]) for r in lst)
        down_total = sum(int(r["downBytes"]) for r in lst)
        ratio = up_total / down_total if down_total > 0 else 99
        is_new = any(_bool(_meta(r), "isNewDestination") for r in lst)
        if up_total >= 100_000_000 and ratio > 4 and is_new:
            src, dst = key.split("|")
            out.append(_draft(
                "DATA_EXFIL", "数据外泄检测", "data", "critical",
                f"{src} 向新目的 {dst} 上传 {up_total / 1048576:.0f}MB（上下行比 {ratio:.0f}:1）",
                src, dst, 80 + up_total / 104857600,
                {
                    "上行总量": f"{up_total / 1048576:.1f}MB", "下行总量": f"{down_total / 1048576:.1f}MB",
                    "上下行字节比": f"{ratio:.1f}", "会话数": len(lst),
                    "是否新目的": "是（7 天内首次出现）",
                    "上行载荷熵": _str(_meta(lst[0]), "payloadEntropyUp"),
                    "涉及文件": sorted({_str(_meta(r), "fileName") for r in lst if _str(_meta(r), "fileName")}),
                },
                [r["sessionId"] for r in lst[:20]],
            ))
    return out


def bulk_transfer(rows):
    out = []
    for r in rows:
        total = int(r["upBytes"]) + int(r["downBytes"])
        if total >= 150_000_000:
            m = _meta(r)
            out.append(_draft(
                "BULK_TRANSFER", "异常大流量传输", "data", "high",
                f"{r['srcIp']} ↔ {r['dstIp']} 单会话传输 {total / 1048576:.0f}MB",
                r["srcIp"], r["dstIp"], 55 + total / 20971520,
                {
                    "会话总字节": f"{total / 1048576:.1f}MB",
                    "类型": "上传型" if int(r["upBytes"]) > int(r["downBytes"]) else "下载型",
                    "会话时长": f"{r['duration'] / 60000:.1f} 分钟",
                    "下行速率": f"{_num(m, 'downByteRate') / 1048576:.1f}MB/s",
                    "基线偏离倍数": _str(m, "hostBaselineDeviation"),
                },
                [r["sessionId"]],
            ))
    return out


def cleartext_abuse(rows):
    out = []
    hits = [r for r in rows if _bool(_meta(r), "isCleartextProto")
            and (_num(_meta(r), "authAttempts") > 0 or _num(_meta(r), "fileTransferCount") > 0)]
    for src, lst in _group_by(hits, lambda r: r["srcIp"]).items():
        if len(lst) >= 2:
            protos = sorted({r["appProtocol"] for r in lst})
            out.append(_draft(
                "CLEARTEXT_ABUSE", "敏感协议滥用", "data", "medium",
                f"{src} 通过明文协议（{'/'.join(protos)}）传输认证信息或文件",
                src, None, 40 + len(lst) * 4,
                {
                    "涉及协议": protos, "会话数": len(lst),
                    "文件传输数": int(sum(_num(_meta(r), "fileTransferCount") for r in lst)),
                    "传输文件": sorted({_str(_meta(r), "fileName") for r in lst if _str(_meta(r), "fileName")}),
                    "上行总量": f"{sum(int(r['upBytes']) for r in lst) / 1048576:.1f}MB",
                },
                [r["sessionId"] for r in lst[:20]],
            ))
    return out


def off_hours(rows):
    out = []
    for src, lst in _group_by(rows, lambda r: r["srcIp"]).items():
        night = [r for r in lst if _bool(_meta(r), "isNight")]
        ratio = len(night) / len(lst)
        night_bytes = sum(int(r["upBytes"]) for r in night)
        if ratio > 0.4 and night_bytes > 10_000_000 and len(lst) >= 10:
            hour_dist = [
                {"hour": h, "count": len([r for r in lst if _num(_meta(r), "hourOfDay") == h])}
                for h in range(24)
            ]
            out.append(_draft(
                "OFF_HOURS", "非工作时间活动", "baseline", "medium",
                f"{src} 深夜会话占比 {ratio * 100:.0f}%，深夜上行 {night_bytes / 1048576:.0f}MB",
                src, None, 40 + ratio * 50,
                {
                    "深夜会话占比": f"{ratio * 100:.1f}%", "深夜上行字节": f"{night_bytes / 1048576:.1f}MB",
                    "会话总数": len(lst), "时段分布": hour_dist,
                },
                [r["sessionId"] for r in night[:20]],
            ))
    return out


def geo_anomaly(rows):
    out = []
    hits = [r for r in rows if _bool(_meta(r), "dstIsHighRiskGeo") or _bool(_meta(r), "dstIsTor")
            or _bool(_meta(r), "dstIsKnownC2") or _num(_meta(r), "dstThreatScore") >= 80]
    for key, lst in _group_by(hits, lambda r: r["dstIp"]).items():
        m = _meta(lst[0])
        reasons = [x for x in [
            _bool(m, "dstIsHighRiskGeo") and "高危地区",
            _bool(m, "dstIsTor") and "Tor 出口",
            _bool(m, "dstIsKnownC2") and "命中 C2 情报",
            _num(m, "dstThreatScore") >= 80 and f"威胁评分 {_num(m, 'dstThreatScore'):.0f}",
        ] if x]
        out.append(_draft(
            "GEO_ANOMALY", "地理位置异常", "baseline", "high",
            f"与 {_str(m, 'dstCountry')}（{key}）存在 {len(lst)} 次异常通信：{'、'.join(reasons)}",
            lst[0]["srcIp"], key, 60 + _num(m, "dstThreatScore") / 3,
            {
                "目的国家": _str(m, "dstCountry"), "目的城市": _str(m, "dstCity"),
                "命中原因": reasons, "通信次数": len(lst),
                "源主机": sorted({r["srcIp"] for r in lst}),
                "威胁评分": _num(m, "dstThreatScore"), "IP信誉": _str(m, "ipReputation"),
            },
            [r["sessionId"] for r in lst[:20]],
        ))
    return out


def baseline_deviation(rows):
    out = []
    for src, lst in _group_by(rows, lambda r: r["srcIp"]).items():
        up_total = sum(int(r["upBytes"]) for r in lst)
        baseline = _num(_meta(lst[0]), "hostUpBytesBaseline")
        if baseline <= 0:
            continue
        deviation = up_total / baseline
        if deviation >= 8 and up_total - baseline > 50_000_000:
            out.append(_draft(
                "BASELINE_DEVIATION", "流量基线偏离", "baseline", "medium",
                f"{src} 上行流量偏离基线 {deviation:.1f} 倍",
                src, None, 45 + deviation * 2,
                {
                    "上行总量": f"{up_total / 1048576:.1f}MB", "基线": f"{baseline / 1048576:.1f}MB",
                    "偏离倍数": f"{deviation:.1f}", "会话数": len(lst),
                    "活跃时间占比": _str(_meta(lst[0]), "activeRatio"),
                },
                [r["sessionId"] for r in lst[:20]],
            ))
    return out


ANALYZERS = {
    "PORT_SCAN": port_scan,
    "LATERAL_MOVE": lateral_move,
    "BRUTE_FORCE": brute_force,
    "WEB_ATTACK": web_attack,
    "C2_BEACON": c2_beacon,
    "DNS_TUNNEL": dns_tunnel,
    "DGA_DOMAIN": dga_domain,
    "COVERT_CHANNEL": covert_channel,
    "DATA_EXFIL": data_exfil,
    "BULK_TRANSFER": bulk_transfer,
    "CLEARTEXT_ABUSE": cleartext_abuse,
    "OFF_HOURS": off_hours,
    "GEO_ANOMALY": geo_anomaly,
    "BASELINE_DEVIATION": baseline_deviation,
}

SESSION_COLS = ("id, session_id, src_ip, src_port, dst_ip, dst_port, protocol, app_protocol, "
                "direction, start_time, duration, up_packets, down_packets, up_bytes, down_bytes, "
                "dst_country, threat_score, meta")


def _normalize(rows: list[dict]) -> list[dict]:
    """下划线列名 → camelCase，保持与前端契约一致"""
    out = []
    for r in rows:
        out.append({
            "id": r["id"], "sessionId": r["session_id"], "srcIp": r["src_ip"],
            "srcPort": r["src_port"], "dstIp": r["dst_ip"], "dstPort": r["dst_port"],
            "protocol": r["protocol"], "appProtocol": r["app_protocol"],
            "direction": r["direction"], "startTime": r["start_time"],
            "duration": r["duration"], "upPackets": r["up_packets"],
            "downPackets": r["down_packets"], "upBytes": int(r["up_bytes"]),
            "downBytes": int(r["down_bytes"]), "dstCountry": r["dst_country"],
            "threatScore": r["threat_score"], "meta": _meta(r),
        })
    return out


def load_sessions() -> list[dict]:
    return _normalize(query_all(f"SELECT {SESSION_COLS} FROM sessions"))


def run_analysis(rule_code: str) -> dict:
    rule = next((r for r in ANALYSIS_RULES if r["code"] == rule_code), None)
    if not rule:
        raise ValueError(f"未知规则: {rule_code}")
    analyzer = ANALYZERS.get(rule_code)
    if not analyzer:
        raise ValueError(f"规则 {rule_code} 未实现")

    t0 = time.time()
    run_id = insert(
        "INSERT INTO analysis_runs (rule_code, status) VALUES (%s, 'running')", (rule_code,))

    rows = load_sessions()
    drafts = analyzer(rows)

    # 原型系统：每次运行刷新该规则的告警
    execute("DELETE FROM alerts WHERE rule_code = %s", (rule_code,))
    for d in drafts:
        insert(
            "INSERT INTO alerts (rule_code, rule_name, category, severity, title, src_ip, dst_ip, "
            "score, evidence, related_sessions, run_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (d["ruleCode"], d["ruleName"], d["category"], d["severity"], d["title"],
             d["srcIp"], d["dstIp"], round(d["score"]),
             json.dumps(d["evidence"], ensure_ascii=False),
             json.dumps(d["relatedSessions"], ensure_ascii=False), run_id),
        )

    duration_ms = int((time.time() - t0) * 1000)
    execute(
        "UPDATE analysis_runs SET status='success', sessions_scanned=%s, alerts_generated=%s, "
        "duration_ms=%s, finished_at=%s WHERE id=%s",
        (len(rows), len(drafts), duration_ms,
         datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), run_id),
    )
    return {"runId": run_id, "alerts": len(drafts), "scanned": len(rows), "durationMs": duration_ms}


def run_all_analyses() -> list[dict]:
    results = []
    for rule in ANALYSIS_RULES:
        r = run_analysis(rule["code"])
        results.append({"ruleCode": rule["code"], "alerts": r["alerts"], "durationMs": r["durationMs"]})
    return results
