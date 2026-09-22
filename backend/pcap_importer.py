"""pcap 解析结果 → 会话元数据入库（Python 版）"""
import json
import math
import re

from .db import insert, executemany
from .pcap_parser import is_private_ip

_seq = 0


def _entropy(s: str) -> float:
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    e = 0.0
    for n in counts.values():
        p = n / len(s)
        e -= p * math.log2(p)
    return round(e, 2)


def _infer_app_protocol(f: dict) -> str:
    if f["dns"]:
        return "DNS"
    if f["tls"]:
        return "HTTPS"
    if f["http"]:
        return "HTTP"
    port = min(f["dstPort"], f["srcPort"])
    m = {53: "DNS", 80: "HTTP", 443: "HTTPS", 22: "SSH", 445: "SMB",
         3389: "RDP", 21: "FTP", 25: "SMTP", 23: "TELNET", 135: "WMI", 5985: "WMI"}
    return m.get(port) or m.get(f["dstPort"]) or "OTHER"


def _direction_of(f: dict) -> str:
    s, d = is_private_ip(f["srcIp"]), is_private_ip(f["dstIp"])
    if s and d:
        return "内到内"
    if s:
        return "内到外"
    if d:
        return "外到内"
    return "外到外"


def _stats(lens: list[int]) -> dict:
    if not lens:
        return {"avg": 0, "std": 0, "smallRatio": 0}
    avg = sum(lens) / len(lens)
    std = math.sqrt(sum((v - avg) ** 2 for v in lens) / len(lens))
    small = len([v for v in lens if v < 128]) / len(lens)
    return {"avg": round(avg), "std": round(std, 1), "smallRatio": round(small, 2)}


SQL_PATTERN = re.compile(r"('|%27|union|select|or\s+\d+=\d+)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(<script>|%3Cscript|onerror=|alert\()", re.IGNORECASE)
TRAV_PATTERN = re.compile(r"(\.\./|\.\.%2f|%2e%2e)", re.IGNORECASE)


def _flow_to_row(f: dict, batch_tag: str) -> tuple:
    global _seq
    _seq += 1
    session_id = f"P-{batch_tag}-{str(_seq).zfill(5)}"
    app = _infer_app_protocol(f)
    direction = _direction_of(f)
    up = _stats(f["upPktLens"])
    down = _stats(f["downPktLens"])
    dur_sec = max(f["duration"] / 1000, 0.001)
    hour = f["startTime"].hour
    dow = f["startTime"].isoweekday()
    is_dns = app == "DNS"
    is_http = app == "HTTP"
    is_tls = app == "HTTPS"
    dns = f["dns"] or {}
    tls = f["tls"] or {}
    http = f["http"] or {}
    dns_name = dns.get("queryName")

    meta = {
        # 五元组与链路
        "sessionId": session_id, "srcIp": f["srcIp"], "srcPort": f["srcPort"],
        "dstIp": f["dstIp"], "dstPort": f["dstPort"],
        "protocol": f["protocol"], "ipVersion": "IPv4", "vlanId": None,
        "ingressIf": None, "egressIf": None, "direction": direction,
        "srcMac": None, "dstMac": None, "sensorId": "pcap-upload",
        # 会话流统计
        "startTime": f["startTime"].isoformat(), "endTime": f["endTime"].isoformat(),
        "duration": f["duration"], "upPackets": f["upPackets"], "downPackets": f["downPackets"],
        "totalPackets": f["upPackets"] + f["downPackets"],
        "upBytes": f["upBytes"], "downBytes": f["downBytes"],
        "totalBytes": f["upBytes"] + f["downBytes"],
        "upDownByteRatio": round(f["upBytes"] / f["downBytes"], 2) if f["downBytes"] > 0 else None,
        "upPacketRate": round(f["upPackets"] / dur_sec, 1),
        "downPacketRate": round(f["downPackets"] / dur_sec, 1),
        "upByteRate": round(f["upBytes"] / dur_sec), "downByteRate": round(f["downBytes"] / dur_sec),
        "avgPktLenUp": up["avg"], "avgPktLenDown": down["avg"],
        "maxPktLenUp": max(f["upPktLens"]) if f["upPktLens"] else 0,
        "minPktLenUp": min(f["upPktLens"]) if f["upPktLens"] else 0,
        "pktLenStdUp": up["std"], "pktLenStdDown": down["std"],
        "smallPktRatio": round((up["smallRatio"] * f["upPackets"] + down["smallRatio"] * f["downPackets"])
                               / max(1, f["upPackets"] + f["downPackets"]), 2),
        "retransCount": None, "retransRatio": None, "outOfOrderCount": None, "fragCount": None,
        "payloadEntropyUp": None, "payloadEntropyDown": None, "idleTimeTotal": None,
        # TCP
        "synCount": f["synCount"], "synAckCount": f["synAckCount"], "ackCount": f["ackCount"],
        "finCount": f["finCount"], "rstCount": f["rstCount"], "pshCount": f["pshCount"],
        "urgCount": f["urgCount"], "handshakeRtt": None,
        "handshakeSuccess": f["handshakeSuccess"], "closeReason": f["closeReason"],
        "tcpState": {"FIN": "CLOSED", "RST": "RESET"}.get(f["closeReason"], "TIMEOUT"),
        "initWinSize": f["initWinSize"], "winScale": None, "mss": f["mss"],
        "ttlInit": f["ttlInit"], "zeroWinCount": None,
        # DNS
        "dnsQueryName": dns_name if is_dns else None,
        "dnsQueryType": dns.get("queryType") if is_dns else None,
        "dnsRcode": dns.get("rcode") if is_dns else None,
        "dnsAnswerCount": dns.get("answerCount", 0) if is_dns else 0,
        "dnsAnswerIps": ",".join(dns.get("answerIps", [])) or None if is_dns and dns else None,
        "dnsTtl": dns.get("ttl") if is_dns else None,
        "dnsQueryLen": len(dns_name) if is_dns and dns_name else 0,
        "dnsSubdomainLen": len(dns_name.split(".")[0]) if is_dns and dns_name else 0,
        "dnsNameEntropy": _entropy(dns_name) if is_dns and dns_name else 0,
        "dnsDigitRatio": round(len(re.findall(r"\d", dns_name)) / len(dns_name), 2) if is_dns and dns_name else 0,
        "dnsIsNxdomain": dns.get("rcode") == "NXDOMAIN" if is_dns else False,
        "dnsNxdomainRatio": None, "dnsQpsHost": None, "dnsUniqueDomains": None,
        "dnsTxtCount": 1 if is_dns and dns.get("queryType") == "TXT" else 0,
        "dnsLongQueryCount": 1 if is_dns and dns_name and len(dns_name) > 52 else 0,
        "dnsServerIp": (f["srcIp"] if f["srcPort"] == 53 else f["dstIp"]) if is_dns else None,
        "dnsResponseSize": dns.get("responseSize", 0) if is_dns else 0,
        "dnsIsDoH": False, "dnsEdns": None, "dnsRtt": None,
        "dnsTld": "." + dns_name.split(".")[-1] if is_dns and dns_name else None,
        # HTTP
        "httpMethod": http.get("method") if is_http else None,
        "httpHost": http.get("host") if is_http else None,
        "httpUri": http.get("uri") if is_http else None,
        "httpUriLen": len(http["uri"]) if is_http and http.get("uri") else 0,
        "httpUserAgent": http.get("userAgent") if is_http else None,
        "httpStatus": http.get("status") if is_http else None,
        "httpContentType": None, "httpContentLen": None, "httpReferer": None, "httpCookieCount": None,
        "httpHasSqlPattern": bool(is_http and http.get("uri") and SQL_PATTERN.search(http["uri"])),
        "httpHasXssPattern": bool(is_http and http.get("uri") and XSS_PATTERN.search(http["uri"])),
        "httpHasPathTraversal": bool(is_http and http.get("uri") and TRAV_PATTERN.search(http["uri"])),
        "httpAuthFailCount": None, "httpVersion": "HTTP/1.1" if is_http else None, "httpIsProxy": None,
        # TLS
        "tlsVersion": tls.get("version") if is_tls else None,
        "tlsSni": tls.get("sni") if is_tls else None,
        "tlsCipherSuite": None, "tlsJa3": None, "tlsJa3s": None,
        "tlsCertSubject": None, "tlsCertIssuer": None, "tlsCertSelfSigned": None,
        "tlsCertValidDays": None, "tlsCertExpired": None, "tlsCertSnMatch": None,
        "tlsAlpn": None, "tlsSessionResumed": None, "tlsWeakCipher": None,
        "tlsOldVersion": tls.get("version") in ("TLS1.0", "TLS1.1") if is_tls and tls.get("version") else None,
        "tlsClientHelloLen": None,
        "tlsServerNameLen": len(tls["sni"]) if is_tls and tls.get("sni") else None,
        "tlsHandshakeMs": None, "tlsCertChainLen": None, "tlsEncPayloadRatio": None,
        # 时间
        "hourOfDay": hour, "dayOfWeek": dow,
        "isWorkHour": 9 <= hour < 18 and dow <= 5,
        "isNight": 0 <= hour < 6,
        "intervalMean": None, "intervalStd": None, "intervalCv": None, "periodicityScore": None,
        "burstCount": None, "activeRatio": None, "nightSessionRatio": None, "weekendRatio": None,
        "firstSeen": None, "isNewDestination": None,
        # 地理情报（离线 pcap 无情报源，留空）
        "srcCountry": None, "dstCountry": None, "srcAsn": None, "dstAsn": None, "dstAsnOrg": None,
        "dstIsCloud": None, "dstIsTor": None, "dstIsProxy": None,
        "dstThreatScore": 0, "dstIsKnownC2": False, "dstIsHighRiskGeo": False,
        "geoDistanceKm": None, "dstCity": None, "ipReputation": None,
        # 应用内容
        "appProtocol": app, "appName": app, "appCategory": None,
        "isCleartextProto": app in ("FTP", "TELNET", "HTTP", "SMTP"),
        "authAttempts": None, "authSuccess": None,
        "fileTransferCount": None, "fileName": None, "fileMime": None, "fileSize": None,
        "fileHashMd5": None, "emailFrom": None, "emailToCount": None, "emailAttachCount": None,
        "dnsOverTls": False, "rpcService": "SMB" if app == "SMB" else None,
        # 关联聚合（由分析引擎实时计算，此处留空）
        "hostUniqueDstIp": None, "hostUniqueDstPort": None, "hostUniqueDstDomain": None,
        "hostSessionCount": None, "hostFanOut": None, "hostFailConnRatio": None,
        "hostUpBytesTotal": None, "hostDownBytesTotal": None, "hostUpBytesBaseline": None,
        "hostBaselineDeviation": None, "portDiversity": None, "dstSessionFanIn": None,
        "pairSessionCount": None, "pairByteSymmetry": None, "samePortHitCount": None,
        "newDestCount": None,
        # 来源标记
        "pcapBatch": batch_tag,
    }

    return (
        session_id, f["srcIp"], f["srcPort"], f["dstIp"], f["dstPort"],
        f["protocol"], app, direction, f["startTime"], f["duration"],
        f["upPackets"], f["downPackets"], f["upBytes"], f["downBytes"],
        None, 0, json.dumps(meta, ensure_ascii=False),
    )


INSERT_SQL = (
    "INSERT INTO sessions (session_id, src_ip, src_port, dst_ip, dst_port, protocol, "
    "app_protocol, direction, start_time, duration, up_packets, down_packets, up_bytes, "
    "down_bytes, dst_country, threat_score, meta) "
    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
)


def import_flows(flows: list[dict], opts: dict) -> dict:
    batch_id = insert(
        "INSERT INTO ingest_batches (filename, size_bytes, packets, flows, skipped, duration_ms) "
        "VALUES (%s,%s,%s,%s,%s,%s)",
        (opts["filename"], opts["sizeBytes"], opts["packets"],
         len(flows), opts["skipped"], opts["durationMs"]),
    )
    batch_tag = str(batch_id).zfill(3)
    rows = [_flow_to_row(f, batch_tag) for f in flows]
    BATCH = 200
    for i in range(0, len(rows), BATCH):
        executemany(INSERT_SQL, rows[i: i + BATCH])
    return {"batchId": batch_id, "imported": len(rows)}
