"""流量会话元数据生成器（Python 版）
生成 7 天正常背景流量 + 14 类攻击/异常场景会话，每条会话携带全量建模字段（meta）。
用法：python3 -m backend.seed
"""
import json
import math
import random
import re
import time
from datetime import datetime, timedelta

from .db import query_one, executemany
from .pcap_importer import INSERT_SQL

# ---------- 可复现随机数 ----------

_rand = random.Random(20260921)


def ri(a: int, b: int) -> int:
    return _rand.randint(a, b)


def rf(a: float, b: float, digits: int = 2) -> float:
    return round(_rand.uniform(a, b), digits)


def pick(arr):
    return arr[_rand.randrange(len(arr))]


# ---------- 常量 ----------

INTERNAL_HOSTS = [f"10.12.{ri(1, 9)}.{i + 10}" for i in range(40)]
DMZ_WEB = "10.12.0.10"
DNS_SERVER = "10.12.0.2"
LEGIT_DOMAINS = [
    "www.baidu.com", "www.aliyun.com", "mail.corp.example", "oa.corp.example",
    "cdn.tencent.com", "update.microsoft.com", "www.apple.com", "fonts.gstatic.com",
    "api.github.com", "mirrors.ustc.edu.cn", "www.zhihu.com", "docs.corp.example",
]
LEGIT_IPS = {d: f"93.184.{200 + i}.{ri(2, 250)}" for i, d in enumerate(LEGIT_DOMAINS)}
CLOUD_IPS = ["104.18.32.7", "140.205.220.96", "117.18.237.29", "13.107.42.14"]
HIGH_RISK = [
    {"ip": "175.45.176.14", "country": "朝鲜", "city": "平壤"},
    {"ip": "5.160.24.9", "country": "伊朗", "city": "德黑兰"},
    {"ip": "95.213.200.51", "country": "俄罗斯", "city": "莫斯科"},
]
C2_IP = "203.0.113.66"
ATTACKER_IP = "198.51.100.77"
EXFIL_IP = "203.0.113.200"
TOR_EXIT = "185.220.101.4"
ASN_ORGS = ["Google LLC", "Cloudflare Inc", "阿里云", "腾讯云计算", "Microsoft Corp"]

UA_GOOD = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
UA_BAD = "sqlmap/1.7.2#stable (https://sqlmap.org)"

NOW = datetime.now()


def entropy_of(s: str) -> float:
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    e = 0.0
    for n in counts.values():
        p = n / len(s)
        e -= p * math.log2(p)
    return round(e, 2)


def random_string(n: int, alpha: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> str:
    return "".join(alpha[_rand.randrange(len(alpha))] for _ in range(n))


_seq = 0


def ts(days_ago: float, hour: int, minute: int = None, second: int = None) -> datetime:
    minute = ri(0, 59) if minute is None else minute
    second = ri(0, 59) if second is None else second
    base = NOW - timedelta(days=days_ago)
    return base.replace(hour=hour, minute=minute, second=second,
                        microsecond=ri(0, 999) * 1000)


def make_session(o: dict) -> dict:
    """生成一条会话的完整 meta（覆盖全部建模字段），调用方传场景覆盖项 metaExtra"""
    global _seq
    _seq += 1
    meta_extra = o.get("metaExtra", {})
    up = o.get("upPackets", ri(4, 120))
    down = o.get("downPackets", ri(4, 120))
    up_bytes = o.get("upBytes", up * ri(60, 900))
    down_bytes = o.get("downBytes", down * ri(200, 1400))
    start = o.get("startTime", ts(ri(0, 6), ri(8, 20)))
    dur = o.get("duration", ri(200, 120_000))
    hour = start.hour
    is_night = 0 <= hour < 6
    dow = start.isoweekday()
    direction = o.get("direction", "内到外")
    app = o.get("appProtocol", "HTTPS")
    dns_name = meta_extra.get("dnsQueryName") or pick(LEGIT_DOMAINS)
    is_dns = app == "DNS"
    is_http = app == "HTTP"
    is_tls = app == "HTTPS"
    clear = app in ("FTP", "TELNET", "HTTP", "SMTP")
    end = start + timedelta(milliseconds=dur)

    meta = {
        # 五元组与链路
        "sessionId": f"S-{str(_seq).zfill(6)}",
        "srcIp": o.get("srcIp"), "srcPort": o.get("srcPort"),
        "dstIp": o.get("dstIp"), "dstPort": o.get("dstPort"),
        "protocol": o.get("protocol", "TCP"), "ipVersion": "IPv4", "vlanId": ri(100, 130),
        "ingressIf": "eth0", "egressIf": "eth1", "direction": direction,
        "srcMac": f"00:1A:2B:{ri(10, 99)}:{ri(10, 99)}:{ri(10, 99)}",
        "dstMac": f"00:5E:4D:{ri(10, 99)}:{ri(10, 99)}:{ri(10, 99)}",
        "sensorId": pick(["sensor-core-01", "sensor-dmz-02", "sensor-edge-03"]),
        # 会话流统计
        "startTime": start.isoformat(), "endTime": end.isoformat(),
        "duration": dur, "upPackets": up, "downPackets": down, "totalPackets": up + down,
        "upBytes": up_bytes, "downBytes": down_bytes, "totalBytes": up_bytes + down_bytes,
        "upDownByteRatio": round(up_bytes / down_bytes, 2) if down_bytes > 0 else 99,
        "upPacketRate": round(up / (dur / 1000 + 0.01), 0),
        "downPacketRate": round(down / (dur / 1000 + 0.01), 0),
        "upByteRate": round(up_bytes / (dur / 1000 + 0.01)),
        "downByteRate": round(down_bytes / (dur / 1000 + 0.01)),
        "avgPktLenUp": round(up_bytes / up), "avgPktLenDown": round(down_bytes / down),
        "maxPktLenUp": 1460, "minPktLenUp": 54,
        "pktLenStdUp": rf(10, 300), "pktLenStdDown": rf(50, 500),
        "smallPktRatio": rf(0.1, 0.5), "retransCount": ri(0, 4), "retransRatio": rf(0, 0.02, 3),
        "outOfOrderCount": ri(0, 2), "fragCount": 0,
        "payloadEntropyUp": rf(4.5, 7.8, 1), "payloadEntropyDown": rf(5.0, 7.9, 1),
        "idleTimeTotal": ri(0, 5000),
        # TCP
        "synCount": 1, "synAckCount": 1, "ackCount": up + down - 2, "finCount": 2,
        "rstCount": 0, "pshCount": round((up + down) / 2), "urgCount": 0,
        "handshakeRtt": ri(1, 80), "handshakeSuccess": True, "closeReason": "FIN",
        "tcpState": "CLOSED",
        "initWinSize": pick([64240, 65535, 29200]), "winScale": 8, "mss": 1460,
        "ttlInit": pick([64, 128, 255]), "zeroWinCount": 0,
        # DNS
        "dnsQueryName": dns_name if is_dns else None,
        "dnsQueryType": pick(["A", "A", "A", "AAAA", "MX"]) if is_dns else None,
        "dnsRcode": "NOERROR" if is_dns else None,
        "dnsAnswerCount": ri(1, 6) if is_dns else 0,
        "dnsAnswerIps": (LEGIT_IPS.get(dns_name) or f"93.184.{ri(2, 250)}.{ri(2, 250)}") if is_dns else None,
        "dnsTtl": pick([60, 300, 600, 3600]) if is_dns else None,
        "dnsQueryLen": len(dns_name) if is_dns else 0,
        "dnsSubdomainLen": len(dns_name.split(".")[0]) if is_dns else 0,
        "dnsNameEntropy": entropy_of(dns_name) if is_dns else 0,
        "dnsDigitRatio": round(len(re.findall(r"\d", dns_name)) / len(dns_name), 2) if is_dns else 0,
        "dnsIsNxdomain": False, "dnsNxdomainRatio": rf(0.01, 0.08),
        "dnsQpsHost": rf(0.05, 0.6), "dnsUniqueDomains": ri(5, 60),
        "dnsTxtCount": 0, "dnsLongQueryCount": 0,
        "dnsServerIp": DNS_SERVER if is_dns else None,
        "dnsResponseSize": ri(60, 220) if is_dns else 0,
        "dnsIsDoH": False, "dnsEdns": True, "dnsRtt": ri(2, 60) if is_dns else None,
        "dnsTld": ".com" if is_dns else None,
        # HTTP
        "httpMethod": pick(["GET", "GET", "POST"]) if is_http else None,
        "httpHost": dns_name if is_http else None,
        "httpUri": pick(["/", "/index.html", "/api/v1/list", "/static/app.js"]) if is_http else None,
        "httpUriLen": ri(1, 40) if is_http else 0,
        "httpUserAgent": UA_GOOD if is_http else None,
        "httpStatus": pick([200, 200, 200, 304, 404]) if is_http else None,
        "httpContentType": pick(["text/html", "application/json", "text/css"]) if is_http else None,
        "httpContentLen": ri(500, 80_000) if is_http else 0,
        "httpReferer": "https://www.baidu.com/" if is_http else None,
        "httpCookieCount": ri(0, 5) if is_http else 0,
        "httpHasSqlPattern": False, "httpHasXssPattern": False, "httpHasPathTraversal": False,
        "httpAuthFailCount": 0, "httpVersion": "HTTP/1.1" if is_http else None, "httpIsProxy": False,
        # TLS
        "tlsVersion": pick(["TLS1.2", "TLS1.3", "TLS1.3"]) if is_tls else None,
        "tlsSni": dns_name if is_tls else None,
        "tlsCipherSuite": pick(["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]) if is_tls else None,
        "tlsJa3": "769,4865-4866-4867,0-11-10,29-23-24,0" if is_tls else None,
        "tlsJa3s": "769,4865,0-43-51" if is_tls else None,
        "tlsCertSubject": f"CN={dns_name}" if is_tls else None,
        "tlsCertIssuer": "CN=DigiCert TLS RSA SHA256 2020 CA1" if is_tls else None,
        "tlsCertSelfSigned": False, "tlsCertValidDays": ri(90, 398) if is_tls else None,
        "tlsCertExpired": False, "tlsCertSnMatch": True,
        "tlsAlpn": "h2" if is_tls else None, "tlsSessionResumed": _rand.random() > 0.7,
        "tlsWeakCipher": False, "tlsOldVersion": False,
        "tlsClientHelloLen": ri(400, 600) if is_tls else None,
        "tlsServerNameLen": len(dns_name) if is_tls else None,
        "tlsHandshakeMs": ri(40, 200) if is_tls else None,
        "tlsCertChainLen": ri(2, 4) if is_tls else None,
        "tlsEncPayloadRatio": rf(0.85, 0.98) if is_tls else None,
        # 时间
        "hourOfDay": hour, "dayOfWeek": dow,
        "isWorkHour": 9 <= hour < 18 and dow <= 5, "isNight": is_night,
        "intervalMean": 0, "intervalStd": 0, "intervalCv": 0, "periodicityScore": ri(5, 40),
        "burstCount": ri(0, 3), "activeRatio": rf(0.05, 0.4),
        "nightSessionRatio": rf(0.02, 0.15), "weekendRatio": rf(0.05, 0.25),
        "firstSeen": (NOW - timedelta(days=ri(30, 180))).isoformat(), "isNewDestination": False,
        # 地理情报
        "srcCountry": "中国", "dstCountry": o.get("dstCountry") or pick(["中国", "美国", "日本", "新加坡", "德国"]),
        "srcAsn": 4134, "dstAsn": pick([15169, 13335, 37963, 45090]),
        "dstAsnOrg": pick(ASN_ORGS), "dstIsCloud": _rand.random() > 0.5,
        "dstIsTor": False, "dstIsProxy": False,
        "dstThreatScore": o.get("threatScore", ri(0, 25)), "dstIsKnownC2": False,
        "dstIsHighRiskGeo": False,
        "geoDistanceKm": ri(200, 11000),
        "dstCity": pick(["北京", "上海", "东京", "新加坡", "法兰克福"]),
        "ipReputation": "良好",
        # 应用内容
        "appProtocol": app, "appName": "Web 浏览" if is_tls else app,
        "appCategory": "办公" if is_tls else "基础协议",
        "isCleartextProto": clear, "authAttempts": 0, "authSuccess": True,
        "fileTransferCount": 0, "fileName": None, "fileMime": None, "fileSize": 0,
        "fileHashMd5": None,
        "emailFrom": "user@corp.example" if app == "SMTP" else None,
        "emailToCount": ri(1, 3) if app == "SMTP" else 0, "emailAttachCount": 0,
        "dnsOverTls": False, "rpcService": "SMB2" if app == "SMB" else None,
        # 关联聚合
        "hostUniqueDstIp": ri(5, 60), "hostUniqueDstPort": ri(3, 40), "hostUniqueDstDomain": ri(5, 80),
        "hostSessionCount": ri(50, 800), "hostFanOut": ri(0, 3), "hostFailConnRatio": rf(0.01, 0.1),
        "hostUpBytesTotal": ri(1_000_000, 50_000_000), "hostDownBytesTotal": ri(5_000_000, 200_000_000),
        "hostUpBytesBaseline": ri(1_000_000, 40_000_000), "hostBaselineDeviation": rf(0.5, 2.5),
        "portDiversity": rf(0.05, 0.3), "dstSessionFanIn": ri(1, 20),
        "pairSessionCount": ri(1, 30), "pairByteSymmetry": rf(0.1, 0.6),
        "samePortHitCount": ri(0, 2), "newDestCount": ri(0, 5),
        **meta_extra,
    }

    return {
        "sessionId": meta["sessionId"],
        "srcIp": o["srcIp"], "srcPort": o["srcPort"],
        "dstIp": o["dstIp"], "dstPort": o["dstPort"],
        "protocol": o.get("protocol", "TCP"),
        "appProtocol": app, "direction": direction,
        "startTime": start, "duration": dur,
        "upPackets": up, "downPackets": down, "upBytes": up_bytes, "downBytes": down_bytes,
        "dstCountry": meta.get("dstCountry"),
        "threatScore": meta.get("dstThreatScore", 0),
        "meta": meta,
    }


# ---------- 场景生成 ----------

def normal_traffic() -> list[dict]:
    out = []
    for _ in range(1500):
        host = pick(INTERNAL_HOSTS)
        kind = _rand.random()
        if kind < 0.18:
            domain = pick(LEGIT_DOMAINS)
            out.append(make_session({
                "srcIp": host, "srcPort": ri(49152, 65535), "dstIp": DNS_SERVER, "dstPort": 53,
                "protocol": "UDP", "appProtocol": "DNS", "direction": "内到内",
                "upPackets": 1, "downPackets": 1, "upBytes": ri(40, 90), "downBytes": ri(60, 300),
                "duration": ri(5, 120), "metaExtra": {"dnsQueryName": domain},
            }))
        elif kind < 0.72:
            domain = pick(LEGIT_DOMAINS)
            out.append(make_session({
                "srcIp": host, "srcPort": ri(49152, 65535),
                "dstIp": pick([LEGIT_IPS[domain], *CLOUD_IPS]),
                "dstPort": 443, "appProtocol": "HTTPS", "metaExtra": {"dnsQueryName": domain},
            }))
        elif kind < 0.78:
            out.append(make_session({
                "srcIp": host, "srcPort": ri(49152, 65535),
                "dstIp": pick([LEGIT_IPS[d] for d in LEGIT_DOMAINS]), "dstPort": 80,
                "appProtocol": "HTTP",
            }))
        elif kind < 0.84:
            out.append(make_session({
                "srcIp": host, "srcPort": ri(49152, 65535), "dstIp": "10.12.0.25", "dstPort": 25,
                "appProtocol": "SMTP", "direction": "内到内",
            }))
        elif kind < 0.92:
            out.append(make_session({
                "srcIp": host, "srcPort": ri(49152, 65535), "dstIp": f"10.12.0.{ri(20, 40)}",
                "dstPort": 445, "appProtocol": "SMB", "direction": "内到内",
            }))
        else:
            out.append(make_session({
                "srcIp": host, "srcPort": ri(49152, 65535), "dstIp": f"10.12.0.{ri(20, 40)}",
                "dstPort": 22, "appProtocol": "SSH", "direction": "内到内",
                "metaExtra": {"authAttempts": 1},
            }))
    return out


def port_scan() -> list[dict]:
    out = []
    scanner = "10.12.7.66"
    for _ in range(260):
        out.append(make_session({
            "srcIp": scanner, "srcPort": ri(49152, 65535), "dstIp": f"10.13.0.{ri(2, 30)}",
            "dstPort": ri(1, 1024), "appProtocol": "OTHER", "direction": "内到内",
            "startTime": ts(2, 14, ri(0, 9)), "duration": ri(1, 30),
            "upPackets": 1, "downPackets": 1, "upBytes": 54, "downBytes": 54,
            "metaExtra": {
                "rstCount": 1, "closeReason": "RST", "tcpState": "RESET", "handshakeSuccess": False,
                "smallPktRatio": 1, "synCount": 1, "synAckCount": 0, "ackCount": 0, "finCount": 0,
                "hostUniqueDstPort": 260, "hostFailConnRatio": 0.87, "portDiversity": 0.95,
                "pktLenStdUp": 0.5, "appProtocol": "OTHER", "appName": "未知", "appCategory": "未识别",
            },
        }))
    return out


def lateral_move() -> list[dict]:
    out = []
    src = "10.12.7.66"
    for _ in range(22):
        port = pick([445, 3389, 22, 5985])
        out.append(make_session({
            "srcIp": src, "srcPort": ri(49152, 65535), "dstIp": f"10.12.{ri(1, 9)}.{ri(10, 60)}",
            "dstPort": port,
            "appProtocol": {445: "SMB", 3389: "RDP", 22: "SSH"}.get(port, "WMI"),
            "direction": "内到内", "startTime": ts(2, 15, ri(0, 59)),
            "duration": ri(1000, 20000),
            "metaExtra": {
                "hostFanOut": 22, "samePortHitCount": 9, "authAttempts": ri(1, 3),
                "authSuccess": _rand.random() > 0.4, "appCategory": "远程控制",
            },
        }))
    return out


def brute_force() -> list[dict]:
    out = []
    src = "10.12.9.23"
    for _ in range(60):
        out.append(make_session({
            "srcIp": src, "srcPort": ri(49152, 65535), "dstIp": DMZ_WEB, "dstPort": 22,
            "appProtocol": "SSH", "direction": "内到内", "startTime": ts(1, 22, ri(0, 29)),
            "duration": ri(300, 2500), "upPackets": ri(6, 14), "downPackets": ri(6, 14),
            "metaExtra": {
                "authAttempts": 1, "authSuccess": False, "closeReason": "RST", "rstCount": 1,
                "appCategory": "远程控制",
            },
        }))
    return out


def web_attack() -> list[dict]:
    out = []
    payloads = [
        {"uri": "/login.php?id=1' OR '1'='1", "sql": True, "xss": False, "trav": False},
        {"uri": "/search?q=<script>alert(1)</script>", "sql": False, "xss": True, "trav": False},
        {"uri": "/download?file=../../../../etc/passwd", "sql": False, "xss": False, "trav": True},
        {"uri": "/api/user?id=1 UNION SELECT username,password FROM users--", "sql": True, "xss": False, "trav": False},
    ]
    for _ in range(36):
        p = pick(payloads)
        out.append(make_session({
            "srcIp": ATTACKER_IP, "srcPort": ri(49152, 65535), "dstIp": DMZ_WEB, "dstPort": 80,
            "appProtocol": "HTTP", "direction": "外到内", "startTime": ts(3, ri(10, 16)),
            "metaExtra": {
                "httpMethod": "GET", "httpHost": "www.corp.example", "httpUri": p["uri"],
                "httpUriLen": len(p["uri"]), "httpUserAgent": UA_BAD,
                "httpStatus": pick([200, 403, 500]), "httpHasSqlPattern": p["sql"],
                "httpHasXssPattern": p["xss"], "httpHasPathTraversal": p["trav"],
                "httpAuthFailCount": ri(0, 2), "srcCountry": "美国", "dstCountry": "中国",
                "ipReputation": "恶意", "dstThreatScore": 0,
            },
            "threatScore": 0,
        }))
    return out


def c2_beacon() -> list[dict]:
    out = []
    src = "10.12.3.45"
    for i in range(48):
        start = NOW - timedelta(days=2) + timedelta(hours=i, seconds=ri(-20, 20))
        out.append(make_session({
            "srcIp": src, "srcPort": 52413, "dstIp": C2_IP, "dstPort": 443,
            "appProtocol": "HTTPS", "startTime": start, "duration": ri(200, 800),
            "upPackets": 3, "downPackets": 3, "upBytes": ri(120, 160), "downBytes": ri(130, 170),
            "metaExtra": {
                "intervalMean": 3600, "intervalStd": 15, "intervalCv": 0.004, "periodicityScore": 97,
                "pktLenStdUp": 4.2, "pktLenStdDown": 5.1, "pairByteSymmetry": 0.93,
                "pairSessionCount": 48, "smallPktRatio": 1, "avgPktLenUp": 48,
                "tlsSni": "cdn-sync.akamai-cdn.example", "tlsCertSelfSigned": True,
                "tlsCertSnMatch": False, "tlsCertValidDays": 30, "tlsCertIssuer": "CN=localhost",
                "dstThreatScore": 88, "dstIsKnownC2": True, "ipReputation": "恶意",
                "dstCountry": "美国", "dstCity": "洛杉矶",
                "payloadEntropyUp": 7.8, "payloadEntropyDown": 7.9,
                "isNewDestination": True, "dnsQueryName": "cdn-sync.akamai-cdn.example",
            },
            "threatScore": 88,
        }))
    return out


def dns_tunnel() -> list[dict]:
    out = []
    src = "10.12.5.88"
    for _ in range(80):
        q = f"{random_string(52)}.tunnel.exfil-cdn.example"
        out.append(make_session({
            "srcIp": src, "srcPort": ri(49152, 65535), "dstIp": DNS_SERVER, "dstPort": 53,
            "protocol": "UDP", "appProtocol": "DNS", "direction": "内到内",
            "startTime": ts(1, ri(0, 23)), "duration": ri(10, 200),
            "upPackets": 1, "downPackets": 1, "upBytes": ri(90, 120), "downBytes": ri(350, 500),
            "metaExtra": {
                "dnsQueryName": q, "dnsQueryType": "TXT", "dnsQueryLen": len(q),
                "dnsSubdomainLen": 52, "dnsNameEntropy": entropy_of(q), "dnsTxtCount": 1,
                "dnsLongQueryCount": 1, "dnsResponseSize": ri(350, 500), "dnsTtl": 30,
                "payloadEntropyUp": 7.4, "dnsQpsHost": 2.4,
            },
        }))
    return out


def dga_domains() -> list[dict]:
    out = []
    src = "10.12.6.30"
    for _ in range(90):
        d = f"{random_string(ri(12, 18))}.{pick(['xyz', 'top', 'club', 'info'])}"
        nx = _rand.random() > 0.25
        out.append(make_session({
            "srcIp": src, "srcPort": ri(49152, 65535), "dstIp": DNS_SERVER, "dstPort": 53,
            "protocol": "UDP", "appProtocol": "DNS", "direction": "内到内",
            "startTime": ts(4, ri(0, 23)), "duration": ri(5, 100),
            "upPackets": 1, "downPackets": 1, "upBytes": ri(50, 80), "downBytes": ri(50, 90),
            "metaExtra": {
                "dnsQueryName": d, "dnsQueryType": "A",
                "dnsRcode": "NXDOMAIN" if nx else "NOERROR",
                "dnsIsNxdomain": nx, "dnsNxdomainRatio": 0.74, "dnsNameEntropy": entropy_of(d),
                "dnsDigitRatio": round(len(re.findall(r"\d", d)) / len(d), 2),
                "dnsUniqueDomains": 90, "dnsTld": "." + d.split(".")[-1],
            },
        }))
    return out


def covert_channel() -> list[dict]:
    out = []
    src = "10.12.8.77"
    for _ in range(14):
        out.append(make_session({
            "srcIp": src, "srcPort": ri(49152, 65535), "dstIp": f"45.155.204.{ri(2, 250)}",
            "dstPort": 8443, "appProtocol": "HTTPS", "startTime": ts(ri(1, 5), ri(0, 23)),
            "metaExtra": {
                "tlsSni": "update.win-svc.example", "tlsCertSnMatch": False,
                "tlsCertSelfSigned": True, "tlsCertValidDays": 14, "tlsCertIssuer": "CN=localhost",
                "tlsOldVersion": True, "tlsVersion": "TLS1.0", "tlsWeakCipher": True,
                "dstThreatScore": 65, "ipReputation": "可疑", "dstCountry": "荷兰",
            },
            "threatScore": 65,
        }))
    return out


def data_exfil() -> list[dict]:
    out = []
    src = "10.12.4.19"
    for _ in range(18):
        up = ri(15_000_000, 30_000_000)
        out.append(make_session({
            "srcIp": src, "srcPort": ri(49152, 65535), "dstIp": EXFIL_IP, "dstPort": 443,
            "appProtocol": "HTTPS", "startTime": ts(1, ri(1, 4)),
            "duration": ri(300_000, 900_000), "upPackets": round(up / 1200),
            "downPackets": ri(50, 200), "upBytes": up, "downBytes": ri(60_000, 200_000),
            "metaExtra": {
                "upDownByteRatio": rf(80, 200), "isNewDestination": True,
                "firstSeen": (NOW - timedelta(days=1.2)).isoformat(),
                "payloadEntropyUp": 7.9, "fileTransferCount": ri(1, 4),
                "fileName": pick(["backup_2026.zip", "财务汇总.q3.enc", "rd_docs.tar.gz"]),
                "fileMime": "application/zip", "fileSize": up,
                "hostUpBytesTotal": 420_000_000, "hostUpBytesBaseline": 25_000_000,
                "hostBaselineDeviation": 16.8, "dstCountry": "美国", "dstIsCloud": True,
                "dstAsnOrg": "未知 IDC", "nightSessionRatio": 0.7, "isNight": True,
            },
        }))
    return out


def bulk_transfer() -> list[dict]:
    out = []
    src = "10.12.8.12"
    for _ in range(6):
        down = ri(120_000_000, 200_000_000)
        out.append(make_session({
            "srcIp": src, "srcPort": ri(49152, 65535), "dstIp": pick(CLOUD_IPS), "dstPort": 443,
            "appProtocol": "HTTPS", "startTime": ts(0, ri(10, 17)),
            "duration": ri(600_000, 1_800_000), "downPackets": round(down / 1400),
            "upPackets": ri(500, 2000), "downBytes": down, "upBytes": ri(400_000, 1_500_000),
            "metaExtra": {
                "hostBaselineDeviation": 9.2, "hostDownBytesTotal": 950_000_000,
                "dstIsCloud": True, "appCategory": "文件传输",
            },
        }))
    return out


def cleartext_abuse() -> list[dict]:
    out = []
    src = "10.12.2.51"
    for _ in range(8):
        out.append(make_session({
            "srcIp": src, "srcPort": ri(49152, 65535), "dstIp": "10.12.0.30", "dstPort": 21,
            "appProtocol": "FTP", "direction": "内到内", "startTime": ts(ri(0, 4), ri(9, 18)),
            "upBytes": ri(2_000_000, 20_000_000),
            "metaExtra": {
                "authAttempts": 1, "authSuccess": True, "fileTransferCount": ri(1, 5),
                "fileName": pick(["design.psd", "合同扫描件.pdf", "salary.xls"]),
                "fileMime": "application/octet-stream", "appCategory": "文件传输",
            },
        }))
    out.append(make_session({
        "srcIp": "10.12.2.52", "srcPort": 49190, "dstIp": "10.12.0.31", "dstPort": 23,
        "appProtocol": "TELNET", "direction": "内到内", "startTime": ts(2, 11),
        "metaExtra": {"authAttempts": 3, "authSuccess": True, "appCategory": "远程控制"},
    }))
    return out


def off_hours() -> list[dict]:
    out = []
    src = "10.12.6.41"
    for _ in range(26):
        out.append(make_session({
            "srcIp": src, "srcPort": ri(49152, 65535),
            "dstIp": pick([LEGIT_IPS[d] for d in LEGIT_DOMAINS]),
            "dstPort": 443, "appProtocol": "HTTPS", "startTime": ts(ri(0, 5), ri(0, 5)),
            "upBytes": ri(1_000_000, 8_000_000),
            "metaExtra": {"nightSessionRatio": 0.62, "isNight": True, "isWorkHour": False},
        }))
    return out


def geo_anomaly() -> list[dict]:
    out = []
    for hr in HIGH_RISK:
        for _ in range(4):
            out.append(make_session({
                "srcIp": pick(INTERNAL_HOSTS), "srcPort": ri(49152, 65535),
                "dstIp": hr["ip"], "dstPort": pick([443, 8080]),
                "appProtocol": "HTTPS", "startTime": ts(ri(0, 4), ri(0, 23)),
                "metaExtra": {
                    "dstCountry": hr["country"], "dstCity": hr["city"], "dstIsHighRiskGeo": True,
                    "dstThreatScore": ri(80, 95), "ipReputation": "恶意", "geoDistanceKm": ri(5000, 9000),
                },
                "threatScore": 85,
            }))
    for _ in range(5):
        out.append(make_session({
            "srcIp": "10.12.9.99", "srcPort": ri(49152, 65535), "dstIp": TOR_EXIT, "dstPort": 9001,
            "appProtocol": "TOR", "startTime": ts(1, ri(0, 23)),
            "metaExtra": {
                "dstIsTor": True, "dstCountry": "德国", "dstThreatScore": 78,
                "ipReputation": "可疑", "appCategory": "代理工具",
            },
            "threatScore": 78,
        }))
    return out


def baseline_deviation() -> list[dict]:
    out = []
    src = "10.12.1.88"
    for _ in range(30):
        up = ri(8_000_000, 15_000_000)
        out.append(make_session({
            "srcIp": src, "srcPort": ri(49152, 65535), "dstIp": pick(CLOUD_IPS), "dstPort": 443,
            "appProtocol": "HTTPS", "startTime": ts(0, ri(9, 20)),
            "upBytes": up, "upPackets": round(up / 1300),
            "metaExtra": {
                "hostUpBytesTotal": 380_000_000, "hostUpBytesBaseline": 22_000_000,
                "hostBaselineDeviation": 17.3, "activeRatio": 0.82, "hostSessionCount": 1450,
            },
        }))
    return out


def generate_all() -> list[dict]:
    return [
        *normal_traffic(), *port_scan(), *lateral_move(), *brute_force(), *web_attack(),
        *c2_beacon(), *dns_tunnel(), *dga_domains(), *covert_channel(), *data_exfil(),
        *bulk_transfer(), *cleartext_abuse(), *off_hours(), *geo_anomaly(), *baseline_deviation(),
    ]


def main():
    existing = query_one("SELECT COUNT(*) AS c FROM sessions")["c"]
    if existing:
        print(f"sessions 表已有 {existing} 条数据，跳过种子生成（如需重置请先清空表）")
        return
    sessions = generate_all()
    rows = [
        (s["sessionId"], s["srcIp"], s["srcPort"], s["dstIp"], s["dstPort"], s["protocol"],
         s["appProtocol"], s["direction"], s["startTime"], s["duration"],
         s["upPackets"], s["downPackets"], s["upBytes"], s["downBytes"],
         s["dstCountry"], s["threatScore"], json.dumps(s["meta"], ensure_ascii=False))
        for s in sessions
    ]
    BATCH = 200
    for i in range(0, len(rows), BATCH):
        executemany(INSERT_SQL, rows[i: i + BATCH])
    print(f"已生成 {len(rows)} 条演示会话元数据")


if __name__ == "__main__":
    main()
