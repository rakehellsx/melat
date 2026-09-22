"""纯 Python pcap 解析器
支持 classic pcap（libpcap）格式、Ethernet(含 VLAN) / IPv4 / TCP / UDP，
会话化为五元组流，并深度解析 DNS、TLS ClientHello(SNI)、HTTP 要素。
"""
import math
import struct
from datetime import datetime, timezone

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
             16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY", 65: "HTTPS"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
TLS_VERSIONS = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}

INACTIVE_TIMEOUT_MS = 30_000  # 类 NetFlow 非活跃超时：超过则切分为新会话


def ip4(buf: bytes, off: int) -> str:
    return f"{buf[off]}.{buf[off + 1]}.{buf[off + 2]}.{buf[off + 3]}"


def is_private_ip(ip: str) -> bool:
    p = [int(x) for x in ip.split(".")]
    return p[0] == 10 or p[0] == 127 or (p[0] == 172 and 16 <= p[1] <= 31) or (p[0] == 192 and p[1] == 168)


def _flow_key(src_ip, src_port, dst_ip, dst_port, proto) -> str:
    return f"{src_ip}:{src_port}|{dst_ip}:{dst_port}|{proto}"


# ---------- DNS 解析 ----------

def _parse_dns_name(buf: bytes, off: int) -> tuple[str, int]:
    labels = []
    pos = off
    jumped = False
    nxt = off
    hops = 0
    while pos < len(buf) and hops < 32:
        hops += 1
        length = buf[pos]
        if length == 0:
            if not jumped:
                nxt = pos + 1
            break
        if (length & 0xC0) == 0xC0:
            ptr = ((length & 0x3F) << 8) | buf[pos + 1]
            if not jumped:
                nxt = pos + 2
            pos = ptr
            jumped = True
            continue
        labels.append(buf[pos + 1: pos + 1 + length].decode("latin1"))
        pos += 1 + length
        if not jumped:
            nxt = pos
    return ".".join(labels), nxt


def _parse_dns(payload: bytes) -> dict | None:
    if len(payload) < 12:
        return None
    flags = struct.unpack_from(">H", payload, 2)[0]
    is_response = (flags & 0x8000) != 0
    rcode = flags & 0x000F
    qdcount = struct.unpack_from(">H", payload, 4)[0]
    ancount = struct.unpack_from(">H", payload, 6)[0]
    if qdcount == 0:
        return None

    qname, pos = _parse_dns_name(payload, 12)
    if pos + 4 > len(payload):
        return None
    qtype = struct.unpack_from(">H", payload, pos)[0]
    pos += 4

    answer_ips = []
    first_ttl = None
    p = pos
    for _ in range(min(ancount, 20)):
        _, p = _parse_dns_name(payload, p)
        if p + 10 > len(payload):
            break
        rtype = struct.unpack_from(">H", payload, p)[0]
        ttl = struct.unpack_from(">I", payload, p + 4)[0]
        rdlen = struct.unpack_from(">H", payload, p + 8)[0]
        p += 10
        if p + rdlen > len(payload):
            break
        if first_ttl is None:
            first_ttl = ttl
        if rtype == 1 and rdlen == 4:
            answer_ips.append(ip4(payload, p))
        p += rdlen

    return {
        "queryName": qname,
        "queryType": DNS_TYPES.get(qtype, f"TYPE{qtype}"),
        "rcode": DNS_RCODES.get(rcode, f"RCODE{rcode}"),
        "answerCount": ancount,
        "answerIps": answer_ips,
        "ttl": first_ttl,
        "responseSize": len(payload),
        "isResponse": is_response,
    }


# ---------- TLS ClientHello 解析 ----------

def _parse_tls_client_hello(payload: bytes) -> dict | None:
    if len(payload) < 9 or payload[0] != 0x16:
        return None
    rec_ver = struct.unpack_from(">H", payload, 1)[0]
    if payload[5] != 0x01:  # ClientHello
        return None
    ver = TLS_VERSIONS.get(rec_ver)
    pos = 5 + 4 + 2 + 32  # hs header + client version + random
    if pos + 1 > len(payload):
        return {"sni": None, "version": ver, "cipherSuites": 0}
    sid_len = payload[pos]
    pos += 1 + sid_len
    if pos + 2 > len(payload):
        return {"sni": None, "version": ver, "cipherSuites": 0}
    cs_len = struct.unpack_from(">H", payload, pos)[0]
    cipher_suites = cs_len // 2
    pos += 2 + cs_len
    if pos + 1 > len(payload):
        return {"sni": None, "version": ver, "cipherSuites": cipher_suites}
    comp_len = payload[pos]
    pos += 1 + comp_len
    if pos + 2 > len(payload):
        return {"sni": None, "version": ver, "cipherSuites": cipher_suites}
    ext_total = struct.unpack_from(">H", payload, pos)[0]
    pos += 2
    ext_end = min(pos + ext_total, len(payload))
    sni = None
    while pos + 4 <= ext_end:
        ext_type, ext_len = struct.unpack_from(">HH", payload, pos)
        pos += 4
        if ext_type == 0x0000 and pos + ext_len <= len(payload):
            sp = pos + 2  # list length
            if sp + 3 <= pos + ext_len:
                name_type = payload[sp]
                name_len = struct.unpack_from(">H", payload, sp + 1)[0]
                if name_type == 0 and sp + 3 + name_len <= len(payload):
                    sni = payload[sp + 3: sp + 3 + name_len].decode("latin1")
            break
        pos += ext_len
    return {"sni": sni, "version": ver, "cipherSuites": cipher_suites}


# ---------- HTTP 解析 ----------

import re

HTTP_REQ_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\S+) HTTP/1\.[01]\r?\n")
HTTP_RESP_RE = re.compile(r"^HTTP/1\.[01] (\d{3})")
HTTP_HOST_RE = re.compile(r"(?:^|\r?\n)Host: ([^\r\n]+)", re.IGNORECASE)
HTTP_UA_RE = re.compile(r"(?:^|\r?\n)User-Agent: ([^\r\n]+)", re.IGNORECASE)


def _parse_http(payload: bytes) -> dict | None:
    if len(payload) < 16:
        return None
    head = payload[: min(len(payload), 2048)].decode("latin1")
    m = HTTP_REQ_RE.match(head)
    if m:
        host = HTTP_HOST_RE.search(head)
        ua = HTTP_UA_RE.search(head)
        return {"method": m.group(1), "host": host.group(1).strip() if host else None,
                "uri": m.group(2), "userAgent": ua.group(1).strip() if ua else None, "status": None}
    m = HTTP_RESP_RE.match(head)
    if m:
        return {"method": None, "host": None, "uri": None, "userAgent": None,
                "status": int(m.group(1))}
    return None


# ---------- 主解析入口 ----------

def _new_flow(src_ip, src_port, dst_ip, dst_port, proto, ts_ms, ttl) -> dict:
    t = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).replace(tzinfo=None)
    return {
        "srcIp": src_ip, "srcPort": src_port, "dstIp": dst_ip, "dstPort": dst_port,
        "protocol": proto, "startTime": t, "endTime": t, "duration": 0,
        "startMs": ts_ms, "endMs": ts_ms,  # 内部字段：超时判定用 epoch 毫秒，避免时区歧义
        "upPackets": 0, "downPackets": 0, "upBytes": 0, "downBytes": 0,
        "synCount": 0, "synAckCount": 0, "ackCount": 0, "finCount": 0,
        "rstCount": 0, "pshCount": 0, "urgCount": 0,
        "handshakeSuccess": False, "closeReason": "TIMEOUT",
        "initWinSize": None, "mss": None, "ttlInit": ttl, "firstUpPktLen": None,
        "upPktLens": [], "downPktLens": [],
        "seenSyn": False, "seenSynAck": False,
        "dns": None, "tls": None, "http": None,
    }


def parse_pcap(buf: bytes) -> dict:
    if len(buf) < 24:
        raise ValueError("文件太小，不是有效的 pcap 文件")
    magic = struct.unpack_from("<I", buf, 0)[0]
    if magic == 0xA1B2C3D4:
        endian, ns = "<", False
    elif magic == 0xD4C3B2A1:
        endian, ns = ">", False
    elif magic == 0xA1B23C4D:
        endian, ns = "<", True
    elif magic == 0x4D3CB2A1:
        endian, ns = ">", True
    elif magic == 0x0A0D0D0A:
        raise ValueError("检测到 pcapng 格式，当前仅支持 classic pcap（可用 editcap -F pcap 转换）")
    else:
        raise ValueError("无法识别的文件格式，请上传 .pcap 文件")

    link_type = struct.unpack_from(f"{endian}H", buf, 20)[0]
    if link_type != 1:
        raise ValueError(f"暂不支持链路类型 {link_type}（仅支持 Ethernet/LINKTYPE_ETHERNET）")

    flows: dict[str, list[dict]] = {}
    packets = 0
    skipped = 0
    off = 24

    while off + 16 <= len(buf):
        ts_sec, ts_frac, incl_len = struct.unpack_from(f"{endian}III", buf, off)
        off += 16
        if off + incl_len > len(buf):
            break
        frame = buf[off: off + incl_len]
        off += incl_len
        packets += 1
        ts_ms = ts_sec * 1000 + (ts_frac / 1e6 if ns else ts_frac / 1000)

        # Ethernet（含单层 VLAN）
        if len(frame) < 14:
            skipped += 1
            continue
        eth_type = struct.unpack_from(">H", frame, 12)[0]
        l3 = 14
        if eth_type == 0x8100 and len(frame) >= 18:
            eth_type = struct.unpack_from(">H", frame, 16)[0]
            l3 = 18
        if eth_type != 0x0800:  # 仅 IPv4
            skipped += 1
            continue
        if len(frame) < l3 + 20:
            skipped += 1
            continue

        ihl = (frame[l3] & 0x0F) * 4
        total_len = struct.unpack_from(">H", frame, l3 + 2)[0]
        proto = frame[l3 + 9]
        ttl = frame[l3 + 8]
        src_ip = ip4(frame, l3 + 12)
        dst_ip = ip4(frame, l3 + 16)
        l4 = l3 + ihl
        if len(frame) < l4 + 4:
            skipped += 1
            continue

        src_port, dst_port = struct.unpack_from(">HH", frame, l4)

        flags = 0
        win_size = None
        mss = None
        payload_off = l4 + 8
        if proto == 6:  # TCP
            if len(frame) < l4 + 20:
                skipped += 1
                continue
            data_off = ((frame[l4 + 12] >> 4) & 0x0F) * 4
            flags = frame[l4 + 13]
            win_size = struct.unpack_from(">H", frame, l4 + 14)[0]
            payload_off = l4 + data_off
            # TCP 选项中的 MSS
            if (flags & 0x02) and data_off > 20:
                op = l4 + 20
                op_end = l4 + data_off
                while op < op_end:
                    kind = frame[op]
                    if kind == 0:
                        break
                    if kind == 1:
                        op += 1
                        continue
                    olen = frame[op + 1]
                    if kind == 2 and olen == 4:
                        mss = struct.unpack_from(">H", frame, op + 2)[0]
                    op += olen or 1
        elif proto != 17:  # 仅 TCP/UDP
            skipped += 1
            continue

        proto_name = "TCP" if proto == 6 else "UDP"
        payload_len = max(0, min(total_len, len(frame) - l3) - (payload_off - l3))
        payload = frame[payload_off: min(len(frame), payload_off + payload_len)]

        # 会话化：首包方向为上行；同五元组超非活跃超时则切分为新会话
        fwd = _flow_key(src_ip, src_port, dst_ip, dst_port, proto_name)
        rev = _flow_key(dst_ip, dst_port, src_ip, src_port, proto_name)
        up = True
        lst = flows.get(fwd)
        if lst is None:
            lst = flows.get(rev)
            up = False
        f = lst[-1] if lst else None
        if f and ts_ms - f["endMs"] > INACTIVE_TIMEOUT_MS:
            f = None  # 超时切分
        if f is None:
            # 方向继承：已有同五元组流则沿用其方向，否则以当前包为上行
            anchor = lst[0] if lst else None
            f_src_ip = anchor["srcIp"] if anchor else src_ip
            f_src_port = anchor["srcPort"] if anchor else src_port
            f_dst_ip = anchor["dstIp"] if anchor else dst_ip
            f_dst_port = anchor["dstPort"] if anchor else dst_port
            up = (src_ip == anchor["srcIp"] and src_port == anchor["srcPort"]) if anchor else True
            f = _new_flow(f_src_ip, f_src_port, f_dst_ip, f_dst_port, proto_name, ts_ms, ttl)
            key = fwd if up else rev
            flows.setdefault(key, []).append(f)

        f["endTime"] = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).replace(tzinfo=None)
        f["endMs"] = ts_ms
        if up:
            f["upPackets"] += 1
            f["upBytes"] += payload_len
            if len(f["upPktLens"]) < 512:
                f["upPktLens"].append(payload_len)
            if f["firstUpPktLen"] is None and payload_len > 0:
                f["firstUpPktLen"] = payload_len
        else:
            f["downPackets"] += 1
            f["downBytes"] += payload_len
            if len(f["downPktLens"]) < 512:
                f["downPktLens"].append(payload_len)

        if proto == 6:
            syn = (flags & 0x02) != 0
            ack = (flags & 0x10) != 0
            if syn and not ack:
                f["synCount"] += 1
                if up:
                    f["seenSyn"] = True
                    f["initWinSize"] = win_size
                    f["mss"] = mss
            if syn and ack:
                f["synAckCount"] += 1
                if not up:
                    f["seenSynAck"] = True
            if ack and not syn:
                f["ackCount"] += 1
            if flags & 0x01:
                f["finCount"] += 1
                f["closeReason"] = "FIN"
            if flags & 0x04:
                f["rstCount"] += 1
                f["closeReason"] = "RST"
            if flags & 0x08:
                f["pshCount"] += 1
            if flags & 0x20:
                f["urgCount"] += 1
            if f["seenSyn"] and f["seenSynAck"]:
                f["handshakeSuccess"] = True

        # 应用层解析（每流只抓首次命中）
        if f["dns"] is None and (src_port == 53 or dst_port == 53) and len(payload) > 12:
            d = _parse_dns(payload)
            if d:
                f["dns"] = d
        if f["tls"] is None and len(payload) > 9 and payload[0] == 0x16:
            t = _parse_tls_client_hello(payload)
            if t and (t["sni"] or t["version"]):
                f["tls"] = t
        if f["http"] is None and len(payload) > 16:
            h = _parse_http(payload)
            if h:
                f["http"] = h

    out = []
    for lst in flows.values():
        for f in lst:
            f["duration"] = max(0, int(f["endMs"] - f["startMs"]))
            del f["startMs"], f["endMs"]
            out.append(f)
    return {"flows": out, "packets": packets, "skipped": skipped}
