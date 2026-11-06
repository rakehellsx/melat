"""PyShark/TShark protocol dissection and bidirectional session aggregation.

PCAP/PCAPNG, supported link types, IPv4/IPv6, and TCP reassembly are
handled by TShark. Output preserves the existing session importer contract.
"""
import asyncio
import ipaddress
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from .flow_store import FlowStore

INACTIVE_TIMEOUT_MS = 30_000
DNS_TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
             16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS', 255: 'ANY'}
DNS_RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}
TLS_VERSIONS = {0x0301: 'TLS1.0', 0x0302: 'TLS1.1', 0x0303: 'TLS1.2', 0x0304: 'TLS1.3'}
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(v) for v in
                         ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
                          '169.254.0.0/16', 'fc00::/7', 'fe80::/10'))


def is_private_ip(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return address.is_loopback or any(address.version == n.version and address in n for n in PRIVATE_NETWORKS)


def _time(ms):
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).replace(tzinfo=None)


def _layer(packet, name):
    try:
        return packet[name]
    except (KeyError, AttributeError):
        return None


def _value(layer, *names):
    if layer is not None:
        for name in names:
            values = _field_values(layer, name)
            value = values[0] if values else None
            if value is not None:
                return str(value)
    return None


def _values(layer, name):
    if layer is None:
        return []
    return [str(value) for value in _field_values(layer, name)]


def _field_values(layer, name):
    # EK avoids constructing XML field objects for every packet. Read its raw
    # flattened fields so repeated TLS/DNS values retain the same semantics.
    fields = getattr(layer, '_fields_dict', None)
    if fields is not None:
        prefix = layer.layer_name
        values = []
        for fields_dict in fields if isinstance(fields, list) else [fields]:
            if not isinstance(fields_dict, dict):
                continue
            value = fields_dict.get(f'{prefix}_{prefix}_{name}', fields_dict.get(f'{prefix}_{name}'))
            values.extend(value if isinstance(value, list) else ([] if value is None else [value]))
        return values
    field = layer.get_field(name)
    return [str(item.show) for item in field.all_fields] if field else []


def _has_field(layer, name):
    fields = getattr(layer, '_fields_dict', None)
    if fields is None:
        return layer.get_field(name) is not None
    prefix = layer.layer_name
    keys = (f'{prefix}_{prefix}_{name}', f'{prefix}_{name}')
    # Expert flags in EK have a null value and live in nested expert records.
    pending = fields[:] if isinstance(fields, list) else [fields]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if any(key in node for key in keys):
                return True
            expert = node.get('_ws_expert')
            if expert is not None:
                pending.extend(expert if isinstance(expert, list) else [expert])
    return False


def _number(value, default=None):
    if str(value).lower() in ('true', 'false'):
        return int(str(value).lower() == 'true')
    try:
        return int(value, 0)
    except (ValueError, TypeError):
        try:
            return int(float(value))
        except (ValueError, TypeError):
            return default


def _merge(target, values):
    target.update({key: value for key, value in values.items() if value is not None})


def _application_fields(packet, flow, payload_length):
    dns = _layer(packet, 'dns')
    if dns is not None:
        current = flow['dns'] or {}
        response = _number(_value(dns, 'flags_response'), 0) == 1
        qtype = _number(_value(dns, 'qry_type'))
        _merge(current, {'queryName': _value(dns, 'qry_name'),
                         'queryType': DNS_TYPES.get(qtype, f'TYPE{qtype}') if qtype else None})
        if response or not flow['dns']:
            rcode = _number(_value(dns, 'flags_rcode'), 0)
            _merge(current, {'rcode': DNS_RCODES.get(rcode, f'RCODE{rcode}'),
                             'answerCount': _number(_value(dns, 'count_answers'), 0),
                             'answerIps': list(dict.fromkeys(_values(dns, 'a') + _values(dns, 'aaaa'))),
                             'ttl': _number(_value(dns, 'resp_ttl')),
                             'responseSize': payload_length if response else 0, 'isResponse': response})
        flow['dns'] = current
    http = _layer(packet, 'http')
    if http is not None:
        current = flow['http'] or {}
        _merge(current, {'method': _value(http, 'request_method'), 'host': _value(http, 'host'),
                         'uri': _value(http, 'request_uri'), 'userAgent': _value(http, 'user_agent'),
                         'status': _number(_value(http, 'response_code')),
                         'version': _value(http, 'request_version', 'response_version'),
                         'contentType': _value(http, 'content_type'),
                         'contentLength': _number(_value(http, 'content_length')),
                         'referer': _value(http, 'referer')})
        flow['http'] = current
    tls = _layer(packet, 'tls')
    if tls is not None:
        current = flow['tls'] or {'detected': True}
        handshake = _number(_value(tls, 'handshake_type'))
        version = _number(_value(tls, 'handshake_version'))
        # A ClientHello advertises several versions; a ServerHello selects one.
        if handshake == 2:
            version = _number(_value(tls, 'handshake_extensions_supported_version'), version)
        if version in TLS_VERSIONS and (handshake == 2 or not current.get('version')):
            current['version'] = TLS_VERSIONS[version]
        _merge(current, {'sni': _value(tls, 'handshake_extensions_server_name'),
                         'ja3': _value(tls, 'handshake_ja3'), 'ja3s': _value(tls, 'handshake_ja3s'),
                         'alpn': _value(tls, 'handshake_extensions_alpn_str')})
        if handshake == 2:
            _merge(current, {'cipherSuite': _value(tls, 'handshake_ciphersuite')})
        flow['tls'] = current
    names = {layer.layer_name.lower() for layer in packet.layers}
    for name, label in [('ssh', 'SSH'), ('smb2', 'SMB'), ('smb', 'SMB'), ('ftp', 'FTP'),
                        ('smtp', 'SMTP'), ('rdp', 'RDP'), ('telnet', 'TELNET'), ('dcerpc', 'WMI')]:
        if name in names:
            flow['appProtocol'] = label
            break


def _new_flow(src, sport, dst, dport, protocol, timestamp, network, packet):
    eth, vlan = _layer(packet, 'eth'), _layer(packet, 'vlan')
    return {
        'srcIp': src, 'srcPort': sport, 'dstIp': dst, 'dstPort': dport, 'protocol': protocol,
        'ipVersion': 'IPv6' if ':' in src else 'IPv4', 'vlanId': _number(_value(vlan, 'id')),
        'srcMac': _value(eth, 'src'), 'dstMac': _value(eth, 'dst'),
        'startTime': _time(timestamp), 'endTime': _time(timestamp), 'duration': 0,
        '_startMs': timestamp, '_endMs': timestamp,
        'upPackets': 0, 'downPackets': 0, 'upBytes': 0, 'downBytes': 0,
        'synCount': 0, 'synAckCount': 0, 'ackCount': 0, 'finCount': 0,
        'rstCount': 0, 'pshCount': 0, 'urgCount': 0, 'handshakeSuccess': False,
        'closeReason': 'TIMEOUT', 'initWinSize': None, 'mss': None,
        'ttlInit': _number(_value(network, 'ttl', 'hlim')), 'firstUpPktLen': None,
        'upPktLens': [], 'downPktLens': [], '_seenSyn': False, '_seenSynAck': False,
        'retransCount': 0, 'outOfOrderCount': 0, 'zeroWinCount': 0,
        'dns': None, 'tls': None, 'http': None,
    }


def _aggregate(capture, store=None, progress=None):
    groups, output = store if store is not None else {}, []
    packets = skipped = 0
    for packet in capture:
        packets += 1
        if progress and packets % 1000 == 0:
            progress(packets)
        network = _layer(packet, 'ip')
        if network is None:
            network = _layer(packet, 'ipv6')
        transport, protocol = _layer(packet, 'tcp'), 'TCP'
        if transport is None:
            transport, protocol = _layer(packet, 'udp'), 'UDP'
        if network is None or transport is None:
            skipped += 1
            continue
        src, dst = _value(network, 'src'), _value(network, 'dst')
        sport, dport = _number(_value(transport, 'srcport')), _number(_value(transport, 'dstport'))
        if not src or not dst or sport is None or dport is None:
            skipped += 1
            continue
        raw_timestamp = packet.sniff_timestamp
        try:
            timestamp = float(raw_timestamp) * 1000
        except ValueError:
            # Older TShark EK output uses ISO 8601 rather than epoch seconds.
            timestamp = datetime.fromisoformat(raw_timestamp.replace('Z', '+00:00')).timestamp() * 1000
        key = (protocol, tuple(sorted(((src, sport), (dst, dport)))), _value(transport, 'stream'))
        flow = groups.get(key)
        # Merged captures may jump backwards by months on the same UDP stream.
        # Only tolerate reordering within the inactivity window on either side.
        if (flow is None or timestamp - flow['_endMs'] > INACTIVE_TIMEOUT_MS
                or flow['_startMs'] - timestamp > INACTIVE_TIMEOUT_MS):
            anchor = (flow[k] for k in ('srcIp', 'srcPort', 'dstIp', 'dstPort')) if flow else (src, sport, dst, dport)
            flow = _new_flow(*anchor, protocol, timestamp, network, packet)
            groups[key] = flow
            if store is None:
                output.append(flow)
        up = src == flow['srcIp'] and sport == flow['srcPort']
        direction = 'up' if up else 'down'
        payload_length = (_number(_value(transport, 'len'), 0) if protocol == 'TCP'
                          else max(0, _number(_value(transport, 'length'), 8) - 8))
        flow[direction + 'Packets'] += 1
        flow[direction + 'Bytes'] += payload_length
        if len(flow[direction + 'PktLens']) < 512:
            flow[direction + 'PktLens'].append(payload_length)
        if up and flow['firstUpPktLen'] is None and payload_length:
            flow['firstUpPktLen'] = payload_length
        flow['_startMs'] = min(flow['_startMs'], timestamp)
        flow['_endMs'] = max(flow['_endMs'], timestamp)
        if protocol == 'TCP':
            flags = _number(_value(transport, 'flags'), 0)
            syn, ack = bool(flags & 2), bool(flags & 16)
            if syn and not ack:
                flow['synCount'] += 1
                if up:
                    flow['_seenSyn'] = True
                    flow['initWinSize'] = _number(_value(transport, 'window_size_value'))
                    flow['mss'] = _number(_value(transport, 'options_mss_val'))
            if syn and ack:
                flow['synAckCount'] += 1
                if not up:
                    flow['_seenSynAck'] = True
            if ack and not syn:
                flow['ackCount'] += 1
            for mask, field in [(1, 'finCount'), (4, 'rstCount'), (8, 'pshCount'), (32, 'urgCount')]:
                if flags & mask:
                    flow[field] += 1
            if flags & 4:
                flow['closeReason'] = 'RST'
            elif flags & 1 and flow['closeReason'] != 'RST':
                flow['closeReason'] = 'FIN'
            flow['handshakeSuccess'] = flow['_seenSyn'] and flow['_seenSynAck']
            if any(_has_field(transport, name) for name in
                   ('analysis_retransmission', 'analysis_fast_retransmission', 'analysis_spurious_retransmission')):
                flow['retransCount'] += 1
            if _has_field(transport, 'analysis_out_of_order'):
                flow['outOfOrderCount'] += 1
            if _has_field(transport, 'analysis_zero_window'):
                flow['zeroWinCount'] += 1
        _application_fields(packet, flow, payload_length)
    if store is not None:
        return {'flows': (_finalize_flow(f) for f in store.iter_flows()), 'flowCount': store.count,
                'packets': packets, 'skipped': skipped}
    return {'flows': [_finalize_flow(f) for f in output], 'packets': packets, 'skipped': skipped}


def _finalize_flow(flow):
    flow['startTime'], flow['endTime'] = _time(flow['_startMs']), _time(flow['_endMs'])
    flow['duration'] = max(0, round(flow['_endMs'] - flow['_startMs']))
    for key in [key for key in flow if key.startswith('_')]:
        del flow[key]
    return flow


async def _close_failed_capture(capture):
    # PyShark 0.6 aborts cleanup on a failed TShark exit, leaving its destructor
    # to access a closed event loop. Reap every process before releasing ours.
    for process in tuple(capture._running_processes):
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await process.wait()
    capture._running_processes.clear()
    await asyncio.gather(*capture._stderr_handling_tasks, return_exceptions=True)


def validate_capture_header(buf: bytes):
    if len(buf) < 24:
        raise ValueError('文件太小，不是有效的 pcap/pcapng 文件')
    if buf[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1',
                       b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a'):
        raise ValueError('无法识别的文件格式，请上传 pcap/pcapng 文件')


@contextmanager
def _normalized_capture(source):
    """Repair overflowing classic-PCAP subsecond values in a temporary copy.

    Some exporters store negative microseconds as uint32 or omit carrying
    whole seconds. TShark versions render these invalid epochs differently.
    Interpret wrapped values as signed offsets, then carry into seconds;
    never alter the original upload or any packet bytes.
    """
    repaired = source.with_suffix('.timestamps.pcap')
    count, output = 0, None
    try:
        with source.open('rb') as stream:
            header = stream.read(24)
            formats = {b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),
                       b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
                       b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),
                       b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000)}
            if header[:4] not in formats:
                yield source, 0
                return
            endian, scale = formats[header[:4]]
            size = source.stat().st_size
            while raw := stream.read(16):
                if len(raw) != 16:
                    raise ValueError('抓包文件包含不完整的报文头')
                seconds, fraction, captured, original = struct.unpack(endian + 'IIII', raw)
                if captured > size - stream.tell():
                    raise ValueError('抓包文件包含不完整的报文内容')
                if fraction >= scale:
                    if output is None:
                        repaired.unlink(missing_ok=True)
                        output = repaired.open('xb')
                        repaired.chmod(0o600)
                        prefix = stream.tell() - 16
                        stream.seek(0)
                        while prefix:
                            chunk = stream.read(min(prefix, 1024 * 1024))
                            output.write(chunk)
                            prefix -= len(chunk)
                        stream.seek(16, 1)
                    offset = fraction if fraction < 0x80000000 else fraction - 0x100000000
                    carry, fraction = divmod(offset, scale)
                    seconds += carry
                    if not 0 <= seconds <= 0xffffffff:
                        raise ValueError('抓包时间戳溢出，无法规范化')
                    raw = struct.pack(endian + 'IIII', seconds, fraction, captured, original)
                    count += 1
                if output is None:
                    stream.seek(captured, 1)
                else:
                    output.write(raw)
                    remaining = captured
                    while remaining:
                        chunk = stream.read(min(remaining, 1024 * 1024))
                        output.write(chunk)
                        remaining -= len(chunk)
        if output is not None:
            output.close()
        yield repaired if count else source, count
    finally:
        if output is not None:
            output.close()
        repaired.unlink(missing_ok=True)


def _parse_capture(source: Path, store=None, progress=None, use_ek=True):
    with source.open('rb') as stream:
        validate_capture_header(stream.read(24))
    import pyshark
    from pyshark.capture.capture import TSharkCrashException
    loop = asyncio.new_event_loop()
    try:
        capture = pyshark.FileCapture(
            str(source), keep_packets=False, eventloop=loop, use_ek=use_ek, custom_parameters=['-n'],
            override_prefs={'tcp.desegment_tcp_streams': 'TRUE', 'tls.desegment_ssl_records': 'TRUE',
                            'tls.desegment_ssl_application_data': 'TRUE'})
        try:
            try:
                return _aggregate(capture, store, progress)
            finally:
                capture.close()
        except TSharkCrashException as error:
            loop.run_until_complete(_close_failed_capture(capture))
            raise ValueError('抓包文件损坏或无法被 TShark 解析') from error
    finally:
        loop.close()


@contextmanager
def parse_pcap_file(source, progress=None, cache_size=256):
    """Do not read the upload or retain all flow state in application memory."""
    source = Path(source)
    scratch = source.with_suffix('.flows.sqlite')
    scratch.unlink(missing_ok=True)
    store = FlowStore(scratch, cache_size=cache_size)
    try:
        with _normalized_capture(source) as (capture_source, normalized):
            result = _parse_capture(capture_source, store, progress)
            result['normalizedTimestamps'] = normalized
            yield result
    finally:
        store.close()
        scratch.unlink(missing_ok=True)


def parse_pcap(buf: bytes) -> dict:
    """Compatibility helper for small in-memory fixtures; uploads use the file API."""
    validate_capture_header(buf[:24])
    with tempfile.TemporaryDirectory(prefix='melat-pcap-') as directory:
        source = Path(directory) / 'capture.pcap'
        source.write_bytes(buf)
        with _normalized_capture(source) as (capture_source, normalized):
            result = _parse_capture(capture_source)
            result['normalizedTimestamps'] = normalized
            return result
