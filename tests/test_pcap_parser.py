"""Integration fixtures exercise real TShark dissection, not parser mocks."""
import asyncio
import ipaddress
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from backend.pcap_parser import parse_pcap, _normalized_capture, _parse_capture

SRC, DST = '10.1.2.3', '203.0.113.8'


def checksum(data):
    data += b'\0' if len(data) % 2 else b''
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def frame(payload, src=SRC, dst=DST, protocol=6, vlan=None):
    source, target = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if source.version == 6:
        network = struct.pack('!IHBB16s16s', 6 << 28, len(payload), protocol, 64,
                              source.packed, target.packed)
        ethertype = 0x86dd
    else:
        network = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0,
                              64, protocol, 0, source.packed, target.packed)
        network = network[:10] + struct.pack('!H', checksum(network)) + network[12:]
        ethertype = 0x0800
    ethernet = bytes.fromhex('00112233445566778899aabb')
    ethernet += (struct.pack('!HHH', 0x8100, vlan, ethertype) if vlan is not None
                 else struct.pack('!H', ethertype))
    return ethernet + network + payload


def tcp(data=b'', reverse=False, seq=1001, ack=5001, flags=0x18, port=80):
    src, dst = (DST, SRC) if reverse else (SRC, DST)
    sport, dport = (port, 45000) if reverse else (45000, port)
    header = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    pseudo = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
    pseudo += struct.pack('!BBH', 0, 6, len(header) + len(data))
    header = header[:16] + struct.pack('!H', checksum(pseudo + header + data)) + header[18:]
    return frame(header + data, src, dst)


def handshake(port=80):
    return [tcp(seq=1000, ack=0, flags=2, port=port),
            tcp(reverse=True, seq=5000, ack=1001, flags=0x12, port=port),
            tcp(flags=0x10, port=port)]


def dns_data(response=False):
    question = b'\x07example\x03com\0' + struct.pack('!HH', 1, 1)
    header = struct.pack('!HHHHHH', 42, 0x8180 if response else 0x0100, 1, int(response), 0, 0)
    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 120, 4) + bytes([93, 184, 216, 34])
    return header + question + (answer if response else b'')


def udp_dns(response=False, ipv6=False, vlan=None):
    src, dst = ('fd00::1', '2001:db8::53') if ipv6 else (SRC, DST)
    sport, dport = 53000, 53
    if response:
        src, dst, sport, dport = dst, src, dport, sport
    payload = dns_data(response)
    header = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    if ipv6:
        pseudo = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
        pseudo += struct.pack('!I3xB', 8 + len(payload), 17)
        header = header[:6] + struct.pack('!H', checksum(pseudo + header + payload))
    return frame(header + payload, src, dst, 17, vlan)


def pcap(frames, times=None):
    output = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for i, packet in enumerate(frames):
        timestamp = times[i] if times is not None else i * .01
        seconds = 1700000000 + int(timestamp)
        micros = round((timestamp % 1) * 1000000)
        output += struct.pack('<IIII', seconds, micros, len(packet), len(packet)) + packet
    return output


def tls_record(body, kind):
    handshake_data = bytes([kind]) + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x03' + struct.pack('!H', len(handshake_data)) + handshake_data


def tls_hellos():
    name = b'secure.example.com'
    server_name = b'\0' + struct.pack('!H', len(name)) + name
    sni = struct.pack('!H', len(server_name)) + server_name
    ext = struct.pack('!HH', 0, len(sni)) + sni
    ext += struct.pack('!HH', 43, 5) + b'\x04\x03\x04\x03\x03'
    client = b'\x03\x03' + b'A' * 32 + b'\0\0\x02\x13\x01\x01\0'
    client += struct.pack('!H', len(ext)) + ext
    ext = struct.pack('!HHH', 43, 2, 0x0304)
    server = b'\x03\x03' + b'B' * 32 + b'\0\x13\x01\0' + struct.pack('!H', len(ext)) + ext
    return tls_record(client, 1), tls_record(server, 2)


@unittest.skipUnless(shutil.which('tshark'), 'TShark required')
class ProtocolParsingTests(unittest.TestCase):
    def test_overflowing_and_wrapped_microseconds(self):
        data = bytearray(pcap(handshake()))
        offset = 24
        for micros in (1_500_000, 0xffffffff - 249_999, 750_000):
            struct.pack_into('<I', data, offset + 4, micros)
            offset += 16 + struct.unpack_from('<I', data, offset + 8)[0]
        result = parse_pcap(bytes(data))
        self.assertEqual(result['normalizedTimestamps'], 2)
        self.assertEqual(result['packets'], 3)
        flow = result['flows'][0]
        self.assertEqual(flow['duration'], 1750)
        self.assertEqual(flow['startTime'].microsecond, 750000)
        self.assertTrue(flow['handshakeSuccess'])

    def test_ek_matches_xml_with_multiple_tls_records(self):
        client, server = tls_hellos()
        frames = handshake(443) + [tcp(client + b'\x14\x03\x03\x00\x01\x01', port=443),
                                   tcp(server, reverse=True, port=443)]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'tls.pcap'
            source.write_bytes(pcap(frames))
            self.assertEqual(_parse_capture(source, use_ek=True), _parse_capture(source, use_ek=False))

    def test_repository_capture_preserves_counts_and_merges_responses(self):
        result = parse_pcap(Path('示例抓包文件.pcap').read_bytes())
        self.assertEqual((result['packets'], result['skipped'], len(result['flows'])), (166, 0, 55))
        http = next(f['http'] for f in result['flows'] if f['http'])
        self.assertEqual((http['method'], http['host'], http['status']), ('GET', 'www.example.com', 200))
        dns = next(f['dns'] for f in result['flows'] if f['dns'])
        self.assertEqual(dns['answerIps'], ['93.184.216.35'])
        self.assertEqual(dns['answerCount'], 1)

    def test_dns_response_answers_and_ttl(self):
        flow = parse_pcap(pcap([udp_dns(), udp_dns(True)]))['flows'][0]
        self.assertEqual((flow['upPackets'], flow['downPackets']), (1, 1))
        self.assertEqual(flow['dns']['answerIps'], ['93.184.216.34'])
        self.assertEqual(flow['dns']['ttl'], 120)

    def test_http_tcp_reassembly_and_both_directions(self):
        request = b'GET /split HTTP/1.1\r\nHost: split.example.com\r\nUser-Agent: test\r\n\r\n'
        response = b'HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n'
        frames = handshake() + [tcp(request[:13]), tcp(request[13:], seq=1014),
                                tcp(response, reverse=True, ack=1001 + len(request))]
        flow = parse_pcap(pcap(frames))['flows'][0]
        self.assertTrue(flow['handshakeSuccess'])
        self.assertEqual(flow['http']['host'], 'split.example.com')
        self.assertEqual(flow['http']['uri'], '/split')
        self.assertEqual(flow['http']['status'], 201)
        self.assertEqual(flow['upBytes'], len(request))
        self.assertEqual(flow['downBytes'], len(response))

    def test_tls_segmented_sni_and_negotiated_version(self):
        client, server = tls_hellos()
        frames = handshake(443) + [tcp(client[:20], port=443), tcp(client[20:], seq=1021, port=443),
                                   tcp(server, reverse=True, ack=1001 + len(client), port=443)]
        flow = parse_pcap(pcap(frames))['flows'][0]
        self.assertEqual(flow['tls']['sni'], 'secure.example.com')
        self.assertEqual(flow['tls']['version'], 'TLS1.3')
        self.assertTrue(flow['tls']['ja3'])
        self.assertTrue(flow['tls']['cipherSuite'])

    def test_ipv6_and_vlan(self):
        for ipv6, vlan in [(True, None), (False, 77)]:
            with self.subTest(ipv6=ipv6, vlan=vlan):
                flow = parse_pcap(pcap([udp_dns(ipv6=ipv6, vlan=vlan),
                                        udp_dns(True, ipv6=ipv6, vlan=vlan)]))['flows'][0]
                self.assertEqual(flow['ipVersion'], 'IPv6' if ipv6 else 'IPv4')
                self.assertEqual(flow['vlanId'], vlan)
                self.assertEqual(flow['srcMac'], '66:77:88:99:aa:bb')
                self.assertEqual(flow['dns']['answerCount'], 1)

    def test_timeout_preserves_direction(self):
        result = parse_pcap(pcap([udp_dns(), udp_dns(True)], [0, 31]))
        self.assertEqual(len(result['flows']), 2)
        self.assertEqual(result['flows'][1]['srcIp'], SRC)
        self.assertEqual(result['flows'][1]['downPackets'], 1)

    def test_backwards_capture_segment_does_not_merge_months_apart(self):
        frames = [udp_dns(), udp_dns(True), udp_dns(), udp_dns(True)]
        result = parse_pcap(pcap(frames, [280 * 86400, 280 * 86400 + .01, 0, .01]))
        self.assertEqual((result['packets'], len(result['flows'])), (4, 2))
        self.assertTrue(all(f['duration'] == 10 for f in result['flows']))
        self.assertTrue(all((f['upPackets'], f['downPackets']) == (1, 1) for f in result['flows']))

    def test_small_timestamp_reordering_still_merges(self):
        result = parse_pcap(pcap([udp_dns(), udp_dns(True)], [1, 0]))
        self.assertEqual(len(result['flows']), 1)
        self.assertEqual(result['flows'][0]['duration'], 1000)
        self.assertEqual(result['flows'][0]['dns']['answerCount'], 1)

    def test_pcapng(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, dest = Path(tmp) / 'test.pcap', Path(tmp) / 'test.pcapng'
            source.write_bytes(pcap([udp_dns(), udp_dns(True)]))
            subprocess.run(['editcap', '-F', 'pcapng', str(source), str(dest)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            self.assertEqual(parse_pcap(dest.read_bytes())['flows'][0]['dns']['answerCount'], 1)

    def test_non_transport_packets_are_skipped(self):
        arp = bytes.fromhex('ffffffffffff66778899aabb0806') + b'\0' * 28
        result = parse_pcap(pcap([arp, udp_dns()]))
        self.assertEqual((result['packets'], result['skipped']), (2, 1))

    def test_invalid_and_truncated_capture(self):
        for data in [b'', b'invalid-pcap' * 10, pcap([udp_dns()])[:-10]]:
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                parse_pcap(data)

    def test_worker_thread_inside_async_server(self):
        async def run():
            return await asyncio.to_thread(parse_pcap, pcap([udp_dns()]))
        self.assertEqual(asyncio.run(run())['packets'], 1)


class CaptureNormalizationTests(unittest.TestCase):
    def test_all_classic_encodings_preserve_packet_bytes_and_source(self):
        for endian in ('<', '>'):
            for scale, magic in ((1_000_000, 0xa1b2c3d4), (1_000_000_000, 0xa1b23c4d)):
                with self.subTest(endian=endian, scale=scale), tempfile.TemporaryDirectory() as tmp:
                    source = Path(tmp) / 'test.pcap'
                    payload = b'packet data'
                    header = struct.pack(endian + 'IHHIIII', magic, 2, 4, 0, 0, 65535, 1)
                    data = header
                    for sub in (scale // 4, scale + scale // 2, 0x100000000 - scale // 4):
                        data += struct.pack(endian + 'IIII', 1700000000, sub, len(payload), len(payload)) + payload
                    source.write_bytes(data)
                    with _normalized_capture(source) as (normalized, count):
                        self.assertEqual(count, 2)
                        repaired = normalized.read_bytes()
                        offset = 24
                        for expected in ((1700000000, scale // 4), (1700000001, scale // 2),
                                         (1699999999, 3 * scale // 4)):
                            self.assertEqual(struct.unpack_from(endian + 'II', repaired, offset), expected)
                            self.assertEqual(repaired[offset + 16:offset + 16 + len(payload)], payload)
                            offset += 16 + len(payload)
                    self.assertEqual(source.read_bytes(), data)
                    self.assertFalse(source.with_suffix('.timestamps.pcap').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
