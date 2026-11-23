from dataclasses import dataclass, field
from collections import defaultdict
import time
import psutil
from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw

@dataclass
class Record:
    packet: object
    src: str
    dst: str
    protocol: str
    sport: int = 0
    dport: int = 0
    pid: int | None = None
    process: str = ''
    flow: object = None

def flow_key(src, sport, dst, dport):
    return tuple(sorted(((src, sport), (dst, dport))))

def parse(packet):
    net = packet.getlayer(IP) or packet.getlayer(IPv6)
    src, dst = (net.src, net.dst) if net else ('-', '-')
    proto = 'IPv6' if packet.haslayer(IPv6) else 'IPv4' if packet.haslayer(IP) else '其他'
    sport = dport = 0
    if packet.haslayer(TCP):
        t = packet[TCP]; sport, dport = t.sport, t.dport; proto = 'TCP'
        data = bytes(t.payload)
        if data.startswith((b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ', b'HTTP/')):
            proto = 'HTTP'
    elif packet.haslayer(UDP):
        t = packet[UDP]; sport, dport = t.sport, t.dport; proto = 'UDP'
    elif packet.haslayer(ICMP): proto = 'ICMP'
    elif packet.haslayer(IPv6) and 'ICMPv6' in packet.summary(): proto = 'ICMPv6'
    key = flow_key(src, sport, dst, dport) if packet.haslayer(TCP) else None
    return Record(packet, src, dst, proto, sport, dport, flow=key)

def matches(r, protocol='全部', query=''):
    p = protocol.upper()
    if p == 'TCP' and not r.packet.haslayer(TCP): return False
    if p == 'UDP' and not r.packet.haslayer(UDP): return False
    if p == 'IPV4' and not r.packet.haslayer(IP): return False
    if p == 'IPV6' and not r.packet.haslayer(IPv6): return False
    if p == 'ICMP' and not (r.protocol in ('ICMP', 'ICMPv6')): return False
    if p == 'HTTP' and r.protocol != 'HTTP': return False
    s = f'{r.src} {r.dst} {r.sport} {r.dport} {r.pid or ""} {r.process}'.lower()
    return query.strip().lower() in s

def process_snapshot():
    result = {}
    try:
        for c in psutil.net_connections(kind='tcp'):
            if not c.laddr or not c.raddr or c.pid is None: continue
            try: name = psutil.Process(c.pid).name()
            except (psutil.Error, OSError): name = '未知'
            result[flow_key(c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)] = (c.pid, name)
    except (psutil.Error, OSError): pass
    return result

def reassemble(segments):
    """Return ordered bytes with visible gap markers; first received byte wins overlaps."""
    if not segments: return b''
    base = segments[0][0]
    chunks = sorted((((seq - base + 2**31) % 2**32 - 2**31, data) for seq, data in segments), key=lambda x:x[0])
    out = bytearray(); end = chunks[0][0]
    for pos, data in chunks:
        if pos > end:
            out.extend(f'\n[缺失 {pos-end} 字节]\n'.encode()); end = pos
        skip = max(0, end-pos)
        if skip < len(data): out.extend(data[skip:]); end = pos + len(data)
    return bytes(out)

def stream_text(records, key):
    directions = defaultdict(list)
    for r in records:
        if r.flow != key or not r.packet.haslayer(TCP): continue
        tcp = r.packet[TCP]; data = bytes(tcp.payload)
        if data:
            seq = (int(tcp.seq) + (1 if tcp.flags.S else 0)) % 2**32
            directions[(r.src, r.sport, r.dst, r.dport)].append((seq, data))
    blocks = []
    for direction, segments in directions.items():
        data = reassemble(segments)
        blocks.append(f'{direction[0]}:{direction[1]} → {direction[2]}:{direction[3]}\n' + data.decode('utf-8', errors='replace') + '\n\n十六进制：\n' + data.hex(' '))
    return '\n\n'.join(blocks) if blocks else '此流没有已捕获的 TCP 载荷。'

