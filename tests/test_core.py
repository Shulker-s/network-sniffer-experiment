import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scapy.all import IP, TCP, UDP, Raw
from core import parse, matches, reassemble, stream_text, flow_key

def test_parse_and_filters():
    p=IP(src='127.0.0.1',dst='127.0.0.2')/TCP(sport=1234,dport=80,seq=1)/Raw(b'GET / HTTP/1.1\r\n')
    r=parse(p)
    assert r.protocol=='HTTP' and matches(r,'TCP','1234') and matches(r,'HTTP')
    assert not matches(r,'UDP')

def test_reassembly_overlap_reorder_and_gap():
    assert reassemble([(4,b'def'),(1,b'abc'),(2,b'bc')])==b'abcdef'
    assert '缺失 2 字节' in reassemble([(1,b'a'),(4,b'b')]).decode()

def test_stream_both_directions():
    a=parse(IP(src='127.0.0.1',dst='127.0.0.2')/TCP(sport=1234,dport=80,seq=1)/Raw(b'hello'))
    b=parse(IP(src='127.0.0.2',dst='127.0.0.1')/TCP(sport=80,dport=1234,seq=4)/Raw(b'world'))
    assert a.flow==b.flow and 'hello' in stream_text([a,b],a.flow) and 'world' in stream_text([a,b],a.flow)
