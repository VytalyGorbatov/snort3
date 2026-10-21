#!/usr/bin/env python3
"""Generate test PCAP fixtures T1-T7 for neural risk group evaluation."""

import os
import socket
import struct

def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def make_pcap_header() -> bytes:
    return struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def make_packet(ts_sec: int, ts_usec: int, payload: bytes) -> bytes:
    l = len(payload)
    return struct.pack('!IIII', ts_sec, ts_usec, l, l) + payload

def make_ipv4_tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                         seq: int, ack: int, flags: int, payload: bytes = b'') -> bytes:
    dst_mac = b'\x00\x50\x56\xfa\x01\x02'
    src_mac = b'\x00\x50\x56\xfa\x01\x01'
    eth_hdr = dst_mac + src_mac + struct.pack('!H', 0x0800)

    s_ip = socket.inet_aton(src_ip)
    d_ip = socket.inet_aton(dst_ip)
    ip_len = 20 + 20 + len(payload)
    ip_hdr_no_ck = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, 54321, 0x4000, 64, 6, 0, s_ip, d_ip)
    ip_ck = checksum(ip_hdr_no_ck)
    ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, 54321, 0x4000, 64, 6, ip_ck, s_ip, d_ip)

    tcp_hdr_no_ck = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, (5 << 4), flags, 64240, 0, 0)
    pseudo_hdr = s_ip + d_ip + struct.pack('!BBH', 0, 6, 20 + len(payload))
    tcp_ck = checksum(pseudo_hdr + tcp_hdr_no_ck + payload)
    tcp_hdr = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, (5 << 4), flags, 64240, tcp_ck, 0)

    return eth_hdr + ip_hdr + tcp_hdr + payload

def make_ipv4_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    dst_mac = b'\x00\x50\x56\xfa\x01\x02'
    src_mac = b'\x00\x50\x56\xfa\x01\x01'
    eth_hdr = dst_mac + src_mac + struct.pack('!H', 0x0800)

    s_ip = socket.inet_aton(src_ip)
    d_ip = socket.inet_aton(dst_ip)
    udp_len = 8 + len(payload)
    ip_len = 20 + udp_len
    ip_hdr_no_ck = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, 54322, 0x4000, 64, 17, 0, s_ip, d_ip)
    ip_ck = checksum(ip_hdr_no_ck)
    ip_hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_len, 54322, 0x4000, 64, 17, ip_ck, s_ip, d_ip)

    udp_hdr_no_ck = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    pseudo_hdr = s_ip + d_ip + struct.pack('!BBH', 0, 17, udp_len)
    udp_ck = checksum(pseudo_hdr + udp_hdr_no_ck + payload)
    udp_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, udp_ck)

    return eth_hdr + ip_hdr + udp_hdr + payload

def build_http_session(src_ip="192.168.1.100", dst_ip="192.168.1.10",
                       src_port=49152, dst_port=80, http_payload=b"") -> bytes:
    """Build a complete TCP 3-way handshake + HTTP data + FIN sequence."""
    SYN = 0x02
    ACK = 0x10
    PSH = 0x08
    FIN = 0x01

    cli_seq = 1000
    srv_seq = 5000

    pkts = []
    # 1. SYN
    p1 = make_ipv4_tcp_packet(src_ip, dst_ip, src_port, dst_port, cli_seq, 0, SYN)
    pkts.append(make_packet(1, 1000, p1))
    # 2. SYN/ACK
    p2 = make_ipv4_tcp_packet(dst_ip, src_ip, dst_port, src_port, srv_seq, cli_seq + 1, SYN | ACK)
    pkts.append(make_packet(1, 2000, p2))
    # 3. ACK
    p3 = make_ipv4_tcp_packet(src_ip, dst_ip, src_port, dst_port, cli_seq + 1, srv_seq + 1, ACK)
    pkts.append(make_packet(1, 3000, p3))
    # 4. PSH/ACK with HTTP payload
    p4 = make_ipv4_tcp_packet(src_ip, dst_ip, src_port, dst_port, cli_seq + 1, srv_seq + 1, PSH | ACK, http_payload)
    pkts.append(make_packet(1, 4000, p4))
    # 5. Server ACK
    p5 = make_ipv4_tcp_packet(dst_ip, src_ip, dst_port, src_port, srv_seq + 1, cli_seq + 1 + len(http_payload), ACK)
    pkts.append(make_packet(1, 5000, p5))

    return make_pcap_header() + b''.join(pkts)

def generate_all(out_dir: str):
    os.makedirs(out_dir, exist_ok=True)

    # T1: Log4j Alert (teacher alert on 1:58723)
    t1_http = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 192.168.1.10\r\n"
        b"User-Agent: ${jndi:ldap://127.0.0.1/exploit}\r\n"
        b"Connection: close\r\n\r\n"
    )
    with open(os.path.join(out_dir, "T1_log4j_alert.pcap"), "wb") as f:
        f.write(build_http_session(http_payload=t1_http))

    # T2: Log4j Near-Miss (hits ${ fast pattern in header for 1:58742, fails PCRE, no alert)
    t2_http = (
        b"GET / HTTP/1.1\r\n"
        b"Host: 192.168.1.10\r\n"
        b"User-Agent: ${safe_internal_variable}\r\n"
        b"Connection: close\r\n\r\n"
    )
    with open(os.path.join(out_dir, "T2_log4j_near_miss.pcap"), "wb") as f:
        f.write(build_http_session(http_payload=t2_http))

    # T3: Body WebAttack Near-Miss (hits 'string=ajax' fast pattern in body for 1:51620, fails widgetConfig, no alert)
    body_t3 = b"routemap=true&string=ajax&action=test"
    t3_http = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: 192.168.1.10\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body_t3)).encode('ascii') + b"\r\n"
        b"Connection: close\r\n\r\n" + body_t3
    )
    with open(os.path.join(out_dir, "T3_body_webattack_near_miss.pcap"), "wb") as f:
        f.write(build_http_session(http_payload=t3_http))

    # T4: HTTP Other Near-Miss (hits '/shoutbox.php' in URI for 1:2142, fails conf=, no alert -> routes to C)
    t4_http = (
        b"GET /shoutbox.php?user=guest HTTP/1.1\r\n"
        b"Host: 192.168.1.10\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Connection: close\r\n\r\n"
    )
    with open(os.path.join(out_dir, "T4_http_other_near_miss.pcap"), "wb") as f:
        f.write(build_http_session(http_payload=t4_http))

    # T5: HTTP Benign (no fast-pattern hit for any bound group)
    t5_http = (
        b"GET /static/styles.css HTTP/1.1\r\n"
        b"Host: 192.168.1.10\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Connection: close\r\n\r\n"
    )
    with open(os.path.join(out_dir, "T5_http_benign.pcap"), "wb") as f:
        f.write(build_http_session(http_payload=t5_http))

    # T6: Multi Group (hits A in header and B in body)
    body_t6 = b"routemap=true&string=ajax&action=test"
    t6_http = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: 192.168.1.10\r\n"
        b"User-Agent: ${safe_internal_variable}\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body_t6)).encode('ascii') + b"\r\n"
        b"Connection: close\r\n\r\n" + body_t6
    )
    with open(os.path.join(out_dir, "T6_multi_group.pcap"), "wb") as f:
        f.write(build_http_session(http_payload=t6_http))

    # T7: SIP Control (UDP port 5060, negative control)
    sip_body = (
        b"INVITE sip:bob@biloxi.com SIP/2.0\r\n"
        b"Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8\r\n"
        b"Max-Forwards: 70\r\n"
        b"To: Bob <sip:bob@biloxi.com>\r\n"
        b"From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
        b"Call-ID: a84b4c76e66710\r\n"
        b"CSeq: 314159 INVITE\r\n"
        b"Contact: <sip:alice@pc33.atlanta.com>\r\n"
        b"Content-Type: application/sdp\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    p_sip = make_ipv4_udp_packet("192.168.1.100", "192.168.1.10", 5060, 5060, sip_body)
    sip_pcap = make_pcap_header() + make_packet(1, 1000, p_sip)
    with open(os.path.join(out_dir, "T7_sip_control.pcap"), "wb") as f:
        f.write(sip_pcap)

    print(f"Generated 7 PCAPs in {out_dir}")

if __name__ == "__main__":
    import sys
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "/home/vhorbato/Academy/IDS/neural_risk_tests/pcaps"
    generate_all(out_dir)
