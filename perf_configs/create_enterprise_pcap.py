#!/usr/bin/env python3
"""
Create a composite multi-protocol enterprise PCAP by concatenating
high-volume benign web traffic, web attacks, SMB benign sessions, and SMB attacks.
"""

import os
import sys
import struct

SOURCES = [
    ("/home/vhorbato/Academy/http-lab/shared/pcaps/benign_100000.pcap", "Benign HTTP (1M pkts)"),
    ("/home/vhorbato/Academy/http-lab/shared/pcaps/attack_10000.pcap", "Attack HTTP (100k pkts)"),
    ("/home/vhorbato/Academy/ntlm-lab/shared/pcaps/benign_basic.pcap", "Benign SMB/NTLM (15.8k pkts)"),
    ("/home/vhorbato/Academy/ntlm-lab/shared/pcaps/attack_basic.pcap", "Attack SMB/NTLM (13k pkts)"),
]

def merge_pcaps(output_path):
    print(f"Creating Enterprise Composite PCAP at: {output_path}")
    total_pkts = 0
    header_written = False

    with open(output_path, "wb") as out_f:
        for pcap_path, desc in SOURCES:
            if not os.path.exists(pcap_path):
                print(f"  [WARN] Skipping missing source: {pcap_path}")
                continue

            count = 0
            with open(pcap_path, "rb") as in_f:
                magic = in_f.read(4)
                if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                    print(f"  [WARN] Non-standard PCAP magic in {pcap_path}: {magic!r}")
                    continue

                # Read remainder of 24-byte global pcap header
                hdr_rest = in_f.read(20)
                if not header_written:
                    out_f.write(magic + hdr_rest)
                    header_written = True

                # Stream packets
                while True:
                    pkt_hdr = in_f.read(16)
                    if len(pkt_hdr) < 16:
                        break
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack("IIII", pkt_hdr)
                    payload = in_f.read(incl_len)
                    out_f.write(pkt_hdr + payload)
                    count += 1

            total_pkts += count
            print(f"  [+] Appended {count:>7d} packets from {desc}")

    size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"\nSuccessfully created {output_path}: {total_pkts:,} total packets ({size_mb:.2f} MB)")

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "/home/vhorbato/Academy/IDS/snort3/perf_configs/enterprise_mix_1.1m.pcap"
    merge_pcaps(out)
