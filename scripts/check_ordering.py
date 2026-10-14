#!/usr/bin/env python3
"""Checks that no flow's packets were reordered on the way through the router.

    check_ordering.py <capture.pcap> [--flows N] [--min-packets N]

Reads a pcap (Ethernet, as tcpdump writes it) of the datagrams bench/system/gen sent, picks them
out by gen's payload magic, and for each flow -- addresses, ports and gen's flow number -- asserts
that they arrived in the order they were sent:

  - the sequence number in the payload strictly increases, and
  - the IP ID strictly increases too, compared as a 16-bit serial number (RFC 1982): 100,000
    datagrams wrap the ID, so "increases" means the step from one to the next is 1 to 32767 modulo
    65536 -- checked wherever fewer than 32768 datagrams of the flow were lost in between, since
    across a wider gap the IDs alone cannot say which came first. Run gen with --ip-id-sequence,
    or the IDs are the kernel's and this half fails.

Gaps are allowed and reported -- a router may drop under load -- but going backwards is not.
--flows N also requires exactly N flows to have arrived, and --min-packets N at least N datagrams
in all. Exits 0 when every check passes, 1 otherwise. Standard library only.
"""

import argparse
import struct
import sys

MAGIC = b"NPFGEN01"
LINKTYPE_ETHERNET = 1
ETH_P_IPV4 = 0x0800
ETH_P_VLAN = 0x8100
IPPROTO_UDP = 17


def records(path):
    """Yields each record's bytes from a classic pcap file, in either byte order."""
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            raise ValueError(f"{path}: not a pcap file (too short)")
        magic = struct.unpack("<I", header[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            order = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            order = ">"
        else:
            raise ValueError(f"{path}: not a pcap file (magic {magic:#010x})")
        linktype = struct.unpack(order + "I", header[20:24])[0]
        if linktype != LINKTYPE_ETHERNET:
            raise ValueError(f"{path}: link type {linktype}, not Ethernet")
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            incl_len = struct.unpack(order + "I", rec[8:12])[0]
            data = f.read(incl_len)
            if len(data) < incl_len:
                return  # a capture cut short mid-record
            yield data


def gen_datagram(frame):
    """(flow key, IP ID, sequence number) for a datagram of gen's, or None for anything else."""
    if len(frame) < 14:
        return None
    off = 12
    ethertype = struct.unpack("!H", frame[off:off + 2])[0]
    if ethertype == ETH_P_VLAN:
        off += 4
        ethertype = struct.unpack("!H", frame[off:off + 2])[0]
    off += 2
    if ethertype != ETH_P_IPV4 or len(frame) < off + 20:
        return None
    ip = frame[off:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[0] >> 4 != 4 or ihl < 20 or ip[9] != IPPROTO_UDP or len(ip) < ihl + 8 + 20:
        return None
    ip_id = struct.unpack("!H", ip[4:6])[0]
    src, dst = ip[12:16], ip[16:20]
    udp = ip[ihl:]
    sport, dport = struct.unpack("!HH", udp[0:4])
    payload = udp[8:]
    if payload[:8] != MAGIC:
        return None
    flow, seq = struct.unpack("!IQ", payload[8:20])
    return (src, dst, sport, dport, flow), ip_id, seq


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("pcap")
    parser.add_argument("--flows", type=int)
    parser.add_argument("--min-packets", type=int, default=1)
    args = parser.parse_args()

    last = {}  # flow -> (IP ID, sequence number) of its latest datagram
    counts = {}
    gaps = 0
    errors = []
    for frame in records(args.pcap):
        got = gen_datagram(frame)
        if got is None:
            continue
        key, ip_id, seq = got
        counts[key] = counts.get(key, 0) + 1
        if key in last:
            prev_id, prev_seq = last[key]
            if seq <= prev_seq:
                errors.append(f"flow {key[4]}: sequence {seq} arrived after {prev_seq}")
            else:
                gaps += seq - prev_seq - 1
            # Across a gap of half the ID space or more, the IDs can no longer say which came first.
            step = (ip_id - prev_id) % 65536
            if seq > prev_seq and seq - prev_seq < 32768 and not 1 <= step <= 32767:
                errors.append(f"flow {key[4]}: IP ID {ip_id} arrived after {prev_id} "
                              f"(sequence {seq} after {prev_seq})")
        last[key] = (ip_id, seq)

    total = sum(counts.values())
    print(f"check_ordering: {total} datagrams in {len(counts)} flows; {gaps} missing "
          f"(lost, not reordered); {len(errors)} out of order")
    for e in errors[:20]:
        print(f"  {e}")
    if len(errors) > 20:
        print(f"  ... and {len(errors) - 20} more")
    ok = not errors
    if total < args.min_packets:
        print(f"check_ordering: FAIL: {total} datagrams, fewer than {args.min_packets}")
        ok = False
    if args.flows is not None and len(counts) != args.flows:
        print(f"check_ordering: FAIL: {len(counts)} flows arrived, expected {args.flows}")
        ok = False
    print("check_ordering: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
