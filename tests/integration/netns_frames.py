#!/usr/bin/env python3
"""Raw Ethernet frames for the netns integration tests, using nothing but the standard library.

    netns_frames.py lldp <iface>
        Send one LLDP frame (EtherType 0x88cc): not IPv4, not ARP, so never routed.
    netns_frames.py bad-checksum <iface> <dst-mac> <src-ip> <dst-ip>
        Send one ICMP echo request whose IPv4 header checksum is wrong.
    netns_frames.py echo-ttls <iface> <count> <seconds>
        Print "listening", then "ttl N src > dst" for each ICMP echo request received on <iface>,
        until <count> have arrived or <seconds> have passed. Does what `tcpdump -v` is used for,
        where tcpdump cannot run: inside an unprivileged user namespace it fails to drop privileges.
"""

import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4


def mac_bytes(text):
    return bytes(int(octet, 16) for octet in text.split(":"))


def own_mac(iface):
    with open(f"/sys/class/net/{iface}/address", encoding="ascii") as f:
        return mac_bytes(f.read().strip())


def checksum(data):
    """RFC 1071: the one's complement of the one's-complement sum of 16-bit words."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def send(iface, frame):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as s:
        s.bind((iface, 0))
        s.send(frame)


def lldp(iface):
    mac = own_mac(iface)
    tlvs = (
        bytes([0x02, 0x07, 0x04]) + mac  # chassis ID: a MAC address
        + bytes([0x04, 0x02, 0x07]) + b"1"  # port ID: locally assigned, "1"
        + bytes([0x06, 0x02, 0x00, 0x78])  # time to live: 120 s
        + bytes([0x00, 0x00])  # end of LLDPDU
    )
    frame = mac_bytes("01:80:c2:00:00:0e") + mac + struct.pack("!H", 0x88CC) + tlvs
    send(iface, frame.ljust(60, b"\0"))


def bad_checksum(iface, dst_mac, src_ip, dst_ip):
    icmp = bytearray(struct.pack("!BBHHH", 8, 0, 0, 0x4E50, 1) + b"npf-test")
    struct.pack_into("!H", icmp, 2, checksum(bytes(icmp)))
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 0, 0, 64, 1, 0,
                                   socket.inet_aton(src_ip), socket.inet_aton(dst_ip)))
    struct.pack_into("!H", header, 10, checksum(bytes(header)) ^ 0x0101)  # wrong on purpose
    frame = mac_bytes(dst_mac) + own_mac(iface) + struct.pack("!H", 0x0800) + header + icmp
    send(iface, bytes(frame))


def echo_ttls(iface, count, seconds):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)) as s:
        s.bind((iface, 0))
        s.settimeout(0.2)
        print("listening", flush=True)
        seen = 0
        deadline = time.monotonic() + seconds
        while seen < count and time.monotonic() < deadline:
            try:
                frame, address = s.recvfrom(65535)
            except socket.timeout:
                continue
            if address[2] == PACKET_OUTGOING or len(frame) < 34 or frame[12:14] != b"\x08\x00":
                continue
            ihl = (frame[14] & 0x0F) * 4
            if frame[23] != 1 or len(frame) <= 14 + ihl or frame[14 + ihl] != 8:
                continue  # IPv4, but not an ICMP echo request
            source = socket.inet_ntoa(frame[26:30])
            destination = socket.inet_ntoa(frame[30:34])
            print(f"ttl {frame[22]} {source} > {destination}", flush=True)
            seen += 1


def main(argv):
    commands = {
        "lldp": (lldp, 1),
        "bad-checksum": (bad_checksum, 4),
        "echo-ttls": (lambda i, c, s: echo_ttls(i, int(c), float(s)), 3),
    }
    if len(argv) < 2 or argv[1] not in commands or len(argv) - 2 != commands[argv[1]][1]:
        print(__doc__, file=sys.stderr)
        return 2
    commands[argv[1]][0](*argv[2:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
