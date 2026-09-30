#!/usr/bin/env python3
"""Generates the pcap fixtures in tests/fixtures/, one frame per file.

The pcaps are committed; rerun this only to add or change a fixture:

    python3 scripts/make_fixtures.py

scapy builds the frames. They are written by a minimal pcap writer below, with zero timestamps
and fixed addresses, so that regenerating produces byte-identical files and git shows no change.

The expected field values in tests/unit/test_ethernet.cpp, test_arp.cpp, test_ipv4.cpp and
test_l4.cpp come from the constants here; change both together.
"""

import pathlib
import struct

from scapy.layers.inet import ICMP, IP, TCP, UDP, IPOption_RR, fragment
from scapy.layers.l2 import ARP, Dot1AD, Dot1Q, Ether
from scapy.packet import Raw

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures"

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
CLIENT_MAC = "02:00:00:00:01:02"
ROUTER_MAC = "02:00:00:00:01:01"
SERVER_MAC = "02:00:00:00:02:02"
LLDP_MULTICAST = "01:80:c2:00:00:0e"


def write_pcap(name: str, *frames: bytes) -> None:
    """Classic pcap: little-endian, microsecond timestamps, LINKTYPE_ETHERNET, a record per frame."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for frame in frames:
        out += struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    (FIXTURES / f"{name}.pcap").write_bytes(out)
    print(f"  {name}.pcap  {' + '.join(str(len(f)) for f in frames)} bytes")


def lldp_payload() -> bytes:
    """Chassis ID (MAC), Port ID (local), TTL and End TLVs: a minimal valid LLDPDU."""

    def tlv(kind: int, value: bytes) -> bytes:
        return struct.pack("!H", kind << 9 | len(value)) + value

    chassis = bytes([4]) + bytes.fromhex(SERVER_MAC.replace(":", ""))
    return tlv(1, chassis) + tlv(2, bytes([7]) + b"veth-s") + tlv(3, struct.pack("!H", 120)) + tlv(0, b"")


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    print(f"writing {FIXTURES}")

    arp_request = bytes(
        Ether(dst=BROADCAST, src=CLIENT_MAC)
        / ARP(op=1, hwsrc=CLIENT_MAC, psrc="10.0.1.2", hwdst=ZERO_MAC, pdst="10.0.1.1")
    )
    arp_reply = bytes(
        Ether(dst=CLIENT_MAC, src=ROUTER_MAC)
        / ARP(op=2, hwsrc=ROUTER_MAC, psrc="10.0.1.1", hwdst=CLIENT_MAC, pdst="10.0.1.2")
    )
    # Gratuitous: sender and target protocol addresses are the same (RFC 5227 announcement).
    arp_gratuitous = bytes(
        Ether(dst=BROADCAST, src=SERVER_MAC)
        / ARP(op=1, hwsrc=SERVER_MAC, psrc="10.0.2.2", hwdst=ZERO_MAC, pdst="10.0.2.2")
    )
    # Port 9 (discard), so tools do not try to decode the payload as some real protocol.
    udp = IP(src="10.0.1.2", dst="10.0.2.2", ttl=64) / UDP(sport=40000, dport=9) / Raw(b"npf-fixture")

    write_pcap("arp_request", arp_request)
    write_pcap("arp_reply", arp_reply)
    write_pcap("arp_gratuitous", arp_gratuitous)
    # Short frames are zero-padded to the 60-byte Ethernet minimum on a real wire.
    write_pcap("arp_reply_padded_60", arp_reply + bytes(60 - len(arp_reply)))
    # Priority 5 in the tag, so a parser that forgets to mask the TCI reports the wrong VLAN.
    write_pcap("vlan_ipv4", bytes(Ether(dst=ROUTER_MAC, src=CLIENT_MAC) / Dot1Q(prio=5, vlan=100) / udp))
    write_pcap("dot1ad_arp", bytes(Ether(dst=BROADCAST, src=CLIENT_MAC) / Dot1AD(vlan=300) / ARP(
        op=1, hwsrc=CLIENT_MAC, psrc="10.0.1.2", hwdst=ZERO_MAC, pdst="10.0.1.1")))
    write_pcap("qinq_double_tag",
               bytes(Ether(dst=ROUTER_MAC, src=CLIENT_MAC) / Dot1AD(vlan=200) / Dot1Q(vlan=100) / udp))
    write_pcap("lldp", bytes(Ether(dst=LLDP_MULTICAST, src=SERVER_MAC, type=0x88CC) / Raw(lldp_payload())))
    write_pcap("runt_13", arp_request[:13])

    # A 30-byte datagram in a 60-byte frame: total_length, not the frame, must bound the payload.
    small = bytes(Ether(dst=ROUTER_MAC, src=CLIENT_MAC) / IP(
        src="10.0.1.2", dst="10.0.2.2", ttl=64, id=0x1234, flags="DF") / UDP(sport=40000, dport=9) / Raw(b"hi"))
    write_pcap("ipv4_udp_padded_60", small + bytes(60 - len(small)))
    # Record Route with three empty slots: 15 option bytes, padded to 16, so ihl is 9, not 5.
    write_pcap("ipv4_options_rr", bytes(Ether(dst=ROUTER_MAC, src=CLIENT_MAC) / IP(
        src="10.0.1.2", dst="10.0.2.2", ttl=64, id=0x5678, options=[IPOption_RR(routers=["0.0.0.0"] * 3)])
        / UDP(sport=40000, dport=9) / Raw(b"npf")))

    # 108 bytes of UDP split 48 + 48 + 12. The data is arranged so that the second fragment begins
    # with 01 bb 1f 90: bytes that would read as ports 443 -> 8080 to a parser that trusted a
    # non-initial fragment.
    data = bytes(range(40)) + bytes.fromhex("01bb1f90") + bytes(range(56))
    datagram = IP(src="10.0.1.2", dst="10.0.2.2", ttl=64, id=0x9ABC) / UDP(sport=40000, dport=9) / Raw(data)
    write_pcap("udp_fragmented",
               *[bytes(Ether(dst=ROUTER_MAC, src=CLIENT_MAC) / f) for f in fragment(datagram, fragsize=48)])
    # One option (MSS), so the data offset is 6, not 5.
    write_pcap("tcp_syn", bytes(Ether(dst=ROUTER_MAC, src=CLIENT_MAC) / IP(
        src="10.0.1.2", dst="10.0.2.2", ttl=64, id=0x2468, flags="DF") / TCP(
        sport=40001, dport=443, seq=0x12345678, flags="S", window=64240, options=[("MSS", 1460)])))
    write_pcap("icmp_echo_request", bytes(Ether(dst=ROUTER_MAC, src=CLIENT_MAC) / IP(
        src="10.0.1.2", dst="10.0.2.2", ttl=64, id=0x1357) / ICMP(type=8, id=0x0457, seq=1)
        / Raw(b"npf-ping-payload")))
    # What a router sends back when a datagram's TTL runs out: its IP header and first 8 bytes.
    expired = bytes(IP(src="10.0.1.2", dst="10.0.2.2", ttl=1, id=0x0001) / UDP(sport=40000, dport=9)
                    / Raw(b"npf-fixture"))[:28]
    write_pcap("icmp_time_exceeded", bytes(Ether(dst=CLIENT_MAC, src=ROUTER_MAC) / IP(
        src="10.0.1.1", dst="10.0.1.2", ttl=64, id=0x0002) / ICMP(type=11, code=0) / Raw(expired)))


if __name__ == "__main__":
    main()
