#!/usr/bin/env python3
"""Generates the pcap fixtures in tests/fixtures/, and the golden cases in tests/fixtures/golden/.

Everything it writes is committed; rerun this only to add or change a fixture:

    python3 scripts/make_fixtures.py

scapy builds the frames. They are written by a minimal pcap writer below, with fixed timestamps
and addresses, so that regenerating produces byte-identical files and git shows no change.

The expected field values in tests/unit/test_ethernet.cpp, test_arp.cpp, test_ipv4.cpp and
test_l4.cpp come from the constants here; change both together.

A golden case is four files: <case>.pcap, the frames npf replay reads; <case>.conf, the router it
replays them through; and what it must produce -- <case>.expected.pcap, the frames it must write,
and <case>.expected.json, the counters it must end with. A case with a packet filter has a fifth,
<case>.filter, which its .conf names. tests/integration/test_golden.cpp runs every case and
compares. The expected files are built here, by a model of what a router must do to each frame
written from docs/BUILD_PLAN.md's description of the case, never from npf's own output: a golden
file copied from the code under test would only pin today's behaviour, bugs and all. When the two
disagree, one of them is wrong; find out which before changing either.
"""

import dataclasses
import ipaddress
import json
import pathlib
import socket
import struct

from scapy.layers.inet import ICMP, IP, TCP, UDP, IPOption_RR, fragment
from scapy.layers.inet6 import ICMPv6ND_RS, IPv6
from scapy.layers.l2 import ARP, Dot1AD, Dot1Q, Ether
from scapy.packet import Raw

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures"
GOLDEN = FIXTURES / "golden"

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
CLIENT_MAC = "02:00:00:00:01:02"
ROUTER_MAC = "02:00:00:00:01:01"
SERVER_MAC = "02:00:00:00:02:02"
LLDP_MULTICAST = "01:80:c2:00:00:0e"


def pcap_bytes(records: list[tuple[int, bytes]]) -> bytes:
    """Classic pcap: little-endian, microsecond timestamps, LINKTYPE_ETHERNET, a record per frame."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts_us, frame in records:
        out += struct.pack("<IIII", ts_us // 1_000_000, ts_us % 1_000_000, len(frame), len(frame))
        out += frame
    return out


def write_pcap(name: str, *frames: bytes) -> None:
    """A unit-test fixture: every record stamped zero."""
    (FIXTURES / f"{name}.pcap").write_bytes(pcap_bytes([(0, frame) for frame in frames]))
    print(f"  {name}.pcap  {' + '.join(str(len(f)) for f in frames)} bytes")


def lldp_payload() -> bytes:
    """Chassis ID (MAC), Port ID (local), TTL and End TLVs: a minimal valid LLDPDU."""

    def tlv(kind: int, value: bytes) -> bytes:
        return struct.pack("!H", kind << 9 | len(value)) + value

    chassis = bytes([4]) + bytes.fromhex(SERVER_MAC.replace(":", ""))
    return tlv(1, chassis) + tlv(2, bytes([7]) + b"veth-s") + tlv(3, struct.pack("!H", 120)) + tlv(0, b"")


# --- the golden cases ----------------------------------------------------------------------------

# The router every golden case replays through: the netns topology's two routed ports, with their
# MACs given, as a replay has no interface to read one from, and both hosts' MACs preloaded, so
# that it never asks for one. Every input frame arrives on port 0, from the client.
PORT0_MAC = ROUTER_MAC
PORT1_MAC = "02:00:00:00:02:01"
PORT0_IP = "10.0.1.1"
CLIENT_IP = "10.0.1.2"
SERVER_IP = "10.0.2.2"
POOL_SIZE = 64
GOLDEN_CONF = """\
# Golden case {name}: {what}.
# Written by scripts/make_fixtures.py; tests/integration/test_golden.cpp replays it.
interface veth-cr port 0 ip 10.0.1.1/24 mode routed mac 02:00:00:00:01:01
interface veth-sr port 1 ip 10.0.2.1/24 mode routed mac 02:00:00:00:02:01
route 10.0.1.0/24 dev 0
route 10.0.2.0/24 dev 1
arp 10.0.1.2 02:00:00:00:01:02 dev 0
arp 10.0.2.2 02:00:00:00:02:02 dev 1
pool_size {pool_size}
io pcap
"""

# Input record i is stamped T0 plus i milliseconds. Not zero: npf replay stamps a frame the router
# made with the time of the record that caused it, and tells the two kinds apart by a nonzero time.
T0_US = 1_700_000_000_000_000

DROP_REASONS = ("ShortFrame", "BadEtherType", "BadIpv4Header", "BadChecksum", "MartianSource",
                "TtlExpired", "NoRoute", "ArpUnresolved", "FilterDeny", "NoOutPort",
                "UnknownDestPort", "SamePort", "TxFull", "PoolExhausted")


def to_router(l3) -> bytes:
    """An IPv4 packet from the client, in a frame addressed to the router's port 0."""
    return bytes(Ether(dst=PORT0_MAC, src=CLIENT_MAC) / l3)


def forwarded(frame: bytes) -> bytes:
    """A frame the router forwards to the server: MACs replaced, TTL one less, the IPv4 header
    checksum computed again from scratch. Everything else, a VLAN tag included, as it came."""
    p = Ether(frame)
    p[Ether].src = PORT1_MAC
    p[Ether].dst = SERVER_MAC
    p[IP].ttl -= 1
    del p[IP].chksum
    out = bytes(p)
    assert len(out) == len(frame)
    return out


def icmp_error(frame: bytes, icmp_type: int, code: int) -> bytes:
    """The ICMP error the router sends back for an untagged frame that came in on port 0: from port
    0's address and MAC to the frame's sender, quoting the original's header and the first 8 bytes
    of its data exactly as received (RFC 792). TTL 64, ID 0 with DF, and precedence 6 with the
    original's TOS bits: the choices docs/rfc1812-conformance.md records."""
    l3 = frame[14:]
    header_len = (l3[0] & 0x0F) * 4
    total_len = struct.unpack("!H", l3[2:4])[0]
    quote = l3[:header_len] + l3[header_len:total_len][:8]
    error = bytes(Ether(dst=Ether(frame).src, src=PORT0_MAC)
                  / IP(src=PORT0_IP, dst=socket.inet_ntoa(l3[12:16]), ttl=64, id=0, flags="DF",
                       tos=0xC0 | (l3[1] & 0x1E))
                  / ICMP(type=icmp_type, code=code) / Raw(quote))
    icmp = error[34:]
    assert icmp[0] == icmp_type and icmp[1] == code and icmp[4:8] == bytes(4) and icmp[8:] == quote
    return error


def arp_reply_to(request: bytes) -> bytes:
    """The reply to a request for port 0's address: the asker becomes the target, the port the
    sender. 42 bytes: the request's padding is not sent back."""
    asked = Ether(request)[ARP]
    return bytes(Ether(dst=asked.hwsrc, src=PORT0_MAC)
                 / ARP(op=2, hwsrc=PORT0_MAC, psrc=asked.pdst, hwdst=asked.hwsrc, pdst=asked.psrc))


def counters(inputs: list[bytes], outputs: list[bytes], protocols: dict[int, int] | None = None,
             **counted: int) -> dict[str, int]:
    """Every counter npf replay --stats-json reports, in its order: zero but for the traffic and
    what is named. protocols counts the IPv4 packets per protocol number that passed the header
    checks; pool_available must be all of the pool again, with nothing leaked."""
    c = {"rx_packets": len(inputs), "rx_bytes": sum(map(len, inputs)),
         "tx_packets": len(outputs), "tx_bytes": sum(map(len, outputs)),
         "forwarded": 0, "flooded": 0, "to_host": 0, "arp_requests_rx": 0, "arp_replies_rx": 0,
         "arp_requests_tx": 0, "arp_replies_tx": 0, "icmp_generated": 0}
    c.update(dict.fromkeys(DROP_REASONS, 0))
    for protocol, n in sorted((protocols or {}).items()):
        c[f"ip_proto_{protocol}"] = n
    c["pool_available"] = POOL_SIZE
    c["pool_capacity"] = POOL_SIZE
    for name, value in counted.items():
        assert name in c, name
        c[name] = value
    return c


def write_golden(name: str, what: str, inputs: list[bytes], outputs: list[tuple[int, bytes]],
                 expected: dict[str, int], filter_text: str | None = None,
                 conf_template: str = "") -> None:
    """One case. outputs pairs each frame the router must write with the input it answers, whose
    timestamp it must carry. filter_text, if given, is the case's filter file; conf_template, if
    given, the router it replays through instead of the usual two routed ports."""
    conf = (conf_template or GOLDEN_CONF).format(name=name, what=what, pool_size=POOL_SIZE)
    if filter_text is not None:
        (GOLDEN / f"{name}.filter").write_text(filter_text)
        conf += f"filter {name}.filter\n"
    (GOLDEN / f"{name}.conf").write_text(conf)
    stamp = [T0_US + 1000 * i for i in range(len(inputs))]
    (GOLDEN / f"{name}.pcap").write_bytes(pcap_bytes(list(zip(stamp, inputs))))
    (GOLDEN / f"{name}.expected.pcap").write_bytes(
        pcap_bytes([(stamp[cause], frame) for cause, frame in outputs]))
    (GOLDEN / f"{name}.expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    print(f"  golden/{name}: {len(inputs)} frames in, {len(outputs)} out")


def golden_cases() -> None:
    """docs/BUILD_PLAN.md phase 9's eight cases."""
    GOLDEN.mkdir(parents=True, exist_ok=True)
    print(f"writing {GOLDEN}")
    payload = Raw(b"npf-golden")

    def tcp_syn(ttl: int) -> bytes:
        return to_router(IP(src=CLIENT_IP, dst=SERVER_IP, ttl=ttl, id=0x2468, flags="DF")
                         / TCP(sport=40001, dport=443, seq=0x12345678, flags="S", window=64240,
                               options=[("MSS", 1460)]))

    syn = tcp_syn(64)
    write_golden("basic_fwd", "one IPv4 TCP packet, with a route and the next hop's ARP entry",
                 [syn], [(0, forwarded(syn))], counters([syn], [forwarded(syn)], {6: 1}, forwarded=1))

    expiring = tcp_syn(1)
    reply = icmp_error(expiring, 11, 0)
    write_golden("ttl_expired", "the same packet with TTL 1: Time Exceeded back to its sender",
                 [expiring], [(0, reply)],
                 counters([expiring], [reply], {6: 1}, TtlExpired=1, icmp_generated=1))

    lost = to_router(IP(src=CLIENT_IP, dst="10.9.9.9", ttl=64, id=0x1111)
                     / UDP(sport=40000, dport=9) / payload)
    reply = icmp_error(lost, 3, 0)
    write_golden("no_route", "a destination no route covers: Net Unreachable back to its sender",
                 [lost], [(0, reply)],
                 counters([lost], [reply], {17: 1}, NoRoute=1, icmp_generated=1))

    bad = bytearray(to_router(IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=0x2222)
                              / UDP(sport=40000, dport=9) / payload))
    bad[14 + 10] ^= 0x01  # the header checksum's high byte: now it sums wrong
    bad_checksum = bytes(bad)
    write_golden("bad_checksum", "a corrupted IPv4 header checksum: dropped, and nothing sent",
                 [bad_checksum], [], counters([bad_checksum], [], BadChecksum=1))

    martian = to_router(IP(src="127.0.0.1", dst=SERVER_IP, ttl=64, id=0x3333)
                        / UDP(sport=40000, dport=9) / payload)
    write_golden("martian", "source 127.0.0.1: dropped, and nothing sent",
                 [martian], [], counters([martian], [], {17: 1}, MartianSource=1))

    datagram = (IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=0x9ABC) / UDP(sport=40000, dport=9)
                / Raw(bytes(range(100))))
    pieces = [to_router(f) for f in fragment(datagram, fragsize=48)]
    assert len(pieces) == 3
    sent = [forwarded(f) for f in pieces]
    write_golden("fragment", "a UDP datagram in three fragments: each forwarded as it is",
                 pieces, list(enumerate(sent)), counters(pieces, sent, {17: 3}, forwarded=3))

    request = bytes(Ether(dst=BROADCAST, src=CLIENT_MAC)
                    / ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, hwdst=ZERO_MAC, pdst=PORT0_IP))
    request += bytes(60 - len(request))  # padded to the Ethernet minimum, as on a wire
    answer = arp_reply_to(request)
    write_golden("arp_request", "who-has 10.0.1.1, port 0's address: one ARP reply",
                 [request], [(0, answer)],
                 counters([request], [answer], to_host=1, arp_requests_rx=1, arp_replies_tx=1))

    tagged = bytes(Ether(dst=PORT0_MAC, src=CLIENT_MAC) / Dot1Q(prio=5, vlan=100)
                   / IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=0x4444)
                   / UDP(sport=40000, dport=9) / payload)
    write_golden("vlan", "a VLAN-tagged IPv4 packet: forwarded, leaving with the same tag",
                 [tagged], [(0, forwarded(tagged))],
                 counters([tagged], [forwarded(tagged)], {17: 1}, forwarded=1))


# --- the packet filter (phase 11) -----------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class FilterRule:
    """One line of a filter file. None is any; an address without a length is a /32."""
    action: str  # "allow" or "deny"
    protocol: int | None = None
    src: str | None = None
    sport: tuple[int, int] | None = None
    dst: str | None = None
    dport: tuple[int, int] | None = None
    in_port: int | None = None

    def line(self) -> str:
        def side(address: str | None, ports: tuple[int, int] | None) -> str:
            text = address or "any"
            if ports:
                text += f" port {ports[0]}" if ports[0] == ports[1] else f" port {ports[0]}-{ports[1]}"
            return text
        protocol = {None: "any", 1: "icmp", 6: "tcp", 17: "udp"}.get(self.protocol, str(self.protocol))
        line = f"{self.action} {protocol} {side(self.src, self.sport)} -> {side(self.dst, self.dport)}"
        return line + (f" in-port {self.in_port}" if self.in_port is not None else "")


def filter_verdict(frame: bytes, rules: list[FilterRule], policy: str, in_port: int = 0) -> str:
    """What the filter must do with an untagged IPv4 frame, as docs/BUILD_PLAN.md phase 11 and
    docs/ARCHITECTURE.md §8 and §11 describe it: the first rule that matches decides, and a packet no
    rule matches gets the policy. A rule with ports cannot match a packet without readable ones -- a
    non-initial fragment above all, whose first bytes are data. And while any rule has ports, a TCP
    or UDP packet whose header cannot be read is denied before any rule is tried."""
    l3 = frame[14:]
    header_len = (l3[0] & 0x0F) * 4
    total_len = struct.unpack("!H", l3[2:4])[0]
    first_fragment = struct.unpack("!H", l3[6:8])[0] & 0x1FFF == 0
    protocol = l3[9]
    src, dst = ipaddress.IPv4Address(l3[12:16]), ipaddress.IPv4Address(l3[16:20])
    l4 = l3[header_len:total_len]
    unreadable = False
    if first_fragment and protocol == 6:
        unreadable = len(l4) < 20 or not 20 <= (l4[12] >> 4) * 4 <= len(l4)
    elif first_fragment and protocol == 17:
        unreadable = len(l4) < 8 or struct.unpack("!H", l4[4:6])[0] < 8
    if unreadable and any(r.sport or r.dport for r in rules):
        return "deny"
    readable_ports = first_fragment and protocol in (6, 17) and not unreadable
    ports = struct.unpack("!HH", l4[:4]) if readable_ports else None
    for r in rules:
        if ((r.in_port is not None and r.in_port != in_port)
                or (r.protocol is not None and r.protocol != protocol)
                or (r.src and src not in ipaddress.IPv4Network(r.src))
                or (r.dst and dst not in ipaddress.IPv4Network(r.dst))):
            continue
        if r.sport or r.dport:
            if (ports is None or (r.sport and not r.sport[0] <= ports[0] <= r.sport[1])
                    or (r.dport and not r.dport[0] <= ports[1] <= r.dport[1])):
                continue
        return r.action
    return policy


def filter_case() -> None:
    """docs/BUILD_PLAN.md phase 11's golden case: a default-deny filter that denies by port, by
    protocol and by default, and lets one kind of fragment through a port rule but not the other."""
    rules = [
        FilterRule("deny", 17, None, None, SERVER_IP, (53, 53)),
        FilterRule("deny", 6, None, None, SERVER_IP, (23, 23)),
        FilterRule("allow", 6, "10.0.1.0/24", None, "10.0.2.0/24"),
        FilterRule("deny", 1, "10.0.3.0/24"),
        FilterRule("allow", None, "10.0.1.0/24", in_port=0),
    ]
    policy = "deny"
    payload = Raw(b"npf-golden")

    def syn(dport: int, ident: int) -> bytes:
        return to_router(IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=ident, flags="DF")
                         / TCP(sport=40001, dport=dport, seq=0x10000000 + dport, flags="S"))

    dns = to_router(IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=0x5001)
                    / UDP(sport=40000, dport=53) / payload)
    # A DNS query in two fragments, of which only the second is sent. Its data begins with what
    # reads as a UDP header for 40000 -> 53; a filter that believed it would deny the fragment.
    lookalike = struct.pack("!HHHH", 40000, 53, 8, 0) + bytes(range(16))
    dns_tail = to_router(fragment(IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=0x5002)
                                  / UDP(sport=40000, dport=53) / Raw(lookalike), fragsize=8)[1])
    # RFC 1858's tiny fragment: the first fragment of a telnet SYN, cut after 8 bytes of TCP.
    tiny = to_router(IP(src=CLIENT_IP, dst=SERVER_IP, ttl=64, id=0x5005, flags="MF", proto=6)
                     / Raw(struct.pack("!HHI", 40003, 23, 0x10000017)))
    stray = to_router(IP(src="10.0.3.5", dst=SERVER_IP, ttl=64, id=0x5006)
                      / ICMP(type=8, id=7, seq=1) / payload)
    stray_tail = to_router(fragment(IP(src="10.0.3.5", dst=SERVER_IP, ttl=64, id=0x5007)
                                    / ICMP(type=8, id=7, seq=2) / Raw(bytes(range(32))),
                                    fragsize=16)[1])
    stranger = to_router(IP(src="192.168.7.7", dst=SERVER_IP, ttl=64, id=0x5008)
                         / UDP(sport=5000, dport=9999) / payload)
    # Each frame, with what the plan says must happen to it: the model must agree.
    plan = [(dns, "deny"),           # the port rule
            (dns_tail, "allow"),     # past the port rule, to the last rule
            (syn(443, 0x5003), "allow"),
            (syn(23, 0x5004), "deny"),
            (tiny, "deny"),          # unreadable TCP, while there are port rules
            (stray, "deny"),         # the protocol rule
            (stray_tail, "deny"),    # the protocol rule matches a fragment too
            (stranger, "deny")]      # no rule: the policy
    inputs = [frame for frame, _ in plan]
    for frame, verdict in plan:
        assert filter_verdict(frame, rules, policy) == verdict, (Ether(frame).summary(), verdict)
    outputs = [(i, forwarded(frame)) for i, frame in enumerate(inputs)
               if filter_verdict(frame, rules, policy) == "allow"]
    sent = [frame for _, frame in outputs]
    text = ("# Golden case filter_deny's packet filter, which filter_deny.conf names.\n"
            "# Written by scripts/make_fixtures.py.\n"
            f"policy {policy}\n" + "".join(r.line() + "\n" for r in rules))
    write_golden("filter_deny", "a filter that denies by port, by protocol and by default",
                 inputs, outputs,
                 counters(inputs, sent, {1: 2, 6: 3, 17: 3}, forwarded=len(sent),
                          FilterDeny=len(inputs) - len(sent)),
                 filter_text=text)


# --- switching (phase 12) ------------------------------------------------------------------------

# The router as a three-port switch: every port bridged, in bridge domain 1, with no address. Burst
# 1, so that each input is handled, and its copies sent, before the next is read: the output then
# holds each input's copies together, in port order.
BRIDGE_CONF = """\
# Golden case {name}: {what}.
# Written by scripts/make_fixtures.py; tests/integration/test_golden.cpp replays it.
interface veth-h1 port 0 mode bridged bridge-domain 1 mac 02:00:00:00:09:01
interface veth-h2 port 1 mode bridged bridge-domain 1 mac 02:00:00:00:09:02
interface veth-h3 port 2 mode bridged bridge-domain 1 mac 02:00:00:00:09:03
pool_size {pool_size}
burst 1
io pcap
"""
BRIDGE_PORTS = (0, 1, 2)
H1_MAC = "02:00:00:00:a0:01"
H2_MAC = "02:00:00:00:a0:02"
H4_MAC = "02:00:00:00:a0:04"


def switch_model(frames: list[bytes], in_port: int = 0) -> tuple[list[tuple[int, bytes]], dict]:
    """What a learning switch must do with frames that all arrive on in_port, as docs/BUILD_PLAN.md
    phase 12 says: learn every unicast source's port; flood a frame to a group address, or to one
    not learned, out of every other port of the bridge domain, in port order; send one to a learned
    destination out of that port; and drop it if that is the port it came in on. Returns the frames
    sent, each with the input it came from, and the counters that moves."""
    table: dict[bytes, int] = {}
    sent: list[tuple[int, bytes]] = []
    counted = {"flooded": 0, "forwarded": 0, "SamePort": 0}
    for i, frame in enumerate(frames):
        dst, src = frame[0:6], frame[6:12]
        if not src[0] & 1:
            table[src] = in_port
        if dst[0] & 1 or dst not in table:
            counted["flooded"] += 1
            sent += [(i, frame) for port in BRIDGE_PORTS if port != in_port]
        elif table[dst] == in_port:
            counted["SamePort"] += 1
        else:
            counted["forwarded"] += 1
            sent.append((i, frame))
    return sent, counted


def switch_case() -> None:
    """docs/BUILD_PLAN.md phase 12's golden case. A replay delivers every frame on port 0, so this
    shows flooding -- a broadcast ARP request, a frame to a station not yet heard from, an IPv6
    multicast -- and a frame to a station learned on the port it came in on, dropped."""
    payload = Raw(b"npf-golden")
    who_has = bytes(Ether(dst=BROADCAST, src=H1_MAC)
                    / ARP(op=1, hwsrc=H1_MAC, psrc="10.0.9.1", hwdst=ZERO_MAC, pdst="10.0.9.2"))
    who_has += bytes(60 - len(who_has))  # padded to the Ethernet minimum, as on a wire
    unknown = bytes(Ether(dst=H2_MAC, src=H1_MAC)
                    / IP(src="10.0.9.1", dst="10.0.9.2", ttl=64, id=0x6001)
                    / ICMP(type=8, id=9, seq=1) / payload)
    solicit = bytes(Ether(dst="33:33:00:00:00:02", src=H1_MAC)
                    / IPv6(src="fe80::a0:1", dst="ff02::2", hlim=255) / ICMPv6ND_RS())
    # A station behind port 0 too, writing to h1, which the first frame showed is on port 0.
    same_port = bytes(Ether(dst=H1_MAC, src=H4_MAC)
                      / IP(src="10.0.9.4", dst="10.0.9.1", ttl=64, id=0x6004)
                      / ICMP(type=8, id=9, seq=2) / payload)
    inputs = [who_has, unknown, solicit, same_port]
    sent, counted = switch_model(inputs)
    assert counted == {"flooded": 3, "forwarded": 0, "SamePort": 1}, counted
    write_golden("l2_flood", "a three-port switch floods, and drops a frame to its own port",
                 inputs, sent, counters(inputs, [frame for _, frame in sent], **counted),
                 conf_template=BRIDGE_CONF)


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

    golden_cases()
    filter_case()
    switch_case()


if __name__ == "__main__":
    main()
