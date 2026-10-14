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
    netns_frames.py frames <iface> <seconds>
        Print "listening", then a line for each frame received on <iface> for <seconds>, in the
        shape `tcpdump -t -e -n -Q in` gives it, so a test reads either the same way:
        "src > dst, ethertype ARP (0x0806), length N: Request who-has A tell B", and so on.
    netns_frames.py pcap <iface> <seconds> <file>
        Print "listening", then write every frame received on <iface> for <seconds>, or until
        SIGTERM, to <file> as a pcap: what `tcpdump -w` is used for, where tcpdump cannot run.
        A Python loop drops frames a fast sender outruns; scripts/check_ordering.py allows gaps.
    netns_frames.py send-pcap <iface> <file>
        Send every frame in the pcap <file> out of <iface>, in order: a replay's input, live.
    netns_frames.py count <file>
        Print how many frames the pcap <file> holds.
    netns_frames.py same-frames <a.pcap> <b.pcap>
        Exit 0 if both files hold the same frames in the same order, timestamps aside; otherwise
        say where they first differ, and exit 1.
    netns_frames.py same-frame-set <expected.pcap> <file>...
        Exit 0 if the files together hold exactly the frames <expected.pcap> does, in any order:
        a replay writes every port's frames to one file, and a live run's leave by several ports.
    netns_frames.py same-frame-set-untagged <expected.pcap> <file>...
        The same, with any VLAN tag taken out of the expected frames first.
"""

import signal
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 0x10
TP_STATUS_VLAN_TPID_VALID = 0x40


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


def mac_text(b):
    return ":".join(f"{octet:02x}" for octet in b)


def describe(frame):
    """One received frame, as tcpdump -t -e -n prints the parts the switching test reads."""
    head = f"{mac_text(frame[6:12])} > {mac_text(frame[0:6])}"
    kind = struct.unpack("!H", frame[12:14])[0]
    if kind == 0x0806 and len(frame) >= 42:
        op = struct.unpack("!H", frame[20:22])[0]
        spa, tpa = socket.inet_ntoa(frame[28:32]), socket.inet_ntoa(frame[38:42])
        what = (f"Request who-has {tpa} tell {spa}" if op == 1
                else f"Reply {spa} is-at {mac_text(frame[22:28])}")
        return f"{head}, ethertype ARP (0x0806), length {len(frame)}: {what}"
    if kind == 0x0800 and len(frame) >= 34:
        ihl = (frame[14] & 0x0F) * 4
        src, dst = socket.inet_ntoa(frame[26:30]), socket.inet_ntoa(frame[30:34])
        what = f"{src} > {dst}: ip-proto-{frame[23]}"
        if frame[23] == 1 and len(frame) > 14 + ihl:
            icmp_type = frame[14 + ihl]
            what = f"{src} > {dst}: ICMP " + {8: "echo request", 0: "echo reply"}.get(
                icmp_type, f"type {icmp_type}")
        return f"{head}, ethertype IPv4 (0x0800), length {len(frame)}: {what}"
    return f"{head}, ethertype 0x{kind:04x}, length {len(frame)}"


def frames(iface, seconds):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)) as s:
        s.bind((iface, 0))
        s.settimeout(0.2)
        print("listening", flush=True)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                frame, address = s.recvfrom(65535)
            except socket.timeout:
                continue
            if address[2] != PACKET_OUTGOING and len(frame) >= 14:
                print(describe(frame), flush=True)


def with_vlan_tag(frame, ancdata):
    """The frame as it was on the wire. The kernel takes a VLAN tag out of every frame it receives,
    before any packet socket sees it, and hands it over beside the frame (PACKET_AUXDATA)."""
    for level, kind, data in ancdata:
        if level == SOL_PACKET and kind == PACKET_AUXDATA and len(data) >= 20:
            status, _, _, _, _, tci, tpid = struct.unpack("=IIIHHHH", data[:20])
            if status & TP_STATUS_VLAN_VALID:
                tpid = tpid if status & TP_STATUS_VLAN_TPID_VALID else 0x8100
                return frame[:12] + struct.pack("!HH", tpid, tci) + frame[12:]
    return frame


def pcap(iface, seconds, path):
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(True))
    with (socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)) as s,
          open(path, "wb") as out):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        s.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        s.bind((iface, 0))
        s.settimeout(0.2)
        # The classic header: magic, version 2.4, no time zone, snap length, Ethernet.
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        print("listening", flush=True)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not stop:
            try:
                frame, ancdata, _, address = s.recvmsg(65535, socket.CMSG_SPACE(32))
            except (socket.timeout, InterruptedError):
                continue
            if address[2] == PACKET_OUTGOING:
                continue
            frame = with_vlan_tag(frame, ancdata)
            now = time.time()
            out.write(struct.pack("<IIII", int(now), int((now % 1) * 1e6), len(frame), len(frame)))
            out.write(frame)


def read_pcap(path):
    """The frames of a classic pcap, either byte order, microsecond timestamps."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError(f"{path}: not a pcap")
    order = "<" if data[:4] == bytes.fromhex("d4c3b2a1") else ">"
    if struct.unpack(order + "I", data[:4])[0] != 0xA1B2C3D4:
        raise ValueError(f"{path}: not a microsecond pcap")
    out, off = [], 24
    while off + 16 <= len(data):
        incl = struct.unpack(order + "I", data[off + 8:off + 12])[0]
        if off + 16 + incl > len(data):
            raise ValueError(f"{path}: record {len(out) + 1} is cut short")
        out.append(data[off + 16:off + 16 + incl])
        off += 16 + incl
    return out


def send_pcap(iface, path):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as s:
        s.bind((iface, 0))
        for frame in read_pcap(path):
            s.send(frame)


def same_frames(a, b):
    left, right = read_pcap(a), read_pcap(b)
    for i, (x, y) in enumerate(zip(left, right)):
        if x != y:
            print(f"frame {i + 1} differs:\n  {x.hex()}\n  {y.hex()}")
            return 1
    if len(left) != len(right):
        print(f"{len(left)} frames against {len(right)}")
        return 1
    return 0


def untagged(frame):
    """The frame without its outer VLAN tag, if it has one."""
    tagged = frame[12:14] in (bytes.fromhex("8100"), bytes.fromhex("88a8"))
    return frame[:12] + frame[16:] if tagged else frame


def same_frame_set(expected, *files, strip_vlan=False):
    want = sorted(untagged(f) if strip_vlan else f for f in read_pcap(expected))
    got = sorted(frame for f in files for frame in read_pcap(f))
    if want == got:
        return 0
    for frame in want:
        if frame in got:
            got.remove(frame)
        else:
            print(f"missing: {frame.hex()}")
    for frame in got:
        print(f"extra:   {frame.hex()}")
    return 1


def main(argv):
    commands = {
        "lldp": (lldp, 1),
        "bad-checksum": (bad_checksum, 4),
        "echo-ttls": (lambda i, c, s: echo_ttls(i, int(c), float(s)), 3),
        "frames": (lambda i, s: frames(i, float(s)), 2),
        "pcap": (lambda i, s, f: pcap(i, float(s), f), 3),
        "send-pcap": (send_pcap, 2),
        "count": (lambda f: print(len(read_pcap(f))), 1),
        "same-frames": (same_frames, 2),
        "same-frame-set": (same_frame_set, -2),  # negative: at least that many
        "same-frame-set-untagged": (lambda *f: same_frame_set(*f, strip_vlan=True), -2),
    }
    if len(argv) < 2 or argv[1] not in commands:
        print(__doc__, file=sys.stderr)
        return 2
    want = commands[argv[1]][1]
    if (want >= 0 and len(argv) - 2 != want) or (want < 0 and len(argv) - 2 < -want):
        print(__doc__, file=sys.stderr)
        return 2
    return commands[argv[1]][0](*argv[2:]) or 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
