#!/usr/bin/env python3
"""Flattens a RouteViews MRT RIB dump to the IPv4 prefixes in it, for bench/micro/bench_lpm.cpp.

    python3 scripts/mrt_to_prefixes.py <rib.YYYYMMDD.HHMM.bz2> <out-dir>

scripts/fetch_bgp_table.sh runs it. It reads the dump's RFC 6396 TABLE_DUMP_V2 records with nothing
but the standard library, and writes:

    <out-dir>/bgp_prefixes.txt        every IPv4 unicast prefix in it, one a line: "a.b.c.d/len id"
    <out-dir>/bgp_prefixes_10.txt     uniform samples of those lines, of 10, 1,000 and 100,000,
    <out-dir>/bgp_prefixes_1k.txt     for the benchmark's sweep of table sizes, drawn with a fixed
    <out-dir>/bgp_prefixes_100k.txt   seed: the same dump makes the same files

A prefix's id names the BGP NEXT_HOP of the first entry the dump lists for it -- the route the
collector's first listed peer has -- numbered from 0 in the order first seen. There are as many as
the collector has peers to learn from, a few dozen, much as a router has neighbours.
"""

import bz2
import collections
import pathlib
import random
import socket
import struct
import sys

MRT_TABLE_DUMP_V2 = 13  # RFC 6396 section 4.3
RIB_IPV4_UNICAST = 2
ATTR_NEXT_HOP = 3  # BGP path attribute type (RFC 4271)
ATTR_EXTENDED_LENGTH = 0x10
SAMPLES = {"10": 10, "1k": 1_000, "100k": 100_000}
SEED = 20261004


def records(stream):
    """(type, subtype, body) of every MRT record: a 12-byte header, then the body it sizes."""
    while True:
        header = stream.read(12)
        if not header:
            return
        if len(header) < 12:
            raise ValueError("the dump ends inside a record's header")
        _timestamp, kind, subtype, length = struct.unpack("!IHHI", header)
        body = stream.read(length)
        if len(body) < length:
            raise ValueError("the dump ends inside a record")
        yield kind, subtype, body


def next_hop(attributes):
    """The NEXT_HOP among a RIB entry's BGP path attributes, as 4 bytes, or None."""
    at = 0
    while at + 3 <= len(attributes):
        flags, kind = attributes[at], attributes[at + 1]
        if flags & ATTR_EXTENDED_LENGTH:
            (length,) = struct.unpack_from("!H", attributes, at + 2)
            at += 4
        else:
            length = attributes[at + 2]
            at += 3
        if kind == ATTR_NEXT_HOP and length == 4:
            return attributes[at:at + 4]
        at += length
    return None


def rib_ipv4_unicast(body):
    """(prefix, length, next hop) of a RIB_IPV4_UNICAST record, the next hop being the first
    entry's that has one, or None."""
    # Sequence number (4), prefix length (1), as many of the prefix's octets as the length
    # needs, entry count (2); then per entry: peer index (2), originated time (4), attribute
    # length (2), and the attributes.
    length = body[4]
    if length > 32:
        raise ValueError(f"a prefix length of {length}")
    octets = (length + 7) // 8
    prefix = int.from_bytes(body[5:5 + octets].ljust(4, b"\0"), "big")
    (entries,) = struct.unpack_from("!H", body, 5 + octets)
    at = 7 + octets
    for _ in range(entries):
        (attribute_length,) = struct.unpack_from("!H", body, at + 6)
        hop = next_hop(body[at + 8:at + 8 + attribute_length])
        if hop is not None:
            return prefix, length, hop
        at += 8 + attribute_length
    return prefix, length, None


def main():
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <rib.bz2> <out-dir>")
    dump, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    hop_ids = {}
    lines = []
    lengths = collections.Counter()
    without_hop = 0
    stray_bits = 0
    with bz2.open(dump, "rb") as stream:
        for kind, subtype, body in records(stream):
            if kind != MRT_TABLE_DUMP_V2 or subtype != RIB_IPV4_UNICAST:
                continue
            prefix, length, hop = rib_ipv4_unicast(body)
            mask = (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF
            if prefix & ~mask & 0xFFFFFFFF:
                stray_bits += 1  # set past the length: not a valid prefix as it stands
                prefix &= mask
            if hop is None:
                without_hop += 1
                continue
            hop_id = hop_ids.setdefault(hop, len(hop_ids))
            lines.append(f"{socket.inet_ntoa(prefix.to_bytes(4, 'big'))}/{length} {hop_id}\n")
            lengths[length] += 1

    out.mkdir(parents=True, exist_ok=True)
    (out / "bgp_prefixes.txt").write_text("".join(lines))
    rng = random.Random(SEED)
    for name, count in SAMPLES.items():
        picked = sorted(rng.sample(range(len(lines)), count))  # kept in the dump's order
        (out / f"bgp_prefixes_{name}.txt").write_text("".join(lines[i] for i in picked))

    print(f"{len(lines)} IPv4 prefixes from {dump.name}, {len(hop_ids)} distinct next hops")
    print(f"skipped {without_hop} with no NEXT_HOP; masked {stray_bits} with bits set past their length")
    common = ", ".join(f"/{n}: {c}" for n, c in sorted(lengths.items(), key=lambda kv: -kv[1])[:6])
    print(f"most common lengths: {common}")
    print(f"shortest /{min(lengths)}, longest /{max(lengths)}")
    known = {line.split()[0] for line in lines}
    for prefix in ("8.8.8.0/24", "1.1.1.0/24"):
        print(f"{prefix}: {'present' if prefix in known else 'MISSING'}")
    print("wrote " + ", ".join(["bgp_prefixes.txt"] + [f"bgp_prefixes_{n}.txt" for n in SAMPLES]))


if __name__ == "__main__":
    main()
