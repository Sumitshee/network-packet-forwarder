# RFC 1812 conformance

Where `npf` stands on the requirements of RFC 1812, *Requirements for IP Version 4 Routers*, that
bear on what it does so far: forwarding IPv4 between Ethernet ports, resolving its neighbours with
ARP, answering ARP and pings, sending ICMP errors, and filtering what it forwards. Section numbers
are RFC 1812's own, except where a row names RFC 1122, whose ARP requirements RFC 1812 §3.3.2
adopts.

- **implemented** — met by the code named in the last column, and tested.
- **deferred** — not met. The note says why, and which phase of `docs/BUILD_PLAN.md` meets it, if
  one does.
- **n-a** — does not apply to this router.

A requirement met only in part is split into rows: the part that is met, and the part that is not.
The pipeline steps named below are those of `docs/ARCHITECTURE.md` §11.

## IP header validation and options

| Requirement | § | Level | Status | Where, or why not |
|---|---|---|---|---|
| Discard a packet whose header fails validation: shorter than 20 bytes, bad checksum, version not 4, IHL below 5, total length below the header length | 5.2.2 | MUST | implemented | `Ipv4View::parse` and `ipv4_checksum_valid`, steps 5 and 6 (`BadIpv4Header`, `BadChecksum`); `test_ipv4`, `test_forward`, netns exit test |
| Discard a packet shorter than its total length says | 5.2.2 | MUST | implemented | `Ipv4View::parse`; `test_ipv4` |
| Log header validation errors | 5.2.2 | SHOULD | deferred | Counted per reason (`npf show stats`), not logged per packet: a log line for every bad packet would let any sender flood the log. |
| Parameter Problem for a bad length or a truncated packet | 5.2.2 | MAY, SHOULD | deferred | The router sends no Parameter Problem messages. |
| Pass unrecognized options through unchanged | 5.3.13.1 | MUST | implemented | Options are skipped by IHL and never touched; forwarding rewrites only the TTL and checksum. `test_forward` `IpOptionsAreForwardedUntouched` |
| Interpret the options it understands, in datagrams addressed to it | 4.2.2.1 | MUST | deferred | No option is understood: the build plan's phase 7 fence is "no IP option processing beyond skipping them". |
| Source routing, in forwarded packets | 5.3.13.4 | MUST | deferred | A source-routed packet is forwarded by its destination address, its option ignored. Honouring the option needs the option processing above, and source routing is commonly filtered as a security risk anyway. |

## Address resolution (ARP)

| Requirement | § | Level | Status | Where, or why not |
|---|---|---|---|---|
| Never report a destination unreachable just for want of an ARP entry: queue a few packets while asking | 3.3.2 | MUST NOT, SHOULD | implemented | Step 12 queues up to 3 packets per neighbour (`ArpCache::resolve_and_queue`, `Verdict::Queued`), and sends them when it answers. `test_arp_cache`, `test_forward`, ARP exit test: the first ping through a router that knows no one gets an answer |
| Report the destination unreachable for one of the queued packets, and only once asking has failed | 3.3.2 | SHOULD | implemented | A Host Unreachable for the head of the queue, after three requests a second apart go unanswered. `test_arp_cache`, `test_forward`, ARP exit test |
| Never believe an ARP message giving another station a broadcast or multicast MAC | 3.3.2 | MUST NOT | implemented | `ArpCache::on_reply` and `on_unsolicited` ignore one. `test_arp_cache` `NoAnswerNamingABroadcastOrMulticastMacIsBelieved` |
| Flush out-of-date entries | RFC 1122 2.3.2.1 | MUST | implemented | An entry not heard from for 30 s is asked about again the next time it is used, and deleted if three requests go unanswered. One not used for 60 s is deleted. `test_arp_cache` |
| Make that timeout configurable | RFC 1122 2.3.2.1 | SHOULD | deferred | Fixed at 30 s and 60 s. |
| Prevent ARP flooding: at most one request a second per destination | RFC 1122 2.3.2.1 | MUST | implemented | One request a second per neighbour, however many packets wait on it or use it. `test_arp_cache` |
| Keep a packet for an address being resolved, and send it once resolved | RFC 1122 2.3.2.2 | SHOULD | implemented | The first three. |
| ...and of the packets kept, keep the latest | RFC 1122 2.3.2.2 | SHOULD | deferred | A full queue refuses the newest packet, as `docs/BUILD_PLAN.md` phase 8 specifies; Linux drops the oldest instead. |

## TTL and Time Exceeded

| Requirement | § | Level | Status | Where, or why not |
|---|---|---|---|---|
| Decrement the TTL of every forwarded packet by at least one | 5.3.1 | MUST | implemented | Step 13, `rewrite_for_forwarding`, with the RFC 1624 checksum update; netns exit test (TTL 63 at the server) |
| Discard a packet whose TTL reaches zero | 5.3.1 | MUST | implemented | Step 9 (`TtlExpired`) |
| Send Time Exceeded, code 0, unless the destination is multicast | 5.3.1, 5.2.7.3 | MUST | implemented | `ControlPlane::error_for`; `test_forward`; traceroute exit test |

## Destination Unreachable

| Requirement | § | Level | Status | Where, or why not |
|---|---|---|---|---|
| Network Unreachable (code 0) when there is no route at all | 4.3.3.1, 5.2.7.1 | MUST | implemented | Step 11 (`NoRoute`), `ControlPlane::error_for`; `test_forward`; netns exit test |
| Host Unreachable (code 1) when a directly connected host does not answer ARP | 4.3.3.1, 5.2.7.1 | MUST | implemented | When three ARP requests a second apart go unanswered: `ArpCache::tick`, `ControlPlane::host_unreachable`. `test_arp_cache`, `test_forward` `ANeighbourThatNeverAnswersEarnsHostUnreachable`, ARP exit test |
| Protocol Unreachable (code 2) for a transport protocol the destination lacks | 5.2.7.1 | (definition) | implemented | For any packet to one of the router's addresses but ICMP: it runs no transport protocol. `test_forward` |
| Port Unreachable (code 3) | 5.2.7.1 | (definition) | n-a | Without a transport layer, code 2 is the true answer. |
| Fragmentation Needed (code 4) | 5.2.7.1 | MUST, when sent | deferred | No MTU check: see fragmentation, below. |
| Communication Administratively Prohibited (code 13) for filtered packets | 5.2.7.1 | SHOULD | deferred | A packet the filter denies is dropped silently, which §5.3.9 requires a router to be able to do (see packet filtering, below). §5.2.7.1 itself allows a configuration option that stops code 13 being sent; `npf` behaves as if that option were always on. |

## ICMP in general

| Requirement | § | Level | Status | Where, or why not |
|---|---|---|---|---|
| Silently discard an ICMP message of a type it does not know | 4.3.2.1 | MUST | implemented | `ControlPlane::deliver_to_host`; `test_forward` `OtherIcmpForTheRouterIsConsumedSilently` |
| Set the TTL of an ICMP message it originates, never copying the trigger's | 4.3.2.2 | MUST | implemented | `kIcmpTtl` (64), `icmp_gen.cpp`; `test_icmp_gen` |
| Quote the original header and data exactly as received | 4.3.2.3 | MUST | implemented | `build_icmp_error`; nothing is rewritten before a drop; `test_icmp_gen`, `test_forward` |
| Quote as much of the original as fits in 576 bytes | 4.3.2.3 | SHOULD | deferred | The header and the first 8 bytes of data, as RFC 792 asks and `docs/ARCHITECTURE.md` §8b specifies. |
| Source address: one of the addresses of the interface the message is sent from | 4.3.2.4 | MUST | implemented | An error goes back out of the port its trigger came in on, from that port's address, which is also the hop traceroute must show. `test_forward` |
| Errors: the trigger's TOS bits, precedence 6 | 4.3.2.5 | SHOULD | implemented | `build_icmp_error`; `test_icmp_gen` |
| Replies: the request's TOS and precedence | 4.3.2.5 | SHOULD, MUST | implemented | `build_echo_reply`; `test_icmp_gen` |
| No error for an ICMP error message | 4.3.2.7 | MUST NOT | implemented | `may_send_icmp_error`: types 3, 4, 5, 11 and 12; `test_icmp_gen`, `test_forward` |
| No error for a packet that fails header validation | 4.3.2.7 | MUST NOT | implemented | Such a packet is dropped at step 5 or 6, and those drops never earn one. `test_forward` `OtherDropsEarnNoError` |
| No error for a packet to an IP broadcast or multicast address | 4.3.2.7 | MUST NOT | implemented | `may_send_icmp_error` covers the limited broadcast and multicast. A directed broadcast to an attached subnet waits for an ARP answer no host gives, and `ControlPlane::host_unreachable` sends no error when the cache gives up on it (`is_directed_broadcast`). `test_forward` `NoHostUnreachableForTheBroadcastAddressOfAnAttachedSubnet` |
| No error for a packet received as a link-layer broadcast or multicast | 4.3.2.7 | MUST NOT | implemented | The L2/L3 rule (`docs/ARCHITECTURE.md` §2) routes such a frame only when it is for the router itself, which never earns an error. |
| No error for a source that is not one host: network 0, 127/8, multicast, class E, all ones | 4.3.2.7 | MUST NOT | implemented | `may_send_icmp_error`; step 7 drops such sources before any error could be considered. |
| No error for a fragment other than the first | 4.3.2.7 | MUST NOT | implemented | `may_send_icmp_error`; `test_icmp_gen`, `test_forward` |
| Limit the rate of ICMP errors | 4.3.2.8 | SHOULD | implemented | `IcmpRateLimiter`: at most 100 errors in any one second, in bursts of up to 100. Echo replies are not limited. `test_icmp_gen`, `test_forward` |
| Make the rate limit configurable | 4.3.2.8 | SHOULD | deferred | Fixed at 100 a second. |
| Send Host Redirects | 4.3.3.2, 5.2.7.2 | MUST | deferred | A packet routed back out of the port it came in on is forwarded, not redirected. Redirects need per-subnet checks, and many networks turn them off as a security risk. |

## Echo

| Requirement | § | Level | Status | Where, or why not |
|---|---|---|---|---|
| Answer echo requests sent to the router | 4.3.3.6 | MUST | implemented | `ControlPlane::deliver_to_host`, `build_echo_reply`; traceroute exit test (`ping 10.0.1.1`) |
| Reply from the address the request was sent to | 4.3.3.6 | MUST | implemented | `test_forward` `PingToAnotherPortsAddressIsAnsweredFromThatAddress` |
| Include all of the request's data in the reply | 4.3.3.6 | MUST | implemented | `test_icmp_gen` |
| Reassemble and answer requests up to the larger of 576 bytes and the MTU | 4.3.3.6 | MUST | deferred | No reassembly: a request that arrives fragmented goes unanswered. See reassembly, below. |
| Update Record Route and Timestamp options in the reply; reverse a Source Route | 4.3.3.6 | SHOULD, MUST | deferred | No option processing. A reply carries no options. |
| A switch to ignore all echo requests | 4.3.3.6 | SHOULD | deferred | Not configurable. |
| Echo requests to a broadcast or multicast address may go unanswered | 4.3.3.6 | MAY | implemented | They are not answered. |

## Forwarding

| Requirement | § | Level | Status | Where, or why not |
|---|---|---|---|---|
| Deliver to the router a packet addressed to one of its addresses | 5.2.3 | MUST | implemented | Step 8, any port's address, arriving on any port; `test_forward` |
| Deliver to the router a packet to the limited broadcast, 255.255.255.255 | 5.2.3, 5.3.5.1 | MUST | implemented | Steps 4 and 8, `is_local_destination`. Nothing on the router listens for one, so it is consumed there. `test_forward` `TheLimitedBroadcastIsDeliveredLocallyAndNeverForwarded` |
| Never forward the limited broadcast | 5.3.5.1 | MUST NOT | implemented | As above, even when a default route covers it. |
| Never forward a packet received as a link-layer broadcast or multicast, unless it is to an IP multicast address | 5.3.4 | MUST NOT | implemented | The L2/L3 rule routes such a frame only when it is for the router itself, and never forwards one, IP multicast included. `test_forward` |
| Forward directed broadcasts by default, with a switch to stop | 5.3.5.2 | MUST | deferred | RFC 2644 (BCP 34) later reversed the default to not forwarding them. Here a directed broadcast to an attached subnet ends as `ArpUnresolved`, since no host answers ARP for a broadcast address, and earns no error. Delivering one locally on its own subnet (§5.2.3) is not done either. |
| Do not forward a packet from a martian source: network 0, 127/8, multicast, class E, the limited broadcast | 5.3.7 | SHOULD NOT | implemented | Step 7, `is_martian_source` (`MartianSource`); `test_ipv4`, `test_forward` |
| Do not forward a packet to a martian destination: network 0, 127/8, class E | 5.3.7 | SHOULD NOT | deferred | A packet to 127/8, say, is routed if a route covers it, as the default route in `configs/router.conf` does. The same goes for an IP multicast destination reached through the router's own MAC. Dropping them needs a drop reason that `docs/ARCHITECTURE.md` §1 does not have. |
| Never reassemble a datagram before forwarding it | 5.2.6 | MUST NOT | implemented | Every fragment is forwarded as it is. `test_forward` `FragmentsAreForwardedAsTheyAre` |
| Fragment a datagram too large for the next link | 4.2.2.7, 5.2.6 | MUST | deferred | No MTU check: every port of the test topology has the same MTU, so nothing arrives too large to send. The build plan defers path MTU work beyond this phase. |
| Reassemble datagrams addressed to the router | 4.2.2.8 | MUST | deferred | The router only answers pings, and a ping too large for one frame is rare. Reassembly needs buffers held across packets, with timers and limits: a design of its own. |

## Packet filtering

| Requirement | § | Level | Status | Where, or why not |
|---|---|---|---|---|
| Be able to filter what is forwarded, or to forward everything | 5.3.9 | SHOULD | implemented | `Filter`, step 10 (`FilterDeny`), with the rules of the filter file a configuration names; without one, everything is forwarded. `test_filter`, `test_forward`, golden case `filter_deny` |
| Filter on source and destination prefixes, of any length | 5.3.9 | SHOULD | implemented | A rule's source and destination are each any prefix from /0 to /32; `test_filter` `RuleMatrix` |
| Accept a value matching any address: the keyword any, or a prefix of length zero | 5.3.9 | MUST | implemented | Both, `any` and `0.0.0.0/0`; `test_config`, `test_filter` |
| Be configurable as an include list or as an exclude list | 5.3.9 | SHOULD | implemented | `policy deny` with `allow` rules is an include list, and `policy allow` with `deny` rules an exclude list; a file may mix the two, the first matching rule deciding. |
| Filter on protocol and ports as well | 5.3.9 | MAY | implemented | Any IP protocol number, and TCP and UDP ports, one or a range. A non-initial fragment carries no ports, so no rule with ports matches one: the README's "Known limitations" says what that allows. |
| Be able to discard packets silently | 5.3.9 | MUST | implemented | A denied packet is dropped and counted, and nothing is sent. |
| Be able to send Destination Unreachable, code 13, for a discarded packet, configurably per rule | 5.3.9 | SHOULD | deferred | No ICMP is sent for a filtered packet, as for code 13 above. |
| Count the packets not forwarded | 5.3.9 | SHOULD | implemented | The `FilterDeny` counter: one total, not one per rule. |
| Selective logging of the packets not forwarded | 5.3.9 | SHOULD | deferred | No packet is logged, for the reason given under header validation: any sender could flood the log. |
