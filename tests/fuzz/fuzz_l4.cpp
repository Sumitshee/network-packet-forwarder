// libFuzzer harness for parse_l4 and IcmpView. The input is an Ethernet payload: an IPv4 packet,
// if it parses as one. Clang only; see tests/fuzz/CMakeLists.txt.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <npf/core/byte_span.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/icmp.hpp>
#include <npf/proto/ipv4.hpp>
#include <npf/proto/l4.hpp>
#include <span>

namespace {

// A broken invariant must look like a crash to libFuzzer, in every build type.
void require(bool ok) {
  if (!ok) {
    std::abort();
  }
}

// Every accessor, checked against the raw bytes; ASan watches each read.
void check_icmp(std::span<const std::byte> msg) {
  const auto icmp = npf::proto::IcmpView::parse(msg);
  if (!icmp) {
    return;
  }
  require(msg.size() >= npf::proto::IcmpView::kMinSize);
  require(npf::proto::ones_complement_sum(msg) == 0xFFFF);
  require(icmp->type() == npf::core::rd_u8(msg, 0) && icmp->code() == npf::core::rd_u8(msg, 1));
  require(icmp->checksum() == npf::core::rd_be16(msg, 2));
  require(icmp->echo_id() == npf::core::rd_be16(msg, 4));
  require(icmp->echo_seq() == npf::core::rd_be16(msg, 6));
  const std::uint8_t t = icmp->type();
  require(icmp->is_error() == (t == 3 || t == 4 || t == 5 || t == 11 || t == 12));
  require(icmp->payload().data() == msg.data() + 8 && icmp->payload().size() == msg.size() - 8);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using npf::core::rd_be16;
  using npf::core::rd_be32;
  using npf::core::rd_u8;
  const std::span<const std::byte> buf = std::as_bytes(std::span{data, size});

  check_icmp(buf);  // the raw input as an ICMP message, whatever it is

  const auto ip = npf::proto::Ipv4View::parse(buf);
  if (!ip) {
    return 0;
  }
  const auto l4 = npf::proto::parse_l4(*ip);
  if (!ip->is_first_fragment()) {
    // The hard rule: a non-initial fragment yields its protocol and nothing else, never malformed.
    require(l4.has_value());
    require(l4->protocol == ip->protocol() && !l4->ports_valid);
    require(l4->sport == 0 && l4->dport == 0 && l4->tcp_flags == 0 && l4->seq == 0 &&
            l4->ack == 0 && l4->icmp_type == 0 && l4->icmp_code == 0);
    return 0;
  }

  const std::span<const std::byte> payload = ip->payload();
  switch (ip->protocol()) {
    case npf::proto::kIpProtoTcp: {
      const bool well_formed = payload.size() >= 20 &&
                               (std::size_t{rd_u8(payload, 12)} >> 4U) >= 5 &&
                               (std::size_t{rd_u8(payload, 12)} >> 4U) * 4 <= payload.size();
      require(l4.has_value() == well_formed);
      if (l4) {
        require(l4->ports_valid && l4->sport == rd_be16(payload, 0) &&
                l4->dport == rd_be16(payload, 2));
        require(l4->seq == rd_be32(payload, 4) && l4->ack == rd_be32(payload, 8));
        require(l4->tcp_flags == rd_u8(payload, 13));
      }
      break;
    }
    case npf::proto::kIpProtoUdp: {
      const bool well_formed = payload.size() >= 8 && rd_be16(payload, 4) >= 8;
      require(l4.has_value() == well_formed);
      if (l4) {
        require(l4->ports_valid && l4->sport == rd_be16(payload, 0) &&
                l4->dport == rd_be16(payload, 2));
      }
      break;
    }
    case npf::proto::kIpProtoIcmp:
      require(l4.has_value() == (payload.size() >= 8));
      if (l4) {
        require(!l4->ports_valid && l4->icmp_type == rd_u8(payload, 0) &&
                l4->icmp_code == rd_u8(payload, 1));
      }
      check_icmp(payload);
      break;
    default:
      require(l4.has_value() && l4->protocol == ip->protocol() && !l4->ports_valid);
      break;
  }
  return 0;
}
