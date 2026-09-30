// libFuzzer harness for Ipv4View and the checksums. The input is an Ethernet payload. Clang only;
// see tests/fuzz/CMakeLists.txt.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <npf/core/byte_span.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/ipv4.hpp>
#include <span>

namespace {

// A broken invariant must look like a crash to libFuzzer, in every build type.
void require(bool ok) {
  if (!ok) {
    std::abort();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using npf::core::rd_be16;
  using npf::core::rd_be32;
  using npf::core::rd_u8;
  const std::span<const std::byte> buf = std::as_bytes(std::span{data, size});

  // Whatever the bytes are, any length, odd ones included, the two sums agree.
  require(npf::proto::ones_complement_sum(buf) == npf::proto::checksum_reference(buf));

  const auto ip = npf::proto::Ipv4View::parse(buf);
  if (!ip) {
    return 0;
  }
  const std::size_t hdr = ip->header_len();
  require(hdr == std::size_t{ip->ihl()} * 4 && hdr >= 20 && hdr <= 60);
  require(ip->total_length() >= hdr && ip->total_length() <= size);
  require(ip->header().data() == buf.data() && ip->header().size() == hdr);
  require(ip->payload().data() == buf.data() + hdr);
  require(ip->payload().size() == ip->total_length() - hdr);
  require(ip->is_first_fragment() == (ip->frag_offset() == 0));
  require(ip->is_fragment() == (ip->mf() || ip->frag_offset() != 0));
  require(ip->ttl() == rd_u8(buf, 8) && ip->protocol() == rd_u8(buf, 9));
  require(ip->checksum() == rd_be16(buf, 10));
  require(ip->src() == rd_be32(buf, 12) && ip->dst() == rd_be32(buf, 16));

  // RFC 1624 on this very header: give it a correct checksum, decrement the TTL (0 wrapping to 255
  // is fine: any change to the word must be handled), and the incremental update has to equal a
  // full recompute.
  std::array<std::byte, 60> copy{};
  std::copy(ip->header().begin(), ip->header().end(), copy.begin());
  const std::span<std::byte> h = std::span{copy}.first(hdr);
  npf::core::wr_be16(h, 10, npf::proto::ipv4_header_checksum(h));
  require(npf::proto::ipv4_checksum_valid(h));
  const std::uint16_t old_word = rd_be16(h, 8);
  npf::core::wr_u8(h, 8, static_cast<std::uint8_t>(rd_u8(h, 8) - 1));
  const std::uint16_t new_word = rd_be16(h, 8);
  require(npf::proto::checksum_update16(rd_be16(h, 10), old_word, new_word) ==
          npf::proto::ipv4_header_checksum(h));
  return 0;
}
