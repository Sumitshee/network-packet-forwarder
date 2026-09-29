// libFuzzer harness for ArpView. The input is an Ethernet payload. Clang only; see
// tests/fuzz/CMakeLists.txt.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <npf/core/byte_span.hpp>
#include <npf/proto/arp.hpp>
#include <npf/proto/ethernet.hpp>
#include <npf/proto/mac.hpp>
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
  const std::span<const std::byte> buf = std::as_bytes(std::span{data, size});
  const auto arp = npf::proto::ArpView::parse(buf);
  if (!arp) {
    return 0;
  }
  // parse() accepted it, so everything it claims to validate must hold ...
  require(size >= npf::proto::ArpView::kMinSize);
  require(npf::core::rd_be16(buf, 0) == npf::proto::ArpView::kHtypeEthernet);
  require(npf::core::rd_be16(buf, 2) == npf::proto::kEtherTypeIpv4);
  require(npf::core::rd_u8(buf, 4) == 6 && npf::core::rd_u8(buf, 5) == 4);
  // ... and every accessor must read the right bytes, which ASan watches.
  require(arp->oper() == npf::core::rd_be16(buf, 6));
  require(arp->sha() == npf::proto::rd_mac(buf, 8));
  require(arp->spa() == npf::core::rd_be32(buf, 14));
  require(arp->tha() == npf::proto::rd_mac(buf, 18));
  require(arp->tpa() == npf::core::rd_be32(buf, 24));
  return 0;
}
