// libFuzzer harness for EthView. Clang only; see tests/fuzz/CMakeLists.txt.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <npf/core/byte_span.hpp>
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
  const auto eth = npf::proto::EthView::parse(buf);
  if (!eth) {
    require(size < npf::proto::EthView::kTaggedSize);
    return 0;
  }
  // Every accessor, checked against the raw bytes: ASan reports any read that the factory did
  // not validate, and require() any value the view misreports.
  const std::size_t hdr = eth->header_len();
  require(hdr == npf::proto::EthView::kMinSize || hdr == npf::proto::EthView::kTaggedSize);
  require(size >= hdr);
  require(eth->has_vlan() == (hdr == npf::proto::EthView::kTaggedSize));
  require(eth->dst() == npf::proto::rd_mac(buf, 0));
  require(eth->src() == npf::proto::rd_mac(buf, 6));
  require(eth->ethertype() == npf::core::rd_be16(buf, hdr - 2));
  require(eth->vlan_id() <= 0x0FFF);
  require(eth->has_vlan() || eth->vlan_id() == 0);
  require(eth->payload().data() == buf.data() + hdr);
  require(eth->payload().size() == size - hdr);
  return 0;
}
