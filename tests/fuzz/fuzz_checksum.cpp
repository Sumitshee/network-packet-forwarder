// [phase 18] libFuzzer harness for the sums of checksum_simd.hpp: on any input, every one this
// machine runs must give checksum_reference()'s answer, from any start offset. Clang only; see
// tests/fuzz/CMakeLists.txt.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <npf/core/byte_span.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/checksum_simd.hpp>
#include <span>

namespace {

void require(bool ok) {
  if (!ok) {
    std::abort();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::byte> all = std::as_bytes(std::span{data, size});
  if (all.empty() || all.size() > npf::proto::kMaxSummedBytes) {
    return 0;
  }
  // The first byte picks a start offset, so the vector loads meet every alignment.
  const std::size_t off = std::to_integer<std::size_t>(all[0]) % all.size();
  const npf::core::CBytes buf = all.subspan(off);
  const std::uint16_t want = npf::proto::checksum_reference(buf);
  require(npf::proto::ones_complement_sum_scalar(buf) == want);
  require(npf::proto::ones_complement_sum_fast(buf) == want);
#if defined(__x86_64__)
  if (__builtin_cpu_supports("avx2") != 0) {
    require(npf::proto::ones_complement_sum_avx2(buf) == want);
  }
#endif
#if defined(__aarch64__)
  require(npf::proto::ones_complement_sum_neon(buf) == want);
#endif
  return 0;
}
