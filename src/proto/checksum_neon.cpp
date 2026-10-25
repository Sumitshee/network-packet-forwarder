// The one's complement sum with NEON, 32 bytes a step. Built only on aarch64, where NEON is part of
// the architecture.

#include <arm_neon.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <npf/core/byte_span.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/checksum_simd.hpp>

#include "checksum_lanes.hpp"

namespace npf::proto {

// vpadalq_u16 adds each pair of 16-bit words into a 32-bit lane: two accumulators of four lanes,
// each lane growing by at most 2 * 0xFFFF a step. At kMaxSummedBytes that is 4096 steps, well
// short of overflowing.
std::uint16_t ones_complement_sum_neon(core::CBytes data) noexcept {
  assert(data.size() <= kMaxSummedBytes);
  constexpr std::size_t kHalf = sizeof(uint16x8_t);
  constexpr std::size_t kStep = 2 * kHalf;
  uint32x4_t acc0 = vdupq_n_u32(0);
  uint32x4_t acc1 = vdupq_n_u32(0);
  std::size_t i = 0;
  for (; i + kStep <= data.size(); i += kStep) {
    uint16x8_t a;
    uint16x8_t b;
    std::memcpy(&a, data.subspan(i, kHalf).data(), kHalf);  // unaligned loads, no cast
    std::memcpy(&b, data.subspan(i + kHalf, kHalf).data(), kHalf);
    acc0 = vpadalq_u16(acc0, a);
    acc1 = vpadalq_u16(acc1, b);
  }
  const std::uint64_t vec = vaddlvq_u32(acc0) + vaddlvq_u32(acc1);
  return lanes::fold_and_swap(vec + lanes::tail_le(data, i));
}

}  // namespace npf::proto
