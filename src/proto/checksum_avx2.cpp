// The one's complement sum with AVX2, 32 bytes a step. The only file built with -mavx2: nothing
// else in npf may assume the CPU has it, and ones_complement_sum_fast() calls this only when
// __builtin_cpu_supports("avx2") says it does.

#include <immintrin.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <npf/core/byte_span.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/checksum_simd.hpp>

#include "checksum_lanes.hpp"

namespace npf::proto {

// Each 32-bit lane takes the low and the high word of its 4 bytes, so per step it grows by at most
// 2 * 0xFFFF. At kMaxSummedBytes that is 4096 steps, 536,862,720 at most: no lane can overflow.
std::uint16_t ones_complement_sum_avx2(core::CBytes data) noexcept {
  assert(data.size() <= kMaxSummedBytes);
  constexpr std::size_t kStep = sizeof(__m256i);
  const __m256i low_words = _mm256_set1_epi32(0xFFFF);
  __m256i acc = _mm256_setzero_si256();
  std::size_t i = 0;
  for (; i + kStep <= data.size(); i += kStep) {
    __m256i v;
    std::memcpy(&v, data.subspan(i, kStep).data(), kStep);  // an unaligned load, no cast
    acc = _mm256_add_epi32(acc, _mm256_and_si256(v, low_words));
    acc = _mm256_add_epi32(acc, _mm256_srli_epi32(v, 16));
  }
  std::array<std::uint32_t, kStep / sizeof(std::uint32_t)> lane{};
  std::memcpy(lane.data(), &acc, kStep);
  std::uint64_t sum = lanes::tail_le(data, i);
  for (const std::uint32_t l : lane) {
    sum += l;
  }
  return lanes::fold_and_swap(sum);
}

}  // namespace npf::proto
