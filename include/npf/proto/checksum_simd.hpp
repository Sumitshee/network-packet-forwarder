#pragma once

#include <cstdint>
#include <npf/core/byte_span.hpp>

namespace npf::proto {

// [phase 18] The one's complement sum of checksum.hpp, for buffers longer than a header, in more
// than one way (ARCHITECTURE.md §4). Each returns exactly what ones_complement_sum() returns, for
// any data up to kMaxSummedBytes; the tests hold every one of them to checksum_reference().
//
// The vector versions sum the data as little-endian 16-bit words, the order the CPU loads them in,
// and swap the bytes of the folded result: the one's complement sum of byte-swapped words is the
// byte-swapped sum (RFC 1071, section 2(B)), so no word needs swapping on the way in. A trailing
// odd byte is the low byte of a little-endian word, which after the swap is the high byte of a
// big-endian one, as RFC 1071 pads it.

[[nodiscard]] std::uint16_t ones_complement_sum_scalar(core::CBytes data) noexcept;

#if defined(__x86_64__)
// Callers make sure the CPU has AVX2 first: ones_complement_sum_fast() does.
[[nodiscard]] std::uint16_t ones_complement_sum_avx2(core::CBytes data) noexcept;
#endif

#if defined(__aarch64__)
[[nodiscard]] std::uint16_t ones_complement_sum_neon(core::CBytes data) noexcept;
#endif

// The best of the above that this CPU runs, chosen the first time it is called.
[[nodiscard]] std::uint16_t ones_complement_sum_fast(core::CBytes data) noexcept;

// Which one ones_complement_sum_fast() chose: "avx2", "neon" or "scalar". For logs and results.
[[nodiscard]] const char* checksum_implementation() noexcept;

}  // namespace npf::proto
