// The scalar sum, and the choice between it and the vector ones (ARCHITECTURE.md §4).

#include <cstdint>
#include <npf/core/byte_span.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/checksum_simd.hpp>

namespace npf::proto {
namespace {

using SumFn = std::uint16_t (*)(core::CBytes) noexcept;

struct Choice {
  SumFn fn;
  const char* name;
};

Choice choose() noexcept {
#if defined(__x86_64__)
  __builtin_cpu_init();  // the CPU model is read in a constructor that may not have run yet
  const bool avx2 = __builtin_cpu_supports("avx2");  // an int from GCC, a bool from Clang
  if (avx2) {
    return {&ones_complement_sum_avx2, "avx2"};
  }
  return {&ones_complement_sum_scalar, "scalar"};
#elif defined(__aarch64__)
  return {&ones_complement_sum_neon, "neon"};  // NEON is part of ARMv8: nothing to ask
#else
  return {&ones_complement_sum_scalar, "scalar"};
#endif
}

// Chosen once, on first use, and never changed: a constant, not global state.
const Choice& chosen() noexcept {
  static const Choice c = choose();
  return c;
}

}  // namespace

std::uint16_t ones_complement_sum_scalar(core::CBytes data) noexcept {
  return ones_complement_sum(data);
}

std::uint16_t ones_complement_sum_fast(core::CBytes data) noexcept {
  return chosen().fn(data);
}

const char* checksum_implementation() noexcept {
  return chosen().name;
}

}  // namespace npf::proto
