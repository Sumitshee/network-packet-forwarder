// [phase 18] Every sum in checksum_simd.hpp held to checksum_reference(), the oracle: every length
// from 0 to 2048 bytes, from every one of 32 start offsets (the vector loads are unaligned), plus
// the longest buffer allowed, random and all-ones.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <npf/core/byte_span.hpp>
#include <npf/proto/checksum.hpp>
#include <npf/proto/checksum_simd.hpp>
#include <random>
#include <span>
#include <string>
#include <vector>

namespace {

using npf::core::CBytes;
using npf::proto::checksum_reference;
using npf::proto::kMaxSummedBytes;

using SumFn = std::uint16_t (*)(CBytes) noexcept;

struct Impl {
  const char* name;
  SumFn fn;
};

// Every implementation this machine can run: scalar and the dispatched one always, the vector one
// of its architecture when the CPU has it.
std::vector<Impl> implementations() {
  std::vector<Impl> out{{"scalar", &npf::proto::ones_complement_sum_scalar},
                        {"fast", &npf::proto::ones_complement_sum_fast}};
#if defined(__x86_64__)
  if (__builtin_cpu_supports("avx2") != 0) {
    out.push_back({"avx2", &npf::proto::ones_complement_sum_avx2});
  }
#endif
#if defined(__aarch64__)
  out.push_back({"neon", &npf::proto::ones_complement_sum_neon});
#endif
  return out;
}

std::vector<std::byte> random_bytes(std::size_t n, std::uint32_t seed) {
  std::mt19937 rng(seed);
  std::uniform_int_distribution<int> byte(0, 255);
  std::vector<std::byte> out(n);
  std::ranges::generate(out, [&] { return static_cast<std::byte>(byte(rng)); });
  return out;
}

TEST(ChecksumSimd, EveryLengthAndOffsetAgreesWithTheReference) {
  constexpr std::size_t kMaxLen = 2048;
  constexpr std::size_t kOffsets = 32;
  const std::vector<std::byte> buf = random_bytes(kMaxLen + kOffsets, 18);
  for (const Impl& impl : implementations()) {
    std::size_t wrong = 0;
    for (std::size_t off = 0; off < kOffsets; ++off) {
      for (std::size_t len = 0; len <= kMaxLen; ++len) {
        const CBytes data = CBytes(buf).subspan(off, len);
        if (impl.fn(data) != checksum_reference(data)) {
          ADD_FAILURE() << impl.name << ": offset " << off << ", length " << len;
          if (++wrong == 10) {
            return;
          }
        }
      }
    }
  }
}

TEST(ChecksumSimd, TheLongestBufferAgreesWithTheReference) {
  const std::vector<std::byte> random = random_bytes(kMaxSummedBytes, 1071);
  const std::vector<std::byte> ones(kMaxSummedBytes, std::byte{0xFF});
  for (const Impl& impl : implementations()) {
    EXPECT_EQ(impl.fn(random), checksum_reference(random)) << impl.name;
    EXPECT_EQ(impl.fn(ones), checksum_reference(ones))
        << impl.name << ": every lane at its fullest";
    EXPECT_EQ(impl.fn(CBytes(ones).first(kMaxSummedBytes - 1)),
              checksum_reference(CBytes(ones).first(kMaxSummedBytes - 1)))
        << impl.name << ": odd length";
  }
}

// RFC 1071's own example, section 3: the sum of 00 01 f2 03 f4 f5 f6 f7 is ddf2.
TEST(ChecksumSimd, TheRfcExample) {
  const std::array<std::byte, 8> data{std::byte{0x00}, std::byte{0x01}, std::byte{0xf2},
                                      std::byte{0x03}, std::byte{0xf4}, std::byte{0xf5},
                                      std::byte{0xf6}, std::byte{0xf7}};
  for (const Impl& impl : implementations()) {
    EXPECT_EQ(impl.fn(data), 0xddf2) << impl.name;
  }
}

TEST(ChecksumSimd, TheDispatchedSumNamesItsChoice) {
  const std::string chosen = npf::proto::checksum_implementation();
#if defined(__x86_64__)
  EXPECT_EQ(chosen, __builtin_cpu_supports("avx2") != 0 ? "avx2" : "scalar");
#elif defined(__aarch64__)
  EXPECT_EQ(chosen, "neon");
#else
  EXPECT_EQ(chosen, "scalar");
#endif
}

}  // namespace
