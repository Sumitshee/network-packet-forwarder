#pragma once

#include <cstdint>

namespace npf::pipe {

// A 32-bit avalanche finaliser: every input bit affects every output bit, each flipping it with
// probability close to one half. The shape -- xorshift, multiply by an odd constant, twice, and a
// last xorshift -- is the one MurmurHash3's fmix32 made familiar; these shifts and multipliers are
// the "lowbias32" set Chris Wellons found by search ("Prospecting for Hash Functions", 2018). A
// multiply carries a bit only upwards and a right shift brings high bits down, so alternating the
// two is what lets the low bits -- the ones `& (workers - 1)` keeps -- depend on all 32.
[[nodiscard]] constexpr std::uint32_t mix32(std::uint32_t x) noexcept {
  x ^= x >> 16U;
  x *= 0x7FEB352DU;
  x ^= x >> 15U;
  x *= 0x846CA68BU;
  x ^= x >> 16U;
  return x;
}

// A flow's hash, the same for both of its directions, so the pipeline's RX threads send a
// connection's packets and its replies to one worker. XOR is what makes it symmetric: swapping
// source and destination swaps the operands of each ^, and a ^ b == b ^ a. A naive hash of
// (sip, dip, sp, dp) in that order is not: it mixes each field at its own position, so
// hash(A, B, a, b) and hash(B, A, b, a) are as unrelated as any two different flows.
//
// The price of the symmetry is collisions a positional hash would not have: every flow whose
// addresses XOR to the same value and whose ports XOR to the same value lands together -- for
// example 10.0.0.1 <-> 10.0.0.2 and 10.0.0.5 <-> 10.0.0.6, and A:a -> B:b with B:a -> A:b, since
// the XORs cannot tell which port went with which address. That costs balance, never correctness.
//
// The addresses and ports are host order, as the views return them. Multiplying a by an odd
// constant before the final mix keeps it from cancelling against mix32(b).
// The plan's signature. Swapping the addresses, or the ports, is the point: it changes nothing.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
[[nodiscard]] constexpr std::uint32_t symmetric_hash_5tuple(std::uint32_t sip, std::uint32_t dip,
                                                            std::uint16_t sp, std::uint16_t dp,
                                                            std::uint8_t proto) noexcept {
  const std::uint32_t a = sip ^ dip;
  const std::uint32_t b = (std::uint32_t{sp} ^ std::uint32_t{dp}) | (std::uint32_t{proto} << 16U);
  return mix32((a * 0x9E3779B1U) ^ mix32(b));
}

}  // namespace npf::pipe
