#pragma once

#include <cstdint>
#include <format>
#include <npf/proto/mac.hpp>
#include <string>

namespace npf::proto {

// Addresses as people write them, for configuration, logs and `npf dump`. These allocate, so
// they never run on the datapath.

// Host order in, dotted quad out: 10.0.2.254.
[[nodiscard]] inline std::string format_ipv4(std::uint32_t a) {
  return std::format("{}.{}.{}.{}", a >> 24U, a >> 16U & 0xFFU, a >> 8U & 0xFFU, a & 0xFFU);
}

// Lower-case, colon-separated: aa:bb:cc:dd:ee:02.
[[nodiscard]] inline std::string format_mac(const MacAddr& m) {
  return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m.b[0], m.b[1], m.b[2], m.b[3],
                     m.b[4], m.b[5]);
}

}  // namespace npf::proto
