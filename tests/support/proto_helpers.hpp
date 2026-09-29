#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <npf/proto/mac.hpp>
#include <ostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "support/pcap_reader.hpp"

namespace npf::test {

// The frame in tests/fixtures/<name>.pcap, which scripts/make_fixtures.py writes with exactly one.
// NPF_FIXTURE_DIR is defined by tests/CMakeLists.txt.
inline std::vector<std::byte> fixture_frame(const std::string& name) {
  auto frames = read_pcap(std::filesystem::path{NPF_FIXTURE_DIR} / (name + ".pcap"));
  if (frames.size() != 1) {
    throw std::runtime_error(name + ".pcap: expected exactly one frame");
  }
  return std::move(frames.front());
}

constexpr std::uint32_t ip4(std::uint32_t a, std::uint32_t b, std::uint32_t c, std::uint32_t d) {
  return a << 24U | b << 16U | c << 8U | d;
}

}  // namespace npf::test

namespace npf::proto {

// Found by argument-dependent lookup, so GoogleTest prints aa:bb:cc:dd:ee:ff instead of raw bytes.
inline void PrintTo(const MacAddr& m, std::ostream* os) {
  std::array<char, 18> text{};
  std::snprintf(text.data(), text.size(), "%02x:%02x:%02x:%02x:%02x:%02x", unsigned{m.b[0]},
                unsigned{m.b[1]}, unsigned{m.b[2]}, unsigned{m.b[3]}, unsigned{m.b[4]},
                unsigned{m.b[5]});
  *os << text.data();
}

}  // namespace npf::proto
