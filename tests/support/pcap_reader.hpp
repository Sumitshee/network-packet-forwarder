#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace npf::test {

// Minimal classic-pcap reader for tests: microsecond timestamps, LINKTYPE_ETHERNET, either byte
// order. Nanosecond pcaps and pcapng are rejected, never misread. Throws std::runtime_error naming
// the file on anything malformed. Test-only; the datapath's pcap backend is phase 9's.
inline std::vector<std::vector<std::byte>> read_pcap(const std::filesystem::path& path) {
  const auto fail = [&path](const std::string& why) {
    return std::runtime_error(path.string() + ": " + why);
  };
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw fail("cannot open");
  }
  const std::vector<char> raw{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
  const auto octet = [&raw](std::size_t i) {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(raw[i]));
  };
  const auto le32 = [&octet](std::size_t o) {
    return octet(o) | octet(o + 1) << 8U | octet(o + 2) << 16U | octet(o + 3) << 24U;
  };
  const auto be32 = [&octet](std::size_t o) {
    return octet(o) << 24U | octet(o + 1) << 16U | octet(o + 2) << 8U | octet(o + 3);
  };

  if (raw.size() < 24) {
    throw fail("shorter than a pcap global header");
  }
  bool big_endian = false;
  switch (le32(0)) {
    case 0xA1B2C3D4:
      break;
    case 0xD4C3B2A1:
      big_endian = true;
      break;
    case 0xA1B23C4D:
    case 0x4D3CB2A1:
      throw fail("nanosecond-resolution pcap is not supported");
    default:
      throw fail("not a classic pcap file (pcapng?)");
  }
  const auto u32 = [&](std::size_t o) { return big_endian ? be32(o) : le32(o); };
  if (u32(20) != 1) {
    throw fail("link type is not Ethernet");
  }

  std::vector<std::vector<std::byte>> frames;
  for (std::size_t off = 24; off < raw.size();) {
    if (raw.size() - off < 16) {
      throw fail("truncated record header");
    }
    const std::size_t incl_len = u32(off + 8);
    off += 16;
    if (raw.size() - off < incl_len) {
      throw fail("truncated record");
    }
    std::vector<std::byte> frame(incl_len);
    for (std::size_t i = 0; i < incl_len; ++i) {
      frame[i] = static_cast<std::byte>(raw[off + i]);
    }
    frames.push_back(std::move(frame));
    off += incl_len;
  }
  return frames;
}

}  // namespace npf::test
