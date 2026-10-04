// Classic pcap, by hand; pcap_file.hpp lays out the format.

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/backend.hpp>
#include <npf/io/pcap_file.hpp>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace npf::io {
namespace {

constexpr std::uint32_t kMagicSwapped = 0xD4C3B2A1;  // kPcapMagic, as a big-endian writer wrote it
constexpr std::uint32_t kMagicNano = 0xA1B23C4D;     // nanosecond timestamps, either byte order
constexpr std::uint32_t kMagicNanoSwapped = 0x4D3CB2A1;
constexpr std::uint32_t kPcapngMagic = 0x0A0D0D0A;  // a pcapng section header, either byte order
constexpr std::uint16_t kVersionMajor = 2;
constexpr std::uint16_t kVersionMinor = 4;
constexpr std::uint32_t kSnaplen = 65535;
constexpr std::uint64_t kMicrosPerSecond = 1'000'000;
constexpr std::size_t kBufferSize = std::size_t{64} * 1024;  // far more than any frame needs

PcapContents failure(std::string why) {
  return {.records = {}, .error = std::move(why)};
}

std::vector<std::byte> read_file(const std::filesystem::path& path) {
  // open(2) is variadic in C, for the mode only O_CREAT reads.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
  const core::UniqueFd fd{::open(path.c_str(), O_RDONLY | O_CLOEXEC)};
  if (!fd.valid()) {
    throw std::system_error(errno, std::generic_category(), "cannot open " + path.string());
  }
  std::vector<std::byte> bytes;
  std::vector<std::byte> chunk(kBufferSize);
  for (;;) {
    const ssize_t n = ::read(fd.get(), chunk.data(), chunk.size());
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n < 0) {
      throw std::system_error(errno, std::generic_category(), "cannot read " + path.string());
    }
    if (n == 0) {
      return bytes;
    }
    bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + n);
  }
}

std::vector<PcapRecord> records_of(const std::filesystem::path& path, core::CBytes file) {
  PcapContents contents = parse_pcap(file);
  if (!contents.error.empty()) {
    throw std::runtime_error(path.string() + ": " + contents.error);
  }
  return std::move(contents.records);
}

// The ports as the configuration describes them, indexed by port id.
std::vector<PortInfo> port_table(std::span<const core::InterfaceConfig> interfaces) {
  if (interfaces.empty()) {
    throw std::invalid_argument("there are no interfaces to replay through");
  }
  std::vector<PortInfo> ports(interfaces.size());
  std::vector<bool> seen(interfaces.size(), false);
  for (const core::InterfaceConfig& iface : interfaces) {
    if (iface.port >= ports.size() || seen[iface.port]) {
      throw std::invalid_argument(
          std::format("port ids must run from 0 to {}, each used once; interface {} has port {}",
                      ports.size() - 1, iface.name, iface.port));
    }
    if (!iface.mac) {
      throw std::invalid_argument(
          std::format("interface {} has no MAC address, and a replay has no interface to read "
                      "one from: give it in the configuration, as 'mac <address>'",
                      iface.name));
    }
    seen[iface.port] = true;
    PortInfo& p = ports[iface.port];
    p.id = iface.port;
    p.name = iface.name;
    p.mac = *iface.mac;
    p.ip = iface.ip;
    p.prefix_len = iface.prefix_len;
    p.mode = iface.mode;
    p.up = true;
  }
  return ports;
}

}  // namespace

PcapContents parse_pcap(core::CBytes file) {
  if (file.size() < kPcapFileHeaderSize) {
    return failure(std::format("{} bytes, too short for the {}-byte pcap file header", file.size(),
                               kPcapFileHeaderSize));
  }
  bool swapped = false;
  switch (const std::uint32_t magic = core::rd_le32(file, 0)) {
    case kPcapMagic:
      break;
    case kMagicSwapped:
      swapped = true;
      break;
    case kMagicNano:
    case kMagicNanoSwapped:
      return failure(
          "a nanosecond pcap: only microsecond timestamps are read, and these would be "
          "misread");
    case kPcapngMagic:
      return failure("a pcapng file: only the classic pcap format is read");
    default:
      return failure(std::format("not a pcap file: magic number 0x{:08x}", magic));
  }
  const auto u16 = [swapped](std::size_t off, core::CBytes b) {
    return swapped ? core::rd_be16(b, off) : core::rd_le16(b, off);
  };
  const auto u32 = [swapped](std::size_t off, core::CBytes b) {
    return swapped ? core::rd_be32(b, off) : core::rd_le32(b, off);
  };
  if (const std::uint16_t major = u16(4, file); major != kVersionMajor) {
    return failure(std::format("pcap version {}: only version {} is read", major, kVersionMajor));
  }
  if (const std::uint32_t link = u32(20, file); link != kLinktypeEthernet) {
    return failure(
        std::format("link type {}: only Ethernet, {}, is read", link, kLinktypeEthernet));
  }

  PcapContents out;
  for (std::size_t off = kPcapFileHeaderSize; off < file.size();) {
    const std::size_t n = out.records.size() + 1;
    if (file.size() - off < kPcapRecordHeaderSize) {
      return failure(std::format("record {} at byte {}: its header is cut short, {} of {} bytes", n,
                                 off, file.size() - off, kPcapRecordHeaderSize));
    }
    const std::uint32_t sec = u32(off, file);
    const std::uint32_t usec = u32(off + 4, file);
    const std::uint32_t incl_len = u32(off + 8, file);
    if (usec >= kMicrosPerSecond) {
      return failure(
          std::format("record {} at byte {}: {} microseconds is not under a second", n, off, usec));
    }
    if (file.size() - off - kPcapRecordHeaderSize < incl_len) {
      return failure(std::format("record {} at byte {}: {} bytes of frame, but only {} left", n,
                                 off, incl_len, file.size() - off - kPcapRecordHeaderSize));
    }
    out.records.push_back({.ts_us = sec * kMicrosPerSecond + usec,
                           .frame = file.subspan(off + kPcapRecordHeaderSize, incl_len)});
    off += kPcapRecordHeaderSize + incl_len;
  }
  return out;
}

PcapWriter::PcapWriter(const std::filesystem::path& path) : buffer_(kBufferSize) {
  // open(2) is variadic in C, for this mode argument.
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
  fd_.reset(::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
  if (!fd_.valid()) {
    throw std::system_error(errno, std::generic_category(), "cannot create " + path.string());
  }
  const core::Bytes header = std::span(buffer_).first(kPcapFileHeaderSize);
  core::wr_le32(header, 0, kPcapMagic);
  core::wr_le16(header, 4, kVersionMajor);
  core::wr_le16(header, 6, kVersionMinor);
  core::wr_le32(header, 8, 0);   // thiszone: the timestamps are UTC
  core::wr_le32(header, 12, 0);  // sigfigs
  core::wr_le32(header, 16, kSnaplen);
  core::wr_le32(header, 20, kLinktypeEthernet);
  used_ = kPcapFileHeaderSize;
}

PcapWriter::~PcapWriter() {
  flush();
}

void PcapWriter::write(std::uint64_t ts_us, core::CBytes frame) noexcept {
  const std::size_t need = kPcapRecordHeaderSize + frame.size();
  if (buffer_.size() - used_ < need) {
    flush();
  }
  if (!ok_ || buffer_.size() - used_ < need) {
    ok_ = false;  // a failed write before, or a frame larger than the buffer, which none is
    return;
  }
  const core::Bytes record = std::span(buffer_).subspan(used_, need);
  const auto length = static_cast<std::uint32_t>(frame.size());
  core::wr_le32(record, 0, static_cast<std::uint32_t>(ts_us / kMicrosPerSecond));
  core::wr_le32(record, 4, static_cast<std::uint32_t>(ts_us % kMicrosPerSecond));
  core::wr_le32(record, 8, length);
  core::wr_le32(record, 12, length);  // orig_len: the whole frame is written
  std::ranges::copy(frame, record.subspan(kPcapRecordHeaderSize).begin());
  used_ += need;
}

void PcapWriter::flush() noexcept {
  for (std::size_t done = 0; ok_ && done < used_;) {
    const ssize_t n = ::write(fd_.get(), buffer_.data() + done, used_ - done);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      ok_ = false;
      break;
    }
    done += static_cast<std::size_t>(n);
  }
  used_ = 0;
}

PcapFileBackend::PcapFileBackend(const PcapPaths& files,
                                 std::span<const core::InterfaceConfig> interfaces,
                                 core::PacketPool& pool)
    : pool_{&pool},
      ports_{port_table(interfaces)},
      input_{read_file(files.in)},
      records_{records_of(files.in, input_)},
      writer_{files.out} {}

std::size_t PcapFileBackend::rx_burst(core::Packet** out, std::size_t max) noexcept {
  std::size_t got = 0;
  while (got < max && next_ < records_.size()) {
    core::Packet* p = pool_->acquire();
    if (p == nullptr) {
      break;  // the pool is empty: the record waits, as a frame would wait in a socket
    }
    const PcapRecord& r = records_[next_++];
    clock_us_ = r.ts_us;
    if (r.frame.size() > p->capacity()) {
      ++rx_oversized_;
      pool_->release(p);
      continue;
    }
    p->resize(r.frame.size());
    std::ranges::copy(r.frame, p->data().begin());
    p->set_in_port(0);
    p->set_rx_tsc(r.ts_us);
    out[got++] = p;
  }
  return got;
}

// The parameters are ARCHITECTURE.md §9's, so their order is not this file's to change.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
std::size_t PcapFileBackend::tx_burst(core::Packet* const* in, std::size_t n,
                                      std::uint16_t port) noexcept {
  if (port >= ports_.size()) {
    return 0;
  }
  for (core::Packet* p : std::span(in, n)) {
    // A frame the router made itself has no receive time: it takes that of the record that
    // caused it, the last one read.
    const std::uint64_t ts_us = p->rx_tsc() != 0 ? p->rx_tsc() : clock_us_;
    writer_.write(ts_us, std::as_const(*p).data());
    pool_->release(p);
  }
  written_ += n;
  return n;
}

}  // namespace npf::io
