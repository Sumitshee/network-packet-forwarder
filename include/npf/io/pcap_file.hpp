#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/backend.hpp>
#include <span>
#include <string>
#include <vector>

namespace npf::io {

// The classic pcap format, read and written here by hand rather than through libpcap: a 24-byte
// file header, then for every frame a 16-byte record header and the frame itself.
//
//   file header    u32 magic 0xa1b2c3d4   u16 major 2   u16 minor 4   i32 thiszone   u32 sigfigs
//                  u32 snaplen   u32 network (1, LINKTYPE_ETHERNET)
//   record header  u32 ts_sec   u32 ts_usec   u32 incl_len   u32 orig_len; then incl_len bytes
//
// Written little-endian, with microsecond timestamps. Read in either byte order, which the magic
// gives away, but only with microsecond timestamps: a nanosecond pcap (magic 0xa1b23c4d) is
// refused, never misread.
inline constexpr std::size_t kPcapFileHeaderSize = 24;
inline constexpr std::size_t kPcapRecordHeaderSize = 16;
inline constexpr std::uint32_t kPcapMagic = 0xA1B2C3D4;
inline constexpr std::uint32_t kLinktypeEthernet = 1;

// One record, as parse_pcap() finds it.
struct PcapRecord {
  std::uint64_t ts_us{0};  // microseconds since the Unix epoch
  core::CBytes frame;      // the incl_len bytes captured, inside the file's own bytes
};

// A whole file's records, or why it is not a classic Ethernet pcap. error is empty on success. On
// failure it says what is wrong and where -- the record, counting from 1, and its byte offset --
// and records is empty.
struct PcapContents {
  std::vector<PcapRecord> records;
  std::string error;
};

// Checks every length against the file before reading what it covers. Start-up code: it builds
// the record list, which allocates.
[[nodiscard]] PcapContents parse_pcap(core::CBytes file);

// Writes a classic pcap, record by record. The constructor creates the file -- or throws
// std::system_error -- and writes its header. After that nothing allocates or throws: a write that
// fails is remembered, for ok(), since a backend's tx_burst() has no way to report it.
class PcapWriter {
 public:
  explicit PcapWriter(const std::filesystem::path& path);
  PcapWriter(const PcapWriter&) = delete;
  PcapWriter(PcapWriter&&) = delete;
  PcapWriter& operator=(const PcapWriter&) = delete;
  PcapWriter& operator=(PcapWriter&&) = delete;
  ~PcapWriter();  // flushes

  void write(std::uint64_t ts_us, core::CBytes frame) noexcept;
  void flush() noexcept;

  // False once any write has failed, and for good.
  [[nodiscard]] bool ok() const noexcept { return ok_; }

 private:
  core::UniqueFd fd_;
  std::vector<std::byte> buffer_;  // sized once; the first used_ bytes are not written out yet
  std::size_t used_{0};
  bool ok_{true};
};

// The two files of a replay, named at the call, {.in = ..., .out = ...}, so they cannot be swapped.
struct PcapPaths {
  std::filesystem::path in;
  std::filesystem::path out;
};

// ARCHITECTURE.md §9: one pcap in, another out, for the golden-file tests and as a traffic source.
// Deterministic, and needs no root.
//
// The input is read whole, and checked, by the constructor. rx_burst() then copies its records
// into packets in file order, every one arriving on port 0: a pcap does not say which port a frame
// came in on, and every golden case arrives from the client's side. tx_burst() appends each frame
// it is given to the output, in the order the router sends them, whatever their port: a forwarded
// frame's source MAC already says which port it left by.
//
// A frame keeps the timestamp of the record it arrived in, carried through the pipeline in
// Packet::rx_tsc -- which here holds microseconds since the epoch, not a TSC reading -- and one the
// router made itself, an ICMP error say, takes the timestamp of the last record read: the one that
// caused it. A record stamped exactly at the epoch cannot be told from the second kind.
class PcapFileBackend final : public IoBackend {
 public:
  // Start-up code. Throws std::invalid_argument unless the port ids run from 0 to N-1 and every
  // interface's MAC is in the configuration -- there is no interface to read one from;
  // std::runtime_error for an input that is not a classic Ethernet pcap; and std::system_error
  // when a file cannot be read or created. The output is created only once the input checks out.
  PcapFileBackend(const PcapPaths& files, std::span<const core::InterfaceConfig> interfaces,
                  core::PacketPool& pool);

  [[nodiscard]] std::size_t rx_burst(core::Packet** out, std::size_t max) noexcept override;
  [[nodiscard]] std::size_t tx_burst(core::Packet* const* in, std::size_t n,
                                     std::uint16_t port) noexcept override;
  void tx_flush() noexcept override { writer_.flush(); }
  [[nodiscard]] std::span<const PortInfo> ports() const noexcept override { return ports_; }
  [[nodiscard]] const char* name() const noexcept override { return "pcap"; }

  // Not part of IoBackend.
  [[nodiscard]] bool done() const noexcept { return next_ == records_.size(); }
  [[nodiscard]] std::size_t records_read() const noexcept { return next_; }
  [[nodiscard]] std::size_t records_written() const noexcept { return written_; }
  [[nodiscard]] bool ok() const noexcept { return writer_.ok(); }  // every write so far succeeded

  // Records skipped because their frame did not fit in a buffer, as AfPacketBackend counts them.
  [[nodiscard]] std::uint64_t rx_oversized() const noexcept { return rx_oversized_; }

 private:
  core::PacketPool* pool_;  // borrowed: owned by the caller, which outlives this backend
  std::vector<PortInfo> ports_;
  std::vector<std::byte> input_;     // the whole input file
  std::vector<PcapRecord> records_;  // its records, pointing into input_
  std::size_t next_{0};              // the next record to read
  std::uint64_t clock_us_{0};        // the timestamp of the last record read
  PcapWriter writer_;
  std::size_t written_{0};
  std::uint64_t rx_oversized_{0};
};

}  // namespace npf::io
