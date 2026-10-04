#include <gtest/gtest.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <npf/core/byte_span.hpp>
#include <npf/core/config.hpp>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <npf/io/pcap_file.hpp>
#include <npf/proto/mac.hpp>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "support/pcap_reader.hpp"
#include "support/proto_helpers.hpp"

namespace {

using npf::core::Packet;
using npf::core::PacketPool;
using npf::io::parse_pcap;
using npf::io::PcapContents;
using npf::io::PcapFileBackend;
using npf::io::PcapWriter;
using npf::proto::MacAddr;
using npf::test::ip4;

using Bytes = std::vector<std::byte>;

constexpr std::size_t kFileHeader = npf::io::kPcapFileHeaderSize;
constexpr std::size_t kRecordHeader = npf::io::kPcapRecordHeaderSize;
constexpr MacAddr kMac0{{0x02, 0x00, 0x00, 0x00, 0x01, 0x01}};
constexpr MacAddr kMac1{{0x02, 0x00, 0x00, 0x00, 0x02, 0x01}};

struct Record {
  std::uint64_t ts_us;
  Bytes frame;
};

// size bytes counting up from first, so that frames differ and a misplaced byte shows.
Bytes frame_of(std::size_t size, std::uint8_t first) {
  Bytes f(size);
  for (std::size_t i = 0; i < size; ++i) {
    f[i] = static_cast<std::byte>(first + i);
  }
  return f;
}

const std::vector<Record> kTwo{{1'700'000'000'000'001, frame_of(60, 1)},
                               {1'700'000'000'500'000, frame_of(14, 90)}};

// Who wrote a file: a little- or big-endian machine, with what magic number and link type.
struct Writer {
  bool big_endian = false;
  std::uint32_t magic = npf::io::kPcapMagic;
  std::uint32_t link = npf::io::kLinktypeEthernet;
  std::uint32_t usec_offset = 0;  // added to every record's microseconds, to make them bad
};

// The file such a writer makes of these records, built here independently of PcapWriter.
Bytes pcap_file(const std::vector<Record>& records, const Writer& w = {}) {
  const auto put32 = [&w](Bytes& b, std::size_t off, std::uint32_t v) {
    if (w.big_endian) {
      npf::core::wr_be32(b, off, v);
    } else {
      npf::core::wr_le32(b, off, v);
    }
  };
  const auto put16 = [&w](Bytes& b, std::size_t off, std::uint16_t v) {
    if (w.big_endian) {
      npf::core::wr_be16(b, off, v);
    } else {
      npf::core::wr_le16(b, off, v);
    }
  };
  Bytes out(kFileHeader);
  put32(out, 0, w.magic);
  put16(out, 4, 2);
  put16(out, 6, 4);
  put32(out, 16, 65535);
  put32(out, 20, w.link);
  for (const Record& r : records) {
    Bytes header(kRecordHeader);
    put32(header, 0, static_cast<std::uint32_t>(r.ts_us / 1'000'000));
    put32(header, 4, static_cast<std::uint32_t>(r.ts_us % 1'000'000) + w.usec_offset);
    put32(header, 8, static_cast<std::uint32_t>(r.frame.size()));
    put32(header, 12, static_cast<std::uint32_t>(r.frame.size()));
    out.insert(out.end(), header.begin(), header.end());
    out.insert(out.end(), r.frame.begin(), r.frame.end());
  }
  return out;
}

void expect_records(const PcapContents& c, const std::vector<Record>& want) {
  ASSERT_TRUE(c.error.empty()) << c.error;
  ASSERT_EQ(c.records.size(), want.size());
  for (std::size_t i = 0; i < want.size(); ++i) {
    EXPECT_EQ(c.records[i].ts_us, want[i].ts_us) << "record " << i + 1;
    EXPECT_TRUE(std::ranges::equal(c.records[i].frame, want[i].frame)) << "record " << i + 1;
  }
}

// A directory of the test's own, gone again when the test ends.
class ScratchDir {
 public:
  ScratchDir()
      : path_{std::filesystem::temp_directory_path() /
              std::format("npf-pcap-{}-{}", ::getpid(),
                          ::testing::UnitTest::GetInstance()->current_test_info()->name())} {
    std::filesystem::create_directories(path_);
  }
  ScratchDir(const ScratchDir&) = delete;
  ScratchDir(ScratchDir&&) = delete;
  ScratchDir& operator=(const ScratchDir&) = delete;
  ScratchDir& operator=(ScratchDir&&) = delete;
  ~ScratchDir() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
  }
  [[nodiscard]] std::filesystem::path operator/(const std::string& name) const {
    return path_ / name;
  }

 private:
  std::filesystem::path path_;
};

void write_file(const std::filesystem::path& path, const Bytes& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
  if (!out) {
    throw std::runtime_error("cannot write " + path.string());
  }
}

Bytes read_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream text;
  text << in.rdbuf();
  const std::string s = text.str();
  Bytes bytes(s.size());
  std::ranges::transform(s, bytes.begin(), [](char c) { return static_cast<std::byte>(c); });
  return bytes;
}

// --- parse_pcap ----------------------------------------------------------------------------------

TEST(ParsePcap, FindsEveryRecordAndItsTimestamp) {
  const Bytes file = pcap_file(kTwo);
  const PcapContents c = parse_pcap(file);
  expect_records(c, kTwo);
  // The frames are views of the file, not copies.
  EXPECT_EQ(c.records.at(0).frame.data(), file.data() + kFileHeader + kRecordHeader);
}

TEST(ParsePcap, ReadsABigEndianWritersFileTheSame) {
  expect_records(parse_pcap(pcap_file(kTwo, {.big_endian = true})), kTwo);
}

TEST(ParsePcap, AFileOfNoRecordsIsOne) {
  expect_records(parse_pcap(pcap_file({})), {});
}

// CLAUDE.md §7's truncation sweep. Every prefix of a valid file either ends exactly between two
// records, and holds those before the cut, or is refused; and none is read past its end, which
// ASan would report: each prefix is a heap copy of exactly that length.
TEST(ParsePcap, EveryPrefixIsRefusedOrEndsBetweenRecords) {
  const Bytes file = pcap_file(kTwo);
  const std::size_t after_first = kFileHeader + kRecordHeader + kTwo[0].frame.size();
  for (std::size_t len = 0; len <= file.size(); ++len) {
    const Bytes cut(file.begin(), file.begin() + static_cast<std::ptrdiff_t>(len));
    const PcapContents c = parse_pcap(cut);
    if (len == kFileHeader) {
      expect_records(c, {});
    } else if (len == after_first) {
      expect_records(c, {kTwo[0]});
    } else if (len == file.size()) {
      expect_records(c, kTwo);
    } else {
      EXPECT_FALSE(c.error.empty()) << "a prefix of " << len << " bytes was accepted";
      EXPECT_TRUE(c.records.empty()) << len;
    }
  }
}

TEST(ParsePcap, SaysWhichRecordIsCutShortAndWhere) {
  Bytes file = pcap_file(kTwo);
  file.pop_back();
  const PcapContents c = parse_pcap(file);
  EXPECT_NE(c.error.find("record 2 at byte 100"), std::string::npos) << c.error;
}

TEST(ParsePcap, RefusesANanosecondPcapRatherThanMisreadIt) {
  for (const bool big_endian : {false, true}) {
    const PcapContents c =
        parse_pcap(pcap_file(kTwo, {.big_endian = big_endian, .magic = 0xA1B23C4D}));
    EXPECT_NE(c.error.find("nanosecond"), std::string::npos) << c.error;
    EXPECT_TRUE(c.records.empty());
  }
}

TEST(ParsePcap, RefusesAMicrosecondCountOfASecondOrMore) {
  const PcapContents c = parse_pcap(pcap_file(kTwo, {.usec_offset = 1'000'000}));
  EXPECT_NE(c.error.find("record 1"), std::string::npos) << c.error;
}

TEST(ParsePcap, RefusesPcapngAndWhateverElseIsNotPcap) {
  Bytes pcapng(28);
  npf::core::wr_le32(pcapng, 0, 0x0A0D0D0A);  // a section header block
  EXPECT_NE(parse_pcap(pcapng).error.find("pcapng"), std::string::npos);
  const Bytes text(40, std::byte{'#'});
  EXPECT_NE(parse_pcap(text).error.find("not a pcap"), std::string::npos);
}

TEST(ParsePcap, RefusesAnyLinkTypeButEthernet) {
  const PcapContents c = parse_pcap(pcap_file(kTwo, {.link = 101}));  // raw IP
  EXPECT_NE(c.error.find("link type 101"), std::string::npos) << c.error;
}

// The library's reader and the tests' own, written separately, agree on every fixture there is.
TEST(ParsePcap, AgreesWithTheTestsOwnReaderOnEveryFixture) {
  std::size_t files = 0;
  for (const std::filesystem::directory_entry& entry :
       std::filesystem::recursive_directory_iterator(NPF_FIXTURE_DIR)) {
    if (entry.path().extension() != ".pcap") {
      continue;
    }
    ++files;
    const Bytes file = read_file(entry.path());
    const PcapContents c = parse_pcap(file);
    ASSERT_TRUE(c.error.empty()) << entry.path() << ": " << c.error;
    const std::vector<std::vector<std::byte>> frames = npf::test::read_pcap(entry.path());
    ASSERT_EQ(c.records.size(), frames.size()) << entry.path();
    for (std::size_t i = 0; i < frames.size(); ++i) {
      EXPECT_TRUE(std::ranges::equal(c.records[i].frame, frames[i])) << entry.path() << " " << i;
    }
  }
  EXPECT_GT(files, 0U) << "no pcap under " << NPF_FIXTURE_DIR;
}

// --- PcapWriter ----------------------------------------------------------------------------------

TEST(PcapWriter, WritesExactlyThePlansLayout) {
  const ScratchDir dir;
  {
    PcapWriter w(dir / "out.pcap");
    for (const Record& r : kTwo) {
      w.write(r.ts_us, r.frame);
    }
    EXPECT_TRUE(w.ok());
  }
  const Bytes written = read_file(dir / "out.pcap");
  EXPECT_EQ(written, pcap_file(kTwo));
  // The file header, spelled out: magic, version 2.4, zone and sigfigs 0, snaplen 65535, Ethernet.
  constexpr std::array<std::uint8_t, kFileHeader> kHeader{
      0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 1, 0, 0, 0};
  ASSERT_GE(written.size(), kFileHeader);
  EXPECT_TRUE(std::ranges::equal(
      std::span(written).first(kFileHeader), kHeader,
      [](std::byte b, std::uint8_t v) { return std::to_integer<std::uint8_t>(b) == v; }));
}

TEST(PcapWriter, RemembersAFailedWriteInsteadOfThrowing) {
  PcapWriter w("/dev/full");  // opens; every write fails with ENOSPC
  w.write(1, frame_of(60, 0));
  w.flush();
  EXPECT_FALSE(w.ok());
}

TEST(PcapWriter, ThrowsWhenTheFileCannotBeCreated) {
  EXPECT_THROW(PcapWriter("/nonexistent-directory/out.pcap"), std::system_error);
}

// --- PcapFileBackend -----------------------------------------------------------------------------

std::vector<npf::core::InterfaceConfig> two_ports() {
  return {{"veth-cr", 0, ip4(10, 0, 1, 1), 24, npf::PortMode::Routed, kMac0},
          {"veth-sr", 1, ip4(10, 0, 2, 1), 24, npf::PortMode::Routed, kMac1}};
}

TEST(PcapFileBackend, PortsAreTheConfigurations) {
  const ScratchDir dir;
  write_file(dir / "in.pcap", pcap_file(kTwo));
  PacketPool pool(4);
  const PcapFileBackend b({.in = dir / "in.pcap", .out = dir / "out.pcap"}, two_ports(), pool);
  ASSERT_EQ(b.ports().size(), 2U);
  EXPECT_EQ(b.ports()[1].mac, kMac1);
  EXPECT_EQ(b.ports()[1].ip, ip4(10, 0, 2, 1));
  EXPECT_EQ(b.ports()[1].name, "veth-sr");
  EXPECT_TRUE(b.ports()[0].up);
  EXPECT_STREQ(b.name(), "pcap");
}

TEST(PcapFileBackend, ReadsEveryRecordInOrderOntoPortZero) {
  const ScratchDir dir;
  write_file(dir / "in.pcap", pcap_file(kTwo));
  PacketPool pool(4);
  PcapFileBackend b({.in = dir / "in.pcap", .out = dir / "out.pcap"}, two_ports(), pool);
  std::array<Packet*, 4> got{};
  EXPECT_FALSE(b.done());
  ASSERT_EQ(b.rx_burst(got.data(), 1), 1U);  // no more than asked for
  ASSERT_EQ(b.rx_burst(&got[1], 3), 1U);
  EXPECT_TRUE(b.done());
  EXPECT_EQ(b.rx_burst(&got[2], 2), 0U);
  EXPECT_EQ(b.records_read(), 2U);
  for (std::size_t i = 0; i < 2; ++i) {
    EXPECT_TRUE(std::ranges::equal(std::as_const(*got.at(i)).data(), kTwo[i].frame)) << i;
    EXPECT_EQ(got.at(i)->in_port(), 0);
    EXPECT_EQ(got.at(i)->rx_tsc(), kTwo[i].ts_us);  // the record's time, carried to the output
    pool.release(got.at(i));
  }
}

TEST(PcapFileBackend, WritesWhatItIsGivenInOrderStampedWithItsCause) {
  const ScratchDir dir;
  write_file(dir / "in.pcap", pcap_file(kTwo));
  PacketPool pool(4);
  {
    PcapFileBackend b({.in = dir / "in.pcap", .out = dir / "out.pcap"}, two_ports(), pool);
    std::array<Packet*, 2> got{};
    ASSERT_EQ(b.rx_burst(got.data(), 2), 2U);
    Packet* made = pool.acquire();  // a frame the router made: no receive time
    ASSERT_NE(made, nullptr);
    const Bytes made_frame = frame_of(42, 200);
    made->resize(made_frame.size());
    std::ranges::copy(made_frame, made->data().begin());
    // Whatever the port, frames go out in the order given.
    const std::array<Packet*, 2> first{got[1], made};
    EXPECT_EQ(b.tx_burst(first.data(), first.size(), 1), 2U);
    EXPECT_EQ(b.tx_burst(got.data(), 1, 0), 1U);
    EXPECT_EQ(b.tx_burst(got.data(), 1, 2), 0U);  // no port 2: refused, and still the caller's
    b.tx_flush();
    EXPECT_TRUE(b.ok());
    EXPECT_EQ(b.records_written(), 3U);
    EXPECT_EQ(pool.available(), pool.capacity());  // a transmitted packet goes back to the pool
  }
  // The made frame carries the time of the last record read, the one that caused it.
  expect_records(parse_pcap(read_file(dir / "out.pcap")),
                 {kTwo[1], {kTwo[1].ts_us, frame_of(42, 200)}, kTwo[0]});
}

TEST(PcapFileBackend, SkipsAndCountsARecordTooBigForABuffer) {
  const ScratchDir dir;
  const std::size_t too_big = npf::core::kMaxFrame;  // more than a buffer holds after headroom
  write_file(dir / "in.pcap",
             pcap_file({kTwo[0], {kTwo[0].ts_us + 1, frame_of(too_big, 0)}, kTwo[1]}));
  PacketPool pool(4);
  PcapFileBackend b({.in = dir / "in.pcap", .out = dir / "out.pcap"}, two_ports(), pool);
  std::array<Packet*, 4> got{};
  ASSERT_EQ(b.rx_burst(got.data(), got.size()), 2U);
  EXPECT_TRUE(b.done());
  EXPECT_EQ(b.records_read(), 3U);
  EXPECT_EQ(b.rx_oversized(), 1U);
  EXPECT_EQ(got[1]->size(), kTwo[1].frame.size());
  pool.release(got[0]);
  pool.release(got[1]);
}

TEST(PcapFileBackend, LeavesARecordUnreadWhileThePoolIsEmpty) {
  const ScratchDir dir;
  write_file(dir / "in.pcap", pcap_file(kTwo));
  PacketPool pool(1);
  PcapFileBackend b({.in = dir / "in.pcap", .out = dir / "out.pcap"}, two_ports(), pool);
  std::array<Packet*, 2> got{};
  ASSERT_EQ(b.rx_burst(got.data(), 2), 1U);
  EXPECT_EQ(b.rx_burst(&got[1], 1),
            0U);  // no buffer: the record waits, as a frame waits in a socket
  EXPECT_EQ(b.records_read(), 1U);
  pool.release(got[0]);
  ASSERT_EQ(b.rx_burst(&got[1], 1), 1U);
  EXPECT_TRUE(std::ranges::equal(std::as_const(*got[1]).data(), kTwo[1].frame));
  pool.release(got[1]);
}

TEST(PcapFileBackend, NeedsEveryMacInTheConfiguration) {
  const ScratchDir dir;
  write_file(dir / "in.pcap", pcap_file(kTwo));
  std::vector<npf::core::InterfaceConfig> ports = two_ports();
  ports[1].mac.reset();  // "mac auto": fine for a live interface, impossible for a replay
  PacketPool pool(4);
  EXPECT_THROW(PcapFileBackend({.in = dir / "in.pcap", .out = dir / "out.pcap"}, ports, pool),
               std::invalid_argument);
  EXPECT_FALSE(std::filesystem::exists(dir / "out.pcap"));
}

TEST(PcapFileBackend, NamesTheInputItRefusesAndCreatesNoOutput) {
  const ScratchDir dir;
  write_file(dir / "in.pcap", pcap_file(kTwo, {.magic = 0xA1B23C4D}));
  PacketPool pool(4);
  try {
    const PcapFileBackend b({.in = dir / "in.pcap", .out = dir / "out.pcap"}, two_ports(), pool);
    ADD_FAILURE() << "a nanosecond pcap was accepted";
  } catch (const std::runtime_error& e) {
    EXPECT_NE(std::string{e.what()}.find("in.pcap: a nanosecond pcap"), std::string::npos)
        << e.what();
  }
  EXPECT_FALSE(std::filesystem::exists(dir / "out.pcap"));
  EXPECT_THROW(
      PcapFileBackend({.in = dir / "missing.pcap", .out = dir / "out.pcap"}, two_ports(), pool),
      std::system_error);
}

}  // namespace
