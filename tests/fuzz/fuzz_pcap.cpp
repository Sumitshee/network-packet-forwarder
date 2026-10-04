// libFuzzer harness for parse_pcap. The input is a whole pcap file. Clang only; see
// tests/fuzz/CMakeLists.txt, which compiles src/io/pcap_file.cpp into this harness so that
// libFuzzer sees inside the parser.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <npf/io/pcap_file.hpp>
#include <span>

namespace {

// A broken invariant must look like a crash to libFuzzer, in every build type.
void require(bool ok) {
  if (!ok) {
    std::abort();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::byte> file = std::as_bytes(std::span{data, size});
  const npf::io::PcapContents contents = npf::io::parse_pcap(file);
  if (!contents.error.empty()) {
    require(contents.records.empty());
    return 0;
  }
  // Accepted: then the records tile the file after its header exactly, in order, every frame
  // inside it -- which ASan also watches.
  require(size >= npf::io::kPcapFileHeaderSize);
  std::size_t at = npf::io::kPcapFileHeaderSize;
  for (const npf::io::PcapRecord& r : contents.records) {
    const auto offset = static_cast<std::size_t>(r.frame.data() - file.data());
    require(offset == at + npf::io::kPcapRecordHeaderSize);
    require(r.frame.size() <= size - offset);
    at = offset + r.frame.size();
  }
  require(at == size);
  return 0;
}
