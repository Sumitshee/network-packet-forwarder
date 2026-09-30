// Seeds the fuzz corpora from the fixture pcaps, one file per frame: every whole frame into
// <out>/ethernet/ for fuzz_ethernet, the Ethernet payload of every ARP frame into <out>/arp/ for
// fuzz_arp, and that of every IPv4 frame into both <out>/ipv4/ and <out>/l4/, one corpus per
// harness. Run by the fuzz_corpus custom command in tests/fuzz/CMakeLists.txt.

#include <cstddef>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <npf/proto/ethernet.hpp>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "support/pcap_reader.hpp"

namespace {

void write_seed(const std::filesystem::path& file, std::span<const std::byte> bytes) {
  std::ofstream out(file, std::ios::binary | std::ios::trunc);
  for (const std::byte b : bytes) {
    out.put(static_cast<char>(b));
  }
  if (!out) {
    throw std::runtime_error("cannot write " + file.string());
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    std::fprintf(stderr, "usage: %s <out-dir> <pcap>...\n", argv[0]);
    return 2;
  }
  try {
    const std::vector<std::string> args(argv + 1, argv + argc);
    const std::filesystem::path out{args[0]};
    for (const char* dir : {"ethernet", "arp", "ipv4", "l4"}) {
      std::filesystem::create_directories(out / dir);
    }

    std::size_t frames = 0;
    std::size_t arp = 0;
    std::size_t ipv4 = 0;
    for (std::size_t i = 1; i < args.size(); ++i) {
      const std::filesystem::path pcap{args[i]};
      const auto records = npf::test::read_pcap(pcap);
      for (std::size_t r = 0; r < records.size(); ++r) {
        const std::string seed = pcap.stem().string() + "-" + std::to_string(r);
        write_seed(out / "ethernet" / seed, records[r]);
        ++frames;
        const auto eth = npf::proto::EthView::parse(records[r]);
        if (eth && eth->ethertype() == npf::proto::kEtherTypeArp) {
          write_seed(out / "arp" / seed, eth->payload());
          ++arp;
        } else if (eth && eth->ethertype() == npf::proto::kEtherTypeIpv4) {
          write_seed(out / "ipv4" / seed, eth->payload());
          write_seed(out / "l4" / seed, eth->payload());
          ++ipv4;
        }
      }
    }
    std::printf("seeded %zu ethernet, %zu arp, and %zu ipv4 and l4 inputs\n", frames, arp, ipv4);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "pcap_to_corpus: %s\n", e.what());
    return 1;
  }
  return 0;
}
