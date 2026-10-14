#pragma once

// The route tables scripts/fetch_bgp_table.sh writes, for the tier A benchmarks that want an
// Internet-sized FIB: "a.b.c.d/len id" lines, the id standing for a next hop.

#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <npf/table/fib.hpp>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace npf::bench {

// The directory the tables are in: NPF_BGP_DATA, or else data/.
inline std::filesystem::path bgp_data_dir() {
  const char* dir = std::getenv("NPF_BGP_DATA");
  return dir != nullptr ? dir : "data";
}

// Every line of path as a route. The next hop is 10.255.<id>, out of port id % 4: any distinct
// value per id will do for a table under test on its own.
inline std::vector<table::Route> load_routes(const std::filesystem::path& path) {
  std::ifstream in(path);
  if (!in) {
    throw std::runtime_error(
        std::format("cannot read {}: run scripts/fetch_bgp_table.sh first", path.string()));
  }
  std::vector<table::Route> routes;
  std::string line;
  while (std::getline(in, line)) {
    unsigned a = 0;
    unsigned b = 0;
    unsigned c = 0;
    unsigned d = 0;
    unsigned len = 0;
    unsigned id = 0;
    char dot1 = 0;
    char dot2 = 0;
    char dot3 = 0;
    char slash = 0;
    std::istringstream fields(line);
    if (!(fields >> a >> dot1 >> b >> dot2 >> c >> dot3 >> d >> slash >> len >> id) ||
        dot1 != '.' || dot2 != '.' || dot3 != '.' || slash != '/' || a > 255 || b > 255 ||
        c > 255 || d > 255 || len > 32) {
      throw std::runtime_error(std::format("{}: cannot read '{}'", path.string(), line));
    }
    const table::Prefix prefix{a << 24U | b << 16U | c << 8U | d, static_cast<std::uint8_t>(len)};
    if (!table::is_valid(prefix)) {
      throw std::runtime_error(
          std::format("{}: '{}' has bits set past its length", path.string(), line));
    }
    routes.push_back({prefix, 0x0AFF0000U + id, static_cast<std::uint16_t>(id % 4)});
  }
  return routes;
}

}  // namespace npf::bench
