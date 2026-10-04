// The golden-file tests of docs/BUILD_PLAN.md phase 9. Every case in tests/fixtures/golden is
// replayed through the real binary, `npf replay`, and both of its outputs compared with what the
// case expects: the frames written, byte for byte, and the counters at the end. Several cases
// write no frames at all, and only their counters show the frame was dropped for the right reason.
// The expected files are scripts/make_fixtures.py's, built from a model of what a router must do,
// not copied from npf's output.
//
// On a mismatch the test says where: the first byte that differs, the record it is in, and both
// sides around it; or every counter, the ones that differ marked. npf's output is then kept.
//
// The suites are named "golden" in lower case so that `ctest -R golden` selects them.

#include <gtest/gtest.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

extern char** environ;  // POSIX's: handed on to npf, so the sanitizer settings reach it too

namespace {

constexpr std::size_t kFileHeader = 24;  // pcap's, and then 16 bytes before every frame
constexpr std::size_t kRecordHeader = 16;

std::filesystem::path golden_dir() {
  return std::filesystem::path{NPF_FIXTURE_DIR} / "golden";
}

// Every case: the name of each <name>.conf in the directory, sorted.
std::vector<std::string> cases() {
  std::vector<std::string> names;
  for (const std::filesystem::directory_entry& entry :
       std::filesystem::directory_iterator(golden_dir())) {
    if (entry.path().extension() == ".conf") {
      names.push_back(entry.path().stem().string());
    }
  }
  std::ranges::sort(names);
  return names;
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw std::runtime_error("cannot read " + path.string());
  }
  std::ostringstream text;
  text << in.rdbuf();
  return text.str();
}

std::vector<std::byte> read_bytes(const std::filesystem::path& path) {
  const std::string text = read_text(path);
  std::vector<std::byte> bytes(text.size());
  std::ranges::transform(text, bytes.begin(), [](char c) { return static_cast<std::byte>(c); });
  return bytes;
}

// Runs npf with these arguments and waits for it. Its exit status; minus the signal that killed
// it, if one did.
int run_npf(const std::vector<std::string>& args) {
  std::vector<std::string> words{NPF_BINARY};
  words.insert(words.end(), args.begin(), args.end());
  std::vector<char*> argv;
  for (std::string& word : words) {
    argv.push_back(word.data());
  }
  argv.push_back(nullptr);
  pid_t pid = 0;
  if (const int rc = ::posix_spawn(&pid, NPF_BINARY, nullptr, nullptr, argv.data(), environ);
      rc != 0) {
    throw std::system_error(rc, std::generic_category(), "cannot start " NPF_BINARY);
  }
  int status = 0;
  if (::waitpid(pid, &status, 0) != pid) {
    throw std::system_error(errno, std::generic_category(), "waitpid");
  }
  return WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
}

// Where offset falls in a pcap file, which is read for its record lengths: little-endian, as both
// npf and make_fixtures.py write them.
std::string place_in(const std::vector<std::byte>& pcap, std::size_t offset) {
  if (offset < kFileHeader) {
    return std::format("byte {} of the file header", offset);
  }
  std::size_t record = 1;
  for (std::size_t at = kFileHeader; at + kRecordHeader <= pcap.size(); ++record) {
    std::uint32_t len = 0;
    for (std::size_t i = 4; i-- > 0;) {
      len = len << 8U | std::to_integer<std::uint32_t>(pcap[at + 8 + i]);
    }
    if (offset < at + kRecordHeader) {
      return std::format("byte {} of record {}'s header", offset - at, record);
    }
    if (offset < at + kRecordHeader + len) {
      return std::format("byte {} of record {}'s frame", offset - at - kRecordHeader, record);
    }
    at += kRecordHeader + len;
  }
  return "past the last record";
}

// Five lines of 16 bytes around mark, the byte at mark in brackets.
std::string hexdump(const std::vector<std::byte>& bytes, std::size_t mark) {
  std::string out;
  const std::size_t first = mark / 16 >= 2 ? (mark / 16 - 2) * 16 : 0;
  const std::size_t last = std::min(bytes.size(), first + 5 * 16);
  for (std::size_t line = first; line < last; line += 16) {
    out += std::format("    {:06x} ", line);
    for (std::size_t i = line; i < std::min(line + 16, last); ++i) {
      const auto value = std::to_integer<unsigned>(bytes[i]);
      out += i == mark ? std::format("[{:02x}]", value) : std::format(" {:02x} ", value);
    }
    out += '\n';
  }
  if (mark >= bytes.size()) {
    out += std::format("    (it ends after {} bytes)\n", bytes.size());
  }
  return out;
}

// Empty if the two files are the same; otherwise where they first differ, and both sides there.
std::string pcap_difference(const std::vector<std::byte>& expected,
                            const std::vector<std::byte>& actual) {
  const auto [e, a] = std::ranges::mismatch(expected, actual);
  if (e == expected.end() && a == actual.end()) {
    return {};
  }
  const auto offset = static_cast<std::size_t>(e - expected.begin());
  return std::format(
      "the files differ first at byte {}, {} of the expected file; it has {} bytes, npf wrote "
      "{}\n  expected:\n{}  written:\n{}",
      offset, place_in(expected, offset), expected.size(), actual.size(), hexdump(expected, offset),
      hexdump(actual, offset));
}

using Counters = std::vector<std::pair<std::string, std::uint64_t>>;  // in the file's order

// A JSON object of names and non-negative integers: the only JSON npf writes or a case holds.
// Throws on anything else.
Counters parse_counters(const std::string& text) {
  Counters out;
  std::size_t i = 0;
  const auto skip_space = [&] {
    while (i < text.size() && (text[i] == ' ' || text[i] == '\n' || text[i] == '\t')) {
      ++i;
    }
  };
  const auto expect = [&](char c) {
    skip_space();
    if (i >= text.size() || text[i] != c) {
      throw std::runtime_error(std::format("expected '{}' at character {}", c, i));
    }
    ++i;
  };
  expect('{');
  skip_space();
  if (i < text.size() && text[i] == '}') {
    return out;
  }
  for (;;) {
    expect('"');
    const std::size_t end = text.find('"', i);
    if (end == std::string::npos) {
      throw std::runtime_error("unterminated name");
    }
    std::string name = text.substr(i, end - i);
    i = end + 1;
    expect(':');
    skip_space();
    std::uint64_t value = 0;
    const auto [next, ec] = std::from_chars(text.data() + i, text.data() + text.size(), value);
    if (ec != std::errc{}) {
      throw std::runtime_error(std::format("{} has no number for a value", name));
    }
    i = static_cast<std::size_t>(next - text.data());
    if (std::ranges::any_of(out, [&name](const auto& counter) { return counter.first == name; })) {
      throw std::runtime_error(name + " appears twice");
    }
    out.emplace_back(std::move(name), value);
    skip_space();
    if (i < text.size() && text[i] == ',') {
      ++i;
      continue;
    }
    expect('}');
    return out;
  }
}

// Empty if the two hold the same counters with the same values; otherwise all of them, side by
// side, the ones that differ marked.
std::string counter_difference(const Counters& expected, const Counters& actual) {
  const std::map<std::string, std::uint64_t> want(expected.begin(), expected.end());
  const std::map<std::string, std::uint64_t> got(actual.begin(), actual.end());
  if (want == got) {
    return {};
  }
  const auto value = [](const std::map<std::string, std::uint64_t>& m, const std::string& k) {
    const auto it = m.find(k);
    return it == m.end() ? std::string{"-"} : std::to_string(it->second);
  };
  std::string out = std::format("  {:<18}{:>10}{:>10}\n", "counter", "expected", "npf");
  const auto row = [&](const std::string& name) {
    const std::string e = value(want, name);
    const std::string a = value(got, name);
    out += std::format("  {:<18}{:>10}{:>10}{}\n", name, e, a, e == a ? "" : "   <-- differs");
  };
  for (const auto& [name, v] : expected) {
    row(name);
  }
  for (const auto& [name, v] : actual) {
    if (!want.contains(name)) {
      row(name);
    }
  }
  return out;
}

class Golden : public ::testing::TestWithParam<std::string> {};

TEST_P(Golden, ReplayMakesTheExpectedFramesAndCounters) {
  const std::string name = GetParam();
  const std::filesystem::path dir = golden_dir();
  const std::filesystem::path scratch =
      std::filesystem::temp_directory_path() / std::format("npf-golden-{}-{}", ::getpid(), name);
  std::filesystem::create_directories(scratch);
  const std::filesystem::path frames = scratch / "out.pcap";
  const std::filesystem::path counters = scratch / "out.json";

  const int status =
      run_npf({"replay", (dir / (name + ".pcap")).string(), frames.string(), "--config",
               (dir / (name + ".conf")).string(), "--stats-json", counters.string()});
  ASSERT_EQ(status, 0) << "npf replay failed; what it said is above";

  const std::string frame_diff =
      pcap_difference(read_bytes(dir / (name + ".expected.pcap")), read_bytes(frames));
  EXPECT_TRUE(frame_diff.empty()) << "npf wrote other frames than " << name
                                  << ".expected.pcap holds: " << frame_diff;
  const std::string counter_diff =
      counter_difference(parse_counters(read_text(dir / (name + ".expected.json"))),
                         parse_counters(read_text(counters)));
  EXPECT_TRUE(counter_diff.empty())
      << "npf's counters are not those " << name << ".expected.json holds:\n"
      << counter_diff;

  if (HasFailure()) {
    std::cout << "npf's output is kept in " << scratch.string() << '\n';
  } else {
    std::filesystem::remove_all(scratch);
  }
}

INSTANTIATE_TEST_SUITE_P(golden, Golden, ::testing::ValuesIn(cases()),
                         [](const ::testing::TestParamInfo<std::string>& test) {
                           return test.param;
                         });

// The plan's eight. Later phases add cases; none may go missing.
TEST(golden, EveryCaseThePlanNamesIsThere) {
  const std::vector<std::string> found = cases();
  for (const std::string name : {"basic_fwd", "ttl_expired", "no_route", "bad_checksum", "martian",
                                 "fragment", "arp_request", "vlan"}) {
    EXPECT_TRUE(std::ranges::find(found, name) != found.end()) << name << ".conf is missing";
    for (const std::string_view suffix : {".pcap", ".expected.pcap", ".expected.json"}) {
      EXPECT_TRUE(std::filesystem::exists(golden_dir() / (name + std::string{suffix})))
          << name << suffix << " is missing";
    }
  }
}

// The test's own parts, on inputs whose answers are known.
TEST(golden, ACounterDifferenceIsReportedAndSamenessIsNot) {
  const Counters a = parse_counters("{\n  \"rx_packets\": 1,\n  \"forwarded\": 1\n}\n");
  ASSERT_EQ(a.size(), 2U);
  EXPECT_EQ(a[1], (std::pair<std::string, std::uint64_t>{"forwarded", 1}));
  EXPECT_TRUE(counter_difference(a, a).empty());
  const Counters b = parse_counters("{\"rx_packets\": 1, \"forwarded\": 0}");
  const std::string report = counter_difference(a, b);
  std::istringstream lines(report);
  int marked = 0;
  for (std::string line; std::getline(lines, line);) {
    const bool differs = line.ends_with("<-- differs");
    marked += differs ? 1 : 0;
    EXPECT_EQ(differs, line.starts_with("  forwarded")) << report;
  }
  EXPECT_EQ(marked, 1) << report;
  EXPECT_THROW((void)parse_counters("{\"rx_packets\": -1}"), std::runtime_error);
  EXPECT_THROW((void)parse_counters("{\"a\": 1, \"a\": 2}"), std::runtime_error);
  EXPECT_THROW((void)parse_counters("[1]"), std::runtime_error);
}

TEST(golden, AFrameDifferenceIsPlacedInItsRecord) {
  std::vector<std::byte> expected(kFileHeader + kRecordHeader + 4, std::byte{0});
  expected[kFileHeader + 8] = std::byte{4};  // one record, of a 4-byte frame
  std::vector<std::byte> actual = expected;
  EXPECT_TRUE(pcap_difference(expected, actual).empty());
  actual[kFileHeader + kRecordHeader + 2] = std::byte{0xAB};
  const std::string report = pcap_difference(expected, actual);
  EXPECT_NE(report.find("byte 42, byte 2 of record 1's frame"), std::string::npos) << report;
  EXPECT_NE(report.find("[ab]"), std::string::npos) << report;
}

}  // namespace
