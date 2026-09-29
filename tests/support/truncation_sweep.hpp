#pragma once

#include <gtest/gtest.h>

#include <cstddef>
#include <span>
#include <vector>

namespace npf::test {

// Parses every proper prefix of a known-good input. Each prefix shorter than View::kMinSize must
// be rejected, and no prefix may be read past its end.
//
// That second half is proved by ASan, and only if the prefix really ends where its span does. A
// slice of the original buffer would leave the rest of the frame readable just past the end, so
// an over-read would go unnoticed. Each prefix is therefore copied into its own exactly-sized
// heap allocation, which ASan guards with a redzone. `touch` is called on every view that
// parses, so its accessors are exercised the same way.
template <class View, class Touch>
void TruncationSweep(std::span<const std::byte> good, Touch touch) {
  for (std::size_t n = 0; n < good.size(); ++n) {
    const auto part = good.first(n);
    const std::vector<std::byte> prefix(part.begin(), part.end());
    const auto view = View::parse(prefix);
    if (n < View::kMinSize) {
      EXPECT_FALSE(view.has_value()) << "accepted " << n << " bytes";
    }
    if (view.has_value()) {
      touch(*view);
    }
  }
}

template <class View>
void TruncationSweep(std::span<const std::byte> good) {
  TruncationSweep<View>(good, [](const View& /*unused*/) {});
}

}  // namespace npf::test
