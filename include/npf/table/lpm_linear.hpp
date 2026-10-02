#pragma once

// THE ORACLE -- NEVER OPTIMISE THIS FILE, OR lpm_linear.cpp.
//
// Every faster FIB is property-tested against this one (phase 10), so its only job is to be
// obviously right. A lookup walks the whole table, O(n), on purpose. Sorting it smarter, indexing
// it, caching it or vectorising it would turn the oracle into a second clever implementation, and
// a bug the two share is a bug no test can find. If a benchmark shows it is slow: it is meant to
// be.

#include <cstddef>
#include <cstdint>
#include <npf/table/fib.hpp>
#include <optional>
#include <vector>

namespace npf::table {

class LinearLpm final : public Fib {
 public:
  bool add(const Route& route) override;
  bool remove(Prefix prefix) override;
  void clear() override;

  [[nodiscard]] std::optional<NextHop> lookup(std::uint32_t dst) const noexcept;  // hot path
  [[nodiscard]] std::optional<NextHop> lookup_v(std::uint32_t dst) const noexcept override {
    return lookup(dst);
  }
  [[nodiscard]] std::size_t size() const noexcept override { return routes_.size(); }
  [[nodiscard]] std::size_t memory_bytes() const noexcept override;
  [[nodiscard]] const char* name() const noexcept override { return "linear"; }

 private:
  // Sorted by descending prefix length, so the first route that contains an address is its
  // longest match. Different prefixes of equal length never both contain one address, so their
  // order among themselves does not matter.
  std::vector<Route> routes_;
};

}  // namespace npf::table
