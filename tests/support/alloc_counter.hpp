#pragma once

#include <cstddef>

namespace npf::test {

// Counts calls to the global allocation and deallocation functions, which alloc_counter.cpp
// replaces. A test binary measures allocations only if that file is compiled into it; the
// AllocCounter tests in test_pool.cpp prove it is, so a zero cannot mean "not measured".
class AllocCounter {
 public:
  static void reset() noexcept;
  [[nodiscard]] static std::size_t allocations() noexcept;
  [[nodiscard]] static std::size_t deallocations() noexcept;
};

}  // namespace npf::test
