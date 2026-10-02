// The oracle. Read the comment at the top of lpm_linear.hpp before changing anything here.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <npf/table/fib.hpp>
#include <npf/table/lpm_linear.hpp>
#include <optional>

namespace npf::table {

bool LinearLpm::add(const Route& route) {
  if (!is_valid(route.prefix)) {
    return false;
  }
  if (const auto same = std::ranges::find(routes_, route.prefix, &Route::prefix);
      same != routes_.end()) {
    *same = route;
    return true;
  }
  // In front of the first shorter prefix, which keeps the table sorted by descending length.
  const auto shorter = std::ranges::find_if(
      routes_, [&route](const Route& r) { return r.prefix.len < route.prefix.len; });
  routes_.insert(shorter, route);
  return true;
}

bool LinearLpm::remove(Prefix prefix) {
  const auto it = std::ranges::find(routes_, prefix, &Route::prefix);
  if (it == routes_.end()) {
    return false;
  }
  routes_.erase(it);
  return true;
}

void LinearLpm::clear() {
  routes_.clear();
}

std::optional<NextHop> LinearLpm::lookup(std::uint32_t dst) const noexcept {
  for (const Route& r : routes_) {
    if (contains(r.prefix, dst)) {
      return NextHop{r.next_hop, r.out_port};
    }
  }
  return std::nullopt;
}

std::size_t LinearLpm::memory_bytes() const noexcept {
  // The vector's whole allocation, spare capacity included: that memory is held either way.
  return sizeof(*this) + (routes_.capacity() * sizeof(Route));
}

}  // namespace npf::table
