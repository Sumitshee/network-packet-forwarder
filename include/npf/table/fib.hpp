#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace npf::table {

struct Prefix {
  std::uint32_t addr{0};  // host order, every bit past len zero
  std::uint8_t len{0};
  friend bool operator==(const Prefix&, const Prefix&) noexcept = default;
};

struct Route {
  Prefix prefix;
  std::uint32_t next_hop{0};  // 0 means "directly connected, next hop is the packet's dst"
  std::uint16_t out_port{0};
  friend bool operator==(const Route&, const Route&) noexcept = default;
};

// What a lookup finds. ip is the matching route's next_hop exactly as it was added, so 0 still
// means "directly connected": substituting the packet's own destination is the caller's job, which
// keeps every implementation a plain map from prefixes to what was stored.
struct NextHop {
  std::uint32_t ip{0};
  std::uint16_t port{0};
  friend bool operator==(const NextHop&, const NextHop&) noexcept = default;
};

// The network mask of a prefix length from 0 to 32. Shifting a 32-bit value by 32 is undefined
// behaviour, so /0 cannot be computed as ~0u << 32 and is a case of its own; /32 shifts by zero.
[[nodiscard]] constexpr std::uint32_t prefix_mask(std::uint8_t len) noexcept {
  assert(len <= 32);
  return len == 0 ? 0U : ~0U << (32U - len);
}

// A prefix a route can have: no longer than an address, and no address bits set past its length.
[[nodiscard]] constexpr bool is_valid(Prefix p) noexcept {
  return p.len <= 32 && (p.addr & ~prefix_mask(p.len)) == 0;
}

// p must be valid.
[[nodiscard]] constexpr bool contains(Prefix p, std::uint32_t addr) noexcept {
  return (addr & prefix_mask(p.len)) == p.addr;
}

// Undefined behaviour is a compile error in a constant expression, so these also prove that
// neither end of the range shifts by 32.
static_assert(prefix_mask(0) == 0 && prefix_mask(1) == 0x80000000U &&
              prefix_mask(24) == 0xFFFFFF00U && prefix_mask(32) == 0xFFFFFFFFU);

// The polymorphic interface exists for tests and benchmarks, which iterate over implementations.
// The datapath does not use it: Forwarder is templated on the concrete FIB type so the lookup is a
// direct call. Each implementation therefore provides lookup() as a non-virtual member, and the
// virtual override simply forwards to it.
//
// Implementations must behave identically, since phase 10 tests each one against LinearLpm. Only a
// lookup is on the datapath; changing the table may allocate.
class Fib {
 public:
  virtual ~Fib() = default;

  // Replaces the route for the same prefix if there is one, so a prefix never has two. Returns
  // false, changing nothing, if the prefix is not valid (see is_valid).
  virtual bool add(const Route& route) = 0;
  // Removes the route for exactly this prefix. False if there is none.
  virtual bool remove(Prefix prefix) = 0;
  virtual void clear() = 0;
  // The route with the longest prefix that contains dst.
  [[nodiscard]] virtual std::optional<NextHop> lookup_v(std::uint32_t dst) const noexcept = 0;
  [[nodiscard]] virtual std::size_t size() const noexcept = 0;          // routes, not bytes
  [[nodiscard]] virtual std::size_t memory_bytes() const noexcept = 0;  // reported by bench_lpm
  [[nodiscard]] virtual const char* name() const noexcept = 0;

 protected:
  // Copying through a Fib& would slice; an implementation can still be copied as itself.
  Fib() = default;
  Fib(const Fib&) = default;
  Fib(Fib&&) = default;
  Fib& operator=(const Fib&) = default;
  Fib& operator=(Fib&&) = default;
};

// Implementations, in build order:
//   LinearLpm    [phase 5]  -- the oracle. Never optimise it.
//   BinaryTrie   [phase 10] -- uncompressed, the cache-behaviour baseline.
//   PatriciaLpm  [phase 10] -- path-compressed.
//   Dir24_8Lpm   [phase 10] -- the fast one; see BUILD_PLAN phase 10 for the layout.

}  // namespace npf::table
