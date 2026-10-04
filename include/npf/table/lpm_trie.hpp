#pragma once

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <npf/table/fib.hpp>
#include <optional>
#include <span>
#include <vector>

namespace npf::table {

// An uncompressed binary trie: a node for every bit of every prefix, so a lookup walks one node
// per bit of the address, up to 33 with the root, remembering the deepest one that held a route.
// Each step is a dependent load from wherever that node happens to sit, and that terrible cache
// behaviour is the point: this is the baseline PatriciaLpm and Dir24_8Lpm improve on.
//
// Nodes live in one vector and name their children by index: half the size of a pointer, and still
// valid when the vector grows. remove() unlinks the nodes a route no longer needs, and add() reuses
// them.
class BinaryTrie final : public Fib {
 public:
  BinaryTrie() = default;

  bool add(const Route& route) override;
  bool remove(Prefix prefix) override;
  void clear() override;

  // Replaces every route with these -- a later route for a prefix wins, as with add() -- and hands
  // back the spare capacity growing left behind. False, changing nothing, if a prefix is invalid.
  bool build(std::span<const Route> routes);

  [[nodiscard]] std::optional<NextHop> lookup(std::uint32_t dst) const noexcept {
    std::optional<NextHop> best;
    std::uint32_t at = kRoot;
    for (std::uint32_t depth = 0;; ++depth) {
      const Node& node = nodes_[at];
      if (node.hop) {
        best = node.hop;
      }
      if (depth == 32) {
        break;
      }
      at = child(node, bit_at(dst, depth));
      if (at == kNone) {
        break;
      }
    }
    return best;
  }
  [[nodiscard]] std::optional<NextHop> lookup_v(std::uint32_t dst) const noexcept override {
    return lookup(dst);
  }
  [[nodiscard]] std::size_t size() const noexcept override { return routes_; }
  [[nodiscard]] std::size_t memory_bytes() const noexcept override;
  [[nodiscard]] const char* name() const noexcept override { return "binary_trie"; }

 private:
  static constexpr std::uint32_t kRoot = 0;
  static constexpr std::uint32_t kNone = 0;  // the root is no node's child, so 0 can mean "none"

  struct Node {
    std::array<std::uint32_t, 2> child{kNone, kNone};
    std::optional<NextHop> hop;
  };

  // Bit pos of addr, counting from the most significant as 0.
  [[nodiscard]] static constexpr std::uint32_t bit_at(std::uint32_t addr,
                                                      std::uint32_t pos) noexcept {
    return (addr >> (31U - pos)) & 1U;
  }
  // A bit is 0 or 1, and so always a valid index.
  [[nodiscard]] static std::uint32_t child(const Node& n, std::uint32_t bit) noexcept {
    assert(bit < 2);
    return n.child[bit];  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
  }
  static std::uint32_t& child(Node& n, std::uint32_t bit) noexcept {
    assert(bit < 2);
    return n.child[bit];  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
  }

  std::uint32_t make_node();

  std::vector<Node> nodes_{Node{}};  // nodes_[kRoot] is the root, the /0 node
  std::vector<std::uint32_t> free_;  // unlinked nodes, for make_node() to reuse
  std::size_t routes_{0};
};

}  // namespace npf::table
