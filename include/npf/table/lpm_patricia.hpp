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

// A path-compressed binary trie. A node keeps its whole prefix -- the bit position where it sits
// and the bits on the way there -- so a chain of single-child nodes collapses into one, and a
// lookup checks the skipped bits with one mask and compare instead of a node per bit. Every node
// but the root holds a route or has two children: fewer nodes and fewer levels than BinaryTrie,
// though still one dependent load per level.
//
// Nodes live in one vector and name their children by index, as in BinaryTrie. The root is the /0
// node, there with or without a default route, so that every prefix has a parent to hang from.
class PatriciaLpm final : public Fib {
 public:
  PatriciaLpm() = default;

  bool add(const Route& route) override;
  bool remove(Prefix prefix) override;
  void clear() override;

  // Replaces every route with these -- a later route for a prefix wins, as with add() -- and hands
  // back the spare capacity growing left behind. False, changing nothing, if a prefix is invalid.
  bool build(std::span<const Route> routes);

  [[nodiscard]] std::optional<NextHop> lookup(std::uint32_t dst) const noexcept {
    std::optional<NextHop> best;
    std::uint32_t at = kRoot;
    for (;;) {
      const Node& node = nodes_[at];
      if ((dst & node.mask) != node.key) {
        break;  // a skipped bit differs: nothing at or below this node matches
      }
      if (node.hop) {
        best = node.hop;
      }
      if (node.len == 32) {
        break;
      }
      at = child(node, bit_at(dst, node.len));
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
  [[nodiscard]] const char* name() const noexcept override { return "patricia"; }

 private:
  static constexpr std::uint32_t kRoot = 0;
  static constexpr std::uint32_t kNone = 0;  // the root is no node's child, so 0 can mean "none"

  struct Node {
    std::uint32_t key{0};   // the prefix's address
    std::uint32_t mask{0};  // and its mask, so a lookup need not compute one per node
    std::uint8_t len{0};    // the bit position this node sits at: its prefix's length
    std::array<std::uint32_t, 2> child{kNone, kNone};  // by the bit at position len
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

  std::uint32_t make_node(Prefix p, std::optional<NextHop> hop);
  void free_node(std::uint32_t n);

  std::vector<Node> nodes_{Node{}};  // nodes_[kRoot] is the root, the /0 node
  std::vector<std::uint32_t> free_;  // unlinked nodes, for make_node() to reuse
  std::size_t routes_{0};
};

}  // namespace npf::table
