#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <npf/table/fib.hpp>
#include <npf/table/lpm_trie.hpp>
#include <span>
#include <vector>

namespace npf::table {

std::uint32_t BinaryTrie::make_node() {
  if (!free_.empty()) {
    const std::uint32_t n = free_.back();
    free_.pop_back();
    return n;
  }
  nodes_.emplace_back();
  return static_cast<std::uint32_t>(nodes_.size() - 1);
}

bool BinaryTrie::add(const Route& route) {
  if (!is_valid(route.prefix)) {
    return false;
  }
  std::uint32_t at = kRoot;
  for (std::uint32_t depth = 0; depth < route.prefix.len; ++depth) {
    const std::uint32_t bit = bit_at(route.prefix.addr, depth);
    std::uint32_t next = child(nodes_[at], bit);
    if (next == kNone) {
      next = make_node();  // may move the nodes: hence indices, never references, across this
      child(nodes_[at], bit) = next;
    }
    at = next;
  }
  Node& node = nodes_[at];
  if (!node.hop) {
    ++routes_;
  }
  node.hop = NextHop{route.next_hop, route.out_port};
  return true;
}

bool BinaryTrie::remove(Prefix prefix) {
  if (!is_valid(prefix)) {
    return false;
  }
  std::array<std::uint32_t, 33> path{};  // path.at(d): the node at depth d
  std::uint32_t at = kRoot;
  for (std::uint32_t depth = 0; depth < prefix.len; ++depth) {
    at = child(nodes_[at], bit_at(prefix.addr, depth));
    if (at == kNone) {
      return false;
    }
    path.at(depth + 1) = at;
  }
  if (!nodes_[at].hop) {
    return false;
  }
  nodes_[at].hop.reset();
  --routes_;
  // From the bottom up, unlink every node left with neither a route nor a child.
  for (std::uint32_t depth = prefix.len; depth > 0; --depth) {
    const std::uint32_t n = path.at(depth);
    const Node& node = nodes_[n];
    if (node.hop || node.child[0] != kNone || node.child[1] != kNone) {
      break;
    }
    child(nodes_[path.at(depth - 1)], bit_at(prefix.addr, depth - 1)) = kNone;
    nodes_[n] = Node{};
    free_.push_back(n);
  }
  return true;
}

// Like a vector's clear(): every route goes, the memory stays. build() hands back what is spare.
void BinaryTrie::clear() {
  nodes_.resize(1);
  nodes_[kRoot] = Node{};
  free_.clear();
  routes_ = 0;
}

bool BinaryTrie::build(std::span<const Route> routes) {
  if (!std::ranges::all_of(routes, [](const Route& r) { return is_valid(r.prefix); })) {
    return false;
  }
  clear();
  for (const Route& r : routes) {
    add(r);
  }
  nodes_.shrink_to_fit();
  free_.shrink_to_fit();
  return true;
}

std::size_t BinaryTrie::memory_bytes() const noexcept {
  // Every allocation, spare capacity included, as LinearLpm counts its own.
  return sizeof(*this) + (nodes_.capacity() * sizeof(Node)) +
         (free_.capacity() * sizeof(std::uint32_t));
}

}  // namespace npf::table
