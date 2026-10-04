#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <npf/table/fib.hpp>
#include <npf/table/lpm_patricia.hpp>
#include <optional>
#include <span>
#include <vector>

namespace npf::table {
namespace {

// How many leading bits two prefixes share, up to the shorter one's length.
std::uint8_t common_length(Prefix a, Prefix b) noexcept {
  const auto differ = static_cast<std::uint8_t>(std::countl_zero(a.addr ^ b.addr));  // 32 if none
  return std::min({a.len, b.len, differ});
}

}  // namespace

std::uint32_t PatriciaLpm::make_node(Prefix p, std::optional<NextHop> hop) {
  std::uint32_t n = 0;
  if (!free_.empty()) {
    n = free_.back();
    free_.pop_back();
  } else {
    nodes_.emplace_back();
    n = static_cast<std::uint32_t>(nodes_.size() - 1);
  }
  Node& node = nodes_[n];
  node = Node{};
  node.key = p.addr;
  node.mask = prefix_mask(p.len);
  node.len = p.len;
  node.hop = hop;
  return n;
}

void PatriciaLpm::free_node(std::uint32_t n) {
  nodes_[n] = Node{};
  free_.push_back(n);
}

bool PatriciaLpm::add(const Route& route) {
  const Prefix p = route.prefix;
  if (!is_valid(p)) {
    return false;
  }
  const NextHop hop{route.next_hop, route.out_port};
  std::uint32_t parent = kNone;
  std::uint32_t side = 0;
  std::uint32_t at = kRoot;
  for (;;) {
    const Prefix here{nodes_[at].key, nodes_[at].len};
    const std::uint8_t common = common_length(here, p);
    if (common == here.len && common == p.len) {  // this node is the prefix
      if (!nodes_[at].hop) {
        ++routes_;
      }
      nodes_[at].hop = hop;
      return true;
    }
    if (common == here.len) {  // the prefix is below this node
      const std::uint32_t bit = bit_at(p.addr, here.len);
      const std::uint32_t next = child(nodes_[at], bit);
      if (next == kNone) {
        const std::uint32_t leaf = make_node(p, hop);  // may move the nodes: indices only
        child(nodes_[at], bit) = leaf;
        ++routes_;
        return true;
      }
      parent = at;
      side = bit;
      at = next;
      continue;
    }
    // The prefix leaves this node's path above it, at bit `common`: something new goes between this
    // node and its parent. Never at the root, which every prefix is below.
    std::uint32_t above = 0;
    if (common == p.len) {  // the prefix itself, with this node as its child
      above = make_node(p, hop);
      child(nodes_[above], bit_at(here.addr, p.len)) = at;
    } else {  // a branch where the two part ways, with this node on one side and the prefix on the
              // other
      above = make_node(Prefix{p.addr & prefix_mask(common), common}, std::nullopt);
      const std::uint32_t leaf = make_node(p, hop);
      child(nodes_[above], bit_at(here.addr, common)) = at;
      child(nodes_[above], bit_at(p.addr, common)) = leaf;
    }
    child(nodes_[parent], side) = above;
    ++routes_;
    return true;
  }
}

bool PatriciaLpm::remove(Prefix prefix) {
  if (!is_valid(prefix)) {
    return false;
  }
  std::uint32_t grandparent = kNone;
  std::uint32_t grandparent_side = 0;
  std::uint32_t parent = kNone;
  std::uint32_t side = 0;
  std::uint32_t at = kRoot;
  for (;;) {
    const Node& node = nodes_[at];
    if (node.len > prefix.len || (prefix.addr & node.mask) != node.key) {
      return false;  // passed the place the prefix would be
    }
    if (node.len == prefix.len) {
      break;
    }
    const std::uint32_t bit = bit_at(prefix.addr, node.len);
    const std::uint32_t next = child(node, bit);
    if (next == kNone) {
      return false;
    }
    grandparent = parent;
    grandparent_side = side;
    parent = at;
    side = bit;
    at = next;
  }
  if (!nodes_[at].hop) {
    return false;
  }
  nodes_[at].hop.reset();
  --routes_;
  if (at == kRoot) {
    return true;  // the root stays, route or not
  }
  // Keep every node but the root holding a route or two children.
  const Node& node = nodes_[at];
  const std::uint32_t only = node.child[0] != kNone ? node.child[0] : node.child[1];
  if (node.child[0] != kNone && node.child[1] != kNone) {
    return true;  // still a branch
  }
  child(nodes_[parent], side) = only;  // the child takes its place, or nothing does
  free_node(at);
  // A parent that has just lost a child may now be a routeless node with one child: splice it out.
  const Node& up = nodes_[parent];
  if (only != kNone || parent == kRoot || up.hop) {
    return true;
  }
  const std::uint32_t remaining = up.child[0] != kNone ? up.child[0] : up.child[1];
  if (up.child[0] != kNone && up.child[1] != kNone) {
    return true;
  }
  child(nodes_[grandparent], grandparent_side) = remaining;
  free_node(parent);
  return true;
}

// Like a vector's clear(): every route goes, the memory stays. build() hands back what is spare.
void PatriciaLpm::clear() {
  nodes_.resize(1);
  nodes_[kRoot] = Node{};
  free_.clear();
  routes_ = 0;
}

bool PatriciaLpm::build(std::span<const Route> routes) {
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

std::size_t PatriciaLpm::memory_bytes() const noexcept {
  // Every allocation, spare capacity included, as LinearLpm counts its own.
  return sizeof(*this) + (nodes_.capacity() * sizeof(Node)) +
         (free_.capacity() * sizeof(std::uint32_t));
}

}  // namespace npf::table
