#pragma once

#include <cassert>
#include <cstddef>
#include <memory>
#include <new>
#include <npf/core/packet.hpp>

namespace npf::core {

// Fixed-capacity packet allocator. The constructor makes one contiguous allocation that never
// grows; acquire() and release() only pop and push an intrusive LIFO free list, so the datapath
// never allocates and never frees.
//
// Not thread-safe, by design: every worker owns its own pool (ARCHITECTURE.md §12) and a packet
// never crosses threads in run-to-completion mode, so the hot path needs no atomics and no locks.
// Sharing one pool between threads is a bug, not a use case.
class PacketPool {
 public:
  // Throws std::invalid_argument for a count of zero, std::bad_alloc if the storage cannot be
  // allocated. Start-up code only.
  explicit PacketPool(std::size_t count);
  PacketPool(const PacketPool&) = delete;
  PacketPool& operator=(const PacketPool&) = delete;
  PacketPool(PacketPool&&) = delete;
  PacketPool& operator=(PacketPool&&) = delete;
  ~PacketPool();

  // nullptr when exhausted; never allocates. The packet comes back empty, with full headroom and
  // zeroed metadata. The caller borrows it until it is released or handed on, never deletes it.
  [[nodiscard]] Packet* acquire() noexcept {
    Packet* p = head_;
    if (p == nullptr) {
      return nullptr;
    }
    head_ = p->free_next_;
    --available_;
    p->reset();
    // Out of the pool, the link points at the packet itself -- a value it can never hold while in
    // the free list -- so release() can recognise a double release in debug builds.
    p->free_next_ = p;
    return p;
  }

  // Never deallocates. p must come from this pool's acquire() and not have been released since.
  void release(Packet* p) noexcept {
    assert(owns(p) && "release() of a packet that does not belong to this pool");
    assert(p->free_next_ == p && "double release, or release of a packet never acquired");
    p->free_next_ = head_;
    head_ = p;
    ++available_;
  }

  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
  [[nodiscard]] std::size_t available() const noexcept { return available_; }  // for leak tests

 private:
  static constexpr std::align_val_t kAlign{64};
  // Each slot is one cache line of Packet metadata followed by that packet's buffer.
  static constexpr std::size_t kSlotSize = sizeof(Packet) + kMaxFrame;

  struct FreeStorage {
    void operator()(std::byte* p) const noexcept { ::operator delete(p, kAlign); }
  };

  [[nodiscard]] bool owns(const Packet* p) const noexcept;

  Packet* head_{nullptr};
  std::size_t available_{0};
  std::size_t capacity_{0};
  std::unique_ptr<std::byte, FreeStorage> storage_;
};

}  // namespace npf::core
