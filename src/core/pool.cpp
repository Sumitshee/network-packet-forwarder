#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <npf/core/packet.hpp>
#include <npf/core/pool.hpp>
#include <stdexcept>
#include <type_traits>

namespace npf::core {

// The pool never runs Packet destructors; it frees the storage they live in.
static_assert(std::is_trivially_destructible_v<Packet>);
// Every slot, and so every Packet and every buffer, starts on a cache line only if the stride
// between slots is a whole number of cache lines.
static_assert((sizeof(Packet) + kMaxFrame) % 64 == 0);

PacketPool::PacketPool(std::size_t count) : available_{count}, capacity_{count} {
  if (count == 0) {
    throw std::invalid_argument("PacketPool: count must be at least 1");
  }
  if (count > std::numeric_limits<std::size_t>::max() / kSlotSize) {
    throw std::bad_alloc();
  }
  // The only allocation this pool ever makes.
  storage_.reset(static_cast<std::byte*>(::operator new(count * kSlotSize, kAlign)));

  // Linked back to front, so the first acquire() hands out the lowest slot.
  for (std::size_t i = count; i-- > 0;) {
    std::byte* slot = storage_.get() + (i * kSlotSize);
    // Constructed in place inside storage_, which owns the memory: placement new creates no
    // second owner, whatever the owning-memory check assumes.
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
    auto* p = ::new (slot) Packet(slot + sizeof(Packet));
    p->free_next_ = head_;
    head_ = p;
  }
}

PacketPool::~PacketPool() = default;

bool PacketPool::owns(const Packet* p) const noexcept {
  const auto addr = reinterpret_cast<std::uintptr_t>(p);
  const auto base = reinterpret_cast<std::uintptr_t>(storage_.get());
  return addr >= base && addr - base < capacity_ * kSlotSize && (addr - base) % kSlotSize == 0;
}

}  // namespace npf::core
