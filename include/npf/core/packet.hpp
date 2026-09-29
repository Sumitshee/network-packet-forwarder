#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>

namespace npf::core {

inline constexpr std::size_t kMaxFrame = 2048;  // 1500 MTU + VLAN + slack, power-of-two friendly
inline constexpr std::size_t kHeadroom = 64;    // room to prepend headers without copying
inline constexpr std::size_t kBurst = 32;       // default batch size; tunable, measured in phase 15

class PacketPool;

// A borrowed, pool-owned frame buffer plus its metadata. Never constructed directly, never
// deleted: acquire one from a PacketPool and release it to the same pool.
//
// The buffer is kMaxFrame bytes. A fresh packet's frame starts kHeadroom bytes into it, so a
// header can be prepended without moving the payload.
//
// alignas(64): the metadata is touched for every packet, so it must sit in exactly one cache
// line rather than straddle two. sizeof(Packet) <= 64 alone does not guarantee that; alignment
// does, and it also makes the pool's slot stride (sizeof(Packet) + kMaxFrame) a multiple of 64.
class alignas(64) Packet {
 public:
  Packet(const Packet&) = delete;
  Packet& operator=(const Packet&) = delete;
  Packet(Packet&&) = delete;
  Packet& operator=(Packet&&) = delete;
  ~Packet() = default;

  [[nodiscard]] std::span<std::byte> data() noexcept { return {base_ + off_, len_}; }
  [[nodiscard]] std::span<const std::byte> data() const noexcept { return {base_ + off_, len_}; }
  [[nodiscard]] std::size_t size() const noexcept { return len_; }

  // The largest size() that resize() accepts: the buffer from the current start to its end.
  // Lets a builder refuse a frame that will not fit instead of tripping resize()'s precondition.
  [[nodiscard]] std::size_t capacity() const noexcept { return kMaxFrame - off_; }

  // Set the frame length. Must fit within the buffer from the current start offset. That is
  // asserted in debug builds; release builds clamp, so data() can never reach past the buffer.
  void resize(std::size_t n) noexcept {
    const std::size_t room = capacity();
    assert(n <= room && "resize() beyond the end of the buffer");
    len_ = static_cast<std::uint16_t>(n <= room ? n : room);
  }

  // Grow the frame at the front by n bytes, consuming headroom. Returns the new start, or nullptr
  // if there is not enough headroom. Does not copy.
  [[nodiscard]] std::byte* push(std::size_t n) noexcept {
    if (n > off_) {
      return nullptr;
    }
    off_ = static_cast<std::uint16_t>(off_ - n);
    len_ = static_cast<std::uint16_t>(len_ + n);
    return base_ + off_;
  }

  // Shrink the frame at the front by n bytes. Returns false if n > size().
  [[nodiscard]] bool pull(std::size_t n) noexcept {
    if (n > len_) {
      return false;
    }
    off_ = static_cast<std::uint16_t>(off_ + n);
    len_ = static_cast<std::uint16_t>(len_ - n);
    return true;
  }

  [[nodiscard]] std::uint16_t in_port() const noexcept { return in_port_; }
  void set_in_port(std::uint16_t p) noexcept { in_port_ = p; }

  // Set by the backend at RX, for latency.
  [[nodiscard]] std::uint64_t rx_tsc() const noexcept { return rx_tsc_; }
  void set_rx_tsc(std::uint64_t t) noexcept { rx_tsc_ = t; }

  // Cached parse offsets, filled by the pipeline so later stages do not re-parse.
  [[nodiscard]] std::uint16_t l3_offset() const noexcept { return l3_off_; }
  [[nodiscard]] std::uint16_t l4_offset() const noexcept { return l4_off_; }
  void set_offsets(std::uint16_t l3, std::uint16_t l4) noexcept {
    l3_off_ = l3;
    l4_off_ = l4;
  }

 private:
  friend class PacketPool;

  explicit Packet(std::byte* base) noexcept : base_{base} {}

  // Back to the state of a fresh packet: empty, full headroom, no metadata.
  void reset() noexcept {
    off_ = kHeadroom;
    len_ = 0;
    in_port_ = 0;
    l3_off_ = 0;
    l4_off_ = 0;
    rx_tsc_ = 0;
  }

  std::byte* base_;               // start of this packet's buffer in the pool's backing storage
  Packet* free_next_{nullptr};    // intrusive free-list link, valid only while in the pool
  std::uint16_t off_{kHeadroom};  // frame start offset within the buffer (>= kHeadroom initially)
  std::uint16_t len_{0};
  std::uint16_t in_port_{0};
  std::uint16_t l3_off_{0}, l4_off_{0};
  std::uint64_t rx_tsc_{0};
};

static_assert(sizeof(Packet) <= 64, "Packet metadata must fit in one cache line");

}  // namespace npf::core
