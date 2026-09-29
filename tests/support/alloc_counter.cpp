#include "support/alloc_counter.hpp"

#include <stdlib.h>  // posix_memalign

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <new>

namespace {

// Global by necessity: the functions being replaced are global. Test-only code.
std::atomic<std::size_t> g_allocations{0};
std::atomic<std::size_t> g_deallocations{0};

// Follows the standard's contract for the throwing forms: a distinct non-null pointer even for
// size 0, and the new-handler loop before giving up with std::bad_alloc.
void* allocate(std::size_t size, std::size_t align) {
  if (size == 0) {
    size = 1;
  }
  for (;;) {
    void* p = nullptr;
    if (align <= alignof(std::max_align_t)) {
      p = std::malloc(size);
    } else if (posix_memalign(&p, align, size) != 0) {
      p = nullptr;
    }
    if (p != nullptr) {
      g_allocations.fetch_add(1, std::memory_order_relaxed);
      return p;
    }
    std::new_handler handler = std::get_new_handler();
    if (handler == nullptr) {
      throw std::bad_alloc();
    }
    handler();
  }
}

void* allocate_nothrow(std::size_t size, std::size_t align) noexcept {
  try {
    return allocate(size, align);
  } catch (...) {
    return nullptr;
  }
}

void deallocate(void* p) noexcept {
  if (p != nullptr) {
    g_deallocations.fetch_add(1, std::memory_order_relaxed);
    std::free(p);
  }
}

std::size_t to_size(std::align_val_t a) noexcept {
  return static_cast<std::size_t>(a);
}

}  // namespace

namespace npf::test {

void AllocCounter::reset() noexcept {
  g_allocations.store(0, std::memory_order_relaxed);
  g_deallocations.store(0, std::memory_order_relaxed);
}

std::size_t AllocCounter::allocations() noexcept {
  return g_allocations.load(std::memory_order_relaxed);
}

std::size_t AllocCounter::deallocations() noexcept {
  return g_deallocations.load(std::memory_order_relaxed);
}

}  // namespace npf::test

// The complete set of replaceable global allocation and deallocation functions, so that no
// allocation path goes uncounted. Clang's static ThreadSanitizer runtime defines these too;
// tests/CMakeLists.txt links that one configuration against the shared runtime instead.

void* operator new(std::size_t n) {
  return allocate(n, 0);
}
void* operator new[](std::size_t n) {
  return allocate(n, 0);
}
void* operator new(std::size_t n, std::align_val_t a) {
  return allocate(n, to_size(a));
}
void* operator new[](std::size_t n, std::align_val_t a) {
  return allocate(n, to_size(a));
}
void* operator new(std::size_t n, const std::nothrow_t& /*unused*/) noexcept {
  return allocate_nothrow(n, 0);
}
void* operator new[](std::size_t n, const std::nothrow_t& /*unused*/) noexcept {
  return allocate_nothrow(n, 0);
}
void* operator new(std::size_t n, std::align_val_t a, const std::nothrow_t& /*unused*/) noexcept {
  return allocate_nothrow(n, to_size(a));
}
void* operator new[](std::size_t n, std::align_val_t a, const std::nothrow_t& /*unused*/) noexcept {
  return allocate_nothrow(n, to_size(a));
}

void operator delete(void* p) noexcept {
  deallocate(p);
}
void operator delete[](void* p) noexcept {
  deallocate(p);
}
void operator delete(void* p, std::align_val_t /*unused*/) noexcept {
  deallocate(p);
}
void operator delete[](void* p, std::align_val_t /*unused*/) noexcept {
  deallocate(p);
}
void operator delete(void* p, std::size_t /*unused*/) noexcept {
  deallocate(p);
}
void operator delete[](void* p, std::size_t /*unused*/) noexcept {
  deallocate(p);
}
void operator delete(void* p, std::size_t /*unused*/, std::align_val_t /*unused*/) noexcept {
  deallocate(p);
}
void operator delete[](void* p, std::size_t /*unused*/, std::align_val_t /*unused*/) noexcept {
  deallocate(p);
}
void operator delete(void* p, const std::nothrow_t& /*unused*/) noexcept {
  deallocate(p);
}
void operator delete[](void* p, const std::nothrow_t& /*unused*/) noexcept {
  deallocate(p);
}
void operator delete(void* p, std::align_val_t /*unused*/,
                     const std::nothrow_t& /*unused*/) noexcept {
  deallocate(p);
}
void operator delete[](void* p, std::align_val_t /*unused*/,
                       const std::nothrow_t& /*unused*/) noexcept {
  deallocate(p);
}
