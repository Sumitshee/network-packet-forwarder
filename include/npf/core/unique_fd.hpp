#pragma once

#include <unistd.h>

#include <utility>

namespace npf::core {

// Owns one file descriptor and closes it exactly once. Move-only, so a descriptor always has a
// single owner and no copy can close it behind that owner's back.
class UniqueFd {
 public:
  UniqueFd() noexcept = default;
  explicit UniqueFd(int fd) noexcept : fd_{fd} {}
  UniqueFd(const UniqueFd&) = delete;
  UniqueFd& operator=(const UniqueFd&) = delete;
  UniqueFd(UniqueFd&& other) noexcept : fd_{std::exchange(other.fd_, -1)} {}
  UniqueFd& operator=(UniqueFd&& other) noexcept {
    reset(std::exchange(other.fd_, -1));  // safe for self-move: the exchange empties *this first
    return *this;
  }
  ~UniqueFd() { reset(); }

  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

  // Closes the descriptor held, if any, and takes ownership of fd.
  void reset(int fd = -1) noexcept {
    if (fd_ >= 0) {
      // Linux releases the descriptor even when close() reports an error, EINTR included, so
      // there is nothing to retry and nothing a caller could do about the result.
      ::close(fd_);
    }
    fd_ = fd;
  }

 private:
  int fd_{-1};
};

}  // namespace npf::core
