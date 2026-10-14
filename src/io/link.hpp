#pragma once

// What the two socket backends share: opening an interface, reading what the kernel says about it,
// binding, fanout, and the checks on their options. Start-up code only: every function here may
// throw. Private to src/io.

#include <cstdint>
#include <npf/core/config.hpp>
#include <npf/core/unique_fd.hpp>
#include <npf/io/af_packet.hpp>
#include <npf/proto/mac.hpp>
#include <optional>
#include <span>
#include <string>

namespace npf::io::link {

// Asked for on every socket. The kernel doubles whatever it is given, to cover its own
// bookkeeping, and caps the request at net.core.rmem_max or wmem_max first -- so the size it
// grants is read back and logged rather than assumed.
inline constexpr int kSocketBufferBytes = 4 * 1024 * 1024;

[[noreturn]] void throw_errno(const std::string& what);

struct LinkFacts {
  proto::MacAddr mac;
  bool up{false};
};

// A raw AF_PACKET socket that receives nothing until bind() names an interface. A socket opened
// with ETH_P_ALL would collect frames from every interface from the moment it exists, and the
// first few could be taken for this port's.
[[nodiscard]] core::UniqueFd open_packet_socket();

[[nodiscard]] unsigned ifindex_of(const std::string& name);
[[nodiscard]] LinkFacts read_link(int fd, const std::string& name);

// Returns the size the kernel granted, or -1 if it would not say. A refusal is not fatal.
int grow_buffer(int fd, int option);

// Binds fd to the interface, every protocol, and puts a bridged port into promiscuous mode.
void bind_to(int fd, unsigned ifindex, const core::InterfaceConfig& iface);

// Joins fd, bound to an interface, to a PACKET_FANOUT_HASH group: group's, or else a new one with
// an id the kernel picks. Returns the group's id.
std::uint16_t join_fanout(int fd, std::optional<std::uint16_t> group, const std::string& name);

// The interfaces and options a backend is given make sense together: ports 0 to N-1, each once,
// and one receive flag and one fanout group per interface where there are any. backend names it in
// the error.
void check_shape(std::span<const core::InterfaceConfig> interfaces, const AfPacketOptions& options,
                 const char* backend);

// The configured MAC wins over the interface's own, with a warning.
[[nodiscard]] proto::MacAddr effective_mac(const core::InterfaceConfig& iface,
                                           const LinkFacts& link);

// The frames the kernel dropped on fd since it was last asked -- PACKET_STATISTICS, which the
// kernel resets on every read -- for a socket of TPACKET_V3 (v3) or any other.
[[nodiscard]] std::uint64_t kernel_drops(int fd, bool v3) noexcept;

}  // namespace npf::io::link
