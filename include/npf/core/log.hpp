#pragma once

#include <cstdio>
#include <format>
#include <string>
#include <string_view>
#include <utility>

namespace npf::core {

// Messages for whoever runs the router -- start-up, configuration, control events -- one line
// each on stderr. Statistics are not log messages; they go to stdout. Never call these on the
// datapath: formatting allocates.

namespace detail {

inline void log_line(std::string_view level, const std::string& message) {
  const std::string line = std::string{"npf: "}.append(level).append(message).append("\n");
  std::fputs(line.c_str(), stderr);
}

}  // namespace detail

template <class... Args>
void log_info(std::format_string<Args...> fmt, Args&&... args) {
  detail::log_line("", std::format(fmt, std::forward<Args>(args)...));
}

template <class... Args>
void log_warn(std::format_string<Args...> fmt, Args&&... args) {
  detail::log_line("warning: ", std::format(fmt, std::forward<Args>(args)...));
}

template <class... Args>
void log_error(std::format_string<Args...> fmt, Args&&... args) {
  detail::log_line("error: ", std::format(fmt, std::forward<Args>(args)...));
}

}  // namespace npf::core
