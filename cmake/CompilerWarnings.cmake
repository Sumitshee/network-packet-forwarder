# The warning set from CLAUDE.md section 6. Link npf_warnings into every first-party target.
# Third-party code (GoogleTest, Google Benchmark) is deliberately not held to it.

add_library(npf_warnings INTERFACE)

target_compile_options(npf_warnings INTERFACE
  -Wall
  -Wextra
  -Wpedantic
  -Wshadow
  -Wconversion
  -Wsign-conversion
  -Wcast-align
  -Wold-style-cast
  -Wnon-virtual-dtor
  -Wnull-dereference
  -Wdouble-promotion
  -Wformat=2
  -Wimplicit-fallthrough)

if(NPF_WERROR)
  target_compile_options(npf_warnings INTERFACE -Werror)
endif()
