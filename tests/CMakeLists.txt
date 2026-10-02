include(GoogleTest)

# One executable per test file keeps failures isolated and lets ctest run them in parallel.
function(npf_add_unit_test name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(${name} PRIVATE npf_warnings npf_core GTest::gtest_main)
  # Where tests/support/proto_helpers.hpp finds the committed pcaps.
  target_compile_definitions(${name} PRIVATE
    NPF_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
  # gtest_discover_tests prefixes both test discovery and every test it registers with this
  # property. CMake 3.29 adds TEST_LAUNCHER for exactly this; 3.28 (Ubuntu 24.04) does not have it.
  if(NPF_TEST_LAUNCHER)
    set_target_properties(${name} PROPERTIES CROSSCOMPILING_EMULATOR "${NPF_TEST_LAUNCHER}")
  endif()
  gtest_discover_tests(${name} DISCOVERY_MODE PRE_TEST)
endfunction()

# alloc_counter.cpp replaces the global operator new and delete, so it is compiled only into the
# tests that measure allocations; every other test keeps the standard allocator.
if(NPF_SANITIZER STREQUAL "tsan" AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  execute_process(COMMAND ${CMAKE_CXX_COMPILER} -print-runtime-dir
                  OUTPUT_VARIABLE npf_clang_runtime_dir
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  COMMAND_ERROR_IS_FATAL ANY)
endif()
function(npf_count_allocations name)
  target_sources(${name} PRIVATE support/alloc_counter.cpp)
  # Clang links its ThreadSanitizer runtime statically, and that archive's operator new and delete
  # clash with the replacements ("multiple definition"). Its shared runtime lets this binary's
  # definitions take precedence, which is how GCC's libtsan.so always behaves.
  if(npf_clang_runtime_dir)
    target_link_options(${name} PRIVATE -shared-libsan "-Wl,-rpath,${npf_clang_runtime_dir}")
  endif()
endfunction()

npf_add_unit_test(test_smoke unit/test_smoke.cpp)
npf_add_unit_test(test_byte_span unit/test_byte_span.cpp)
npf_add_unit_test(test_pool unit/test_pool.cpp)
npf_count_allocations(test_pool)
npf_add_unit_test(test_mac unit/test_mac.cpp)
npf_add_unit_test(test_ethernet unit/test_ethernet.cpp)
npf_add_unit_test(test_arp unit/test_arp.cpp)
npf_add_unit_test(test_checksum unit/test_checksum.cpp)
npf_add_unit_test(test_ipv4 unit/test_ipv4.cpp)
npf_add_unit_test(test_l4 unit/test_l4.cpp)
npf_add_unit_test(test_lpm_linear unit/test_lpm_linear.cpp)
npf_count_allocations(test_lpm_linear)
target_link_libraries(test_lpm_linear PRIVATE npf_table)
npf_add_unit_test(test_config unit/test_config.cpp)
target_compile_definitions(test_config PRIVATE NPF_CONFIG_DIR="${PROJECT_SOURCE_DIR}/configs")

# libFuzzer ships only with Clang, and ThreadSanitizer cannot be combined with the fuzzers' ASan.
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND NOT NPF_SANITIZER STREQUAL "tsan")
  add_subdirectory(fuzz)
endif()
