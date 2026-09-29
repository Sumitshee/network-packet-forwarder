include(GoogleTest)

# One executable per test file keeps failures isolated and lets ctest run them in parallel.
function(npf_add_unit_test name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(${name} PRIVATE npf_warnings npf_core GTest::gtest_main)
  # gtest_discover_tests prefixes both test discovery and every test it registers with this
  # property. CMake 3.29 adds TEST_LAUNCHER for exactly this; 3.28 (Ubuntu 24.04) does not have it.
  if(NPF_TEST_LAUNCHER)
    set_target_properties(${name} PROPERTIES CROSSCOMPILING_EMULATOR "${NPF_TEST_LAUNCHER}")
  endif()
  gtest_discover_tests(${name} DISCOVERY_MODE PRE_TEST)
endfunction()

npf_add_unit_test(test_smoke unit/test_smoke.cpp)
npf_add_unit_test(test_byte_span unit/test_byte_span.cpp)
# alloc_counter.cpp replaces the global operator new and delete, so it is compiled only into the
# test that measures allocations; every other test keeps the standard allocator.
npf_add_unit_test(test_pool unit/test_pool.cpp support/alloc_counter.cpp)
# Clang links its ThreadSanitizer runtime statically, and that archive's operator new and delete
# clash with the replacements ("multiple definition"). Its shared runtime lets this binary's
# definitions take precedence, which is how GCC's libtsan.so always behaves.
if(NPF_SANITIZER STREQUAL "tsan" AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  execute_process(COMMAND ${CMAKE_CXX_COMPILER} -print-runtime-dir
                  OUTPUT_VARIABLE npf_clang_runtime_dir
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  COMMAND_ERROR_IS_FATAL ANY)
  target_link_options(test_pool PRIVATE -shared-libsan "-Wl,-rpath,${npf_clang_runtime_dir}")
endif()
