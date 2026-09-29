include(GoogleTest)

# One executable per test file keeps failures isolated and lets ctest run them in parallel.
function(npf_add_unit_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE npf_warnings GTest::gtest_main)
  # gtest_discover_tests prefixes both test discovery and every test it registers with this
  # property. CMake 3.29 adds TEST_LAUNCHER for exactly this; 3.28 (Ubuntu 24.04) does not have it.
  if(NPF_TEST_LAUNCHER)
    set_target_properties(${name} PROPERTIES CROSSCOMPILING_EMULATOR "${NPF_TEST_LAUNCHER}")
  endif()
  gtest_discover_tests(${name} DISCOVERY_MODE PRE_TEST)
endfunction()

npf_add_unit_test(test_smoke unit/test_smoke.cpp)
