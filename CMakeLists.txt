cmake_minimum_required(VERSION 3.20)

project(network-packet-forwarder
  VERSION 0.0.0
  DESCRIPTION "Userspace L2/L3 packet forwarding engine"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(NPF_BUILD_TESTS "Build unit and integration tests" ON)
option(NPF_BUILD_BENCH "Build Google Benchmark microbenchmarks" OFF)
option(NPF_NATIVE "Compile with -march=native" OFF)
option(NPF_LTO "Enable link-time optimisation" OFF)
option(NPF_WERROR "Treat warnings as errors (CI turns this on)" OFF)
set(NPF_SANITIZER "none" CACHE STRING "Sanitizer applied to every target: none | asan | tsan")
set_property(CACHE NPF_SANITIZER PROPERTY STRINGS none asan tsan)

# A release binary without symbols cannot be profiled, so Release keeps -g. The default Release
# flags are -O3 without -g; the project standard is -O2 -g.
if(NOT CMAKE_CXX_FLAGS_RELEASE MATCHES "-g")
  set(CMAKE_CXX_FLAGS_RELEASE "-O2 -g -DNDEBUG" CACHE STRING "Release flags" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)
include(Sanitizers)

if(NPF_NATIVE)
  add_compile_options(-march=native)
endif()

if(NPF_LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT npf_ipo_ok OUTPUT npf_ipo_msg LANGUAGES CXX)
  if(NOT npf_ipo_ok)
    message(FATAL_ERROR "NPF_LTO=ON but IPO is not supported: ${npf_ipo_msg}")
  endif()
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

# Sanitizers are applied before dependencies are fetched so GoogleTest and Google Benchmark are
# instrumented too; mixing instrumented and uninstrumented code produces false reports.
npf_apply_sanitizer("${NPF_SANITIZER}")

include(Dependencies)

# Phase 0.5 throwaway prototype. Never link it into anything.
add_executable(skeleton tools/skeleton/skeleton.cpp)

add_subdirectory(src)

if(NPF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
