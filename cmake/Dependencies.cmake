# Third-party dependencies, pinned by release tag and verified by SHA-256.
#
# Tag archives are fetched rather than git clones so every build tree (dev, asan, tsan, ci, ...)
# can share one download directory, which CI caches. Extraction and building still happen per
# build tree, so differently-instrumented builds never share object files.

include(FetchContent)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

set(NPF_DEPS_DOWNLOAD_DIR "${CMAKE_SOURCE_DIR}/.deps-cache"
    CACHE PATH "Where dependency tarballs are downloaded and cached")

if(NPF_BUILD_TESTS)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(BUILD_GMOCK ON CACHE BOOL "" FORCE)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
    DOWNLOAD_DIR "${NPF_DEPS_DOWNLOAD_DIR}"
    DOWNLOAD_NAME googletest-v1.15.2.tar.gz)
  FetchContent_MakeAvailable(googletest)
endif()

if(NPF_BUILD_BENCH)
  set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
  set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
  set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(benchmark
    URL https://github.com/google/benchmark/archive/refs/tags/v1.9.0.tar.gz
    URL_HASH SHA256=35a77f46cc782b16fac8d3b107fbfbb37dcd645f7c28eee19f3b8e0758b48994
    DOWNLOAD_DIR "${NPF_DEPS_DOWNLOAD_DIR}"
    DOWNLOAD_NAME benchmark-v1.9.0.tar.gz)
  FetchContent_MakeAvailable(benchmark)
endif()
