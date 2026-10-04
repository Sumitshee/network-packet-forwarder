# Tier A microbenchmarks: in-process, no I/O (CLAUDE.md §9). Built by the bench preset.

# The build facts CLAUDE.md §9 requires every result to carry, embedded at configure time. Facts
# about the run itself -- git SHA, kernel, CPU, PMU -- are passed with --benchmark_context.
string(TOUPPER "${CMAKE_BUILD_TYPE}" npf_bench_config)
set(npf_bench_flags "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${npf_bench_config}}")
if(NPF_NATIVE)
  string(APPEND npf_bench_flags " -march=native")
endif()
if(NPF_LTO)
  string(APPEND npf_bench_flags " (LTO)")
endif()
string(STRIP "${npf_bench_flags}" npf_bench_flags)

function(npf_add_bench name source)
  add_executable(${name} ${source})
  target_link_libraries(${name} PRIVATE npf_warnings npf_core benchmark::benchmark)
  target_compile_definitions(${name} PRIVATE
    NPF_BENCH_COMPILER="${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}"
    NPF_BENCH_BUILD_TYPE="${CMAKE_BUILD_TYPE}"
    NPF_BENCH_FLAGS="${npf_bench_flags}")
endfunction()

npf_add_bench(bench_checksum micro/bench_checksum.cpp)
npf_add_bench(bench_lpm micro/bench_lpm.cpp)
target_link_libraries(bench_lpm PRIVATE npf_table)
