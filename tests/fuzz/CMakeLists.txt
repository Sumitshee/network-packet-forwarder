# libFuzzer harnesses. Added by tests/CMakeLists.txt only for Clang (GCC has no libFuzzer) and
# never under ThreadSanitizer, which cannot be combined with the fuzzers' AddressSanitizer.
#
# Run one, e.g. for the CI's 60 seconds:
#   build/ci/tests/fuzz/fuzz_ethernet -max_total_time=60 build/ci/tests/fuzz/corpus/ethernet
foreach(harness fuzz_ethernet fuzz_arp)
  add_executable(${harness} ${harness}.cpp)
  target_link_libraries(${harness} PRIVATE npf_warnings npf_core)
  # -UNDEBUG keeps assert() live in every preset: a fuzzer should trip on each broken
  # precondition, not only on the ones ASan can see.
  target_compile_options(${harness} PRIVATE
    -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -UNDEBUG)
  target_link_options(${harness} PRIVATE -fsanitize=fuzzer,address,undefined)
endforeach()

# The seed corpora, one file per fixture frame, regenerated whenever a fixture changes.
file(GLOB npf_fixture_pcaps CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/tests/fixtures/*.pcap)
add_executable(pcap_to_corpus pcap_to_corpus.cpp)
target_include_directories(pcap_to_corpus PRIVATE ${PROJECT_SOURCE_DIR}/tests)
target_link_libraries(pcap_to_corpus PRIVATE npf_warnings npf_core)
set(npf_corpus_stamp ${CMAKE_CURRENT_BINARY_DIR}/corpus/.stamp)
add_custom_command(
  OUTPUT ${npf_corpus_stamp}
  COMMAND pcap_to_corpus ${CMAKE_CURRENT_BINARY_DIR}/corpus ${npf_fixture_pcaps}
  COMMAND ${CMAKE_COMMAND} -E touch ${npf_corpus_stamp}
  DEPENDS pcap_to_corpus ${npf_fixture_pcaps}
  COMMENT "Seeding the fuzz corpora from tests/fixtures"
  VERBATIM)
add_custom_target(fuzz_corpus ALL DEPENDS ${npf_corpus_stamp})
