# Tier B (CLAUDE.md §9): tools that drive traffic through the netns topology.

# The phase 13 load generator: N UDP flows, a sequence number in each datagram.
add_executable(gen gen.cpp)
target_link_libraries(gen PRIVATE npf_core npf_warnings)
# build/<preset>/bench/system/gen, where the integration tests look for it next to the npf binary.
set_target_properties(gen PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bench/system)

# The phase 14 receiver: counts gen's datagrams, finds the gaps, and times them.
add_executable(sink sink.cpp)
target_link_libraries(sink PRIVATE npf_core npf_warnings)
set_target_properties(sink PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bench/system)
