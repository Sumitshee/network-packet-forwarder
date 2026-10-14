# Tier B (CLAUDE.md §9): tools that drive traffic through the netns topology.

# The phase 13 load generator: N UDP flows, a sequence number in each datagram.
add_executable(gen gen.cpp)
target_link_libraries(gen PRIVATE npf_core npf_warnings)
# build/<preset>/bench/system/gen, where the integration tests look for it next to the npf binary.
set_target_properties(gen PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bench/system)
