add_library(npf_core
  core/config.cpp
  core/pool.cpp)
target_include_directories(npf_core PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_features(npf_core PUBLIC cxx_std_20)
target_link_libraries(npf_core PRIVATE npf_warnings)

add_library(npf_table
  table/arp_cache.cpp
  table/lpm_linear.cpp)
target_link_libraries(npf_table PUBLIC npf_core PRIVATE npf_warnings)

add_library(npf_io
  io/af_packet.cpp)
target_link_libraries(npf_io PUBLIC npf_core PRIVATE npf_warnings)

add_library(npf_pipe
  pipe/forward.cpp)
target_link_libraries(npf_pipe PUBLIC npf_table npf_core PRIVATE npf_warnings)

add_executable(npf main.cpp)
target_link_libraries(npf PRIVATE npf_pipe npf_io npf_table npf_core npf_warnings)
# build/<preset>/npf, where the plan's commands and the integration tests look for it.
set_target_properties(npf PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
