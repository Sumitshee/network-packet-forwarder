add_library(npf_core
  core/config.cpp
  core/pool.cpp)
target_include_directories(npf_core PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_features(npf_core PUBLIC cxx_std_20)
target_link_libraries(npf_core PRIVATE npf_warnings)

add_library(npf_table
  table/lpm_linear.cpp)
target_link_libraries(npf_table PUBLIC npf_core PRIVATE npf_warnings)
