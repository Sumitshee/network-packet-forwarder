add_library(npf_core
  core/pool.cpp)
target_include_directories(npf_core PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_features(npf_core PUBLIC cxx_std_20)
target_link_libraries(npf_core PRIVATE npf_warnings)
