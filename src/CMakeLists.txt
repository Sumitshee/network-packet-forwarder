add_library(npf_core
  core/config.cpp
  core/pool.cpp)
target_include_directories(npf_core PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_compile_features(npf_core PUBLIC cxx_std_20)
target_link_libraries(npf_core PRIVATE npf_warnings)

add_library(npf_table
  table/arp_cache.cpp
  table/lpm_dir24_8.cpp
  table/lpm_linear.cpp
  table/lpm_patricia.cpp
  table/lpm_trie.cpp
  table/mac_table.cpp)
target_link_libraries(npf_table PUBLIC npf_core PRIVATE npf_warnings)

add_library(npf_io
  io/af_packet.cpp
  io/link.cpp
  io/packet_mmap.cpp
  io/pcap_file.cpp)
target_link_libraries(npf_io PUBLIC npf_core PRIVATE npf_warnings)

# [phase 17] The AF_XDP backend, when libbpf, libxdp and a clang that targets BPF are all here.
# Without them npf still builds, and --io xdp says it was built without AF_XDP.
find_package(Libbpf)
find_program(NPF_BPF_CLANG NAMES clang-18 clang)
if(Libbpf_FOUND AND NPF_BPF_CLANG)
  set(bpf_obj ${CMAKE_CURRENT_BINARY_DIR}/xdp_redirect.o)
  set(bpf_hdr ${CMAKE_CURRENT_BINARY_DIR}/generated/xdp_redirect_object.hpp)
  add_custom_command(
    OUTPUT ${bpf_obj}
    COMMAND ${NPF_BPF_CLANG} -O2 -g -target bpf -I/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}
            -c ${PROJECT_SOURCE_DIR}/bpf/xdp_redirect.c -o ${bpf_obj}
    DEPENDS ${PROJECT_SOURCE_DIR}/bpf/xdp_redirect.c
    COMMENT "Compiling the XDP program bpf/xdp_redirect.c"
    VERBATIM)
  add_custom_command(
    OUTPUT ${bpf_hdr}
    COMMAND ${CMAKE_COMMAND} -DIN=${bpf_obj} -DOUT=${bpf_hdr} -DNAME=kXdpRedirectObject
            -P ${PROJECT_SOURCE_DIR}/cmake/EmbedFile.cmake
    DEPENDS ${bpf_obj} ${PROJECT_SOURCE_DIR}/cmake/EmbedFile.cmake
    VERBATIM)
  # The generated header on its own, for clang-tidy, which reads sources without building them.
  add_custom_target(npf_xdp_object DEPENDS ${bpf_hdr})
  target_sources(npf_io PRIVATE io/af_xdp.cpp ${bpf_hdr})
  target_include_directories(npf_io PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
  target_link_libraries(npf_io PRIVATE Libbpf::libxdp)
  target_compile_definitions(npf_io PUBLIC NPF_HAVE_XDP=1)
  message(STATUS "AF_XDP backend: on (libbpf ${Libbpf_VERSION}, libxdp ${Libxdp_VERSION}, ${NPF_BPF_CLANG})")
else()
  add_custom_target(npf_xdp_object)
  message(STATUS "AF_XDP backend: off (needs libbpf-dev, libxdp-dev and clang)")
endif()

add_library(npf_pipe
  pipe/filter.cpp
  pipe/forward.cpp
  pipe/icmp_gen.cpp
  pipe/worker.cpp)
target_link_libraries(npf_pipe PUBLIC npf_table npf_core Threads::Threads PRIVATE npf_warnings)

add_executable(npf main.cpp)
target_link_libraries(npf PRIVATE npf_pipe npf_io npf_table npf_core npf_warnings)
# build/<preset>/npf, where the plan's commands and the integration tests look for it.
set_target_properties(npf PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
