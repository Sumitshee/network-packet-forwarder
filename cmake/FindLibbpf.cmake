# [phase 17] libbpf and libxdp, for the AF_XDP backend.
#
#   find_package(Libbpf)
#
# Sets Libbpf_FOUND, Libbpf_VERSION and Libxdp_VERSION, and on success defines the imported
# targets Libbpf::libbpf and Libbpf::libxdp. Both libraries are needed: since libbpf 1.0 the AF_XDP
# socket API (xsk.h) lives in libxdp. On Ubuntu: apt install libbpf-dev libxdp-dev.
#
# pkg-config is asked first; without it (Ubuntu does not install it by default), the headers and
# libraries are looked for directly.

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(NPF_PC_LIBBPF QUIET libbpf)
  pkg_check_modules(NPF_PC_LIBXDP QUIET libxdp)
endif()

find_path(Libbpf_INCLUDE_DIR bpf/libbpf.h HINTS ${NPF_PC_LIBBPF_INCLUDE_DIRS})
find_path(Libxdp_INCLUDE_DIR xdp/xsk.h HINTS ${NPF_PC_LIBXDP_INCLUDE_DIRS})
find_library(Libbpf_LIBRARY NAMES bpf HINTS ${NPF_PC_LIBBPF_LIBRARY_DIRS})
find_library(Libxdp_LIBRARY NAMES xdp HINTS ${NPF_PC_LIBXDP_LIBRARY_DIRS})

if(NPF_PC_LIBBPF_VERSION)
  set(Libbpf_VERSION ${NPF_PC_LIBBPF_VERSION})
elseif(Libbpf_INCLUDE_DIR AND EXISTS "${Libbpf_INCLUDE_DIR}/bpf/libbpf_version.h")
  file(STRINGS "${Libbpf_INCLUDE_DIR}/bpf/libbpf_version.h" defs
       REGEX "^#define LIBBPF_(MAJOR|MINOR)_VERSION")
  string(REGEX REPLACE ".*MAJOR_VERSION ([0-9]+).*" "\\1" major "${defs}")
  string(REGEX REPLACE ".*MINOR_VERSION ([0-9]+).*" "\\1" minor "${defs}")
  set(Libbpf_VERSION "${major}.${minor}")
endif()
set(Libxdp_VERSION ${NPF_PC_LIBXDP_VERSION})
if(NOT Libxdp_VERSION AND Libxdp_LIBRARY)
  get_filename_component(real "${Libxdp_LIBRARY}" REALPATH)
  string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+$" Libxdp_VERSION "${real}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libbpf
  REQUIRED_VARS Libbpf_LIBRARY Libbpf_INCLUDE_DIR Libxdp_LIBRARY Libxdp_INCLUDE_DIR
  VERSION_VAR Libbpf_VERSION)
mark_as_advanced(Libbpf_INCLUDE_DIR Libxdp_INCLUDE_DIR Libbpf_LIBRARY Libxdp_LIBRARY)

if(Libbpf_FOUND)
  if(NOT TARGET Libbpf::libbpf)
    add_library(Libbpf::libbpf UNKNOWN IMPORTED)
    set_target_properties(Libbpf::libbpf PROPERTIES
      IMPORTED_LOCATION "${Libbpf_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${Libbpf_INCLUDE_DIR}")
  endif()
  if(NOT TARGET Libbpf::libxdp)
    add_library(Libbpf::libxdp UNKNOWN IMPORTED)
    set_target_properties(Libbpf::libxdp PROPERTIES
      IMPORTED_LOCATION "${Libxdp_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${Libxdp_INCLUDE_DIR}"
      INTERFACE_LINK_LIBRARIES Libbpf::libbpf)
  endif()
endif()
