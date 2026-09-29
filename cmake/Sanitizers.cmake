# Sanitizer interface targets. The presets select one through NPF_SANITIZER; it is then applied to
# every target in the build, dependencies included.

add_library(npf_asan INTERFACE)
target_compile_options(npf_asan INTERFACE
  -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
target_link_options(npf_asan INTERFACE
  -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)

add_library(npf_tsan INTERFACE)
target_compile_options(npf_tsan INTERFACE -fsanitize=thread -fno-omit-frame-pointer)
target_link_options(npf_tsan INTERFACE -fsanitize=thread)

# Also sets NPF_TEST_LAUNCHER in the caller's scope: a command prefix that test executables must
# run under, or empty.
function(npf_apply_sanitizer which)
  set(NPF_TEST_LAUNCHER "" PARENT_SCOPE)
  if(which STREQUAL "none")
    return()
  elseif(which STREQUAL "asan")
    link_libraries(npf_asan)
  elseif(which STREQUAL "tsan")
    link_libraries(npf_tsan)
    # GCC 13's TSan runtime aborts with "unexpected memory mapping" on kernels with high mmap ASLR
    # entropy (observed on the WSL2 6.6 kernel). Clang 18's runtime re-executes itself with ASLR
    # off; GCC's does not, so do it for every test process instead of lowering vm.mmap_rnd_bits
    # for the whole machine. Anything else run from a tsan build tree -- the forwarder itself in
    # phase 13 -- needs the same `setarch -R` prefix.
    find_program(NPF_SETARCH setarch REQUIRED)
    set(NPF_TEST_LAUNCHER "${NPF_SETARCH};-R" PARENT_SCOPE)
  else()
    message(FATAL_ERROR "NPF_SANITIZER must be none, asan or tsan (got '${which}')")
  endif()
endfunction()
