cmake_minimum_required(VERSION 3.25)
project(ck_fs_embedded_linker_probe LANGUAGES C CXX)

# Reproduce an embedding caller which deliberately avoids links in ordinary
# compiler probes. Legacy failed cache values must not mask corrected probes.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
foreach(legacy CK_FS_HAS_BIND_INTERNAL_FUNCTIONS CK_FS_HAS_HIDE_PRIVATE_ARCHIVES CK_FS_HAS_C_EXPORT_BOUNDARY)
  set(${legacy} "" CACHE INTERNAL "Legacy failed static-library linker probe" FORCE)
endforeach()
foreach(probe CK_FS_LINKER_HAS_BSYMBOLIC_FUNCTIONS CK_FS_LINKER_HAS_EXCLUDE_LIBS_ALL CK_FS_LINKER_HAS_C_EXPORT_MAP)
  unset(${probe} CACHE)
endforeach()
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../.." sdk)
if(NOT CMAKE_TRY_COMPILE_TARGET_TYPE STREQUAL "STATIC_LIBRARY")
  message(FATAL_ERROR "SDK linker checks changed the embedding caller's probe mode")
endif()
# The positive results must come from a real linker, not ignored flags. This
# deliberately invalid flag must fail independently of the SDK's three checks.
unset(CK_FS_INVALID_LINKER_ACCEPTED CACHE)
block()
  set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)
  check_linker_flag(CXX "LINKER:--ckfs-intentionally-invalid-linker-option" CK_FS_INVALID_LINKER_ACCEPTED)
endblock()
if(CK_FS_INVALID_LINKER_ACCEPTED)
  message(FATAL_ERROR "Real linker accepted an intentionally invalid option")
endif()
