# Copyright (c) 2026 C. Klukas. All rights reserved.
# SPDX-License-Identifier: LGPL-2.0-or-later
include_guard(GLOBAL)

# Shared by the source-tree CTests and independent installed-SDK qualification.
# This registers only native archive cases, never unsafe legacy OS/IAT hooks.
function(ck_fs_add_native_archive_windows_tests)
  cmake_policy(PUSH)
  if(POLICY CMP0174)
    cmake_policy(SET CMP0174 NEW)
  endif()
  cmake_parse_arguments(PARSE_ARGV 0 A ""
    "NATIVE_TARGET;SOURCE_ROOT;SCRATCH_ROOT;EXPECTED_FS;UNC_ROOT" "")
  cmake_policy(POP)
  # CMake source/command paths use forward separators; native names remain in C++.
  foreach(key SOURCE_ROOT SCRATCH_ROOT UNC_ROOT)
    if(DEFINED A_${key})
      file(TO_CMAKE_PATH "${A_${key}}" A_${key})
    endif()
  endforeach()
  if(A_UNPARSED_ARGUMENTS OR NOT WIN32)
    message(FATAL_ERROR "Native archive Windows registration needs Windows and known arguments")
  endif()
  if(NOT A_EXPECTED_FS MATCHES "^(NTFS|ReFS)$")
    message(FATAL_ERROR "Select an explicit native archive EXPECTED_FS: NTFS or ReFS")
  endif()
  if(NOT IS_ABSOLUTE "${A_SOURCE_ROOT}" OR NOT IS_ABSOLUTE "${A_SCRATCH_ROOT}")
    message(FATAL_ERROR "Native archive source and scratch roots must be absolute")
  endif()
  if(NOT TARGET "${A_NATIVE_TARGET}")
    message(FATAL_ERROR "Native archive registration needs the matching Native target")
  endif()
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_executable(ck_fs_native_archive_write_windows_tests
    "${A_SOURCE_ROOT}/tests/native_archive_write_windows_tests.cpp")
  target_link_libraries(ck_fs_native_archive_write_windows_tests PRIVATE "${A_NATIVE_TARGET}")
  target_compile_features(ck_fs_native_archive_write_windows_tests PRIVATE cxx_std_20)
  if(MSVC)
    target_compile_options(ck_fs_native_archive_write_windows_tests PRIVATE
      /W4 /WX /permissive- /EHsc /GR /utf-8 /UNDEBUG)
    target_link_options(ck_fs_native_archive_write_windows_tests PRIVATE /ENTRY:wmainCRTStartup)
  endif()
  foreach(variant ordinary long raw)
    add_test(NAME native_archive_windows_${variant}
      COMMAND "${Python3_EXECUTABLE}" "${A_SOURCE_ROOT}/tests/run_native_fixture.py"
        $<TARGET_FILE:ck_fs_native_archive_write_windows_tests>
        "${A_SCRATCH_ROOT}" "${A_EXPECTED_FS}" "${variant}")
    set_tests_properties(native_archive_windows_${variant} PROPERTIES
      TIMEOUT 180 RUN_SERIAL TRUE PROCESSORS 1 LABELS "native;archive;windows;${A_EXPECTED_FS}"
      ENVIRONMENT "TEMP=${A_SCRATCH_ROOT};TMP=${A_SCRATCH_ROOT};TMPDIR=${A_SCRATCH_ROOT}")
  endforeach()
  # Optional, explicit reachable UNC fixture: refusal is a native safety result.
  # Unreachable or exit77 is a failure, never an optional-success/skip path.
  if(A_UNC_ROOT)
    if(NOT IS_ABSOLUTE "${A_UNC_ROOT}")
      message(FATAL_ERROR "Configured archive UNC fixture must be absolute")
    endif()
    add_test(NAME native_archive_windows_unc_refusal
      COMMAND "${Python3_EXECUTABLE}" "${A_SOURCE_ROOT}/tests/run_native_fixture.py"
        $<TARGET_FILE:ck_fs_native_archive_write_windows_tests>
        "${A_UNC_ROOT}" "${A_EXPECTED_FS}" unc)
    set_tests_properties(native_archive_windows_unc_refusal PROPERTIES
      TIMEOUT 180 RUN_SERIAL TRUE PROCESSORS 1 LABELS "native;archive;windows;provider-refusal"
      ENVIRONMENT "TEMP=${A_UNC_ROOT};TMP=${A_UNC_ROOT};TMPDIR=${A_UNC_ROOT}")
  endif()
endfunction()
