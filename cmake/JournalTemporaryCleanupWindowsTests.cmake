# Copyright (c) 2026 C. Klukas. All rights reserved.
# SPDX-License-Identifier: LGPL-2.0-or-later
include_guard(GLOBAL)

# Source-tree registration only. The SDK and client must be rebuilt together
# with the dedicated root-directory safe-hook definition. No old OS/IAT hooks.
function(ck_fs_add_journal_temporary_cleanup_windows_tests)
  cmake_parse_arguments(PARSE_ARGV 0 J ""
    "NATIVE_TARGET;SOURCE_ROOT;SCRATCH_ROOT;EXPECTED_FS" "")
  if(J_UNPARSED_ARGUMENTS OR J_KEYWORDS_MISSING_VALUES OR NOT WIN32)
    message(FATAL_ERROR "Journal temporary cleanup registration needs Windows and complete known arguments")
  endif()
  foreach(key SOURCE_ROOT SCRATCH_ROOT)
    file(TO_CMAKE_PATH "${J_${key}}" J_${key})
    if(NOT IS_ABSOLUTE "${J_${key}}")
      message(FATAL_ERROR "Journal temporary cleanup source and scratch roots must be absolute")
    endif()
  endforeach()
  if(NOT J_SCRATCH_ROOT MATCHES "^[A-Za-z]:/" AND
      NOT J_SCRATCH_ROOT MATCHES "^//[?]/[A-Za-z]:/")
    message(FATAL_ERROR "Journal temporary cleanup requires an explicit local provider root; UNC is outside this suite")
  endif()
  if(NOT J_EXPECTED_FS MATCHES "^(NTFS|ReFS)$")
    message(FATAL_ERROR "Select an explicit journal temporary cleanup provider: NTFS or ReFS")
  endif()
  if(NOT TARGET "${J_NATIVE_TARGET}")
    message(FATAL_ERROR "Journal temporary cleanup requires the matching source-tree Native target")
  endif()
  get_target_property(_journal_imported "${J_NATIVE_TARGET}" IMPORTED)
  if(_journal_imported)
    message(FATAL_ERROR "Journal temporary cleanup requires a coherent source-tree SDK, not an imported archive")
  endif()
  get_directory_property(_journal_directory_definitions COMPILE_DEFINITIONS)
  if(NOT "CK_FS_NATIVE_CLOSE_TEST_HOOKS" IN_LIST _journal_directory_definitions)
    message(FATAL_ERROR "Rebuild the complete SDK and clients with the uniform safe-close directory definition")
  endif()
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_executable(ck_fs_journal_temporary_cleanup_windows_tests
    "${J_SOURCE_ROOT}/tests/journal_temporary_cleanup_windows_tests.cpp")
  target_link_libraries(ck_fs_journal_temporary_cleanup_windows_tests PRIVATE "${J_NATIVE_TARGET}")
  target_compile_features(ck_fs_journal_temporary_cleanup_windows_tests PRIVATE cxx_std_20)
  target_compile_definitions(ck_fs_journal_temporary_cleanup_windows_tests PRIVATE NOMINMAX)
  if(MSVC)
    target_compile_options(ck_fs_journal_temporary_cleanup_windows_tests PRIVATE
      /W4 /WX /permissive- /EHsc /GR /utf-8 /UNDEBUG)
    target_link_options(ck_fs_journal_temporary_cleanup_windows_tests PRIVATE /ENTRY:wmainCRTStartup)
  endif()
  foreach(variant ordinary long)
    foreach(mode control native native-oom consumed consumed-oom)
      set(_journal_test "journal_temporary_cleanup_windows_${J_EXPECTED_FS}_${variant}_${mode}")
      # Reuse the archive suite's launcher: one unique extended-path workspace,
      # no Windows Path.resolve(), inherited workstation V policy, exact cleanup.
      add_test(NAME "${_journal_test}"
        COMMAND "${Python3_EXECUTABLE}" "${J_SOURCE_ROOT}/tests/run_native_fixture.py"
          $<TARGET_FILE:ck_fs_journal_temporary_cleanup_windows_tests>
          "${J_SCRATCH_ROOT}" "${mode}" "${J_EXPECTED_FS}" "${variant}")
      set_tests_properties("${_journal_test}" PROPERTIES
        TIMEOUT 180 RUN_SERIAL TRUE PROCESSORS 1
        LABELS "native;journal;windows;cleanup;${J_EXPECTED_FS}"
        ENVIRONMENT "TEMP=${J_SCRATCH_ROOT};TMP=${J_SCRATCH_ROOT};TMPDIR=${J_SCRATCH_ROOT}")
      if(mode MATCHES "-oom$")
        set_property(TEST "${_journal_test}" APPEND PROPERTY LABELS allocation-failure)
      endif()
    endforeach()
  endforeach()
endfunction()
