# Copyright (c) 2026 C. Klukas. All rights reserved.
# SPDX-License-Identifier: LGPL-2.0-or-later
# Native observation-only journal regression; included inside BUILD_TESTING.
if(NOT BUILD_TESTING OR NOT UNIX)
  message(FATAL_ERROR "Held journal reader native regression requires BUILD_TESTING and UNIX")
endif()
add_executable(ck_fs_held_operation_journal_reader_unix_tests
  tests/held_operation_journal_reader_unix_tests.cpp)
target_compile_features(ck_fs_held_operation_journal_reader_unix_tests PRIVATE cxx_std_20)
target_link_libraries(ck_fs_held_operation_journal_reader_unix_tests PRIVATE
  ck_files_platform ${CMAKE_DL_LIBS})
# The dedicated runner owns a unique fixture below the explicit native
# test root and kills/joins its child at 45s, below the outer CTest60. The library itself rejects unsupported/private-owner providers;
# those failures remain failures, never skipped or translated into success.
add_test(NAME held_operation_journal_reader_unix COMMAND ${Python3_EXECUTABLE}
  ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_held_operation_journal_reader_unix.py
  $<TARGET_FILE:ck_fs_held_operation_journal_reader_unix_tests>
  ${CK_CORE_FS_NATIVE_TEST_ROOT})
set_tests_properties(held_operation_journal_reader_unix PROPERTIES
  TIMEOUT 60 RUN_SERIAL TRUE LABELS "unix;native;journal;read-only;finalization"
  ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
