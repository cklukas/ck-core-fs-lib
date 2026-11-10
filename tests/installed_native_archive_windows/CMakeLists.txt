cmake_minimum_required(VERSION 3.25)
project(archive_installed_ctest LANGUAGES CXX)
include(CTest)
find_package(ck-core-fs CONFIG REQUIRED)
if(NOT IS_ABSOLUTE "${ARCHIVE_TEST_SOURCE_ROOT}")
  message(FATAL_ERROR "Select the exact shared archive test source root")
endif()
include("${ARCHIVE_TEST_SOURCE_ROOT}/cmake/NativeArchiveWindowsTests.cmake")
ck_fs_add_native_archive_windows_tests(
  NATIVE_TARGET ck::ck_core_fs_native SOURCE_ROOT "${ARCHIVE_TEST_SOURCE_ROOT}"
  SCRATCH_ROOT "${CK_CORE_FS_NATIVE_TEST_ROOT}" EXPECTED_FS "${CK_CORE_FS_ARCHIVE_TEST_FS}"
  UNC_ROOT "${CK_CORE_FS_ARCHIVE_UNC_TEST_ROOT}")
