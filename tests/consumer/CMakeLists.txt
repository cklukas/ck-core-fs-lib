cmake_minimum_required(VERSION 3.25)
project(ck_core_fs_installed_consumer LANGUAGES C)
# Keep ordinary installed consumers C-only. Instrumented C++ libraries can
# additionally need the matching C++ sanitizer runtime at the final link.
option(CK_CORE_FS_CONSUMER_CXX_LINKER "Link the C11 consumer using the matching C++ driver" OFF)
option(CK_CORE_FS_CONSUMER_MATCH_TEST_PRODUCER
  "Private qualification only: match a BUILD_TESTING=ON producer" OFF)
if(CK_CORE_FS_CONSUMER_CXX_LINKER)
  enable_language(CXX)
endif()
find_package(ck-core-fs 0.5 CONFIG REQUIRED)
add_executable(ck_core_fs_installed_consumer main.c)
set_target_properties(ck_core_fs_installed_consumer PROPERTIES
  C_STANDARD 11 C_STANDARD_REQUIRED YES C_EXTENSIONS NO)
if(CK_CORE_FS_CONSUMER_CXX_LINKER)
  set_property(TARGET ck_core_fs_installed_consumer PROPERTY LINKER_LANGUAGE CXX)
endif()
target_link_libraries(ck_core_fs_installed_consumer PRIVATE ck::ck_file_engine_c)
if(CK_CORE_FS_CONSUMER_MATCH_TEST_PRODUCER)
  target_compile_definitions(ck_core_fs_installed_consumer PRIVATE
    CK_FS_INTERNAL_TEST_HOOKS=1 CK_FS_LEGACY_NATIVE_TEST_OBSERVERS)
  if(WIN32)
    target_compile_definitions(ck_core_fs_installed_consumer PRIVATE CK_FS_NATIVE_CLOSE_TEST_HOOKS)
  endif()
endif()
enable_testing()
add_test(NAME installed_c_consumer COMMAND ck_core_fs_installed_consumer)
