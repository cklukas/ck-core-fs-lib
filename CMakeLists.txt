cmake_minimum_required(VERSION 3.25)

project(ck-core-fs-lib VERSION 0.3.0 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CK_CORE_FS_BUILD_BROWSER "Build the higher-level C++ file browser models" ON)

set(CK_CORE_FS_SOURCES
  src/files/ancestor_walk_job.cpp
  src/files/attributes.cpp
  src/files/child_lookup.cpp
  src/files/data_channels.cpp
  src/files/data_layout.cpp
  src/files/destination_batch_job.cpp
  src/files/destination_conflict_projection.cpp
  src/files/destination_directory_assessment.cpp
  src/files/destination_names_job.cpp
  src/files/directory_access.cpp
  src/files/directory_cursor.cpp
  src/files/directory_entry_probe.cpp
  src/files/directory_index_record.cpp
  src/files/directory_index_store.cpp
  src/files/directory_inventory_job.cpp
  src/files/directory_listing.cpp
  src/files/directory_name_rules.cpp
  src/files/file_limits.cpp
  src/files/file_metadata.cpp
  src/files/frozen_inventory.cpp
  src/files/fscrypt_key_status.cpp
  src/files/fscrypt_policy.cpp
  src/files/held_child.cpp
  src/files/inode_flags.cpp
  src/files/integrity_info.cpp
  src/files/link_metadata.cpp
  src/files/location_info.cpp
  src/files/location_relation.cpp
  src/files/monotonic_clock.cpp
  src/files/name_limits.cpp
  src/files/name_mapping.cpp
  src/files/native_delete_recovery_evidence.cpp
  src/files/native_filesystem.cpp
  src/files/native_name.cpp
  src/files/native_operation_copy_job.cpp
  src/files/native_operation_delete_tree.cpp
  src/files/native_operation_move_job.cpp
  src/files/native_operation_recovery.cpp
  src/files/native_operation_recovery_evidence.cpp
  src/files/native_path.cpp
  src/files/object_inventory_job.cpp
  src/files/opened_entry.cpp
  src/files/operation_batch_job.cpp
  src/files/operation_commit_job.cpp
  src/files/operation_consent.cpp
  src/files/operation_copy_job.cpp
  src/files/operation_evidence_assembly.cpp
  src/files/operation_evidence_job.cpp
  src/files/operation_execution_job.cpp
  src/files/operation_journal.cpp
  src/files/operation_journal_file.cpp
  src/files/operation_metadata_job.cpp
  src/files/operation_plan_assembly.cpp
  src/files/operation_planning_coordinator.cpp
  src/files/operation_recovery.cpp
  src/files/operation_review.cpp
  src/files/operation_topology_projection.cpp
  src/files/preservation_capability_diff.cpp
  src/files/recursive_inventory_job.cpp
  src/files/security.cpp
  src/files/sha256.cpp
  src/files/source_capability_projection.cpp
  src/files/source_target_job.cpp
  src/files/storage_info.cpp
  src/files/stream_copy_job.cpp
  src/files/unicode_scalar.cpp
  src/files/windows_directory_record.cpp
  src/files/windows_name.cpp
  src/files/windows_parent_record.cpp
  src/files/windows_stream_records.cpp
)

add_library(ck_core_fs_engine STATIC ${CK_CORE_FS_SOURCES})
target_sources(ck_core_fs_engine PRIVATE
  src/files/preservation_policy.cpp
  src/files/regular_metadata_preservation.cpp
  src/files/comparison_plan.cpp
  src/files/conflict_rules.cpp
  src/files/sync_baseline.cpp
  src/files/metadata_replay.cpp
  src/files/sync_session.cpp)
target_sources(ck_core_fs_engine PRIVATE src/files/native_trash.cpp)
target_compile_definitions(ck_core_fs_engine PRIVATE CK_FS_POLICY_STATIC)
add_library(ck_file_engine ALIAS ck_core_fs_engine)
set_target_properties(ck_core_fs_engine PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(ck_core_fs_engine
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/files>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include/ck-core-fs>
         $<INSTALL_INTERFACE:include>)
target_compile_features(ck_core_fs_engine PUBLIC cxx_std_20)

# Pane ordering/filtering and index views depend on browser policy. The reusable
# directory_index_record/store primitives remain in the engine below this layer.
if(CK_CORE_FS_BUILD_BROWSER)
  add_library(ck_core_fs_browser STATIC
    src/files/directory_index_listing_job.cpp
    src/files/directory_index_lookup.cpp
    src/files/directory_index_marks.cpp
    src/files/directory_index_sort_job.cpp
    src/files/indexed_pane.cpp
    src/files/indexed_pane_marks.cpp
    src/files/indexed_pane_sources.cpp
    src/files/pane_acquire_job.cpp
    src/files/pane_command.cpp
    src/files/pane_filter.cpp
    src/files/pane_listing_job.cpp
    src/files/pane_model.cpp
    src/files/pane_order.cpp
    src/files/pane_page.cpp
    src/files/pane_refresh_job.cpp)
  add_library(ck_files_core ALIAS ck_core_fs_browser)
  set_target_properties(ck_core_fs_browser PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_link_libraries(ck_core_fs_browser PUBLIC ck_core_fs_engine)
endif()

add_library(ck_files_platform STATIC)
set_target_properties(ck_files_platform PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(WIN32)
  target_sources(ck_files_platform PRIVATE
    src/files/platform/metadata_windows.cpp
    src/files/platform/index_file_windows.cpp
    src/files/platform/operation_journal_file_windows.cpp
    src/files/platform/sync_session_windows.cpp
    src/files/platform/trash_windows.cpp
    src/files/platform/home_windows.cpp)
  target_link_libraries(ck_files_platform PRIVATE ntdll advapi32 bcrypt userenv)
else()
  target_sources(ck_files_platform PRIVATE
    src/files/platform/metadata_posix.cpp
    src/files/platform/index_file_posix.cpp
    src/files/platform/operation_journal_file_posix.cpp
    src/files/platform/sync_session_posix.cpp
    src/files/platform/home_posix.cpp)
endif()
target_link_libraries(ck_files_platform PUBLIC ck_core_fs_engine)
target_include_directories(ck_files_platform PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/files>)
target_compile_features(ck_files_platform PUBLIC cxx_std_20)

# Native operation composition depends on the platform boundary. Keep it above
# the portable engine so static consumers have a directed dependency graph;
# platform implementations can call portable codecs without an archive cycle.
add_library(ck_core_fs_native STATIC
  src/files/reviewed_tree_plan.cpp
  src/files/retained_target.cpp
  src/files/action_jobs.cpp)
set_target_properties(ck_core_fs_native PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(ck_core_fs_native PUBLIC ck_files_platform)
target_compile_features(ck_core_fs_native PUBLIC cxx_std_20)

add_library(ck_file_engine_c SHARED src/c-api/ck_file_engine.cpp src/c-api/preservation_policy_c.cpp
  src/c-api/comparison_plan_c.cpp src/c-api/tree_c.cpp src/c-api/actions_c.cpp src/c-api/session_c.cpp)
target_compile_features(ck_file_engine_c PUBLIC cxx_std_20)
target_compile_definitions(ck_file_engine_c PRIVATE CK_FILE_ENGINE_BUILD)
target_include_directories(ck_file_engine_c
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include>)
target_link_libraries(ck_file_engine_c PRIVATE ck_core_fs_native)
if(WIN32)
  target_compile_definitions(ck_file_engine_c PRIVATE NOMINMAX)
endif()
set_target_properties(ck_file_engine_c PROPERTIES
  OUTPUT_NAME ck-core-fs-lib
  VERSION ${PROJECT_VERSION}
  SOVERSION 0)

include(CTest)
if(BUILD_TESTING)
  enable_testing()
  set(CK_CORE_FS_NATIVE_TEST_ROOT "${CMAKE_CURRENT_BINARY_DIR}/tasks" CACHE PATH
    "Explicit native fixture root; private-store/ownership tests need an ownership-enforcing filesystem")
  if(NOT IS_ABSOLUTE "${CK_CORE_FS_NATIVE_TEST_ROOT}")
    message(FATAL_ERROR "CK_CORE_FS_NATIVE_TEST_ROOT must be absolute")
  endif()
  file(MAKE_DIRECTORY "${CK_CORE_FS_NATIVE_TEST_ROOT}")
  add_executable(ck_core_fs_c_abi_tests tests/c_abi_smoke.c)
  target_link_libraries(ck_core_fs_c_abi_tests PRIVATE ck_file_engine_c)
  target_include_directories(ck_core_fs_c_abi_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  add_test(NAME ck_core_fs_c_abi_tests COMMAND ck_core_fs_c_abi_tests)
  add_executable(ck_fs_preservation_policy_tests tests/preservation_policy_tests.cpp)
  target_compile_definitions(ck_fs_preservation_policy_tests PRIVATE CK_FS_POLICY_STATIC)
  target_link_libraries(ck_fs_preservation_policy_tests PRIVATE ck_core_fs_engine ck_file_engine_c)
  add_test(NAME preservation_policy COMMAND ck_fs_preservation_policy_tests)
  add_executable(ck_fs_comparison_plan_tests tests/comparison_plan_tests.cpp)
  target_link_libraries(ck_fs_comparison_plan_tests PRIVATE ck_core_fs_engine)
  if(MSVC)
    target_compile_options(ck_fs_comparison_plan_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_comparison_plan_tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME comparison_plan COMMAND ck_fs_comparison_plan_tests)
  add_executable(ck_fs_comparison_plan_c_tests tests/comparison_plan_c_tests.c)
  target_link_libraries(ck_fs_comparison_plan_c_tests PRIVATE ck_file_engine_c)
  if(MSVC)
    target_compile_options(ck_fs_comparison_plan_c_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_comparison_plan_c_tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME comparison_plan_c COMMAND ck_fs_comparison_plan_c_tests)
  add_executable(ck_fs_conflict_rules_tests tests/conflict_rules_tests.cpp)
  target_link_libraries(ck_fs_conflict_rules_tests PRIVATE ck_core_fs_engine)
  add_test(NAME conflict_rules COMMAND ck_fs_conflict_rules_tests)
  add_executable(ck_fs_sync_baseline_tests tests/sync_baseline_tests.cpp)
  target_link_libraries(ck_fs_sync_baseline_tests PRIVATE ck_core_fs_engine)
  add_test(NAME sync_baseline COMMAND ck_fs_sync_baseline_tests)
  add_executable(ck_fs_regular_metadata_tests tests/regular_metadata_preservation_tests.cpp)
  target_link_libraries(ck_fs_regular_metadata_tests PRIVATE ck_files_platform)
  add_test(NAME regular_metadata COMMAND ck_fs_regular_metadata_tests)
  set_tests_properties(regular_metadata PROPERTIES
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  add_executable(ck_fs_job_lifecycle_tests tests/job_lifecycle_tests.cpp)
  target_link_libraries(ck_fs_job_lifecycle_tests PRIVATE ck_file_engine_c)
  add_test(NAME job_lifecycle COMMAND ck_fs_job_lifecycle_tests "${CK_CORE_FS_NATIVE_TEST_ROOT}")
  set_tests_properties(job_lifecycle PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_executable(ck_fs_tree_c_tests tests/tree_c_tests.cpp)
  target_link_libraries(ck_fs_tree_c_tests PRIVATE ck_file_engine_c)
  if(MSVC)
    target_compile_options(ck_fs_tree_c_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_tree_c_tests PRIVATE -UNDEBUG)
  endif()
  foreach(tree_case copy stale cancel keepboth)
    add_test(NAME tree_c_${tree_case} COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tree_c.py $<TARGET_FILE:ck_fs_tree_c_tests>
      ${CK_CORE_FS_NATIVE_TEST_ROOT} ${tree_case})
    set_tests_properties(tree_c_${tree_case} PROPERTIES TIMEOUT 60
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  endforeach()
  foreach(native_suite metadata_replay reviewed_tree_plan sync_session actions_c retained_target)
    add_executable(ck_fs_${native_suite}_tests tests/${native_suite}_tests.cpp)
    target_link_libraries(ck_fs_${native_suite}_tests PRIVATE ck_core_fs_native ck_file_engine_c)
    target_include_directories(ck_fs_${native_suite}_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/c-api)
    if(MSVC)
      target_compile_options(ck_fs_${native_suite}_tests PRIVATE /UNDEBUG)
    else()
      target_compile_options(ck_fs_${native_suite}_tests PRIVATE -UNDEBUG)
    endif()
    if(native_suite STREQUAL "actions_c" OR native_suite STREQUAL "retained_target")
      add_test(NAME ${native_suite} COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_native_fixture.py $<TARGET_FILE:ck_fs_${native_suite}_tests>
        ${CK_CORE_FS_NATIVE_TEST_ROOT})
    else()
      add_test(NAME ${native_suite} COMMAND ck_fs_${native_suite}_tests)
    endif()
    set_tests_properties(${native_suite} PROPERTIES TIMEOUT 180
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  endforeach()
endif()

set(CK_CORE_FS_INSTALL_TARGETS ck_core_fs_engine ck_files_platform ck_core_fs_native ck_file_engine_c)
if(CK_CORE_FS_BUILD_BROWSER)
  list(APPEND CK_CORE_FS_INSTALL_TARGETS ck_core_fs_browser)
endif()
install(TARGETS ${CK_CORE_FS_INSTALL_TARGETS}
  EXPORT ck_core_fs_targets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY src/files/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ck-core-fs
  FILES_MATCHING PATTERN "*.hpp")
install(EXPORT ck_core_fs_targets
  FILE ck-core-fs-targets.cmake
  NAMESPACE ck::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ck-core-fs)

configure_file(cmake/ck-core-fs-lib.pc.in ${CMAKE_CURRENT_BINARY_DIR}/ck-core-fs-lib.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ck-core-fs-lib.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

configure_package_config_file(
  cmake/ck-core-fs-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/ck-core-fs-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ck-core-fs)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/ck-core-fs-config-version.cmake
  COMPATIBILITY SameMajorVersion)
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/ck-core-fs-config.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/ck-core-fs-config-version.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ck-core-fs)
