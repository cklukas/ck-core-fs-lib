cmake_minimum_required(VERSION 3.25)

project(ck-core-fs-lib VERSION 0.1.0 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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
  src/files/directory_index_listing_job.cpp
  src/files/directory_index_lookup.cpp
  src/files/directory_index_marks.cpp
  src/files/directory_index_record.cpp
  src/files/directory_index_sort_job.cpp
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
  src/files/indexed_pane.cpp
  src/files/indexed_pane_marks.cpp
  src/files/indexed_pane_sources.cpp
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
  src/files/pane_acquire_job.cpp
  src/files/pane_command.cpp
  src/files/pane_filter.cpp
  src/files/pane_listing_job.cpp
  src/files/pane_model.cpp
  src/files/pane_order.cpp
  src/files/pane_page.cpp
  src/files/pane_refresh_job.cpp
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
add_library(ck_file_engine ALIAS ck_core_fs_engine)
add_library(ck_files_core ALIAS ck_core_fs_engine)
set_target_properties(ck_core_fs_engine PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(ck_core_fs_engine
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/files>
         $<INSTALL_INTERFACE:include/ck-core-fs>)
target_compile_features(ck_core_fs_engine PUBLIC cxx_std_20)

add_library(ck_files_platform STATIC)
set_target_properties(ck_files_platform PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(WIN32)
  target_sources(ck_files_platform PRIVATE
    src/files/platform/metadata_windows.cpp
    src/files/platform/index_file_windows.cpp
    src/files/platform/operation_journal_file_windows.cpp
    src/files/platform/home_windows.cpp)
  target_link_libraries(ck_files_platform PRIVATE ntdll advapi32 bcrypt userenv)
else()
  target_sources(ck_files_platform PRIVATE
    src/files/platform/metadata_posix.cpp
    src/files/platform/index_file_posix.cpp
    src/files/platform/operation_journal_file_posix.cpp
    src/files/platform/home_posix.cpp)
endif()
target_link_libraries(ck_files_platform PUBLIC ck_core_fs_engine)
target_include_directories(ck_files_platform PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/files>)
target_compile_features(ck_files_platform PUBLIC cxx_std_20)

add_library(ck_file_engine_c SHARED src/c-api/ck_file_engine.cpp)
target_compile_features(ck_file_engine_c PUBLIC cxx_std_20)
target_compile_definitions(ck_file_engine_c PRIVATE CK_FILE_ENGINE_BUILD)
target_include_directories(ck_file_engine_c
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include>)
target_link_libraries(ck_file_engine_c PRIVATE ck_files_platform)
if(WIN32)
  target_compile_definitions(ck_file_engine_c PRIVATE NOMINMAX)
endif()
set_target_properties(ck_file_engine_c PROPERTIES OUTPUT_NAME ck-core-fs-lib)

include(CTest)
if(BUILD_TESTING)
  enable_testing()
  add_executable(ck_core_fs_c_abi_tests tests/c_abi_smoke.c)
  target_link_libraries(ck_core_fs_c_abi_tests PRIVATE ck_file_engine_c)
  target_include_directories(ck_core_fs_c_abi_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  add_test(NAME ck_core_fs_c_abi_tests COMMAND ck_core_fs_c_abi_tests)
endif()

install(TARGETS ck_core_fs_engine ck_files_platform ck_file_engine_c
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
