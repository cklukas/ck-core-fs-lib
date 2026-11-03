cmake_minimum_required(VERSION 3.25)

project(ck-core-fs-lib VERSION 0.5.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
find_package(Threads REQUIRED)

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
  src/files/prepared_journal_root.cpp
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
  src/files/metadata_capture_job.cpp
  src/files/native_regular_metadata_job.cpp
  src/files/metadata_ownership_digest.cpp
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
target_link_libraries(ck_core_fs_engine PUBLIC Threads::Threads)

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
target_sources(ck_files_platform PRIVATE
  src/files/private_journal_scope.cpp
  src/files/private_journal_membership.cpp)
set_target_properties(ck_files_platform PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(WIN32)
  target_sources(ck_files_platform PRIVATE
    src/files/platform/metadata_windows.cpp
    src/files/platform/private_journal_scope_windows.cpp
    src/files/platform/private_journal_membership_windows.cpp
    src/files/platform/index_file_windows.cpp
    src/files/platform/operation_journal_file_windows.cpp
    src/files/platform/sync_session_windows.cpp
    src/files/platform/trash_windows.cpp
    src/files/platform/home_windows.cpp)
  target_link_libraries(ck_files_platform PRIVATE ntdll advapi32 bcrypt userenv)
else()
  target_sources(ck_files_platform PRIVATE
    src/files/platform/metadata_posix.cpp
    src/files/platform/private_journal_scope_posix.cpp
    src/files/platform/private_journal_membership_posix.cpp
    src/files/platform/index_file_posix.cpp
    src/files/platform/operation_journal_file_posix.cpp
    src/files/platform/sync_session_posix.cpp
    src/files/platform/home_posix.cpp)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(ck_files_platform PRIVATE
      src/files/platform/linux_anonymous_staging.cpp
      src/files/platform/linux_mount_root.cpp)
  endif()
endif()
target_link_libraries(ck_files_platform PUBLIC ck_core_fs_engine)
target_include_directories(ck_files_platform PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/files>)
target_compile_features(ck_files_platform PUBLIC cxx_std_20)

# Native operation composition depends on the platform boundary. Keep it above
# the portable engine so static consumers have a directed dependency graph;
# platform implementations can call portable codecs without an archive cycle.
add_library(ck_core_fs_native STATIC
  src/files/reviewed_tree_plan.cpp
  src/files/native_main_content_job.cpp
  src/files/regular_execution_source.cpp
  src/files/directory_execution_source.cpp
  src/files/directory_metadata_apply.cpp
  src/files/directory_metadata_verify.cpp
  src/files/native_directory_replay_job.cpp
  src/files/native_directory_replay_verifier.cpp
  src/files/retained_target.cpp
  src/files/action_jobs.cpp
  src/files/native_sync_observation.cpp
  src/files/metadata_semantic_digest.cpp
  src/files/native_sync_ledger.cpp
  src/files/native_sync_coordinator.cpp
  src/files/native_sync_resolution.cpp
  src/files/verified_copy_retry.cpp)
set_target_properties(ck_core_fs_native PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(ck_core_fs_native PUBLIC ck_files_platform)
target_compile_features(ck_core_fs_native PUBLIC cxx_std_20)

add_library(ck_file_engine_c_objects OBJECT src/c-api/ck_file_engine.cpp src/c-api/preservation_policy_c.cpp
  src/c-api/comparison_plan_c.cpp src/c-api/tree_c.cpp src/c-api/actions_c.cpp src/c-api/session_c.cpp
  src/c-api/retry_c.cpp src/c-api/journal_root_c.cpp)
set_target_properties(ck_file_engine_c_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(ck_file_engine_c_objects PRIVATE cxx_std_20)
target_compile_definitions(ck_file_engine_c_objects PRIVATE CK_FILE_ENGINE_BUILD)
target_link_libraries(ck_file_engine_c_objects PRIVATE ck_core_fs_native)
if(WIN32)
  target_compile_definitions(ck_file_engine_c_objects PRIVATE NOMINMAX)
endif()
add_library(ck_file_engine_c SHARED $<TARGET_OBJECTS:ck_file_engine_c_objects>)
target_compile_features(ck_file_engine_c PUBLIC cxx_std_20)
target_compile_definitions(ck_file_engine_c PRIVATE CK_FILE_ENGINE_BUILD)
target_include_directories(ck_file_engine_c
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include>)
target_link_libraries(ck_file_engine_c PRIVATE ck_core_fs_native)
if(WIN32)
  target_compile_definitions(ck_file_engine_c PRIVATE NOMINMAX)
endif()
# Each C ABI runtime owns its private C++ implementation and internal calls.
# Public C declarations explicitly retain their default export visibility.
foreach(_ck_private_target ck_core_fs_engine ck_files_platform ck_core_fs_native ck_file_engine_c_objects)
  set_target_properties(${_ck_private_target} PROPERTIES
    CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN YES)
endforeach()
if(CMAKE_EXECUTABLE_FORMAT STREQUAL "ELF")
  include(CheckLinkerFlag)
  check_linker_flag(CXX "LINKER:-Bsymbolic-functions" CK_FS_HAS_BIND_INTERNAL_FUNCTIONS)
  check_linker_flag(CXX "LINKER:--exclude-libs,ALL" CK_FS_HAS_HIDE_PRIVATE_ARCHIVES)
  set(_ck_c_exports "${CMAKE_CURRENT_SOURCE_DIR}/cmake/ck_core_fs_exports.map")
  check_linker_flag(CXX "LINKER:--version-script,${_ck_c_exports}" CK_FS_HAS_C_EXPORT_BOUNDARY)
  if(NOT CK_FS_HAS_BIND_INTERNAL_FUNCTIONS)
    message(FATAL_ERROR "ELF packaging requires local binding of internal SDK function calls")
  endif()
  if(NOT CK_FS_HAS_HIDE_PRIVATE_ARCHIVES)
    message(FATAL_ERROR "ELF packaging requires hiding private archive symbols")
  endif()
  if(NOT CK_FS_HAS_C_EXPORT_BOUNDARY)
    message(FATAL_ERROR "ELF packaging requires an explicit public C export boundary")
  endif()
  target_link_options(ck_file_engine_c PRIVATE "LINKER:-Bsymbolic-functions"
    "LINKER:--exclude-libs,ALL" "LINKER:--version-script,${_ck_c_exports}")
  set_property(TARGET ck_file_engine_c APPEND PROPERTY LINK_DEPENDS "${_ck_c_exports}")
endif()
set_target_properties(ck_file_engine_c PROPERTIES
  OUTPUT_NAME ck-core-fs-lib
  VERSION ${PROJECT_VERSION}
  SOVERSION 0.5)
if(WIN32)
  # An older 0.3 DLL must not satisfy a new consumer's required imports.
  # Keep the import-library/CMake target name stable; version the runtime DLL.
  set_target_properties(ck_file_engine_c PROPERTIES RUNTIME_OUTPUT_NAME ck-core-fs-lib-0.5)
endif()

include(CTest)
if(BUILD_TESTING)
  if(CMAKE_EXECUTABLE_FORMAT STREQUAL "ELF")
    add_executable(ck_fs_elf_session_interposition_tests
      tests/elf_session_interposition_tests.c tests/elf_probe_cpp_runtime.cpp)
    target_include_directories(ck_fs_elf_session_interposition_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(ck_fs_elf_session_interposition_tests PRIVATE ${CMAKE_DL_LIBS})
    set_target_properties(ck_fs_elf_session_interposition_tests PROPERTIES ENABLE_EXPORTS ON)
    add_dependencies(ck_fs_elf_session_interposition_tests ck_file_engine_c)
    add_test(NAME elf_session_interposition COMMAND ck_fs_elf_session_interposition_tests $<TARGET_FILE:ck_file_engine_c>)
  endif()
  enable_testing()
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  # ELF export surface is checked independently of the interposition probe.
  if(CMAKE_EXECUTABLE_FORMAT STREQUAL "ELF")
    add_test(NAME elf_export_surface COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_elf_exports.py
      ${CMAKE_NM} $<TARGET_FILE:ck_file_engine_c> ${CMAKE_CURRENT_SOURCE_DIR}/include)
  endif()
  set(CK_CORE_FS_SHARED_TSAN_RUNTIME "" CACHE FILEPATH "Exact shared TSan runtime selected by qualification")
  if(CK_CORE_FS_SHARED_TSAN_RUNTIME)
    if(NOT CMAKE_EXECUTABLE_FORMAT STREQUAL "ELF" OR NOT EXISTS "${CK_CORE_FS_SHARED_TSAN_RUNTIME}")
      message(FATAL_ERROR "Shared TSan runtime qualification requires an existing ELF runtime")
    endif()
    add_executable(ck_fs_tsan_allocator_runtime_tests tests/tsan_allocator_runtime_tests.cpp)
    target_compile_features(ck_fs_tsan_allocator_runtime_tests PRIVATE cxx_std_20)
    target_link_libraries(ck_fs_tsan_allocator_runtime_tests PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
    add_test(NAME tsan_allocator_runtime COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tsan_allocator_runtime.py
      $<TARGET_FILE:ck_fs_tsan_allocator_runtime_tests> ${CK_CORE_FS_SHARED_TSAN_RUNTIME})
  endif()
  # Mixed C++/C qualification must contain ONE native implementation. Linking
  # the native static archives and the C shared library into the same process
  # duplicates RTTI/state and triggers a genuine ASan ODR violation. Reuse the
  # exact C wrapper objects with the same native archives for these tests.
  # Pure C ABI/job/installed-consumer tests still load the actual shared library.
  add_library(ck_file_engine_c_test_support STATIC $<TARGET_OBJECTS:ck_file_engine_c_objects>)
  target_link_libraries(ck_file_engine_c_test_support PUBLIC ck_core_fs_native)
  target_include_directories(ck_file_engine_c_test_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_compile_definitions(ck_file_engine_c_test_support INTERFACE
    CK_FILE_ENGINE_STATIC CK_FS_POLICY_STATIC CK_FS_SESSION_STATIC)
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
  add_executable(ck_fs_retry_c_abi_tests tests/retry_c_smoke.c)
  target_compile_definitions(ck_fs_retry_c_abi_tests PRIVATE CKFER_C_SMOKE_MAIN)
  target_link_libraries(ck_fs_retry_c_abi_tests PRIVATE ck_file_engine_c)
  add_test(NAME retry_c_abi COMMAND ck_fs_retry_c_abi_tests)
  add_executable(ck_fs_journal_root_c_abi_tests tests/journal_root_c_smoke.c)
  target_compile_definitions(ck_fs_journal_root_c_abi_tests PRIVATE CKFJR_C_SMOKE_MAIN)
  target_link_libraries(ck_fs_journal_root_c_abi_tests PRIVATE ck_file_engine_c)
  add_test(NAME journal_root_c_abi COMMAND ck_fs_journal_root_c_abi_tests)
  add_executable(ck_fs_journal_root_c_native_tests tests/journal_root_c_native.c)
  target_link_libraries(ck_fs_journal_root_c_native_tests PRIVATE ck_file_engine_c)
  add_test(NAME journal_root_c_native COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_native_fixture.py $<TARGET_FILE:ck_fs_journal_root_c_native_tests>
    ${CK_CORE_FS_NATIVE_TEST_ROOT})
  set_tests_properties(journal_root_c_native PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  add_executable(ck_fs_preservation_policy_tests tests/preservation_policy_tests.cpp)
  target_compile_definitions(ck_fs_preservation_policy_tests PRIVATE CK_FS_POLICY_STATIC)
  target_link_libraries(ck_fs_preservation_policy_tests PRIVATE ck_file_engine_c_test_support)
  add_test(NAME preservation_policy COMMAND ck_fs_preservation_policy_tests)
  add_executable(ck_fs_comparison_plan_tests tests/comparison_plan_tests.cpp)
  target_link_libraries(ck_fs_comparison_plan_tests PRIVATE ck_core_fs_engine)
  if(MSVC)
    target_compile_options(ck_fs_comparison_plan_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_comparison_plan_tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME comparison_plan COMMAND ck_fs_comparison_plan_tests)
  add_executable(ck_fs_comparison_metadata_plan_tests tests/comparison_metadata_plan_tests.cpp)
  target_link_libraries(ck_fs_comparison_metadata_plan_tests PRIVATE ck_core_fs_engine)
  if(MSVC)
    target_compile_options(ck_fs_comparison_metadata_plan_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_comparison_metadata_plan_tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME comparison_metadata_plan COMMAND ck_fs_comparison_metadata_plan_tests)
  add_executable(ck_fs_windows_acl_codec_tests tests/native_sync_security_semantics_tests.cpp)
  add_executable(ck_fs_metadata_capture_job_tests tests/metadata_capture_job_tests.cpp)
  add_executable(ck_fs_native_main_content_job_tests tests/native_main_content_job_tests.cpp)
  target_link_libraries(ck_fs_native_main_content_job_tests PRIVATE ck_core_fs_native ${CMAKE_DL_LIBS})
  add_test(NAME native_main_content_job COMMAND ck_fs_native_main_content_job_tests)
  set_tests_properties(native_main_content_job PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ck_fs_linux_mount_root_tests tests/linux_mount_root_tests.cpp)
    target_link_libraries(ck_fs_linux_mount_root_tests PRIVATE ck_files_platform)
    target_compile_options(ck_fs_linux_mount_root_tests PRIVATE -UNDEBUG)
    add_test(NAME linux_mount_root COMMAND ck_fs_linux_mount_root_tests ${CK_CORE_FS_NATIVE_TEST_ROOT})
    set_tests_properties(linux_mount_root PROPERTIES TIMEOUT 180
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  endif()
  add_executable(ck_fs_native_regular_metadata_job_tests tests/native_regular_metadata_job_tests.cpp)
  target_link_libraries(ck_fs_native_regular_metadata_job_tests PRIVATE ck_core_fs_native)
  add_test(NAME native_regular_metadata_job COMMAND ck_fs_native_regular_metadata_job_tests)
  set_tests_properties(native_regular_metadata_job PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  add_executable(ck_fs_regular_execution_source_tests tests/regular_execution_source_tests.cpp)
  target_link_libraries(ck_fs_regular_execution_source_tests PRIVATE ck_core_fs_native)
  add_test(NAME regular_execution_source COMMAND ck_fs_regular_execution_source_tests)
  set_tests_properties(regular_execution_source PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  add_executable(ck_fs_regular_metadata_review_tests tests/regular_metadata_review_tests.cpp)
  target_link_libraries(ck_fs_regular_metadata_review_tests PRIVATE ck_core_fs_native ${CMAKE_DL_LIBS})
  add_test(NAME regular_metadata_review COMMAND ck_fs_regular_metadata_review_tests --patched)
  set_tests_properties(regular_metadata_review PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  add_executable(ck_fs_native_directory_replay_job_tests tests/native_directory_replay_job_tests.cpp)
  add_executable(ck_fs_directory_postorder_worker_tests tests/directory_postorder_worker_tests.cpp)
  target_link_libraries(ck_fs_directory_postorder_worker_tests PRIVATE ck_core_fs_native)
  if(MSVC)
    target_link_options(ck_fs_directory_postorder_worker_tests PRIVATE /ENTRY:wmainCRTStartup)
    target_compile_options(ck_fs_directory_postorder_worker_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_directory_postorder_worker_tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME directory_postorder_worker COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_directory_replay_job.py
    $<TARGET_FILE:ck_fs_directory_postorder_worker_tests> ${CK_CORE_FS_NATIVE_TEST_ROOT})
  set_tests_properties(directory_postorder_worker PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  target_link_libraries(ck_fs_native_directory_replay_job_tests PRIVATE ck_core_fs_native)
  if(MSVC)
    target_link_options(ck_fs_native_directory_replay_job_tests PRIVATE /ENTRY:wmainCRTStartup)
    target_compile_options(ck_fs_native_directory_replay_job_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_native_directory_replay_job_tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME native_directory_replay_job COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_directory_replay_job.py
    $<TARGET_FILE:ck_fs_native_directory_replay_job_tests> ${CK_CORE_FS_NATIVE_TEST_ROOT})
  set_tests_properties(native_directory_replay_job PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  target_link_libraries(ck_fs_metadata_capture_job_tests PRIVATE ck_core_fs_native)
  add_test(NAME metadata_capture_job COMMAND ck_fs_metadata_capture_job_tests)
  set_tests_properties(metadata_capture_job PROPERTIES
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  target_link_libraries(ck_fs_windows_acl_codec_tests PRIVATE ck_file_engine_c_test_support)
  add_test(NAME windows_acl_codec COMMAND ck_fs_windows_acl_codec_tests --codec)
  if(WIN32)
    set(CK_CORE_FS_SECURITY_NATIVE_FS "" CACHE STRING "Explicit NTFS/ReFS fixture for native persistent-security qualification")
    if(CK_CORE_FS_SECURITY_NATIVE_FS)
      if(NOT CK_CORE_FS_SECURITY_NATIVE_FS MATCHES "^(NTFS|ReFS)$")
        message(FATAL_ERROR "Native security fixture must explicitly select NTFS or ReFS")
      endif()
      add_test(NAME windows_native_security COMMAND ck_fs_windows_acl_codec_tests)
      set_tests_properties(windows_native_security PROPERTIES
        ENVIRONMENT "TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};CK_SECURITY_SEMANTICS_EXPECT_FS=${CK_CORE_FS_SECURITY_NATIVE_FS}")
    endif()
  endif()
  add_executable(ck_fs_comparison_plan_c_tests tests/comparison_plan_c_tests.c)
  target_link_libraries(ck_fs_comparison_plan_c_tests PRIVATE ck_file_engine_c)
  if(MSVC)
    target_compile_options(ck_fs_comparison_plan_c_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_comparison_plan_c_tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME comparison_plan_c COMMAND ck_fs_comparison_plan_c_tests)
  add_executable(ck_fs_tree_diagnostics_cache_tests tests/tree_diagnostics_cache_tests.cpp)
  target_link_libraries(ck_fs_tree_diagnostics_cache_tests PRIVATE ck_file_engine_c_test_support)
  if(MSVC)
    target_compile_options(ck_fs_tree_diagnostics_cache_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_tree_diagnostics_cache_tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME tree_diagnostics_cache COMMAND ck_fs_tree_diagnostics_cache_tests)
  add_executable(ck_fs_action_private_scope_tests tests/action_private_scope_tests.cpp)
  target_link_libraries(ck_fs_action_private_scope_tests PRIVATE ck_file_engine_c_test_support)
  if(MSVC)
    target_compile_options(ck_fs_action_private_scope_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_action_private_scope_tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME action_private_scope COMMAND ck_fs_action_private_scope_tests)
  set_tests_properties(action_private_scope PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  if(WIN32)
    add_executable(ck_fs_action_native_scope_tests tests/action_native_scope_tests.cpp)
    target_link_libraries(ck_fs_action_native_scope_tests PRIVATE ck_core_fs_native)
    target_compile_options(ck_fs_action_native_scope_tests PRIVATE /UNDEBUG)
    add_test(NAME action_native_scope COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_native_fixture.py
      $<TARGET_FILE:ck_fs_action_native_scope_tests> ${CK_CORE_FS_NATIVE_TEST_ROOT})
    set_tests_properties(action_native_scope PROPERTIES TIMEOUT 180
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  endif()
  add_executable(ck_fs_tree_diagnostics_c_tests tests/tree_diagnostics_c_tests.c)
  target_link_libraries(ck_fs_tree_diagnostics_c_tests PRIVATE ck_file_engine_c)
  if(MSVC)
    target_compile_options(ck_fs_tree_diagnostics_c_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_tree_diagnostics_c_tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME tree_diagnostics_c COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tree_diagnostics_c.py
    $<TARGET_FILE:ck_fs_tree_diagnostics_c_tests> ${CK_CORE_FS_NATIVE_TEST_ROOT})
  set_tests_properties(tree_diagnostics_c PROPERTIES TIMEOUT 150
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  add_executable(ck_fs_operation_metadata_job_tests tests/operation_metadata_job_tests.cpp)
  target_link_libraries(ck_fs_operation_metadata_job_tests PRIVATE ck_core_fs_engine)
  add_test(NAME operation_metadata_job COMMAND ck_fs_operation_metadata_job_tests)
  add_executable(ck_fs_conflict_rules_tests tests/conflict_rules_tests.cpp)
  target_link_libraries(ck_fs_conflict_rules_tests PRIVATE ck_core_fs_engine)
  add_test(NAME conflict_rules COMMAND ck_fs_conflict_rules_tests)
  add_executable(ck_fs_sync_baseline_tests tests/sync_baseline_tests.cpp)
  target_link_libraries(ck_fs_sync_baseline_tests PRIVATE ck_core_fs_engine)
  add_test(NAME sync_baseline COMMAND ck_fs_sync_baseline_tests)
  foreach(suite io_finalization recovery_evidence metadata_ownership_digest)
    add_executable(ck_fs_${suite}_tests tests/${suite}_tests.cpp)
    target_link_libraries(ck_fs_${suite}_tests PRIVATE ck_core_fs_engine)
    if(MSVC)
      target_compile_options(ck_fs_${suite}_tests PRIVATE /UNDEBUG)
    else()
      target_compile_options(ck_fs_${suite}_tests PRIVATE -UNDEBUG)
    endif()
    add_test(NAME ${suite} COMMAND ck_fs_${suite}_tests)
  endforeach()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ck_fs_linux_ordinary_metadata_tests tests/linux_ordinary_metadata_tests.cpp)
    target_link_libraries(ck_fs_linux_ordinary_metadata_tests PRIVATE ck_core_fs_native)
    target_compile_options(ck_fs_linux_ordinary_metadata_tests PRIVATE -UNDEBUG)
    # Native mode needs the explicit capability-bearing qualification fixture;
    # the default policy audit does not stand in for those native runs.
    add_test(NAME linux_ordinary_metadata_policy COMMAND ck_fs_linux_ordinary_metadata_tests --policy)
    add_executable(ck_fs_native_sync_resolution_tests tests/native_sync_resolution_tests.cpp)
    target_link_libraries(ck_fs_native_sync_resolution_tests PRIVATE ck_core_fs_native)
    target_compile_options(ck_fs_native_sync_resolution_tests PRIVATE -UNDEBUG)
    add_test(NAME native_sync_resolution COMMAND ck_fs_native_sync_resolution_tests)
    set_tests_properties(native_sync_resolution PROPERTIES TIMEOUT 180
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
    add_executable(ck_fs_native_sync_resolution_c_tests tests/native_sync_resolution_c_tests.c)
    target_link_libraries(ck_fs_native_sync_resolution_c_tests PRIVATE ck_file_engine_c)
    target_compile_options(ck_fs_native_sync_resolution_c_tests PRIVATE -UNDEBUG)
    add_test(NAME native_sync_resolution_c COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_sync_resolution_c.py
      $<TARGET_FILE:ck_fs_native_sync_resolution_c_tests> ${CK_CORE_FS_NATIVE_TEST_ROOT})
    set_tests_properties(native_sync_resolution_c PROPERTIES TIMEOUT 180
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
    add_executable(ck_fs_journal_root_statx_tests tests/journal_root_statx_tests.cpp)
    target_link_libraries(ck_fs_journal_root_statx_tests PRIVATE ck_core_fs_native)
    target_compile_options(ck_fs_journal_root_statx_tests PRIVATE -UNDEBUG)
    target_link_options(ck_fs_journal_root_statx_tests PRIVATE -Wl,--wrap=statx)
    add_test(NAME journal_root_statx COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_native_fixture.py
      $<TARGET_FILE:ck_fs_journal_root_statx_tests> ${CK_CORE_FS_NATIVE_TEST_ROOT})
    set_tests_properties(journal_root_statx PROPERTIES TIMEOUT 60
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
    add_executable(ck_fs_private_journal_scope_mounts_tests tests/private_journal_scope_mounts.cpp)
    target_link_libraries(ck_fs_private_journal_scope_mounts_tests PRIVATE ck_core_fs_native)
    add_test(NAME private_journal_scope_mounts COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_private_scope_mounts.py
      $<TARGET_FILE:ck_fs_private_journal_scope_mounts_tests> ${CK_CORE_FS_NATIVE_TEST_ROOT})
    set_tests_properties(private_journal_scope_mounts PROPERTIES TIMEOUT 180
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
    add_executable(ck_fs_native_staging_tests tests/native_staging_tests.cpp)
    target_link_libraries(ck_fs_native_staging_tests PRIVATE ck_core_fs_native)
    target_compile_options(ck_fs_native_staging_tests PRIVATE -UNDEBUG)
    add_test(NAME native_staging COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_native_fixture.py $<TARGET_FILE:ck_fs_native_staging_tests>
      ${CK_CORE_FS_NATIVE_TEST_ROOT})
    set_tests_properties(native_staging PROPERTIES TIMEOUT 180
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT};CK_FS_REQUIRE_NATIVE_STAGING=1;CK_FS_REQUIRE_UNPRIVILEGED_STAGING=1;CK_FS_REQUIRE_THREAD_FD_STAGING=1")
  endif()
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
  add_executable(ck_fs_tree_c_tests tests/tree_c_tests.cpp)
  target_link_libraries(ck_fs_tree_c_tests PRIVATE ck_file_engine_c)
  if(MSVC)
    target_compile_options(ck_fs_tree_c_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_tree_c_tests PRIVATE -UNDEBUG)
  endif()
  foreach(tree_case copy stale cancel cancelreview keepboth compare prepared_stale)
    add_test(NAME tree_c_${tree_case} COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tree_c.py $<TARGET_FILE:ck_fs_tree_c_tests>
      ${CK_CORE_FS_NATIVE_TEST_ROOT} ${tree_case})
    set_tests_properties(tree_c_${tree_case} PROPERTIES TIMEOUT 60
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  endforeach()
  foreach(native_suite metadata_replay reviewed_tree_plan sync_session actions_c retained_target verified_copy_retry prepared_journal_root private_journal_scope private_journal_membership native_sync_channels)
    add_executable(ck_fs_${native_suite}_tests tests/${native_suite}_tests.cpp)
    if(native_suite STREQUAL "verified_copy_retry")
      target_sources(ck_fs_${native_suite}_tests PRIVATE tests/retry_c_smoke.c)
    endif()
    if(native_suite STREQUAL "prepared_journal_root")
      target_sources(ck_fs_${native_suite}_tests PRIVATE tests/journal_root_c_smoke.c)
    endif()
    if(native_suite STREQUAL "actions_c" OR native_suite STREQUAL "sync_session" OR native_suite STREQUAL "verified_copy_retry" OR native_suite STREQUAL "prepared_journal_root")
      target_link_libraries(ck_fs_${native_suite}_tests PRIVATE ck_file_engine_c_test_support)
    else()
      target_link_libraries(ck_fs_${native_suite}_tests PRIVATE ck_core_fs_native)
    endif()
    target_include_directories(ck_fs_${native_suite}_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/c-api)
    if(MSVC)
      target_compile_options(ck_fs_${native_suite}_tests PRIVATE /UNDEBUG)
    else()
      target_compile_options(ck_fs_${native_suite}_tests PRIVATE -UNDEBUG)
    endif()
    if(native_suite STREQUAL "actions_c" OR native_suite STREQUAL "retained_target" OR native_suite STREQUAL "verified_copy_retry" OR native_suite STREQUAL "prepared_journal_root" OR native_suite STREQUAL "private_journal_scope" OR native_suite STREQUAL "private_journal_membership")
      add_test(NAME ${native_suite} COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_native_fixture.py $<TARGET_FILE:ck_fs_${native_suite}_tests>
        ${CK_CORE_FS_NATIVE_TEST_ROOT})
    else()
      add_test(NAME ${native_suite} COMMAND ck_fs_${native_suite}_tests)
    endif()
    set_tests_properties(${native_suite} PROPERTIES TIMEOUT 180
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  endforeach()
  add_test(NAME reviewed_tree_compare COMMAND ck_fs_reviewed_tree_plan_tests --compare-review-only)
  add_executable(ck_fs_reviewed_tree_root_cancel_tests tests/reviewed_tree_root_cancel_tests.cpp)
  target_link_libraries(ck_fs_reviewed_tree_root_cancel_tests PRIVATE ck_core_fs_native ${CMAKE_DL_LIBS})
  if(MSVC)
    target_compile_options(ck_fs_reviewed_tree_root_cancel_tests PRIVATE /UNDEBUG)
  else()
    target_compile_options(ck_fs_reviewed_tree_root_cancel_tests PRIVATE -UNDEBUG)
  endif()
  add_test(NAME reviewed_tree_root_cancel COMMAND ck_fs_reviewed_tree_root_cancel_tests)
  set_tests_properties(reviewed_tree_root_cancel PROPERTIES TIMEOUT 60
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  set_tests_properties(reviewed_tree_compare PROPERTIES TIMEOUT 60
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  add_test(NAME reviewed_tree_changed_receipts COMMAND ck_fs_reviewed_tree_plan_tests --changed-receipts-only)
  set_tests_properties(reviewed_tree_changed_receipts PROPERTIES TIMEOUT 60
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  add_test(NAME reviewed_tree_private_journal_scope COMMAND ck_fs_reviewed_tree_plan_tests --private-journal-scope)
  add_test(NAME reviewed_tree_progressive_metadata COMMAND ck_fs_reviewed_tree_plan_tests --progressive-metadata)
  add_test(NAME reviewed_tree_loss_main COMMAND ck_fs_reviewed_tree_plan_tests --loss-main)
  set_tests_properties(reviewed_tree_loss_main PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  set_tests_properties(reviewed_tree_progressive_metadata PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  set_tests_properties(reviewed_tree_private_journal_scope PROPERTIES TIMEOUT 180
    ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME reviewed_tree_cancel_writer_finish COMMAND ck_fs_reviewed_tree_plan_tests --cancel-writer-finish)
    set_tests_properties(reviewed_tree_cancel_writer_finish PROPERTIES TIMEOUT 180
      ENVIRONMENT "TMPDIR=${CK_CORE_FS_NATIVE_TEST_ROOT};TEMP=${CK_CORE_FS_NATIVE_TEST_ROOT};TMP=${CK_CORE_FS_NATIVE_TEST_ROOT}")
  endif()
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
