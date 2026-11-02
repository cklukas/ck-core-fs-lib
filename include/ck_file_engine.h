// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef CK_FILE_ENGINE_H
#define CK_FILE_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(CK_FILE_ENGINE_BUILD)
#define CK_FILE_ENGINE_API __declspec(dllexport)
#elif defined(_WIN32)
#define CK_FILE_ENGINE_API __declspec(dllimport)
#else
#define CK_FILE_ENGINE_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ckfe_engine ckfe_engine;
typedef struct ckfe_directory ckfe_directory;
typedef struct ckfe_entry ckfe_entry;
typedef struct ckfe_job ckfe_job;

typedef enum ckfe_api_status {
    CKFE_API_OK = 0,
    CKFE_API_INVALID_ARGUMENT = 1,
    CKFE_API_OUT_OF_MEMORY = 2,
    CKFE_API_EXCEPTION = 3,
    CKFE_API_OPERATION_UNAVAILABLE = 4
} ckfe_api_status;

typedef enum ckfe_observation_state {
    CKFE_OBSERVATION_AVAILABLE = 0,
    CKFE_OBSERVATION_UNSUPPORTED = 1,
    CKFE_OBSERVATION_UNKNOWN = 2,
    CKFE_OBSERVATION_DENIED = 3,
    CKFE_OBSERVATION_GONE = 4,
    CKFE_OBSERVATION_CHANGED = 5,
    CKFE_OBSERVATION_FAILED = 6
} ckfe_observation_state;

typedef enum ckfe_error_domain {
    CKFE_ERROR_NONE = 0,
    CKFE_ERROR_POSIX = 1,
    CKFE_ERROR_WIN32 = 2,
    CKFE_ERROR_ADAPTER = 3,
    CKFE_ERROR_NTSTATUS = 4
} ckfe_error_domain;

typedef enum ckfe_adapter_error {
    CKFE_ADAPTER_INVALID_PATH = 1,
    CKFE_ADAPTER_INVALID_NATIVE_RESULT = 2,
    CKFE_ADAPTER_NOT_APPLICABLE = 3,
    CKFE_ADAPTER_UNSUPPORTED_QUERY = 4,
    CKFE_ADAPTER_UNQUALIFIED_IDENTITY = 5,
    CKFE_ADAPTER_INTERRUPTED_READ = 6,
    CKFE_ADAPTER_FINAL_LINK_REJECTED = 7,
    CKFE_ADAPTER_NOT_DIRECTORY = 8,
    CKFE_ADAPTER_INVENTORY_LIMIT = 9,
    CKFE_ADAPTER_INVALID_LIMIT = 10,
    CKFE_ADAPTER_INVALID_IDENTIFIER = 11,
    CKFE_ADAPTER_INVALID_ACCESS = 12,
    CKFE_ADAPTER_ATTRIBUTE_ABSENT = 13,
    CKFE_ADAPTER_PROVIDER_REVIEW_REQUIRED = 14,
    CKFE_ADAPTER_METADATA_CHANGED = 15,
    CKFE_ADAPTER_UNREPRESENTABLE_NAME = 16,
    CKFE_ADAPTER_PLAN_INVALID = 17,
    CKFE_ADAPTER_PLAN_TOPOLOGY_UNSAFE = 18,
    CKFE_ADAPTER_PLAN_DECISION_STALE = 19
} ckfe_adapter_error;

typedef enum ckfe_job_state {
    CKFE_JOB_READY = 0,
    CKFE_JOB_RUNNING = 1,
    CKFE_JOB_COMPLETED = 2,
    CKFE_JOB_CANCELLED = 3,
    CKFE_JOB_FAILED = 4,
    CKFE_JOB_CHANGED = 5,
    CKFE_JOB_UNSUPPORTED = 6,
    CKFE_JOB_DENIED = 7,
    CKFE_JOB_RECOVERY_REQUIRED = 8
} ckfe_job_state;

typedef enum ckfe_object_kind {
    CKFE_OBJECT_UNKNOWN = 0,
    CKFE_OBJECT_REGULAR_FILE = 1,
    CKFE_OBJECT_DIRECTORY = 2,
    CKFE_OBJECT_SYMBOLIC_LINK = 3,
    CKFE_OBJECT_JUNCTION = 4,
    CKFE_OBJECT_REPARSE_POINT = 5,
    CKFE_OBJECT_OTHER = 255
} ckfe_object_kind;

typedef struct ckfe_error {
    ckfe_observation_state state;
    ckfe_error_domain domain;
    int64_t code;
    char *operation;
} ckfe_error;

enum {
    CKFE_METADATA_KIND = UINT64_C(1) << 0,
    CKFE_METADATA_LOGICAL_SIZE = UINT64_C(1) << 1,
    CKFE_METADATA_ALLOCATED_SIZE = UINT64_C(1) << 2,
    CKFE_METADATA_LINK_COUNT = UINT64_C(1) << 3,
    CKFE_METADATA_IDENTITY = UINT64_C(1) << 4
};

typedef struct ckfe_metadata {
    uint64_t available_fields;
    uint32_t kind;
    uint64_t logical_size;
    uint64_t allocated_size;
    uint64_t link_count;
    uint8_t identity_scheme;
    uint8_t identity_volume[16];
    uint8_t identity_object[16];
    uint8_t has_generation;
    uint64_t generation;
} ckfe_metadata;

typedef struct ckfe_job_snapshot {
    ckfe_job_state state;
    uint64_t processed_items;
    uint64_t total_items;
    uint8_t total_items_known;
    uint64_t processed_bytes;
    uint64_t total_bytes;
    uint8_t total_bytes_known;
} ckfe_job_snapshot;

CK_FILE_ENGINE_API const char *ckfe_version(void);
CK_FILE_ENGINE_API uint32_t ckfe_abi_version_major(void);
CK_FILE_ENGINE_API uint32_t ckfe_abi_version_minor(void);
CK_FILE_ENGINE_API const char *ckfe_api_status_name(ckfe_api_status status);
CK_FILE_ENGINE_API const char *ckfe_job_state_name(ckfe_job_state state);
// Initialize before first use. APIs accepting an error output clear it on
// entry and overwrite it on failure; ckfe_error_free releases the operation
// string owned by the caller. Failed APIs also reset caller-provided output
// handles/metadata to their empty value when those output pointers are nonnull.
CK_FILE_ENGINE_API void ckfe_error_init(ckfe_error *error);
CK_FILE_ENGINE_API void ckfe_error_free(ckfe_error *error);

CK_FILE_ENGINE_API ckfe_api_status ckfe_engine_create(ckfe_engine **out_engine);
CK_FILE_ENGINE_API void ckfe_engine_destroy(ckfe_engine *engine);

// UTF-8 paths/names are absolute UTF-8 lexical addresses on Windows. On POSIX
// the *_utf8 entry points preserve every non-NUL byte verbatim, including
// byte sequences that are not valid UTF-8. Use the UTF-16 entry points for
// exact Windows UTF-16 names. The native adapter performs the final open
// using its platform-native wide/handle boundary; paths are never reopened
// from display text during a job.
CK_FILE_ENGINE_API ckfe_api_status ckfe_directory_open_utf8(
    ckfe_engine *engine, const char *absolute_path_utf8, int follow_final_link,
    ckfe_directory **out_directory, ckfe_error *error);
CK_FILE_ENGINE_API ckfe_api_status ckfe_directory_open_utf16(
    ckfe_engine *engine, const uint16_t *absolute_path_utf16, size_t units,
    int follow_final_link, ckfe_directory **out_directory, ckfe_error *error);
CK_FILE_ENGINE_API void ckfe_directory_destroy(ckfe_directory *directory);

CK_FILE_ENGINE_API ckfe_api_status ckfe_entry_open_utf8(
    ckfe_directory *directory, const char *name_utf8, ckfe_entry **out_entry,
    ckfe_error *error);
CK_FILE_ENGINE_API ckfe_api_status ckfe_entry_open_utf16(
    ckfe_directory *directory, const uint16_t *name_utf16, size_t units,
    ckfe_entry **out_entry, ckfe_error *error);
CK_FILE_ENGINE_API void ckfe_entry_destroy(ckfe_entry *entry);
CK_FILE_ENGINE_API ckfe_api_status ckfe_entry_metadata(
    const ckfe_entry *entry, ckfe_metadata *metadata, ckfe_error *error);

// Starts a worker-owned, journaled regular-file operation. The returned job
// owns all native handles and can be polled without UI callbacks. Destroying a
// job requests cancellation and joins its worker before releasing ownership.
CK_FILE_ENGINE_API ckfe_api_status ckfe_job_start_copy_regular(
    ckfe_entry *source, ckfe_directory *destination, const char *destination_name_utf8,
    const char *journal_root_utf8, int allow_metadata_loss,
    ckfe_job **out_job, ckfe_error *error);
CK_FILE_ENGINE_API ckfe_api_status ckfe_job_start_move_regular(
    ckfe_entry *source, ckfe_directory *destination, const char *destination_name_utf8,
    const char *journal_root_utf8, int allow_metadata_loss,
    ckfe_job **out_job, ckfe_error *error);
CK_FILE_ENGINE_API void ckfe_job_cancel(ckfe_job *job);
CK_FILE_ENGINE_API ckfe_api_status ckfe_job_poll(
    ckfe_job *job, ckfe_job_snapshot *snapshot, ckfe_error *error);
CK_FILE_ENGINE_API void ckfe_job_destroy(ckfe_job *job);

#ifdef __cplusplus
}
#endif

#endif
