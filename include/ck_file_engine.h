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
    CKFE_API_EXCEPTION = 3
} ckfe_api_status;

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
    int32_t state;
    int32_t domain;
    int64_t code;
    char *operation;
} ckfe_error;

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
CK_FILE_ENGINE_API const char *ckfe_api_status_name(ckfe_api_status status);
CK_FILE_ENGINE_API const char *ckfe_job_state_name(ckfe_job_state state);
// Initialize before first use. Every successful API call overwrites an error;
// ckfe_error_free releases the operation string owned by the caller.
CK_FILE_ENGINE_API void ckfe_error_init(ckfe_error *error);
CK_FILE_ENGINE_API void ckfe_error_free(ckfe_error *error);

CK_FILE_ENGINE_API ckfe_api_status ckfe_engine_create(ckfe_engine **out_engine);
CK_FILE_ENGINE_API void ckfe_engine_destroy(ckfe_engine *engine);

// Paths are absolute UTF-8 lexical addresses. The native adapter performs the
// final open using its platform-native wide/handle boundary; paths are never
// reopened from display text during a job.
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
