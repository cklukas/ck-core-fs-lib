// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef CK_FILE_ENGINE_H
#define CK_FILE_ENGINE_H

#include <stddef.h>
#include <stdint.h>
#include "ck_fs_policy.h"

#if defined(CK_FILE_ENGINE_STATIC)
#define CK_FILE_ENGINE_API
#elif defined(_WIN32) && defined(CK_FILE_ENGINE_BUILD)
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
typedef struct ckfe_recovery ckfe_recovery;

typedef enum ckfe_api_status {
    CKFE_API_OK = 0,
    CKFE_API_INVALID_ARGUMENT = 1,
    CKFE_API_OUT_OF_MEMORY = 2,
    CKFE_API_EXCEPTION = 3,
    CKFE_API_OPERATION_UNAVAILABLE = 4,
    CKFE_API_BUFFER_TOO_SMALL = 5,
    CKFE_API_BUSY = 6,
    CKFE_API_STALE_PLAN = 7,
    CKFE_API_NOT_READY = 8
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

typedef struct ckfe_job_event {
    uint64_t sequence;
    ckfe_job_snapshot snapshot;
} ckfe_job_event;

typedef enum ckfe_recovery_action {
    CKFE_RECOVERY_IGNORE_TERMINAL = 0,
    CKFE_RECOVERY_INSPECT_STAGING = 1,
    CKFE_RECOVERY_VERIFY_DESTINATION = 2,
    CKFE_RECOVERY_VERIFY_BEFORE_RETIREMENT = 3,
    CKFE_RECOVERY_INSPECT_PUBLICATION = 4,
    CKFE_RECOVERY_INSPECT_RETIREMENT = 5,
    CKFE_RECOVERY_INSPECT_DELETION = 6,
    CKFE_RECOVERY_REQUIRE_REVIEW = 7
} ckfe_recovery_action;
typedef struct ckfe_recovery_item {
    uint64_t item;
    uint32_t journal_state;
    ckfe_recovery_action action;
    uint8_t requires_reconciliation;
} ckfe_recovery_item;
typedef struct ckfe_recovery_summary {
    uint64_t items;
    uint8_t requires_reconciliation;
    uint8_t untrusted_tail;
    uint8_t untrusted_evidence;
} ckfe_recovery_summary;

enum {
    CKFE_COPY_OPTIONS_VERSION = 1,
    CKFE_METADATA_COMPLETE_V1 = 0,
    CKFE_METADATA_ORDINARY_CALLER_VISIBLE_V1 = 1
};
typedef struct ckfe_copy_options_v1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t metadata_scope;
    uint32_t allow_metadata_loss;
    uint32_t reserved[4];
} ckfe_copy_options_v1;
enum { CKFE_OWNERSHIP_ORIGINAL = 0, CKFE_OWNERSHIP_CURRENT_CALLER = 1 };
typedef struct ckfe_copy_options_v2 {
    uint32_t version; /* 2 */
    uint32_t struct_size;
    uint32_t metadata_scope, allow_metadata_loss;
    uint32_t ownership, allow_privilege_metadata;
    uint32_t reserved[4];
} ckfe_copy_options_v2;

enum {
    CKFE_PRESERVED_ORDINARY_MODE = 1u << 0,
    CKFE_PRESERVED_ACCESS_TIME = 1u << 1,
    CKFE_PRESERVED_MODIFIED_TIME = 1u << 2,
    CKFE_PRESERVED_SOURCE_OWNER = 1u << 3,
    CKFE_PRESERVED_ACL = 1u << 4,
    CKFE_PRESERVED_XATTRS = 1u << 5,
    CKFE_PRESERVED_LABELS_CAPABILITIES = 1u << 6,
    CKFE_PRESERVED_PRIVILEGE_BITS = 1u << 7,
    CKFE_PRESERVED_BIRTH_CHANGE_TIMES = 1u << 8,
    CKFE_PRESERVED_STORAGE_REPRESENTATION = 1u << 9
};
typedef struct ckfe_job_preservation_report_v1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t requested_scope;
    uint32_t current_effective_uid_gid_applied;
    uint64_t source_preserved_fields;
    uint64_t explicitly_excluded_fields;
    uint64_t unknown_fields;
    ckfe_observation_state provider_qualification;
    uint32_t reserved;
} ckfe_job_preservation_report_v1;

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
// Versioned explicit requested scope. COMPLETE requires qualified full replay.
// ORDINARY_CALLER_VISIBLE requests mode0777, atime/mtime and current caller
// ownership, with native visible metadata/ACL/security replay and verification. It
// excludes arbitrary hidden namespaces, original ownership, birth/ctime and
// physical storage representation: they remain unknown/unpreserved. Unsupported
// providers refuse the request. This is not a complete-metadata-copy profile.
CK_FILE_ENGINE_API ckfe_api_status ckfe_job_start_copy_regular_v1(
    ckfe_entry *source, ckfe_directory *destination, const char *destination_name_utf8,
    const char *journal_root_utf8, const ckfe_copy_options_v1 *options,
    ckfe_job **out_job, ckfe_error *error);
/* Explicit security/ownership policy. Privileged ACL/label/capability replay
 * requires opt-in AND actual native rights; this API never elevates. Missing
 * inventory coverage or a failed exact replay refuses strict publication. */
CK_FILE_ENGINE_API ckfe_api_status ckfe_job_start_copy_regular_v2(
    ckfe_entry *source, ckfe_directory *destination, const char *destination_name_utf8,
    const char *journal_root_utf8, const ckfe_copy_options_v2 *options,
    ckfe_job **out_job, ckfe_error *error);
CK_FILE_ENGINE_API ckfe_api_status ckfe_job_start_move_regular(
    ckfe_entry *source, ckfe_directory *destination, const char *destination_name_utf8,
    const char *journal_root_utf8, int allow_metadata_loss,
    ckfe_job **out_job, ckfe_error *error);
CK_FILE_ENGINE_API void ckfe_job_cancel(ckfe_job *job);
CK_FILE_ENGINE_API ckfe_api_status ckfe_job_poll(
    ckfe_job *job, ckfe_job_snapshot *snapshot, ckfe_error *error);
// Worker progress snapshots use a fixed 64-event queue. Overflow replaces
// oldest snapshots and reports the count; the newest terminal snapshot stays
// available through poll even after draining. Sequence numbers are monotonic.
// A capacity of zero is valid. Draining does not wait for native I/O.
CK_FILE_ENGINE_API ckfe_api_status ckfe_job_drain_events(
    ckfe_job *job, ckfe_job_event *events, size_t capacity,
    size_t *count, uint64_t *coalesced, ckfe_error *error);
// Reports achieved fields only after verified successful completion; excluded
// or unknown fields are never promoted to preserved. Ownership means effective
// UID+GID, explicitly including correction of setgid-parent inheritance.
// Completion with allow_metadata_loss=1 does not qualify the requested scope:
// provider_qualification remains UNKNOWN and caller ownership is not claimed.
// Verified basic fields can still be reported independently of scope coverage.
CK_FILE_ENGINE_API ckfe_api_status ckfe_job_get_preservation_report_v1(
    ckfe_job *job, ckfe_job_preservation_report_v1 *report, size_t report_size,
    ckfe_error *error);
CK_FILE_ENGINE_API void ckfe_job_destroy(ckfe_job *job);

// Bounded, read-only journal inspection; call open on a filesystem worker.
// The private journal is opened through the native adapter. Inspection never
// authorizes replay, cleanup or source retirement. Recovery handles are
// immutable and must not be destroyed concurrently with a read.
CK_FILE_ENGINE_API ckfe_api_status ckfe_recovery_open_utf8(
    const char *private_root, const char *journal_name,
    ckfe_recovery **out, ckfe_error *error);
CK_FILE_ENGINE_API ckfe_api_status ckfe_recovery_get_summary(
    const ckfe_recovery *recovery, ckfe_recovery_summary *summary, ckfe_error *error);
// At most 256 rows per call; a zero capacity probes without consuming rows.
CK_FILE_ENGINE_API ckfe_api_status ckfe_recovery_read_page(
    const ckfe_recovery *recovery, uint64_t first, ckfe_recovery_item *items,
    size_t capacity, size_t *count, ckfe_error *error);
CK_FILE_ENGINE_API void ckfe_recovery_destroy(ckfe_recovery *recovery);

#ifdef __cplusplus
}
#endif

#endif
