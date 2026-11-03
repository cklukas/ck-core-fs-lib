// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef CK_FS_ACTIONS_H
#define CK_FS_ACTIONS_H
#include "ck_file_engine.h"
#include "ck_fs_journal_root.h"
#ifdef __cplusplus
#define CKFEA_NOEXCEPT noexcept
extern "C" {
#else
#define CKFEA_NOEXCEPT
#endif
#define CKFEA_VERSION 1u
#define CKFEA_MAX_ITEMS 256u
#define CKFEA_MAX_JOBS 4u
#define CKFEA_MAX_NAME_BYTES 65536u

typedef struct ckfea_job ckfea_job;
typedef struct ckfea_trash_receipt ckfea_trash_receipt;
typedef uint32_t ckfea_status;
enum { CKFEA_OK=0, CKFEA_INVALID_ARGUMENT=1, CKFEA_OUT_OF_MEMORY=2,
    CKFEA_EXCEPTION=3, CKFEA_BUSY=4, CKFEA_NOT_READY=5, CKFEA_STALE_RECEIPT=6,
    CKFEA_BUFFER_TOO_SMALL=7 };
enum { CKFEA_RENAME=1, CKFEA_TRASH=2, CKFEA_RESTORE=3, CKFEA_VERIFY_RECOVERY=4 };
enum { CKFEA_PREVIEWING=0, CKFEA_AWAITING_RECEIPT=1, CKFEA_RUNNING=2,
    CKFEA_FINISHED=3, CKFEA_CANCELLED=4, CKFEA_JOB_FAILED=5 };
enum { CKFEA_PENDING=0, CKFEA_READY=1, CKFEA_NO_CHANGE=2, CKFEA_COLLISION=3,
    CKFEA_CYCLE=4, CKFEA_UNSUPPORTED=5, CKFEA_CHANGED=6, CKFEA_DENIED=7,
    CKFEA_FAILED=8, CKFEA_VERIFIED=9, CKFEA_REVIEW_REQUIRED=10,
    CKFEA_ITEM_CANCELLED=11, CKFEA_EXECUTING=12 };
enum { CKFEA_ALLOW_NATIVE_TRASH=1u, CKFEA_ALLOW_NATIVE_RESTORE=2u };
enum { CKFEA_CASE_ONLY=1u };
enum { CKFEA_POSIX_BYTES=0, CKFEA_WINDOWS_UTF16=1 };
enum { CKFEA_EVIDENCE_PREVIEW=1, CKFEA_EVIDENCE_INTENT=2,
    CKFEA_EVIDENCE_RESULT=3, CKFEA_EVIDENCE_RETRY=4 };
enum { CKFEA_REASON_NONE=0, CKFEA_REASON_SOURCE_NOT_BOUND=1,
    CKFEA_REASON_NATIVE_RECEIPT_UNAVAILABLE=2, CKFEA_REASON_CAPABILITY_REQUIRED=3,
    CKFEA_REASON_JOURNAL_REQUIRED=4, CKFEA_REASON_UNTRUSTED_RECOVERY=5,
    CKFEA_REASON_DEPENDENCY=6 };

// All structures are v1, exact size, with all reserved fields zero. UTF-16 is
// native uint16_t storage (not UTF-8); byte_count must be even. No terminators.
typedef struct ckfea_native_text {
    uint32_t version, struct_size, encoding, reserved;
    const void *data;
    uint64_t byte_count;
} ckfea_native_text;
typedef struct ckfea_item {
    uint32_t version, struct_size, flags, reserved;
    const ckfe_entry *source;
    ckfea_native_text destination_name; // rename only; same held parent
} ckfea_item;
typedef struct ckfea_request {
    uint32_t version, struct_size, operation, capabilities;
    const ckfea_item *items;
    uint32_t item_count, retry_limit; // 1..256; retry_limit 0..2
    // Rename and Trash require a new journal in an existing platform-private root.
    // These are caller-selected native addresses, never Trash metadata paths.
    ckfea_native_text journal_directory, journal_name;
    const ckfe_recovery *recovery; // verification only, copied on creation
    const ckfe_directory *recovery_destination; // pinned on creation
    uint64_t recovery_item, max_verify_bytes; // bounded to 4 GiB
    uint64_t reserved[4];
} ckfea_request;
// Process-local, one-use consent to this immutable preview and its held inputs.
// Not serializable authority; cannot authorize another job or restart replay.
typedef struct ckfea_receipt {
    uint32_t version, struct_size;
    uint64_t job_id, preview_id;
    uint64_t reserved[2];
} ckfea_receipt;
typedef struct ckfea_identity {
    uint32_t scheme, has_generation;
    uint8_t volume[16], object[16];
    uint64_t generation;
} ckfea_identity;
typedef struct ckfea_result {
    uint32_t version, struct_size, state, reason;
    uint32_t observation, error_domain;
    int64_t error_code;
    uint32_t attempts, reserved;
    ckfea_identity source_identity, parent_identity;
} ckfea_result;
typedef struct ckfea_summary {
    uint32_t version, struct_size, state, item_count;
    uint64_t job_id, evidence_count;
    uint32_t ready_count, verified_count, review_count, reserved;
} ckfea_summary;
typedef struct ckfea_evidence {
    uint32_t version, struct_size, kind, item;
    uint64_t sequence, job_id;
    ckfea_result result;
    uint64_t reserved[2];
} ckfea_evidence;

// Receipt-bound restore has a separate request; existing v1 layouts stay fixed.
// Receipts are produced only by verified native Trash jobs. No serialized or
// caller-fabricated receipt importer exists. Live receipts pin native identities
// across job destruction; disposal queues native closes without joining. Fresh held original parents are
// mandatory; $I path text is never used to select a restore destination.
typedef struct ckfea_restore_item {
    uint32_t version, struct_size;
    const ckfea_trash_receipt *receipt;
    const ckfe_directory *original_parent;
    uint64_t reserved[2];
} ckfea_restore_item;
typedef struct ckfea_restore_request {
    uint32_t version, struct_size, capabilities, item_count;
    const ckfea_restore_item *items;
    ckfea_native_text journal_directory, journal_name;
    uint64_t reserved[4];
} ckfea_restore_request;
typedef struct ckfea_trash_info {
    uint32_t version, struct_size, encoding, reserved;
    ckfea_identity original_parent, object, recycle_parent, metadata_identity;
    uint64_t original_name_bytes, data_name_bytes, metadata_name_bytes;
    uint64_t reserved_words[2];
} ckfea_trash_info;
enum { CKFEA_TRASH_ORIGINAL_NAME=0, CKFEA_TRASH_DATA_NAME=1, CKFEA_TRASH_METADATA_NAME=2 };
CK_FILE_ENGINE_API void ckfea_restore_request_init(ckfea_restore_request*) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API void ckfea_restore_item_init(ckfea_restore_item*) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API ckfea_status ckfea_restore_job_create(const ckfea_restore_request*, ckfea_job**) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API ckfea_status ckfea_restore_job_create_with_journal_root(const ckfea_restore_request*, const ckfjr_root*, ckfea_job**) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API ckfea_status ckfea_job_trash_receipt(const ckfea_job*, uint32_t item, ckfea_trash_receipt**) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API ckfea_status ckfea_trash_receipt_info(const ckfea_trash_receipt*, ckfea_trash_info*) CKFEA_NOEXCEPT;
/* Returns CKFE_OBJECT_REGULAR_FILE or CKFE_OBJECT_DIRECTORY, without I/O.
 * Directory receipts do not claim a recursively measured byte total. */
CK_FILE_ENGINE_API ckfea_status ckfea_trash_receipt_get_kind(const ckfea_trash_receipt*, uint32_t *out_kind) CKFEA_NOEXCEPT;
// Native bytes only, no terminator; required size returned on BUFFER_TOO_SMALL.
CK_FILE_ENGINE_API ckfea_status ckfea_trash_receipt_copy_name(const ckfea_trash_receipt*, uint32_t which,
    void *buffer, uint64_t capacity, uint64_t *out_required) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API void ckfea_trash_receipt_destroy(ckfea_trash_receipt*) CKFEA_NOEXCEPT;

CK_FILE_ENGINE_API void ckfea_request_init(ckfea_request*) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API void ckfea_item_init(ckfea_item*) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API void ckfea_native_text_init(ckfea_native_text*) CKFEA_NOEXCEPT;
// All input references/names are copied or retained before returning; callers
// may then destroy source/directory/recovery handles. Do not concurrently use a
// pinned native cursor in another worker. Maximum four live jobs; one worker
// per job. Native calls may block. No callbacks or exceptions cross this ABI.
CK_FILE_ENGINE_API ckfea_status ckfea_job_create(const ckfea_request*, ckfea_job**) CKFEA_NOEXCEPT;
/* Retains a READY native root. journal_directory is optional navigation/encoding
 * metadata, never reopening authority. Empty stays empty; cached hints are not
 * consulted for journal I/O.
 * Journal name remains an exact native component. A finishing/unready root
 * returns NOT_READY. No native I/O runs on this caller or existing v1 layout
 * changes. Finalize the shared root only after all consuming jobs finish. */
CK_FILE_ENGINE_API ckfea_status ckfea_job_create_with_journal_root(const ckfea_request*, const ckfjr_root*, ckfea_job**) CKFEA_NOEXCEPT;
// Outputs require caller-initialized version/struct_size and zero reserved.
// Invalid output headers are left untouched; valid outputs reset on failure.
CK_FILE_ENGINE_API ckfea_status ckfea_job_summary(const ckfea_job*, ckfea_summary*) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API ckfea_status ckfea_job_item(const ckfea_job*, uint32_t, ckfea_result*) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API ckfea_status ckfea_job_receipt(const ckfea_job*, ckfea_receipt*) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API ckfea_status ckfea_job_execute(ckfea_job*, const ckfea_receipt*) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API ckfea_status ckfea_job_evidence(const ckfea_job*, uint64_t, ckfea_evidence*) CKFEA_NOEXCEPT;
CK_FILE_ENGINE_API ckfea_status ckfea_job_cancel(ckfea_job*) CKFEA_NOEXCEPT;
// Nonblocking cancel/release; worker retains itself and all pinned inputs until
// an in-flight native call finishes. Never destroy concurrently with another call.
CK_FILE_ENGINE_API void ckfea_job_destroy(ckfea_job*) CKFEA_NOEXCEPT;
// Bounded wait: 0 is poll, maximum 1000 ms. Native calls are not interrupted.
CK_FILE_ENGINE_API ckfea_status ckfea_job_wait(ckfea_job*, uint32_t milliseconds) CKFEA_NOEXCEPT;
// Preview reports cycles, duplicate sources/targets and occupied destinations.
// Cycles are blocked; chains run from their free end with no-replace publication.
// Two absent targets require qualified native equivalence; unknown aliases are
// review-only. Independent READY rows can execute when others are blocked. No overwrite,
// permanent delete, source retirement, shell call or blind recovery replay.
// POSIX source-name rename races are gated Unsupported. Windows uses a verified
// source handle. Windows Trash/restore support qualified local NTFS ordinary
// single-link files and directories with explicit capability opt-in and durable
// journals. Directory Trash moves one held object; it never recursively erases.
// POSIX and UNC/provider/reparse objects remain Unsupported.
// Use ckfea_restore_job_create for receipt-bound restore; CKFEA_RESTORE in the
// older general request lacks a native receipt and cannot authorize restore.
// No untrusted trashinfo path is parsed. Trash/restore are never retried.
// Retry is only for an unambiguous Win32 rename failure (sharing/lock violation),
// with fresh parent, held source and namespace checks before every attempt.
// Unknown/partial publication or flush failures are review-only, never retried.
// Evidence events are bounded in-memory observations. Mutating renames also
// flush native-ID/name journal evidence before calling the native boundary.
// Existing recovery inspection can require review of rename journals lacking
// content digests. Verification jobs are read-only and never resume mutation.
#ifdef __cplusplus
}
#endif
#undef CKFEA_NOEXCEPT
#endif
