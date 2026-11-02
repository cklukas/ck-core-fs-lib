// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef CK_FS_TREE_H
#define CK_FS_TREE_H
#include "ck_file_engine.h"
#include "ck_fs_plan.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Native inventory and execution, independent of the caller-fact preview API.
 * Every start copies options and retains both roots. No worker calls UI code.
 * Public calls only copy bounded memory or queue commands; native I/O runs on
 * the owned worker. release requests cancellation and returns without joining;
 * the worker retains its resources until it reaches a safe stopping point.
 * Calls on one handle may be concurrent except release, which requires callers
 * to stop using that handle. Cancellation/pause are requests, not OS interrupts.
 */
#define CKFET_VERSION UINT32_C(1)
#define CKFET_MAX_RULES UINT32_C(4096)
#define CKFET_MAX_JOBS UINT32_C(32)
typedef struct ckfet_job ckfet_job;
typedef struct ckfet_native { const void *data; uint64_t units; uint32_t encoding; uint32_t reserved; } ckfet_native;
enum { CKFET_POSIX_BYTES = 0, CKFET_UTF16 = 1 };
enum {
    CKFET_INVENTORY = 0, CKFET_AWAITING_REVIEW = 1, CKFET_REVALIDATING = 2,
    CKFET_EXECUTING = 3, CKFET_COMPLETE = 4, CKFET_FAILED = 5,
    CKFET_CANCELLED = 6, CKFET_PARTIAL = 7, CKFET_NEEDS_RECONCILIATION = 8
};
enum {
    CKFET_REPORT = 0, CKFET_SKIP = 1, CKFET_COPY = 2, CKFET_CREATE_DIRECTORY = 3,
    CKFET_MERGE_DIRECTORY = 4, CKFET_REPLACE = 5, CKFET_REMOVE_FILE = 6, CKFET_REMOVE_DIRECTORY = 7
};
enum { CKFET_ITEM_PENDING = 0, CKFET_ITEM_SKIPPED = 1, CKFET_ITEM_COMPLETE = 2,
    CKFET_ITEM_FAILED = 3, CKFET_ITEM_CANCELLED = 4, CKFET_ITEM_NEEDS_RECONCILIATION = 5 };
enum {
    CKFET_CONFLICT_EXISTING_REGULAR = 0, CKFET_CONFLICT_BOTH_EDITED = 1,
    CKFET_CONFLICT_DELETE_EDIT = 2, CKFET_CONFLICT_DIRECTORY_DELETE_EDITED_CHILD = 3,
    CKFET_CONFLICT_TYPE = 4, CKFET_CONFLICT_LINK = 5, CKFET_CONFLICT_NAME = 6,
    CKFET_CONFLICT_METADATA = 7, CKFET_CONFLICT_UNAVAILABLE = 8, CKFET_CONFLICT_STALE = 9,
    CKFET_CONFLICT_AMBIGUOUS = 10, CKFET_CONFLICT_DIRECTORY_PAIR = 11,
    CKFET_CONFLICT_HARD_LINK = 12, CKFET_CONFLICT_ACCESS = 13, CKFET_CONFLICT_CAPACITY = 14
};
enum {
    CKFET_ASK = 0, CKFET_USE_SOURCE = 1, CKFET_KEEP_TARGET = 2, CKFET_NEWEST = 3,
    CKFET_SOURCE_NEWER = 4, CKFET_NEWER_OR_SIZE_AT_EQUAL_TIME = 5, CKFET_SIZE_DIFFERS = 6,
    CKFET_LARGER = 7, CKFET_SMALLER = 8, CKFET_KEEP_BOTH_INCOMING = 9,
    CKFET_KEEP_BOTH_TARGET = 10, CKFET_RENAME = 11, CKFET_COMPARE = 12,
    CKFET_MERGE_FOLDERS = 13, CKFET_RETRY = 14, CKFET_CANCEL = 15, CKFET_SKIP_MATCHING = 16,
    CKFET_KEEP_LEFT = 17, CKFET_KEEP_RIGHT = 18, CKFET_KEEP_BOTH = 19,
    CKFET_RESTORE_DELETED = 20, CKFET_KEEP_EDITED = 21, CKFET_DELETE_EDITED = 22
};
enum { CKFET_SCOPE_ITEM = 0, CKFET_SCOPE_SELECTED = 1, CKFET_SCOPE_SUBTREE = 2, CKFET_SCOPE_JOB = 3 };
enum { CKFET_SOURCE_TO_TARGET = 0, CKFET_LEFT_TO_RIGHT = 1, CKFET_RIGHT_TO_LEFT = 2 };
enum { CKFET_COMMAND_NONE = 0, CKFET_COMMAND_PENDING = 1, CKFET_COMMAND_ACCEPTED = 2, CKFET_COMMAND_REJECTED = 3 };
enum { CKFET_DECISION_NO_MATCH = 0, CKFET_DECISION_APPLY = 1, CKFET_DECISION_REVIEW = 2,
    CKFET_DECISION_STALE = 3, CKFET_DECISION_INVALID = 4 };
enum { CKFET_RULE_NONE = 0, CKFET_RULE_NO_MATCH = 1, CKFET_RULE_INVALID = 2,
    CKFET_RULE_STALE = 3, CKFET_RULE_CONTRADICTORY = 4, CKFET_RULE_UNQUALIFIED = 5,
    CKFET_RULE_SEPARATE_POLICY = 6, CKFET_RULE_AWAITING_CHOICE = 7,
    CKFET_RULE_ZERO_LENGTH = 8, CKFET_RULE_RETENTION_UNAVAILABLE = 9, CKFET_RULE_RETRY_UNQUALIFIED = 10 };

typedef struct ckfet_options_v1 {
    uint32_t version, struct_size, profile, metadata_scope;
    uint32_t allow_metadata_loss, reserved;
    uint32_t metadata_ownership, allow_privilege_metadata;
    uint64_t timestamp_quantum_ns;
    ckfsp_limits limits;
    ckfsp_filters filters;
    ckfet_native journal_root; /* private absolute native address; required */
    uint8_t operation_id[16]; /* nonzero, caller-generated unique ID */
} ckfet_options_v1;
typedef struct ckfet_rule_v1 {
    uint32_t version, struct_size, kind, choice;
    uint32_t tie, scope, direction, protect_nonempty;
    uint32_t retain_replaced, reserved;
    uint64_t plan_generation;
    const uint64_t *selected_rows;
    uint64_t selected_count;
    ckfsp_bytes subtree_key; /* exact comparison key, not a display/native path */
} ckfet_rule_v1;
enum { CKFET_NAME_INCOMING = 0, CKFET_NAME_TARGET = 1 };
typedef struct ckfet_name_choice_v1 {
    uint64_t row_id;
    uint32_t side, reserved;
    ckfet_native component;
} ckfet_name_choice_v1;
typedef struct ckfet_snapshot_v1 {
    uint32_t version, struct_size, state, paused;
    uint64_t sequence, plan_generation, known_items, completed_items, skipped_items, failed_items;
    uint64_t known_copy_bytes, copied_bytes, current_row;
    uint32_t counts_complete, has_current_row, recovery_required, partial;
    uint64_t command_id, receipt_id;
    uint32_t command_state, reserved;
    uint32_t failure_state, failure_domain;
    int64_t failure_code;
    uint32_t pause_requested, reserved2;
    uint64_t rule_count, unresolved_rows;
} ckfet_snapshot_v1;
typedef struct ckfet_rule_counts_v1 {
    uint64_t matched_rows, applied_rows, unresolved_rows, skipped_rows;
    uint64_t copy_rows, replacement_rows, protected_zero_length_rows, retention_rows;
} ckfet_rule_counts_v1;
enum { CKFET_PRESENCE_UNKNOWN = 0, CKFET_PRESENCE_ABSENT = 1, CKFET_PRESENCE_PRESENT = 2 };
typedef struct ckfet_observed_v1 {
    uint32_t presence, known_fields, kind, metadata_assessment;
    uint64_t size;
    ckfsp_timestamp modified;
    uint64_t timestamp_quantum_ns;
} ckfet_observed_v1;
typedef struct ckfet_row_v1 {
    uint64_t row_id, key_bytes;
    uint32_t relation, reason, proposed_action, action, state;
    uint32_t has_decision, decision_state, decision_choice, decision_reason;
    uint32_t decision_fallback, retain_replaced, reserved;
    uint32_t failure_state, failure_domain;
    int64_t failure_code;
    uint64_t component_count, rule_index;
    uint32_t has_rule_index, recovery_required, has_journal, reserved2;
    uint8_t journal_id[16];
    ckfet_observed_v1 source, destination;
    uint64_t allowed_choices;
    uint32_t retention_available, target_retained, has_name_side, name_side;
    uint32_t has_retention_journal, reserved3;
    uint8_t retention_journal_id[16];
    uint32_t conflict_class, reserved4;
} ckfet_row_v1;
typedef struct ckfet_page_v1 {
    uint64_t plan_generation, row_count, total_rows, next_offset;
    uint32_t has_next, reserved;
} ckfet_page_v1;

CK_FILE_ENGINE_API void ckfet_options_init_v1(ckfet_options_v1 *options);
CK_FILE_ENGINE_API ckfe_api_status ckfet_start_v1(const ckfe_entry *source_root,
    const ckfe_entry *destination_root, const ckfet_options_v1 *options, ckfet_job **out_job, ckfe_error *error);
CK_FILE_ENGINE_API ckfe_api_status ckfet_poll_v1(const ckfet_job *job, ckfet_snapshot_v1 *out_snapshot);
/* Nonblocking shutdown completion. A terminal snapshot records the operation
 * outcome, including all required writes/flushes and any retained recovery
 * evidence. Drained additionally means worker-local native owners are closed
 * and no backend I/O remains. Helpers must observe drained before release/exit;
 * release itself only requests cancellation. The caller must keep job alive. */
CK_FILE_ENGINE_API ckfe_api_status ckfet_worker_drained_v1(const ckfet_job *job, uint32_t *out_drained);
/* Bounded latest-state events; coalesced counts signal a gap. poll + pages are
 * authoritative resynchronization. Terminal/conflict/recovery facts persist. */
CK_FILE_ENGINE_API ckfe_api_status ckfet_drain_v1(ckfet_job *job, ckfet_snapshot_v1 *events,
    uint64_t capacity, uint64_t *out_count, uint64_t *out_coalesced);
CK_FILE_ENGINE_API ckfe_api_status ckfet_page_v1_get(const ckfet_job *job, uint64_t generation,
    uint64_t offset, ckfet_row_v1 *rows, uint64_t capacity, ckfet_page_v1 *out_page);
CK_FILE_ENGINE_API ckfe_api_status ckfet_key_copy_v1(const ckfet_job *job, uint64_t generation,
    uint64_t row_id, void *buffer, uint64_t capacity, uint64_t *out_required);
enum { CKFET_NATIVE_COMPONENT = 0, CKFET_NATIVE_JOURNAL_NAME = 1, CKFET_NATIVE_STAGING_NAME = 2,
    CKFET_NATIVE_RETAINED_NAME = 3, CKFET_NATIVE_PROPOSED_NAME = 4, CKFET_NATIVE_RESULTING_NAME = 5 };
/* Exact native values for presentation/export only. Capacity/required are
 * native units (bytes or uint16_t units); no terminator is included. A key is
 * never parsed back into these values. Output memory belongs to the caller. */
CK_FILE_ENGINE_API ckfe_api_status ckfet_native_copy_v1(const ckfet_job *job, uint64_t generation,
    uint64_t row_id, uint32_t kind, uint64_t component_index, void *buffer,
    uint64_t capacity_units, uint64_t *out_required_units, uint32_t *out_encoding);
CK_FILE_ENGINE_API ckfe_api_status ckfet_rule_counts_get_v1(const ckfet_job *job,
    uint64_t rule_index, ckfet_rule_counts_v1 *out_counts);
/* Rules and exact deletion row IDs are copied at submission. Each accepted
 * review produces a fresh receipt ID and invalidates earlier receipts. A stale
 * generation or unresolved decision is a rejected command, never authority. */
CK_FILE_ENGINE_API ckfe_api_status ckfet_review_v1(ckfet_job *job, uint64_t generation,
    const ckfet_rule_v1 *rules, uint64_t rule_count, const uint64_t *deletion_rows,
    uint64_t deletion_count, uint64_t *out_command);
CK_FILE_ENGINE_API ckfe_api_status ckfet_review_names_v1(ckfet_job *job, uint64_t generation,
    const ckfet_rule_v1 *rules, uint64_t rule_count, const ckfet_name_choice_v1 *names,
    uint64_t name_count, const uint64_t *deletion_rows, uint64_t deletion_count, uint64_t *out_command);
CK_FILE_ENGINE_API ckfe_api_status ckfet_execute_v1(ckfet_job *job, uint64_t generation,
    uint64_t receipt_id, uint64_t *out_command);
/* A command outcome persists until acknowledged. Only one submitted/in-flight
 * or unacknowledged command is admitted; event coalescing cannot erase it. */
CK_FILE_ENGINE_API ckfe_api_status ckfet_acknowledge_command_v1(ckfet_job *job, uint64_t command_id);
CK_FILE_ENGINE_API void ckfet_request_cancel(ckfet_job *job);
CK_FILE_ENGINE_API void ckfet_request_pause(ckfet_job *job, uint32_t paused);
CK_FILE_ENGINE_API void ckfet_release(ckfet_job *job);

#ifdef __cplusplus
}
#endif
#endif
