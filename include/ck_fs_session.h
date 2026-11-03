// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef CK_FS_SESSION_H
#define CK_FS_SESSION_H
#include <stdint.h>
#if defined(_WIN32) && defined(CK_FILE_ENGINE_BUILD)
#define CKFSS_API __declspec(dllexport)
#elif defined(_WIN32) && !defined(CK_FS_SESSION_STATIC)
#define CKFSS_API __declspec(dllimport)
#elif defined(_WIN32)
#define CKFSS_API
#else
#define CKFSS_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
#define CKFSS_NOEXCEPT noexcept
extern "C" {
#else
#define CKFSS_NOEXCEPT
#endif

#define CKFSS_VERSION UINT32_C(1)
typedef struct ckfss_session ckfss_session;
typedef struct ckfjr_root ckfjr_root;
typedef uint32_t ckfss_status;
enum {
    CKFSS_OK=0, CKFSS_INVALID_ARGUMENT=1, CKFSS_OUT_OF_MEMORY=2,
    CKFSS_EXCEPTION=3, CKFSS_UNAVAILABLE=4, CKFSS_BUFFER_TOO_SMALL=5
};
enum { CKFSS_FIRST_RUN=0, CKFSS_READY=1, CKFSS_RECOVERED=2, CKFSS_REVIEW_REQUIRED=3, CKFSS_HISTORY_CHANGED=4 };
enum { CKFSS_POSIX_BYTES=0, CKFSS_WINDOWS_UTF16=1 };
enum { CKFSS_UNKNOWN=0, CKFSS_ABSENT=1, CKFSS_PRESENT=2 };
enum { CKFSS_KIND_UNKNOWN=0, CKFSS_FILE=1, CKFSS_DIRECTORY=2, CKFSS_OTHER=3 };
enum { CKFSS_PENDING=0, CKFSS_CONFIRMED_EQUAL=1 };
// Observation and error-domain ordinals match ck_file_engine.h. operation is a
// fixed, NUL-terminated adapter operation name; no allocation/free is needed.
typedef struct ckfss_error {
    uint32_t observation, domain;
    int64_t code;
    char operation[96];
} ckfss_error;
typedef struct ckfss_native_path {
    const void *data;
    uint64_t units; // bytes for POSIX, exact uint16_t units for Windows; no NUL
    uint32_t encoding, reserved;
} ckfss_native_path;
typedef struct ckfss_limits {
    uint64_t max_rows, max_path_bytes, max_total_path_bytes, max_wire_bytes;
} ckfss_limits;
typedef struct ckfss_options {
    uint32_t version, struct_size;
    ckfss_native_path coordinator, left, right;
    // Hash the digest schema, exclusions, required metadata, comparison and
    // deletion policy. The engine additionally binds ORDERED durable root IDs.
    uint8_t policy_fingerprint[32];
    ckfss_limits limits;
    uint64_t reserved[4];
} ckfss_options;
typedef struct ckfss_entry_status {
    uint32_t presence, kind;
    uint8_t content_digest[32], required_metadata_digest[32];
} ckfss_entry_status;
typedef struct ckfss_update {
    uint32_t version, struct_size;
    const void *relative_key;
    uint64_t relative_key_bytes;
    ckfss_entry_status left, right;
    uint32_t state, reserved;
} ckfss_update;
typedef struct ckfss_snapshot {
    uint32_t version, struct_size, state, reserved;
    uint64_t generation, rows, previous_rows, pending_rows;
    uint32_t has_baseline, has_previous;
    uint8_t left_root[32], right_root[32], bound_policy[32], pair[32];
} ckfss_snapshot;
typedef struct ckfss_row {
    ckfss_entry_status left, right;
    uint64_t relative_key_bytes;
} ckfss_row;

// WORKER ONLY: open, refresh, revalidate and commit call native I/O and may
// block. The frontend's headless worker owns the session. All calls except
// request_cancel are externally serialized; destruction must not race any call.
// Inputs are copied during the call, never retained. No exceptions cross ABI.
// Out handles/results/error are reset on entry. Version/size must match exactly;
// unknown flags, reserved fields and enum values are rejected.
CKFSS_API void ckfss_options_init(ckfss_options*) CKFSS_NOEXCEPT;
CKFSS_API void ckfss_update_init(ckfss_update*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_session_open(const ckfss_options*, ckfss_session**, ckfss_error*) CKFSS_NOEXCEPT;
// WORKER ONLY. Retains the READY provider-owned root until session destruction;
// coordinator address is ignored (it may be empty). No hint/path reopen occurs.
// Destroy the session on its worker to release BOTH root locks and native root
// consumers before ckfjr_finish/wait_drained. Never finish the shared root from
// a per-session finalizer. Cancel alone does not destroy/release these owners.
CKFSS_API ckfss_status ckfss_session_open_with_journal_root(const ckfss_options*,
    const ckfjr_root*, ckfss_session**, ckfss_error*) CKFSS_NOEXCEPT;
// WORKER ONLY, serialized terminal close of consumer-owned native handles and
// locks. Repeated failures remain failures. Revokes verification/commit authority;
// snapshot inspection remains available. This does NOT finish the shared Root.
// Legacy path factories additionally finalize their internally minted root.
// Adopted-root consumers never finish the external root.
// Destroy on the worker after collecting this result, then finish/wait_drained
// the Root lifecycle token to collect its original-handle flush/close errors.
CKFSS_API ckfss_status ckfss_session_finish_io(ckfss_session*, ckfss_error*) CKFSS_NOEXCEPT;
CKFSS_API void ckfss_session_destroy(ckfss_session*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_session_get_snapshot(const ckfss_session*, ckfss_snapshot*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_session_refresh(ckfss_session*, ckfss_error*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_session_revalidate(ckfss_session*, ckfss_error*) CKFSS_NOEXCEPT;
// Snapshot is not execution permission. Locks coordinate sessions (including
// different pair IDs/coordinators), not unrelated filesystem writers. Held
// native ancestry is rechecked; linked/reparse/unknown scope fails closed.
// Source/target nesting and a coordinator inside either root are rejected.
// POSIX supports qualified local filesystems, with exact ancestor-object locks.
// Windows conservatively serializes sessions per native volume, supports local
// NTFS/ReFS and requires directory/volume flush support (volume flush usually
// needs admin access). UNC and unknown durability return Unsupported.
// Missing state is FIRST_RUN requiring explicit approval. Corrupt/lost state
// with surviving evidence is REVIEW_REQUIRED, never silently initialized.
// Generation is durable across restart; expected_generation is a CAS against
// both loaded and on-disk state. Input keys are sorted exact relative '/' keys,
// with no empty/dot/dotdot/NUL/backslash/colon components (codec contract).
// This caller-fact entry point remains UNSUPPORTED. Caller-supplied rows,
// digests and CONFIRMED_EQUAL are preview facts, never verification authority.
// Use native receipts below or the native two-way worker. This entry point
// always fails closed without staging or changing the baseline.
CKFSS_API ckfss_status ckfss_session_commit(ckfss_session*, uint64_t expected_generation,
    const ckfss_update*, uint64_t update_count, uint32_t approve_first_run,
    ckfss_snapshot*, ckfss_error*) CKFSS_NOEXCEPT;
// request_cancel is the only concurrent call. It is sticky until clear_cancel
// (worker only). Checked before durable intent; once intent publication starts,
// commit finishes despite cancellation. Cancel cannot undo synchronized-file
// mutations done by a separate executor; their journal must recover them first.
CKFSS_API void ckfss_session_request_cancel(ckfss_session*) CKFSS_NOEXCEPT;
CKFSS_API void ckfss_session_clear_cancel(ckfss_session*) CKFSS_NOEXCEPT;
// Copy exact key bytes, without NUL. Capacity zero queries required length.
// Previous rows are inspection-only. Pending keys describe the last successful
// verified commit in this handle, and are cleared by refresh.
CKFSS_API ckfss_status ckfss_session_get_row(const ckfss_session*, uint32_t previous,
    uint64_t index, ckfss_row*, void *key, uint64_t capacity, uint64_t *required) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_session_get_pending_key(const ckfss_session*, uint64_t index,
    void *key, uint64_t capacity, uint64_t *required) CKFSS_NOEXCEPT;

// Native convergence API (additive; existing layouts above remain unchanged).
// Raw ckfss_session_commit remains preview-only/Unsupported. Open a verified
// session with an explicit metadata policy; its semantic policy/schema is bound
// into durable pair identity, so changing scope requires a new first-run review.
typedef struct ckfss_receipt ckfss_receipt;
enum { CKFSS_METADATA_COMPLETE_V1=0, CKFSS_METADATA_ORDINARY_V1=1 };
enum { CKFSS_OWNER_ORIGINAL=0, CKFSS_OWNER_CURRENT_CALLER=1 };
enum { CKFSS_VERIFY_PATH=0, CKFSS_SKIP_PATH=1 };
typedef struct ckfss_metadata_policy {
    uint32_t version, struct_size, scope, ownership;
    uint32_t allow_privilege_metadata, reserved;
    uint64_t max_file_bytes, max_total_bytes;
    uint64_t max_metadata_bytes, max_metadata_records, max_total_metadata_bytes;
    uint64_t max_parent_entries, max_components_per_path;
} ckfss_metadata_policy;
typedef struct ckfss_exact_path {
    // Each element is ONE exact native basename in the host encoding. No
    // display-text parsing, absolute paths, dot/dotdot, separator or NUL units.
    const ckfss_native_path *components;
    uint64_t component_count;
    uint32_t disposition, reserved;
} ckfss_exact_path;
// Capability bits describe API scope, never per-path provider qualification.
// get_capabilities returns unconditional session services separately from
// conditional receipt families. Directory/tree and two-way execution stay zero.
enum {
    CKFSS_CAP_OVERLAP_SESSION_LOCKS=1, CKFSS_CAP_DURABLE_BASELINE=2,
    CKFSS_CAP_REGULAR_RECEIPT=4, CKFSS_CAP_FINAL_ABSENCE_RECEIPT=8,
    CKFSS_CAP_DIRECTORY_TREE_RECEIPT=16, CKFSS_CAP_TWO_WAY_EXECUTION=32
};
CKFSS_API ckfss_status ckfss_session_get_capabilities(const ckfss_session*,
    uint64_t *supported, uint64_t *conditional) CKFSS_NOEXCEPT;
// Existing root-pair history under another policy/schema or reversed root
// order is HISTORY_CHANGED, requiring explicit review outside this API. It is
// never automatically rebased as a new FirstRun. Corrupt history requires review.
CKFSS_API void ckfss_metadata_policy_init(ckfss_metadata_policy*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_session_open_verified(const ckfss_options*,
    const ckfss_metadata_policy*, ckfss_session**, ckfss_error*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_session_open_verified_with_journal_root(const ckfss_options*,
    const ckfss_metadata_policy*, const ckfjr_root*, ckfss_session**, ckfss_error*) CKFSS_NOEXCEPT;
// WORKER ONLY, bounded by the configured policy. Policy must exactly match the
// open policy. Both sides are observed natively through identity-checked held
// root cursors; full content hashes and capture_metadata_replay establish each
// regular file's stable version. Definitive final-component absence additionally
// requires complete stable parent enumeration and repeated native missing
// witnesses. Missing intermediate parents and other kinds are Unsupported.
// The engine generates keys losslessly: p+hex(POSIX bytes) or w+hex(UTF16LE),
// '/' between components. These keys are returned by get_row after commit.
// Metadata semantic schema V2 includes mode/flags, modified time, creation time
// in complete scope, actual original uid/gid (Original ownership), sorted exact
// attributes/flags and canonical security semantics. It excludes observation
// identity/owner bindings, atime, ctime, link counts and physical allocation.
// CurrentCaller requires equal observed ownership but excludes it from semantic
// cross-object hashes. Unsupported security encodings/providers fail closed.
// V2 additionally binds qualified exact native DATA-stream names, lengths and
// SHA-256 digests; aggregate content limits include named DATA before hashing.
// Receipts and both native executors share this binding. Older semantic policy
// bindings remain a policy mismatch requiring review, never an implicit reset.
// Unequal sides and explicitly skipped paths are Pending; old evidence remains.
CKFSS_API ckfss_status ckfss_session_verify_exact_paths(ckfss_session*,
    const ckfss_exact_path*, uint64_t path_count, const ckfss_metadata_policy*,
    ckfss_receipt**, ckfss_error*) CKFSS_NOEXCEPT;
CKFSS_API void ckfss_receipt_destroy(ckfss_receipt*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_receipt_get_counts(const ckfss_receipt*,
    uint64_t *confirmed, uint64_t *pending) CKFSS_NOEXCEPT;
// WORKER ONLY. Receipt is opaque, process-local, session-instance/identity/
// generation/policy bound and one-use once commit starts. Rehashes and recaptures
// required metadata, rechecks native versions/membership and qualified absence,
// then uses the durable CAS commit. A foreign/stale/consumed receipt is refused.
// This does not claim a simultaneous cross-root snapshot or block unrelated
// filesystem writers. Later writes are detected by the next sync. Recovery of
// already-published synchronized files must precede requesting this receipt.
CKFSS_API ckfss_status ckfss_session_commit_verified(ckfss_session*, ckfss_receipt*,
    uint32_t approve_first_run, ckfss_snapshot*, ckfss_error*) CKFSS_NOEXCEPT;

// Native two-way composition (additive companion session/plan worker).
// Open acquires and owns a native session; destroy any separate ckfss_session
// for these roots first. One handle binds the inventory, rules, generation,
// policy, ledger and one mixed-direction executor. No caller digest authority.
// WORKER ONLY, externally serialized except request_cancel. Ordinary regular
// files directly below each root are V1 scope; nested trees/structural directory
// metadata are Unsupported. Supported providers execute actual copies and
// retained replacements/deletions, then fresh convergence and durable CAS.
// No cross-root atomicity: each side is verified at its observed version;
// unrelated writers are detected on revalidation or the next sync.
// Coordinator must be outside BOTH roots by held native ancestry (no prefix
// exclusions). Caller must durably provision it and its ancestors before open.
typedef struct ckfss_two_way ckfss_two_way;
enum {
    CKFSS_TW_AWAITING_REVIEW=0, CKFSS_TW_EXECUTING=1, CKFSS_TW_VERIFYING=2,
    CKFSS_TW_COMMITTING=3, CKFSS_TW_COMPLETE=4, CKFSS_TW_CANCELLED=5, CKFSS_TW_NEEDS_REVIEW=6
};
enum {
    CKFSS_TW_UNCHANGED=0, CKFSS_TW_COPY_LEFT_TO_RIGHT=1, CKFSS_TW_COPY_RIGHT_TO_LEFT=2,
    CKFSS_TW_DELETE_LEFT=3, CKFSS_TW_DELETE_RIGHT=4, CKFSS_TW_CONFLICT=5, CKFSS_TW_BLOCKED=6
};
enum { CKFSS_TW_PROPOSAL=0, CKFSS_TW_SKIP=1, CKFSS_TW_LEFT_WINS=2, CKFSS_TW_RIGHT_WINS=3 };
enum { CKFSS_TW_RETAINED_ORIGINAL=1, CKFSS_TW_PROTECTED=1 };
enum {
    CKFSS_TW_REASON_NONE=0, CKFSS_TW_REASON_UNKNOWN=1, CKFSS_TW_REASON_INCOMPLETE=2,
    CKFSS_TW_REASON_INITIAL_DIFFERENCE=3, CKFSS_TW_REASON_CONCURRENT_EDIT=4,
    CKFSS_TW_REASON_DELETE_EDIT=5, CKFSS_TW_REASON_BASELINE_DIVERGED=6,
    CKFSS_TW_REASON_METADATA_DIFFERENCE=7, CKFSS_TW_REASON_POLICY_CHANGED=8,
    CKFSS_TW_REASON_DIRECTORY_SUBTREE=9, CKFSS_TW_REASON_ANCESTOR_CONFLICT=10,
    CKFSS_TW_REASON_DELETION_GUARD=11
};
enum { CKFSS_ID_UNKNOWN=0, CKFSS_ID_POSIX_DEVICE_INODE=1, CKFSS_ID_WINDOWS_128=2, CKFSS_ID_WINDOWS_64=3 };
typedef struct ckfss_two_way_policy {
    uint32_t version, struct_size;
    // Per scan, combined BOTH roots including retained artifacts. At most two
    // full proof sets are retained at once, plus the active native item owners.
    uint64_t max_entries, chunk_bytes;
    uint64_t max_ledger_files, max_ledger_bytes, max_retained_artifacts;
    uint64_t max_deletions;
    uint32_t max_delete_basis_points, reserved;
} ckfss_two_way_policy;
typedef struct ckfss_two_way_info {
    uint32_t version, struct_size, state, has_failure;
    uint64_t generation, rows, protected_artifacts, completed_operations, pending_rows;
    ckfss_error failure;
} ckfss_two_way_info;
typedef struct ckfss_two_way_row {
    ckfss_entry_status left, right;
    uint32_t proposed_action, reason; // CKFSS_TW_* / CKFSS_TW_REASON_*, inspection only
    uint64_t relative_key_bytes, component_count;
} ckfss_two_way_row;
typedef struct ckfss_two_way_decision {
    // Index into THIS handle's frozen rows; never a mutation path or authority
    // imported from another plan. Exactly one choice is required for each row.
    uint64_t row_index;
    uint32_t choice, reserved;
} ckfss_two_way_decision;
typedef struct ckfss_durable_identity {
    uint32_t scheme, has_generation;
    uint8_t volume[16], object[16];
    uint64_t generation;
} ckfss_durable_identity;
typedef struct ckfss_two_way_retained {
    uint32_t kind, protection, right_side, reserved;
    uint64_t component_count;
    ckfss_durable_identity parent, object;
    ckfss_entry_status observed;
} ckfss_two_way_retained;
CKFSS_API void ckfss_two_way_policy_init(ckfss_two_way_policy*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_two_way_open(const ckfss_options*, const ckfss_metadata_policy*,
    const ckfss_two_way_policy*, ckfss_two_way**, ckfss_error*) CKFSS_NOEXCEPT;
// Same held-owner/lifetime contract as session_open_with_journal_root. The one
// owner serves baseline, ledger enumeration/recovery, and operation journals.
CKFSS_API ckfss_status ckfss_two_way_open_with_journal_root(const ckfss_options*,
    const ckfss_metadata_policy*, const ckfss_two_way_policy*, const ckfjr_root*,
    ckfss_two_way**, ckfss_error*) CKFSS_NOEXCEPT;
// WORKER ONLY. Terminal consumer teardown; it never advances a pending baseline
// intent or turns partial execution into Complete. Root owner remains held until
// destroy; collect this result before Root finish/drain, as for session_finish_io.
CKFSS_API ckfss_status ckfss_two_way_finish_io(ckfss_two_way*, ckfss_error*) CKFSS_NOEXCEPT;
CKFSS_API void ckfss_two_way_destroy(ckfss_two_way*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_two_way_get_info(const ckfss_two_way*, ckfss_two_way_info*) CKFSS_NOEXCEPT;
// Family scope only: two-way execution is CONDITIONAL on the exact providers;
// structural directory/tree support remains zero. Never a success guarantee.
CKFSS_API ckfss_status ckfss_two_way_get_capabilities(const ckfss_two_way*, uint64_t *supported, uint64_t *conditional) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_two_way_get_row(const ckfss_two_way*, uint64_t row_index,
    ckfss_two_way_row*, void *key, uint64_t capacity, uint64_t *required) CKFSS_NOEXCEPT;
// Keys are opaque lookup/display labels. Exact native names are separately
// returned here; buffer capacity/required are bytes or uint16_t units according
// to encoding. No NUL terminator is added and no native-name parsing occurs.
CKFSS_API ckfss_status ckfss_two_way_get_component(const ckfss_two_way*, uint64_t row_index,
    uint64_t component_index, uint32_t *encoding, void *units, uint64_t capacity, uint64_t *required) CKFSS_NOEXCEPT;
// Artifacts remain explicitly visible Protected/Retained evidence, never hidden
// by a data filename prefix. Restart ID+digest matches are fresh observations,
// NOT live continuity or authority to clean/rename them. Missing/moved/changed
// artifacts and unresolved intents require review. No cleanup API is exposed.
CKFSS_API ckfss_status ckfss_two_way_get_retained(const ckfss_two_way*, uint64_t artifact_index,
    ckfss_two_way_retained*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_two_way_get_retained_component(const ckfss_two_way*, uint64_t artifact_index,
    uint64_t component_index, uint32_t *encoding, void *units, uint64_t capacity, uint64_t *required) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_two_way_approve(ckfss_two_way*, const ckfss_two_way_decision*,
    uint64_t count, uint32_t approve_first_run, ckfss_error*) CKFSS_NOEXCEPT;
// One worker step; native reads are bounded by the configured limits. Complete
// follows fresh native convergence, journal flush+fallible close, baseline CAS,
// and ledger seal. Partial/cancelled/unknown execution never advances baseline.
// A durable baseline/coordinator intent is recovered idempotently on next open;
// unresolved partial data execution blocks new mutations rather than replaying.
CKFSS_API ckfss_status ckfss_two_way_advance(ckfss_two_way*, ckfss_two_way_info*, ckfss_error*) CKFSS_NOEXCEPT;
CKFSS_API void ckfss_two_way_request_cancel(ckfss_two_way*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_two_way_get_pending_key(const ckfss_two_way*, uint64_t index,
    void *key, uint64_t capacity, uint64_t *required) CKFSS_NOEXCEPT;


// Bulk conflict bridge: frozen native RawFacts -> shared ConflictRule engine ->
// opaque assessed receipt. Frontends must not implement timestamp winner logic.
// Ordinals below match the common tree ConflictRule contract.
typedef struct ckfss_two_way_review ckfss_two_way_review;
enum {
    CKFSS_CONFLICT_EXISTING_REGULAR=0, CKFSS_CONFLICT_BOTH_EDITED=1, CKFSS_CONFLICT_DELETE_EDIT=2,
    CKFSS_CONFLICT_DIRECTORY_DELETE_EDITED_CHILD=3, CKFSS_CONFLICT_TYPE=4, CKFSS_CONFLICT_LINK=5,
    CKFSS_CONFLICT_NAME=6, CKFSS_CONFLICT_METADATA=7, CKFSS_CONFLICT_UNAVAILABLE=8,
    CKFSS_CONFLICT_STALE=9, CKFSS_CONFLICT_AMBIGUOUS=10, CKFSS_CONFLICT_DIRECTORY_PAIR=11,
    CKFSS_CONFLICT_HARD_LINK=12, CKFSS_CONFLICT_ACCESS=13, CKFSS_CONFLICT_CAPACITY=14
};
enum {
    CKFSS_RULE_ASK=0, CKFSS_RULE_USE_SOURCE=1, CKFSS_RULE_KEEP_TARGET=2, CKFSS_RULE_NEWEST=3,
    CKFSS_RULE_SOURCE_NEWER=4, CKFSS_RULE_NEWER_OR_SIZE_AT_EQUAL_TIME=5, CKFSS_RULE_SIZE_DIFFERS=6,
    CKFSS_RULE_LARGER=7, CKFSS_RULE_SMALLER=8, CKFSS_RULE_KEEP_BOTH_INCOMING=9,
    CKFSS_RULE_KEEP_BOTH_TARGET=10, CKFSS_RULE_RENAME=11, CKFSS_RULE_COMPARE=12,
    CKFSS_RULE_MERGE_FOLDERS=13, CKFSS_RULE_RETRY=14, CKFSS_RULE_CANCEL=15,
    CKFSS_RULE_SKIP=16, CKFSS_RULE_KEEP_LEFT=17, CKFSS_RULE_KEEP_RIGHT=18,
    CKFSS_RULE_KEEP_BOTH=19, CKFSS_RULE_RESTORE_DELETED=20, CKFSS_RULE_KEEP_EDITED=21, CKFSS_RULE_DELETE_EDITED=22
};
enum { CKFSS_SCOPE_ITEM=0, CKFSS_SCOPE_SELECTED=1, CKFSS_SCOPE_SUBTREE=2, CKFSS_SCOPE_JOB=3 };
enum { CKFSS_DIRECTION_SOURCE_TO_TARGET=0, CKFSS_DIRECTION_LEFT_TO_RIGHT=1, CKFSS_DIRECTION_RIGHT_TO_LEFT=2 };
enum { CKFSS_DECISION_NO_MATCH=0, CKFSS_DECISION_APPLY=1, CKFSS_DECISION_REVIEW=2, CKFSS_DECISION_STALE=3, CKFSS_DECISION_INVALID=4 };
enum {
    CKFSS_RULE_REASON_NONE=0, CKFSS_RULE_REASON_NO_MATCH=1, CKFSS_RULE_REASON_INVALID=2,
    CKFSS_RULE_REASON_STALE=3, CKFSS_RULE_REASON_CONTRADICTORY=4, CKFSS_RULE_REASON_UNQUALIFIED=5,
    CKFSS_RULE_REASON_SEPARATE_POLICY=6, CKFSS_RULE_REASON_AWAITING_CHOICE=7,
    CKFSS_RULE_REASON_ZERO_LENGTH=8, CKFSS_RULE_REASON_RETENTION_UNAVAILABLE=9, CKFSS_RULE_REASON_RETRY_UNQUALIFIED=10
};
enum { CKFSS_FACT_KIND=1, CKFSS_FACT_SIZE=2, CKFSS_FACT_MODIFIED=4, CKFSS_FACT_REQUIRED_METADATA=8 };
typedef struct ckfss_two_way_observed {
    ckfss_entry_status status;
    uint32_t known_fields, kind; // native ObjectKind ordinal, valid with FACT_KIND
    uint64_t size;
    int64_t modified_seconds;
    uint32_t modified_nanoseconds, reserved;
} ckfss_two_way_observed;
typedef struct ckfss_two_way_raw_facts {
    uint32_t version, struct_size;
    uint64_t row_index, generation;
    uint32_t relation, conflict_class; // common ComparisonRelation / ConflictClass
    ckfss_two_way_observed left, right;
    uint64_t allowed_choices;
    uint32_t left_retention_state, right_retention_state; // ObservationState
    uint32_t left_retention_available, right_retention_available;
    ckfss_error left_retention_failure, right_retention_failure;
} ckfss_two_way_raw_facts;
typedef struct ckfss_two_way_rule {
    uint32_t version, struct_size, kind, choice;
    uint32_t tie, scope, direction, protect_nonempty;
    uint32_t retain_replaced, reserved;
    uint64_t expected_generation;
    const uint64_t *selected_rows; // zero-based indices in THIS frozen worker
    uint64_t selected_count;
    const void *subtree_key; // opaque lookup label; never a mutation address
    uint64_t subtree_key_bytes;
} ckfss_two_way_rule;
typedef struct ckfss_two_way_review_info {
    uint32_t version, struct_size, consumed, reserved;
    uint64_t generation, rows, matched_rows, applied_rows, unresolved_rows, skipped_rows;
} ckfss_two_way_review_info;
typedef struct ckfss_two_way_rule_result {
    uint32_t state, choice, reason, selected_choice;
    uint32_t used_fallback, retain_replaced, has_rule_index, reserved;
    uint64_t rule_index;
} ckfss_two_way_rule_result;
CKFSS_API void ckfss_two_way_rule_init(ckfss_two_way_rule*) CKFSS_NOEXCEPT;
// WORKER ONLY. Returns frozen observed facts, not fresh execution authority.
// Native retention eligibility is qualified without setting a caller trust bit.
CKFSS_API ckfss_status ckfss_two_way_get_facts(ckfss_two_way*, uint64_t row_index,
    ckfss_two_way_raw_facts*, ckfss_error*) CKFSS_NOEXCEPT;
// WORKER ONLY. Quantum: divisor of 1e9 ns or integral seconds, at most one day.
// Invalid/stale/contradictory/ASK/unsupported choices remain typed assessment
// rows. A review with any unresolved row cannot start execution. Missing rules
// follow the native baseline proposal only where it is already nonconflicting.
// SourceToTarget uses left/source, right/target; KeepTarget is a skip. Explicit
// LeftToRight/RightToLeft directions use KeepLeft/KeepRight for convergence.
// KeepBoth/rename retain a typed SeparatePolicy/AwaitingChoice refusal until
// exact native naming plus two-way preservation semantics are qualified.
CKFSS_API ckfss_status ckfss_two_way_assess_rules(ckfss_two_way*, const ckfss_two_way_rule*,
    uint64_t count, uint64_t timestamp_quantum_ns, ckfss_two_way_review**, ckfss_error*) CKFSS_NOEXCEPT;
CKFSS_API void ckfss_two_way_review_destroy(ckfss_two_way_review*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_two_way_review_get_info(const ckfss_two_way_review*, ckfss_two_way_review_info*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_two_way_review_get_row(const ckfss_two_way_review*, uint64_t row_index, ckfss_two_way_rule_result*) CKFSS_NOEXCEPT;
// WORKER ONLY. Revalidates native evidence. The one-use receipt is bound to
// worker instance, frozen native plan, assessment revision, generation, policy
// and full rule preferences. A subsequent assessment invalidates earlier ones.
CKFSS_API ckfss_status ckfss_two_way_approve_review(ckfss_two_way*, ckfss_two_way_review*,
    uint32_t approve_first_run, ckfss_error*) CKFSS_NOEXCEPT;


/* Additive 0.5 API. WORKER ONLY except request_cancel. No callbacks or caller
 * digests. Root-flat regular files; named versions converge while BOTH original
 * objects stay visibly protected/pending. No canonical rename/FullTrees claim.
 * This increment qualifies Linux native providers only. Capabilities depend
 * on genuine native name rules and strong staging publish;
 * unknown providers/metadata return typed Unsupported before publication.
 * One graph, root locks through finish_io; adopted private Root until destroy.
 * finish_io never commits partial work or finishes an adopted Root. */
#define CKFSS_RESOLUTION_ABI_MINOR UINT32_C(5)
typedef struct ckfss_resolution_job ckfss_resolution_job;
typedef struct ckfss_resolution_review ckfss_resolution_review;
enum { CKFSS_RESOLVE_KEEP_BOTH_NAMED=1 };
enum { CKFSS_RESOLUTION_PROTECT_ORIGINAL=0, CKFSS_RESOLUTION_PUBLISH_VERSION=1 };
typedef struct ckfss_named_resolution_v1 {
    uint32_t version, struct_size;
    uint64_t row_index;
    uint32_t mode, reserved;
    ckfss_native_path left_version_name, right_version_name; /* ONE basename each */
} ckfss_named_resolution_v1;
typedef struct ckfss_resolution_limits_v1 {
    uint32_t version, struct_size;
    uint64_t max_resolutions, max_added_paths, max_protected_objects;
    uint64_t max_name_bytes, max_transfer_bytes, max_proof_bytes;
    uint64_t reserved[4];
} ckfss_resolution_limits_v1;
typedef struct ckfss_resolution_operation_v1 {
    uint32_t version, struct_size, operation, destination_right;
    uint64_t source_row;
    uint32_t source_right, original_protected;
    uint64_t component_count, main_data_bytes;
    /* Full stream totals intentionally unavailable in this non-ADS increment. */
} ckfss_resolution_operation_v1;
CKFSS_API void ckfss_named_resolution_init_v1(ckfss_named_resolution_v1*) CKFSS_NOEXCEPT;
CKFSS_API void ckfss_resolution_limits_init_v1(ckfss_resolution_limits_v1*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_open_v1(const ckfss_options*, const ckfss_metadata_policy*, const ckfss_two_way_policy*,
    const ckfss_resolution_limits_v1*, ckfss_resolution_job**, ckfss_error*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_open_with_journal_root_v1(const ckfss_options*, const ckfss_metadata_policy*, const ckfss_two_way_policy*,
    const ckfss_resolution_limits_v1*, const ckfjr_root*, ckfss_resolution_job**, ckfss_error*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_get_info_v1(const ckfss_resolution_job*, ckfss_two_way_info*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_get_row_v1(const ckfss_resolution_job*, uint64_t, ckfss_two_way_row*, void*, uint64_t, uint64_t*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_get_component_v1(const ckfss_resolution_job*, uint64_t row, uint64_t component,
    uint32_t* encoding, void*, uint64_t capacity, uint64_t* required) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_assess_v1(ckfss_resolution_job*, const ckfss_named_resolution_v1*, uint64_t count,
    ckfss_resolution_review**, ckfss_error*) CKFSS_NOEXCEPT;
/* Receipt is one-use, instance/revision/generation/policy bound. These exact
 * names, source versions and four publications per conflict are frozen BEFORE
 * approval. Reassessment invalidates older receipts. No new names afterward. */
CKFSS_API ckfss_status ckfss_resolution_review_get_count_v1(const ckfss_resolution_review*, uint64_t*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_review_get_operation_v1(const ckfss_resolution_review*, uint64_t, ckfss_resolution_operation_v1*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_review_get_component_v1(const ckfss_resolution_review*, uint64_t operation, uint64_t component,
    uint32_t* encoding, void*, uint64_t capacity, uint64_t* required) CKFSS_NOEXCEPT;
CKFSS_API void ckfss_resolution_review_destroy_v1(ckfss_resolution_review*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_approve_v1(ckfss_resolution_job*, const ckfss_resolution_review*, uint32_t approve_first_run, ckfss_error*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_advance_v1(ckfss_resolution_job*, ckfss_two_way_info*, ckfss_error*) CKFSS_NOEXCEPT;
/* Artifacts remain native exact records, never filename-prefix exclusions.
 * Restart ID+SHA protects against mutation, never authorizes cleanup/rename. */
CKFSS_API ckfss_status ckfss_resolution_get_protected_v1(const ckfss_resolution_job*, uint64_t, ckfss_two_way_retained*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_get_protected_component_v1(const ckfss_resolution_job*, uint64_t, uint64_t,
    uint32_t* encoding, void*, uint64_t capacity, uint64_t* required) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_get_pending_key_v1(const ckfss_resolution_job*, uint64_t, void*, uint64_t, uint64_t*) CKFSS_NOEXCEPT;
CKFSS_API void ckfss_resolution_request_cancel_v1(ckfss_resolution_job*) CKFSS_NOEXCEPT;
CKFSS_API ckfss_status ckfss_resolution_finish_io_v1(ckfss_resolution_job*, ckfss_error*) CKFSS_NOEXCEPT;
CKFSS_API void ckfss_resolution_destroy_v1(ckfss_resolution_job*) CKFSS_NOEXCEPT;

#ifdef __cplusplus
}
#endif
#undef CKFSS_NOEXCEPT
#endif
