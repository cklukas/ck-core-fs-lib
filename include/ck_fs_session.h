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
// IMPORTANT: native C advancement is currently UNSUPPORTED. Caller-supplied
// rows/digests/CONFIRMED_EQUAL are untrusted preview facts, never verification
// authority. The native reviewed executor has not yet supplied a session-bound
// post-verification receipt for content AND required metadata convergence. This
// entry point always fails closed without staging or changing the baseline.
// Open/refresh/recovery and inspection ARE implemented. The internal C++ store
// contract supports commits for trusted adapters and deterministic tests.
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
// WORKER ONLY, bounded by the configured policy. Policy must exactly match the
// open policy. Both sides are observed natively through identity-checked held
// root cursors; full content hashes and capture_metadata_replay establish each
// regular file's stable version. Definitive final-component absence additionally
// requires complete stable parent enumeration and repeated native missing
// witnesses. Missing intermediate parents and other kinds are Unsupported.
// The engine generates keys losslessly: p+hex(POSIX bytes) or w+hex(UTF16LE),
// '/' between components. These keys are returned by get_row after commit.
// Metadata semantic schema V1 includes mode/flags, modified time, creation time
// in complete scope, actual original uid/gid (Original ownership), sorted exact
// attributes/flags and canonical security semantics. It excludes observation
// identity/owner bindings, atime, ctime, link counts and physical allocation.
// CurrentCaller requires equal observed ownership but excludes it from semantic
// cross-object hashes. Unsupported security encodings/providers fail closed.
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

#ifdef __cplusplus
}
#endif
#undef CKFSS_NOEXCEPT
#endif
