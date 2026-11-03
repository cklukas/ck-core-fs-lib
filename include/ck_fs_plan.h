// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef CK_FS_PLAN_H
#define CK_FS_PLAN_H

#include <stdint.h>

#if defined(_WIN32) && defined(CK_FILE_ENGINE_BUILD)
#define CK_FS_PLAN_API __declspec(dllexport)
#elif defined(_WIN32)
#define CK_FS_PLAN_API __declspec(dllimport)
#else
#define CK_FS_PLAN_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Caller-supplied facts, PREVIEW ONLY. No held-native proof, mutation authority,
// consent receipt or executable operation can be obtained through this API.
// Handles own immutable copies. Input pointers need live only during each call.
// Concurrent reads are allowed; destruction requires external synchronization.
#define CKFSP_VERSION UINT32_C(1)
#define CKFSP_NO_INDEX UINT64_MAX
#define CKFSP_ALL_KINDS UINT64_C(1023)

typedef struct ckfsp_plan ckfsp_plan;
typedef uint32_t ckfsp_status;
enum {
    CKFSP_OK = 0, CKFSP_INVALID_ARGUMENT = 1, CKFSP_OUT_OF_MEMORY = 2,
    CKFSP_EXCEPTION = 3, CKFSP_PLAN_UNAVAILABLE = 4, CKFSP_BUFFER_TOO_SMALL = 5
};
enum {
    CKFSP_COPY = 0, CKFSP_MOVE = 1, CKFSP_UPDATE = 2, CKFSP_MISSING_ONLY = 3,
    CKFSP_SYNC = 4, CKFSP_MIRROR = 5, CKFSP_COMPARE = 6
};
enum { CKFSP_SIZE_MTIME = 0, CKFSP_SIZE = 1, CKFSP_COMPLETE_DIGEST = 2 };
enum { CKFSP_TOPOLOGY_UNKNOWN = 0, CKFSP_DISJOINT = 1, CKFSP_SAME_ROOT = 2, CKFSP_OVERLAP = 3 };
enum {
    CKFSP_INVENTORY_UNKNOWN = 0, CKFSP_INVENTORY_COMPLETE_STABLE = 1,
    CKFSP_INVENTORY_INCOMPLETE = 2, CKFSP_INVENTORY_DENIED = 3,
    CKFSP_INVENTORY_CHANGED = 4, CKFSP_INVENTORY_FAILED = 5
};
enum {
    CKFSP_OBJECT_UNKNOWN = 0, CKFSP_OBJECT_STABLE = 1, CKFSP_OBJECT_DENIED = 2,
    CKFSP_OBJECT_GONE = 3, CKFSP_OBJECT_CHANGED = 4, CKFSP_OBJECT_FAILED = 5
};
enum {
    CKFSP_DIGEST_UNKNOWN = 0, CKFSP_DIGEST_COMPLETE_STABLE = 1, CKFSP_DIGEST_INCOMPLETE = 2,
    CKFSP_DIGEST_DENIED = 3, CKFSP_DIGEST_CHANGED = 4, CKFSP_DIGEST_FAILED = 5
};
enum { CKFSP_DIGEST_ALGORITHM_UNKNOWN = 0, CKFSP_SHA256 = 1 };
enum { CKFSP_ID_UNKNOWN = 0, CKFSP_ID_POSIX = 1, CKFSP_ID_WINDOWS_128 = 2, CKFSP_ID_WINDOWS_64 = 3 };
// Kind ordinals here are independent of ck_file_engine.h's older kind enum.
enum {
    CKFSP_REGULAR_FILE = 0, CKFSP_DIRECTORY = 1, CKFSP_SYMBOLIC_LINK = 2,
    CKFSP_JUNCTION = 3, CKFSP_REPARSE_POINT = 4, CKFSP_FIFO = 5, CKFSP_SOCKET = 6,
    CKFSP_CHARACTER_DEVICE = 7, CKFSP_BLOCK_DEVICE = 8, CKFSP_OTHER = 9
};
enum {
    CKFSP_FIELD_IDENTITY = 1, CKFSP_FIELD_KIND = 2, CKFSP_FIELD_SIZE = 4,
    CKFSP_FIELD_MODIFIED = 8, CKFSP_FIELD_CHANGE_COOKIE = 16
};
enum { CKFSP_ENTRY_EXCLUDED = 1, CKFSP_ENTRY_NAME_COLLISION = 2 };

typedef struct ckfsp_bytes { const void *data; uint64_t length; } ckfsp_bytes;
typedef struct ckfsp_timestamp { int64_t seconds; uint32_t nanoseconds; uint32_t reserved; } ckfsp_timestamp;
typedef struct ckfsp_identity {
    // Nonzero caller identity namespace; mapped to a per-plan AdapterScope.
    // Reusing a namespace asserts comparability, NOT trusted native provenance.
    uint64_t namespace_id;
    uint32_t scheme;
    uint32_t has_generation;
    uint8_t volume[16];
    uint8_t object[16];
    uint64_t generation;
} ckfsp_identity;
typedef struct ckfsp_object {
    uint32_t state;
    uint32_t known_fields;
    ckfsp_identity identity;
    uint32_t kind;
    uint32_t reserved;
    uint64_t size;
    ckfsp_timestamp modified;
    uint64_t timestamp_quantum_ns; // zero = unknown, never inferred
    uint64_t change_cookie;
} ckfsp_object;
typedef struct ckfsp_digest {
    uint32_t state;
    uint32_t algorithm;
    uint8_t bytes[32];
    uint64_t bytes_read;
    ckfsp_object before;
    ckfsp_object after;
} ckfsp_digest;
typedef struct ckfsp_entry {
    uint32_t version;
    uint32_t struct_size;
    ckfsp_bytes relative_key; // exact bytes, NOT NUL terminated; see key rules below
    ckfsp_object object;
    uint32_t flags;
    uint32_t has_digest;
    ckfsp_digest digest;
} ckfsp_entry;
typedef struct ckfsp_inventory {
    uint32_t state;
    uint32_t has_root;
    ckfsp_identity root;
    const ckfsp_entry *entries;
    uint64_t entry_count; // entire bounded inventory, NOT a scan page
} ckfsp_inventory;
typedef struct ckfsp_filters {
    uint32_t has_minimum_size;
    uint32_t has_maximum_size;
    uint64_t minimum_size;
    uint64_t maximum_size;
    uint32_t has_modified_not_before;
    uint32_t has_modified_before;
    ckfsp_timestamp modified_not_before;
    ckfsp_timestamp modified_before;
    uint64_t allowed_kind_mask; // UINT64_C(1) << CKFSP_* kind
    uint64_t maximum_depth;
} ckfsp_filters;
typedef struct ckfsp_limits {
    uint64_t max_entries; // combined source + destination; hard cap 1,000,000
    uint64_t max_path_bytes; // hard cap 65,536
    uint64_t max_total_path_bytes; // hard cap 256 MiB, includes exclusions
    uint64_t max_exclusions; // hard cap 100,000
    uint64_t max_page_rows; // hard cap 4096
    uint64_t max_aggregate_bytes;
} ckfsp_limits;
typedef struct ckfsp_options {
    uint32_t version;
    uint32_t struct_size;
    uint32_t profile;
    uint32_t comparison_mode;
    uint32_t topology;
    uint32_t reserved;
    uint64_t timestamp_quantum_ns;
    ckfsp_filters filters;
    ckfsp_limits limits;
} ckfsp_options;
typedef struct ckfsp_input {
    uint32_t version;
    uint32_t struct_size;
    ckfsp_options options;
    ckfsp_inventory source;
    ckfsp_inventory destination;
    const ckfsp_bytes *excluded_paths;
    uint64_t exclusion_count;
} ckfsp_input;

enum {
    CKFSP_REL_UNKNOWN = 0, CKFSP_REL_SOURCE_ONLY = 1, CKFSP_REL_DESTINATION_ONLY = 2,
    CKFSP_REL_SAME_SIZE = 3, CKFSP_REL_SAME_SIZE_MTIME = 4, CKFSP_REL_IDENTICAL = 5,
    CKFSP_REL_SOURCE_NEWER = 6, CKFSP_REL_DESTINATION_NEWER = 7, CKFSP_REL_SIZE_DIFFERENT = 8,
    CKFSP_REL_CONTENT_DIFFERENT = 9, CKFSP_REL_TYPE_CONFLICT = 10,
    CKFSP_REL_DIRECTORY_PAIR = 11, CKFSP_REL_PROTECTED = 12,
    /* Additive 0.5 native-tree result; the V1 pure input remains main-data only. */
    CKFSP_REL_METADATA_DIFFERENT = 13
};
enum {
    CKFSP_REASON_UNKNOWN_OBJECT = 0, CKFSP_REASON_INCOMPLETE_INVENTORY = 1,
    CKFSP_REASON_UNQUALIFIED_IDENTITY = 2, CKFSP_REASON_MISSING_SIZE = 3,
    CKFSP_REASON_MISSING_TIMESTAMP = 4, CKFSP_REASON_PRECISION_UNAVAILABLE = 5,
    CKFSP_REASON_DIGEST_UNAVAILABLE = 6, CKFSP_REASON_DIGEST_INCOMPLETE = 7,
    CKFSP_REASON_DIGEST_CHANGED = 8, CKFSP_REASON_DIGEST_BINDING_MISMATCH = 9,
    CKFSP_REASON_SOURCE_MISSING = 10, CKFSP_REASON_DESTINATION_MISSING = 11,
    CKFSP_REASON_SAME_SIZE = 12, CKFSP_REASON_SAME_SIZE_MTIME = 13, CKFSP_REASON_SAME_CONTENT = 14,
    CKFSP_REASON_SOURCE_NEWER = 15, CKFSP_REASON_DESTINATION_NEWER = 16,
    CKFSP_REASON_SIZE_MISMATCH = 17, CKFSP_REASON_DIGEST_MISMATCH = 18,
    CKFSP_REASON_TYPE_MISMATCH = 19, CKFSP_REASON_UNSUPPORTED_KIND = 20,
    CKFSP_REASON_DIRECTORY_PAIR = 21, CKFSP_REASON_EXCLUDED = 22,
    CKFSP_REASON_FILTERED = 23, CKFSP_REASON_FILTER_UNKNOWN = 24,
    CKFSP_REASON_PROTECTED_DESCENDANT = 25, CKFSP_REASON_NAME_COLLISION = 26,
    CKFSP_REASON_EXISTING_DESTINATION = 27, CKFSP_REASON_EQUAL_TIME_CONFLICT = 28,
    CKFSP_REASON_ANCESTOR_CONFLICT = 29, CKFSP_REASON_SAME_OBJECT = 30,
    CKFSP_REASON_METADATA_DIGEST_UNAVAILABLE = 31,
    CKFSP_REASON_METADATA_DIGEST_INCOMPLETE = 32,
    CKFSP_REASON_METADATA_DIGEST_CHANGED = 33,
    CKFSP_REASON_METADATA_DIGEST_BINDING_MISMATCH = 34,
    CKFSP_REASON_METADATA_SCHEMA_MISMATCH = 35,
    CKFSP_REASON_METADATA_POLICY_MISMATCH = 36,
    CKFSP_REASON_METADATA_OWNER_UNAVAILABLE = 37,
    CKFSP_REASON_METADATA_MISMATCH = 38,
    CKFSP_REASON_DIRECTORY_METADATA_UNSUPPORTED = 39
};
enum {
    CKFSP_ACTION_REPORT = 0, CKFSP_ACTION_SKIP = 1, CKFSP_ACTION_REVIEW = 2,
    CKFSP_ACTION_COPY = 3, CKFSP_ACTION_MOVE_AFTER_COMMIT = 4,
    CKFSP_ACTION_CREATE_DIRECTORY = 5, CKFSP_ACTION_MERGE_DIRECTORIES = 6,
    CKFSP_ACTION_REPLACE = 7, CKFSP_ACTION_REMOVE_FILE = 8, CKFSP_ACTION_REMOVE_EMPTY_DIRECTORY = 9
};
// Process-local correlation tokens, never security credentials. Row IDs are
// 1-based within a plan; plan IDs are never reused during this process lifetime.
typedef struct ckfsp_token { uint64_t plan_id; uint64_t row_id; } ckfsp_token;
typedef struct ckfsp_row {
    ckfsp_token token;
    uint64_t source_index; // into sorted immutable inventory; CKFSP_NO_INDEX if absent
    uint64_t destination_index;
    uint64_t relative_key_length;
    uint32_t relation;
    uint32_t reason;
    uint32_t action;
    uint32_t destination_protected;
    uint32_t requires_review;
    uint32_t reserved;
} ckfsp_row;
typedef struct ckfsp_page {
    uint64_t plan_id;
    uint64_t total_rows;
    uint64_t row_count;
    uint64_t next_offset;
    uint32_t has_next;
    uint32_t reserved;
} ckfsp_page;
typedef struct ckfsp_summary {
    uint64_t plan_id;
    uint64_t rows;
    uint64_t unknown_rows;
    uint64_t protected_rows;
    uint64_t review_rows;
    uint64_t proposed_writes;
    uint64_t proposed_removals;
    uint64_t source_bytes;
    uint64_t destination_bytes;
    uint64_t proposed_copy_bytes;
    uint32_t source_bytes_complete;
    uint32_t destination_bytes_complete;
    uint32_t proposed_copy_bytes_complete;
    uint32_t reserved;
} ckfsp_summary;
enum {
    CKFSP_REVALIDATION_NOT_CHECKED = 0, CKFSP_REVALIDATION_MATCHES = 1,
    CKFSP_REVALIDATION_FOREIGN_TOKEN = 2, CKFSP_REVALIDATION_EVIDENCE_CHANGED = 3,
    CKFSP_REVALIDATION_INVALID_INPUT = 4
};

// All input version/struct_size pairs must exactly match this version; unknown
// active flags, enums, booleans, reserved fields and incompatible sizes are rejected.
CK_FS_PLAN_API void ckfsp_input_init(ckfsp_input *input);
CK_FS_PLAN_API void ckfsp_entry_init(ckfsp_entry *entry);
CK_FS_PLAN_API ckfsp_status ckfsp_plan_create(const ckfsp_input *input, ckfsp_plan **out_plan);
CK_FS_PLAN_API void ckfsp_plan_destroy(ckfsp_plan *plan);
CK_FS_PLAN_API ckfsp_status ckfsp_plan_get_summary(const ckfsp_plan *plan, ckfsp_summary *out_summary);
// Caller supplies row_capacity elements; capacity must be 1..max_page_rows.
// On failure page and bounded row output storage are zeroed. Handles/other
// outputs reset on entry. No exceptions cross this C boundary.
CK_FS_PLAN_API ckfsp_status ckfsp_plan_page(const ckfsp_plan *plan, uint64_t offset,
    ckfsp_row *out_rows, uint32_t row_capacity, ckfsp_page *out_page);
// Keys: '/' separated relative components, no empty, '.', '..', NUL, backslash,
// absolute or drive paths. No normalization/case folding. Native adapters must
// encode other names losslessly and flag aliases. Copies have NO NUL terminator.
CK_FS_PLAN_API ckfsp_status ckfsp_plan_path_length(const ckfsp_plan *plan, uint64_t row_id, uint64_t *out_length);
CK_FS_PLAN_API ckfsp_status ckfsp_plan_copy_path(const ckfsp_plan *plan, uint64_t row_id,
    void *buffer, uint64_t capacity, uint64_t *out_written);
// A MATCHES result only compares caller claims with frozen caller claims.
// It cannot authorize execution or prove current native identity/content.
CK_FS_PLAN_API ckfsp_status ckfsp_plan_revalidate(const ckfsp_plan *plan, const ckfsp_token *token,
    const ckfsp_input *fresh_input, uint32_t *out_result);

#ifdef __cplusplus
}
#endif
#endif
