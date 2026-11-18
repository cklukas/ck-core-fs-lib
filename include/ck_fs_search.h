// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef CK_FS_SEARCH_H
#define CK_FS_SEARCH_H

#include "ck_file_engine.h"
#include "ck_fs_plan.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Headless, cancellable recursive filename and content search worker.
 * Public calls copy bounded memory only and never block on native I/O; all
 * directory enumeration and content reads execute on the owned worker through
 * handle-relative DirectoryCursor / OpenedEntry primitives without following
 * descendant symlinks or reparse points. Results stream incrementally while
 * CKFES_RUNNING and remain queryable until ckfes_release().
 */
#define CKFES_VERSION UINT32_C(1)
#define CKFES_MAX_JOBS UINT32_C(16)
#define CKFES_HARD_MAX_RESULTS UINT32_C(200000)
#define CKFES_HARD_MAX_DEPTH UINT32_C(4096)

typedef struct ckfes_job ckfes_job;

enum {
    CKFES_POSIX_BYTES = 0,
    CKFES_UTF16 = 1
};

enum {
    CKFES_RUNNING = 0,
    CKFES_COMPLETE = 1,
    CKFES_CANCELLED = 2,
    CKFES_FAILED = 3
};

enum {
    CKFES_NAME_NONE = 0,
    CKFES_NAME_SUBSTRING = 1,
    CKFES_NAME_GLOB = 2
};

typedef struct ckfes_native {
    const void *data;
    uint64_t units; /* bytes for CKFES_POSIX_BYTES, uint16_t units for CKFES_UTF16; no NUL */
    uint32_t encoding;
    uint32_t reserved;
} ckfes_native;

typedef struct ckfes_options_v1 {
    uint32_t version;
    uint32_t struct_size;
    ckfes_native root_path;
    ckfes_native name_query;
    ckfes_native content_query;
    uint32_t name_mode;           /* CKFES_NAME_* */
    uint32_t case_sensitive;      /* 0 or 1 */
    uint32_t include_hidden;      /* 0 or 1 */
    uint32_t skip_binary_content; /* 0 or 1 */
    uint32_t has_minimum_size;
    uint32_t has_maximum_size;
    uint64_t minimum_size;
    uint64_t maximum_size;
    uint32_t has_modified_not_before;
    uint32_t has_modified_before;
    ckfsp_timestamp modified_not_before;
    ckfsp_timestamp modified_before;
    uint64_t max_depth;              /* 1 = root children only; 1..CKFES_HARD_MAX_DEPTH */
    uint64_t max_results;            /* 1..CKFES_HARD_MAX_RESULTS */
    uint64_t max_content_file_bytes; /* max regular-file size scanned for content_query */
    uint64_t reserved[4];
} ckfes_options_v1;

typedef struct ckfes_snapshot_v1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t state;
    uint32_t truncated;
    uint64_t sequence;
    uint64_t scanned_entries;
    uint64_t scanned_directories;
    uint64_t matched_entries;
    uint64_t denied_entries;
    uint32_t failure_state;
    uint32_t failure_domain;
    int64_t failure_code;
} ckfes_snapshot_v1;

typedef struct ckfes_hit_v1 {
    uint64_t hit_index;
    uint32_t kind; /* ckfe_object_kind */
    uint32_t has_modified;
    uint64_t logical_size;
    ckfsp_timestamp modified;
    uint64_t relative_units;
    uint32_t encoding;
    uint32_t reserved;
} ckfes_hit_v1;

CK_FILE_ENGINE_API void ckfes_options_init_v1(ckfes_options_v1 *options);
CK_FILE_ENGINE_API ckfe_api_status ckfes_start_v1(const ckfes_options_v1 *options,
    ckfes_job **out_job, ckfe_error *error);
CK_FILE_ENGINE_API ckfe_api_status ckfes_poll_v1(const ckfes_job *job,
    ckfes_snapshot_v1 *out_snapshot);
CK_FILE_ENGINE_API ckfe_api_status ckfes_worker_drained_v1(const ckfes_job *job,
    uint32_t *out_drained);
CK_FILE_ENGINE_API ckfe_api_status ckfes_page_v1_get(const ckfes_job *job,
    uint64_t offset, ckfes_hit_v1 *out_hits, uint32_t capacity, uint32_t *out_count);
/* Copies exact relative path units ('/' separated on POSIX, '\\' separated on
 * Windows; no trailing NUL). Returns CKFE_API_BUFFER_TOO_SMALL with required
 * units when capacity_units is smaller than relative_units. */
CK_FILE_ENGINE_API ckfe_api_status ckfes_path_copy_v1(const ckfes_job *job,
    uint64_t hit_index, void *buffer, uint64_t capacity_units,
    uint64_t *out_required_units, uint32_t *out_encoding);
CK_FILE_ENGINE_API void ckfes_request_cancel(ckfes_job *job);
CK_FILE_ENGINE_API void ckfes_release(ckfes_job *job);

#ifdef __cplusplus
}
#endif

#endif
