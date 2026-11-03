/* Copyright (c) 2026 C. Klukas. All rights reserved.
 * SPDX-License-Identifier: LGPL-2.0-or-later */
#ifndef CK_FS_DIAGNOSTICS_H
#define CK_FS_DIAGNOSTICS_H
#include "ck_fs_tree.h"
#ifdef __cplusplus
#define CKFSD_NOEXCEPT noexcept
extern "C" {
#else
#define CKFSD_NOEXCEPT
#endif
#define CKFET_FAILURE_DETAILS_VERSION 1u
#define CKFET_FAILURE_DETAILS_MIN_ABI_MINOR 5u
typedef struct ckfet_failure_details_v1 {
    uint32_t version,struct_size,has_failure,failure_state;
    uint32_t failure_domain,operation_truncated;
    int64_t failure_code;
    uint64_t sequence,plan_generation,current_row;
    uint32_t has_current_row,operation_bytes;
    char operation[96];
    uint64_t reserved[4];
} ckfet_failure_details_v1;
CK_FILE_ENGINE_API void ckfet_failure_details_init_v1(ckfet_failure_details_v1*) CKFSD_NOEXCEPT;
/* Requires ABI minor >=5. Initialize the output before use. Copies one cached
 * publication under the job's cache synchronization: no allocation, native
 * filesystem I/O, callback, or borrowed pointer. The sequence identifies that
 * publication; compare it with snapshot.sequence when correlating separate
 * reads. No failure yields has_failure=0 and an empty tag. Invalid arguments
 * leave the output unchanged. Cached details remain readable after drain.
 * Tags are bounded diagnostic bytes, NEVER mutation or recovery authority. */
CK_FILE_ENGINE_API ckfe_api_status ckfet_get_failure_details_v1(
    const ckfet_job*,ckfet_failure_details_v1*) CKFSD_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef CKFSD_NOEXCEPT
#endif
