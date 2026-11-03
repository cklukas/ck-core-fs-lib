// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef CK_FS_JOURNAL_ROOT_H
#define CK_FS_JOURNAL_ROOT_H
#include "ck_file_engine.h"
#ifdef __cplusplus
#define CKFJR_NOEXCEPT noexcept
extern "C" {
#else
#define CKFJR_NOEXCEPT
#endif
#define CKFJR_VERSION UINT32_C(1)
#define CKFJR_MAX_ROOTS UINT32_C(8)
typedef struct ckfjr_root ckfjr_root;
enum { CKFJR_POSIX_BYTES=0, CKFJR_UTF16=1 };
enum { CKFJR_ADOPT_HELD=0, CKFJR_ADOPT_CHILD=1, CKFJR_PROVISION_CHILD=2 };
enum { CKFJR_PREPARING=0, CKFJR_READY=1, CKFJR_FINISHING=2,
       CKFJR_COMPLETE=3, CKFJR_FAILED=4, CKFJR_CANCELLED=5 };
typedef struct ckfjr_native_v1 {
    uint32_t version,struct_size,encoding,reserved;
    const void *data;
    uint64_t byte_count;
} ckfjr_native_v1;
typedef struct ckfjr_options_v1 {
    uint32_t version,struct_size;
    const ckfe_directory *parent;
    ckfjr_native_v1 child;
    uint32_t disposition,max_ancestors;
    uint64_t reserved_words[4];
} ckfjr_options_v1;
typedef struct ckfjr_snapshot_v1 {
    uint32_t version,struct_size,state,phase;
    uint64_t sequence;
    uint32_t acquired_directories,flushed_directories,directory_creates,recovery_required;
    uint32_t worker_drained,identity_scheme,failure_state,failure_domain;
    uint8_t volume[16],object[16];
    int64_t failure_code;
    char failure_operation[96];
    uint64_t reserved_words[4];
} ckfjr_snapshot_v1;
CK_FILE_ENGINE_API void ckfjr_native_init_v1(ckfjr_native_v1*) CKFJR_NOEXCEPT;
CK_FILE_ENGINE_API void ckfjr_options_init_v1(ckfjr_options_v1*) CKFJR_NOEXCEPT;
CK_FILE_ENGINE_API void ckfjr_snapshot_init_v1(ckfjr_snapshot_v1*) CKFJR_NOEXCEPT;
/* Exact version/size and zero reserved fields. parent is retained in memory
 * before return. child is one exact native component, without terminator;
 * UTF-16 byte_count is even. ADOPT_HELD requires an empty child. max_ancestors
 * is 1..4096. PROVISION_CHILD creates if absent, then adopts the private object
 * actually acquired by native open; no identity-bound mkdir claim is made.
 * All acquisition, privacy/ancestry checks and durability barriers run on the
 * owned worker. READY requires successful barriers. No pathname/procfd reopen
 * can replace the retained native root. Failed/cancelled creation is preserved
 * for explicit recovery, never removed through a potentially replaced name.
 */
CK_FILE_ENGINE_API ckfe_api_status ckfjr_start_v1(const ckfjr_options_v1*,ckfjr_root**) CKFJR_NOEXCEPT;
CK_FILE_ENGINE_API ckfe_api_status ckfjr_poll_v1(const ckfjr_root*,ckfjr_snapshot_v1*) CKFJR_NOEXCEPT;
/* Memory-only copy of the opaque owner; no native I/O or access upgrade. */
CK_FILE_ENGINE_API ckfe_api_status ckfjr_retain_v1(const ckfjr_root*,ckfjr_root**) CKFJR_NOEXCEPT;
/* Stops preparation or requests final closure. New consumer acquisition is
 * refused. Existing shared consumers keep native authority alive. The worker
 * closes only after every consumer releases its shared capability. Per-journal
 * finish closes its own duplicate, never this shared root. Observe drained and
 * the final snapshot to retain delayed flush/close errors before release/exit.
 */
CK_FILE_ENGINE_API ckfe_api_status ckfjr_finish_v1(ckfjr_root*) CKFJR_NOEXCEPT;
CK_FILE_ENGINE_API ckfe_api_status ckfjr_cancel_v1(ckfjr_root*) CKFJR_NOEXCEPT;
CK_FILE_ENGINE_API ckfe_api_status ckfjr_worker_drained_v1(const ckfjr_root*,uint32_t*) CKFJR_NOEXCEPT;
CK_FILE_ENGINE_API ckfe_api_status ckfjr_wait_v1(ckfjr_root*,uint32_t milliseconds) CKFJR_NOEXCEPT;
/* Release never joins or performs filesystem I/O on the caller. Last release
 * requests cancellation/finish. Stop concurrent calls using that handle first.
 */
CK_FILE_ENGINE_API void ckfjr_release(ckfjr_root*) CKFJR_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef CKFJR_NOEXCEPT
#endif
