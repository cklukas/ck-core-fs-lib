// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef CK_FS_RETRY_H
#define CK_FS_RETRY_H
#include "ck_file_engine.h"
#include "ck_fs_journal_root.h"
#ifdef __cplusplus
#define CKFER_NOEXCEPT noexcept
extern "C" {
#else
#define CKFER_NOEXCEPT
#endif
#define CKFER_VERSION UINT32_C(1)
#define CKFER_MAX_JOBS UINT32_C(4)
#define CKFER_MAX_NATIVE_BYTES UINT32_C(65536)
typedef struct ckfer_job ckfer_job;
enum { CKFER_POSIX_BYTES=0, CKFER_UTF16=1 };
enum { CKFER_LOADING_JOURNAL=0, CKFER_REVIEWING=1, CKFER_AWAITING_REVIEW=2,
    CKFER_REVALIDATING=3, CKFER_COPYING=4, CKFER_COMPLETE=5,
    CKFER_REVIEW_REQUIRED=6, CKFER_CANCELLED=7, CKFER_FAILED=8 };
enum { CKFER_COMPLETE_METADATA_V1=0, CKFER_ORDINARY_METADATA_V1=1 };
enum { CKFER_ORIGINAL_OWNERSHIP=0, CKFER_CURRENT_CALLER_OWNERSHIP=1 };
typedef struct ckfer_native_v1 {
    uint32_t version,struct_size,encoding,reserved;
    const void *data;
    uint64_t byte_count;
} ckfer_native_v1;
typedef struct ckfer_options_v1 {
    uint32_t version,struct_size;
    const ckfe_entry *source,*candidate;
    const ckfe_directory *destination;
    ckfer_native_v1 original_journal_root,original_journal_name;
    ckfer_native_v1 attempt_journal_root,attempt_journal_name;
    ckfer_native_v1 staging_hint,destination_name;
    uint64_t original_item,prefix_bytes,max_content_bytes,max_journal_bytes;
    uint32_t metadata_scope,metadata_ownership,allow_privilege_metadata,reserved;
    uint8_t attempt_id[16];
    uint64_t reserved_words[4];
} ckfer_options_v1;
typedef struct ckfer_identity_v1 {
    uint32_t scheme,has_generation;
    uint8_t volume[16],object[16];
    uint64_t generation;
} ckfer_identity_v1;
typedef struct ckfer_snapshot_v1 {
    uint32_t version,struct_size,state,recovery_required;
    uint64_t job_id,review_id,sequence;
    uint64_t source_bytes,reviewed_bytes,copied_bytes,prefix_bytes,copied_prefix_bytes;
    uint32_t has_source_digest,has_origin_digest,worker_drained,reserved;
    uint8_t source_digest[32],origin_journal_digest[32];
    ckfer_identity_v1 source_identity,candidate_identity;
    uint32_t failure_state,failure_domain;
    int64_t failure_code;
    char failure_operation[96]; /* terminated; may be truncated */
    uint64_t reserved_words[4];
} ckfer_snapshot_v1;

/* Exact version/size; every reserved field must be zero. UTF-16 uses native
 * uint16_t storage, byte_count is even, no terminators. No display-path parsing.
 * Required roots are existing native-private journal directories. A new attempt
 * name and nonzero unique attempt_id are mandatory. max_content_bytes <=4 GiB,
 * max_journal_bytes <=4 MiB; native journal history is bounded to 65536 records.
 * Metadata is explicitly qualified; no implicit loss-consent fallback exists.
 * candidate may be NULL only with prefix_bytes=0 (fresh full retry). Otherwise
 * prefix_bytes is an explicit positive extent, bounded by both native objects.
 * The candidate is read-only; its name is never derived from recovery hints.
 */
CK_FILE_ENGINE_API void ckfer_native_init_v1(ckfer_native_v1*) CKFER_NOEXCEPT;
CK_FILE_ENGINE_API void ckfer_options_init_v1(ckfer_options_v1*) CKFER_NOEXCEPT;
CK_FILE_ENGINE_API void ckfer_snapshot_init_v1(ckfer_snapshot_v1*) CKFER_NOEXCEPT;
/* Copies all names/options and retains native input owners before returning.
 * Do not use a retained cursor concurrently on another worker. No callbacks,
 * native I/O or exceptions run on the caller's thread. Four live jobs maximum.
 */
CK_FILE_ENGINE_API ckfe_api_status ckfer_start_v1(const ckfer_options_v1*,ckfer_job**) CKFER_NOEXCEPT;
/* Retains two READY native root capabilities in memory before returning. Both
 * root pathname fields in options must be initialized but EMPTY; journal names
 * remain required. Every revalidation/open runs on the retry worker through
 * the retained roots. No pathname/procfd fallback or per-job root finish occurs.
 * Drain jobs before finishing/draining shared roots, then release/exit.
 */
CK_FILE_ENGINE_API ckfe_api_status ckfer_start_with_journal_roots_v1(const ckfer_options_v1*,
    const ckfjr_root *original_root,const ckfjr_root *attempt_root,ckfer_job**) CKFER_NOEXCEPT;
CK_FILE_ENGINE_API ckfe_api_status ckfer_poll_v1(const ckfer_job*,ckfer_snapshot_v1*) CKFER_NOEXCEPT;
/* Executes exactly this job's one-use review_id. Review binds the whole source
 * SHA, strict metadata, selected held inputs, origin journal bytes and prefix.
 * Revalidation repeats before copying. Candidate-prefix EOF cannot end the
 * full copy. Assembled and independently reread staging SHA must both equal the
 * frozen source SHA before metadata/publication. Publication is no-replace.
 */
CK_FILE_ENGINE_API ckfe_api_status ckfer_execute_v1(ckfer_job*,uint64_t review_id) CKFER_NOEXCEPT;
CK_FILE_ENGINE_API ckfe_api_status ckfer_cancel_v1(ckfer_job*) CKFER_NOEXCEPT;
/* Cached, nonblocking completion of all worker-owned native I/O/destruction.
 * Helpers must observe drained before release/exit. Terminal snapshots retain
 * native failure scalars and journal-close errors. release requests cancellation
 * and never joins; stop all calls using that handle before releasing it.
 */
CK_FILE_ENGINE_API ckfe_api_status ckfer_worker_drained_v1(const ckfer_job*,uint32_t*) CKFER_NOEXCEPT;
CK_FILE_ENGINE_API ckfe_api_status ckfer_wait_v1(ckfer_job*,uint32_t milliseconds) CKFER_NOEXCEPT;
CK_FILE_ENGINE_API void ckfer_release(ckfer_job*) CKFER_NOEXCEPT;
/* This is a new reviewed operation, never in-place adoption/cleanup or blind
 * replay. Any historical publication intent, untrusted journal tail, existing
 * destination or insufficient native qualification remains review-required.
 * No candidate/source write, rename, deletion or retirement is performed. Value IDs
 * and creation times never grant mutation authority. Anonymous hints never
 * select native objects. Progress counts observed bytes, not a snapshot proof.
 */
#ifdef __cplusplus
}
#endif
#undef CKFER_NOEXCEPT
#endif
