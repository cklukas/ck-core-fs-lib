// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_retry.h"
#include <stddef.h>
_Static_assert(sizeof(((ckfer_options_v1*)0)->attempt_id)==16,"ID width");
_Static_assert(sizeof(((ckfer_snapshot_v1*)0)->source_digest)==32,"SHA width");
_Static_assert(sizeof(((ckfer_snapshot_v1*)0)->failure_code)==8,"error width");
#if UINTPTR_MAX == UINT64_MAX
_Static_assert(sizeof(ckfer_native_v1)==32,"native v1 ABI");
_Static_assert(sizeof(ckfer_options_v1)==320,"options v1 ABI");
_Static_assert(sizeof(ckfer_snapshot_v1)==400,"snapshot v1 ABI");
_Static_assert(offsetof(ckfer_snapshot_v1,failure_code)==264,"failure offset v1 ABI");
#endif
int retry_c_smoke(void) {
    ckfer_options_v1 options;ckfer_options_init_v1(&options);
    ckfer_snapshot_v1 snapshot;ckfer_snapshot_init_v1(&snapshot);
    ckfer_job *job=(ckfer_job*)(uintptr_t)1;
    if(options.version!=CKFER_VERSION||options.struct_size!=sizeof(options)||
        options.original_journal_root.struct_size!=sizeof(ckfer_native_v1)||
        snapshot.struct_size!=sizeof(snapshot))return 1;
    if(ckfer_start_v1(&options,&job)!=CKFE_API_INVALID_ARGUMENT||job)return 2;
    if(ckfer_poll_v1(NULL,&snapshot)!=CKFE_API_INVALID_ARGUMENT)return 3;
    if(ckfer_worker_drained_v1(NULL,NULL)!=CKFE_API_INVALID_ARGUMENT)return 4;
    if(ckfer_start_with_journal_roots_v1(&options,NULL,NULL,&job)!=CKFE_API_INVALID_ARGUMENT||job)return 5;
    ckfer_release(NULL);return 0;
}
#ifdef CKFER_C_SMOKE_MAIN
int main(void) { return retry_c_smoke(); }
#endif
