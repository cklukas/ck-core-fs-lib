// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_journal_root.h"
#include <stddef.h>
_Static_assert(sizeof(((ckfjr_snapshot_v1*)0)->failure_code)==8,"native error width");
_Static_assert(sizeof(((ckfjr_snapshot_v1*)0)->object)==16,"native identity width");
int journal_root_c_smoke(void) {
    ckfjr_options_v1 options;ckfjr_options_init_v1(&options);
    ckfjr_snapshot_v1 snapshot;ckfjr_snapshot_init_v1(&snapshot);
    ckfjr_root* root=(ckfjr_root*)(uintptr_t)1;
    if(options.version!=CKFJR_VERSION||options.struct_size!=sizeof(options)||options.max_ancestors!=256||
        options.child.struct_size!=sizeof(ckfjr_native_v1)||snapshot.struct_size!=sizeof(snapshot))return 1;
    if(ckfjr_start_v1(&options,&root)!=CKFE_API_INVALID_ARGUMENT||root)return 2;
    if(ckfjr_poll_v1(NULL,&snapshot)!=CKFE_API_INVALID_ARGUMENT)return 3;
    if(ckfjr_worker_drained_v1(NULL,NULL)!=CKFE_API_INVALID_ARGUMENT)return 4;
    uint32_t drained=1;
    if(ckfjr_worker_drained_v1(NULL,&drained)!=CKFE_API_INVALID_ARGUMENT||drained!=0)return 5;
    ckfjr_release(NULL);return 0;
}
#ifdef CKFJR_C_SMOKE_MAIN
int main(void) {return journal_root_c_smoke();}
#endif
