// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// ELF packaging regression: build with executable exports enabled, pass the
// exact matching SDK shared-library pathname. No native filesystem request
// is valid: the real opener must reject the zeroed options before effects.
// Exit 23 identifies cross-module dispatch/foreign-handle corruption.
#define _GNU_SOURCE
#include "ck_fs_session.h"
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(__ELF__)
#error "This regression requires an ELF platform"
#endif
#ifndef CK_FS_ELF_TEST_INTERPOSE
#define CK_FS_ELF_TEST_INTERPOSE 1
#endif
static unsigned fake_calls;
static unsigned char *foreign;
#if CK_FS_ELF_TEST_INTERPOSE
ckfss_status ckfss_session_open(const ckfss_options *options,ckfss_session **out,ckfss_error *error) {
    (void)options;++fake_calls;if(error)memset(error,0,sizeof(*error));*out=(ckfss_session*)foreign;return CKFSS_OK;
}
#endif
static int symbol(void *module,const char *name,void *destination,size_t size) {
    void *address=dlsym(module,name);if(!address||size!=sizeof(address)){fprintf(stderr,"dlsym %s: %s\n",name,dlerror());return 0;}
    memcpy(destination,&address,size);return 1;
}
int main(int argc,char **argv) {
    if(argc!=2)return 10;
    foreign=calloc(1,1024*1024);if(!foreign)return 11;
#if CK_FS_ELF_TEST_INTERPOSE
    ckfss_status (*exported)(const ckfss_options*,ckfss_session**,ckfss_error*)=NULL;
    if(!symbol(RTLD_DEFAULT,"ckfss_session_open",&exported,sizeof(exported)) ||
        exported!=ckfss_session_open) {
        fprintf(stderr,"interposer is not exported: enable executable exports\n");return 15;
    }
#endif
    void *module=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!module){fprintf(stderr,"dlopen: %s\n",dlerror());return 12;}
    ckfss_status (*real_open)(const ckfss_options*,ckfss_session**,ckfss_error*)=NULL;
    ckfss_status (*verified)(const ckfss_options*,const ckfss_metadata_policy*,ckfss_session**,ckfss_error*)=NULL;
    void (*policy_init)(ckfss_metadata_policy*)=NULL;
    if(!symbol(module,"ckfss_session_open",&real_open,sizeof(real_open))||!symbol(module,"ckfss_session_open_verified",&verified,sizeof(verified))||!symbol(module,"ckfss_metadata_policy_init",&policy_init,sizeof(policy_init)))return 13;
    ckfss_options options={0};ckfss_error error={0};ckfss_session *direct=(ckfss_session*)(uintptr_t)1;
    ckfss_status direct_status=real_open(&options,&direct,&error);
    if(direct_status!=CKFSS_INVALID_ARGUMENT||direct){fprintf(stderr,"direct real open failed control %u %p\n",direct_status,(void*)direct);return 14;}
    ckfss_metadata_policy policy;policy_init(&policy);ckfss_session *out=(ckfss_session*)(uintptr_t)1;
    ckfss_status status=verified(&options,&policy,&out,&error);size_t changed=0;
    for(size_t n=0;n<1024*1024;++n)changed+=foreign[n]!=0;
    printf("{\"interpose\":%u,\"direct_real_status\":%u,\"verified_status\":%u,\"fake_calls\":%u,\"foreign_output\":%u,\"foreign_bytes_changed\":%zu}\n",CK_FS_ELF_TEST_INTERPOSE,direct_status,status,fake_calls,out==(ckfss_session*)foreign,changed);
    const int result=fake_calls||out==(ckfss_session*)foreign||changed?23:status==CKFSS_INVALID_ARGUMENT&&!out?0:24;
    /* Never hand the foreign opaque pointer to another SDK API or destructor. */
    dlclose(module);free(foreign);return result;
}
