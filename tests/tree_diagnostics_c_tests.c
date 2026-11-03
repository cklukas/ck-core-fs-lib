/* Copyright (c) 2026 C. Klukas. All rights reserved.
 * SPDX-License-Identifier: LGPL-2.0-or-later */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "ck_fs_diagnostics.h"
#include "ck_fs_journal_root.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <wchar.h>
typedef wchar_t PathChar;
static void pause_worker(void){Sleep(10);}
static ckfe_api_status open_directory(ckfe_engine* e,const PathChar* path,ckfe_directory** out,ckfe_error* error){
    _Static_assert(sizeof(wchar_t)==sizeof(uint16_t),"native UTF-16 fixture");
    return ckfe_directory_open_utf16(e,(const uint16_t*)path,wcslen(path),0,out,error);
}
#else
#include <time.h>
typedef char PathChar;
static void pause_worker(void){const struct timespec delay={0,10000000};nanosleep(&delay,NULL);}
static ckfe_api_status open_directory(ckfe_engine* e,const PathChar* path,ckfe_directory** out,ckfe_error* error){
    return ckfe_directory_open_utf8(e,path,0,out,error);
}
#endif
static int run(const PathChar* address,const PathChar* source_address){
    ckfe_engine* engine=NULL;ckfe_directory *parent=NULL,*source_parent=NULL;
    ckfe_entry *source=NULL,*destination=NULL;ckfe_error error;ckfe_error_init(&error);
    assert(ckfe_engine_create(&engine)==CKFE_API_OK);
    assert(open_directory(engine,address,&parent,&error)==CKFE_API_OK);
    assert(open_directory(engine,source_address,&source_parent,&error)==CKFE_API_OK);
    ckfjr_options_v1 preparation;ckfjr_options_init_v1(&preparation);
    preparation.parent=source_parent;preparation.disposition=CKFJR_PROVISION_CHILD;
#ifdef _WIN32
    const uint16_t name[]={'p','r','i','v','a','t','e'};
    preparation.child.encoding=CKFJR_UTF16;preparation.child.data=name;preparation.child.byte_count=sizeof(name);
#else
    preparation.child.data="private";preparation.child.byte_count=7;
#endif
    ckfjr_root* root=NULL;assert(ckfjr_start_v1(&preparation,&root)==CKFE_API_OK);
    ckfe_directory_destroy(source_parent);source_parent=NULL;
    ckfjr_snapshot_v1 root_state;ckfjr_snapshot_init_v1(&root_state);
    for(unsigned i=0;i<3000;++i){
        assert(ckfjr_poll_v1(root,&root_state)==CKFE_API_OK);
        if(root_state.state!=CKFJR_PREPARING)break;
        pause_worker();
    }
    assert(root_state.state==CKFJR_READY);
    assert(ckfe_entry_open_utf8(parent,"source",&source,&error)==CKFE_API_OK);
    assert(ckfe_entry_open_utf8(parent,"target",&destination,&error)==CKFE_API_OK);
    ckfet_options_v1 options;ckfet_options_init_v1(&options);
    options.profile=CKFSP_COPY;options.allow_metadata_loss=1;options.operation_id[0]=73;
    ckfet_job* job=NULL;
    assert(ckfet_start_with_journal_root_v1(source,destination,&options,root,&job,&error)==CKFE_API_OK);
    ckfe_entry_destroy(source);ckfe_entry_destroy(destination);
    ckfe_directory_destroy(parent);ckfe_engine_destroy(engine);ckfe_error_free(&error);
    ckfet_snapshot_v1 snapshot;memset(&snapshot,0,sizeof(snapshot));
    snapshot.version=CKFET_VERSION;snapshot.struct_size=sizeof(snapshot);
    uint32_t drained=0;
    for(unsigned i=0;i<3000;++i){
        assert(ckfet_poll_v1(job,&snapshot)==CKFE_API_OK);
        assert(ckfet_worker_drained_v1(job,&drained)==CKFE_API_OK);
        if(drained)break;
        pause_worker();
    }
    assert(drained&&snapshot.state==CKFET_FAILED&&snapshot.plan_generation==0&&snapshot.receipt_id==0);
    ckfet_failure_details_v1 details;ckfet_failure_details_init_v1(&details);
    assert(ckfet_get_failure_details_v1(job,&details)==CKFE_API_OK&&details.has_failure);
    assert(details.sequence==snapshot.sequence&&details.plan_generation==snapshot.plan_generation);
    assert(details.failure_state==snapshot.failure_state&&details.failure_domain==snapshot.failure_domain&&details.failure_code==snapshot.failure_code);
    assert(details.failure_state==CKFE_OBSERVATION_UNSUPPORTED&&details.failure_domain==CKFE_ERROR_ADAPTER&&details.failure_code==18);
    assert(!details.has_current_row&&!details.current_row&&!details.operation_truncated);
    assert(strcmp(details.operation,"journal_scope.private_root_overlap")==0&&details.operation_bytes==strlen(details.operation));
    const ckfet_failure_details_v1 original=details;
    ckfet_request_cancel(job);
    ckfet_row_v1 row;ckfet_page_v1 page;
    assert(ckfet_page_v1_get(job,1,0,&row,1,&page)==CKFE_API_NOT_READY);
    ckfet_snapshot_v1 events[2];uint64_t count=0,coalesced=0;
    assert(ckfet_drain_v1(job,events,2,&count,&coalesced)==CKFE_API_OK);
    assert(ckfet_get_failure_details_v1(job,&details)==CKFE_API_OK&&memcmp(&original,&details,sizeof(details))==0);
    /* A retained terminal Tree cache owns no Root-native consumers. */
    assert(ckfjr_finish_v1(root)==CKFE_API_OK);
    for(unsigned i=0;i<3000;++i){
        assert(ckfjr_poll_v1(root,&root_state)==CKFE_API_OK);
        if(root_state.worker_drained)break;
        pause_worker();
    }
    assert(root_state.worker_drained&&root_state.state==CKFJR_COMPLETE);
    assert(ckfet_get_failure_details_v1(job,&details)==CKFE_API_OK&&memcmp(&original,&details,sizeof(details))==0);
    ckfet_release(job);ckfjr_release(root);
    puts("C diagnostics: native overlap refusal, coherent tuple/tag, terminal inspection and independent Root drain passed");
    return 0;
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv){assert(argc==3);return run(argv[1],argv[2]);}
#else
int main(int argc,char** argv){assert(argc==3);return run(argv[1],argv[2]);}
#endif
