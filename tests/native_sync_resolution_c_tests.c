/* Copyright (c) 2026 C. Klukas. All rights reserved. */
#include "ck_fs_session.h"
#include "ck_fs_journal_root.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"C resolution line %d: %s\n",__LINE__,#x);return 1; } } while(0)
static ckfss_native_path address(const char* p){ckfss_native_path out={p,strlen(p),CKFSS_POSIX_BYTES,0};return out;}
int main(int argc,char** argv){
    CHECK(argc==4);ckfss_options o;ckfss_options_init(&o);o.coordinator=address(argv[1]);o.left=address(argv[2]);o.right=address(argv[3]);
    ckfss_metadata_policy m;ckfss_metadata_policy_init(&m);m.scope=CKFSS_METADATA_ORDINARY_V1;
    ckfss_two_way_policy p;ckfss_two_way_policy_init(&p);ckfss_resolution_limits_v1 limits;ckfss_resolution_limits_init_v1(&limits);
    ckfss_resolution_job* job=NULL;ckfss_error error;ckfss_status status=ckfss_resolution_open_v1(&o,&m,&p,&limits,&job,&error);
    if(status!=CKFSS_OK){fprintf(stderr,"open: %s code=%lld\n",error.operation,(long long)error.code);return 1;}
    ckfss_two_way_info info;CHECK(ckfss_resolution_get_info_v1(job,&info)==CKFSS_OK);CHECK(info.rows==1&&info.generation==0);
    ckfss_named_resolution_v1 names;ckfss_named_resolution_init_v1(&names);names.left_version_name=address("a.left");names.right_version_name=address("a.right");
    ckfss_resolution_review* review=NULL;CHECK(ckfss_resolution_assess_v1(job,&names,1,&review,&error)==CKFSS_OK);
    uint64_t count=0;CHECK(ckfss_resolution_review_get_count_v1(review,&count)==CKFSS_OK&&count==6);
    unsigned publishes=0,protects=0;for(uint64_t i=0;i<count;++i){ckfss_resolution_operation_v1 op;CHECK(ckfss_resolution_review_get_operation_v1(review,i,&op)==CKFSS_OK);CHECK(op.component_count==1&&op.source_row==0);char name[64];uint64_t required=0;uint32_t encoding=99;CHECK(ckfss_resolution_review_get_component_v1(review,i,0,&encoding,name,sizeof(name),&required)==CKFSS_OK);CHECK(encoding==CKFSS_POSIX_BYTES);if(op.operation==CKFSS_RESOLUTION_PROTECT_ORIGINAL){++protects;CHECK(op.original_protected&&required==1&&name[0]=='a');}else{++publishes;CHECK(!op.original_protected&&required>1);}}
    CHECK(protects==2&&publishes==4);CHECK(ckfss_resolution_approve_v1(job,review,0,&error)==CKFSS_UNAVAILABLE);
    CHECK(ckfss_resolution_approve_v1(job,review,1,&error)==CKFSS_OK);CHECK(ckfss_resolution_approve_v1(job,review,1,&error)==CKFSS_UNAVAILABLE);ckfss_resolution_review_destroy_v1(review);
    for(unsigned i=0;i<3000;++i){status=ckfss_resolution_advance_v1(job,&info,&error);if(status!=CKFSS_OK){fprintf(stderr,"advance %s code=%lld\n",error.operation,(long long)error.code);return 1;}if(info.state==CKFSS_TW_COMPLETE)break;}
    CHECK(info.state==CKFSS_TW_COMPLETE&&info.generation==1&&info.completed_operations==4&&info.protected_artifacts==2&&info.pending_rows==1);
    ckfss_two_way_retained protected;CHECK(ckfss_resolution_get_protected_v1(job,0,&protected)==CKFSS_OK);CHECK(protected.protection==CKFSS_TW_PROTECTED&&protected.component_count==1);
    char pending[64];uint64_t bytes=0;CHECK(ckfss_resolution_get_pending_key_v1(job,0,pending,sizeof(pending),&bytes)==CKFSS_OK&&bytes>0);
    CHECK(ckfss_resolution_finish_io_v1(job,&error)==CKFSS_OK);CHECK(ckfss_resolution_finish_io_v1(job,&error)==CKFSS_OK);ckfss_resolution_destroy_v1(job);job=NULL;
    CHECK(ckfss_resolution_open_v1(&o,&m,&p,&limits,&job,&error)==CKFSS_OK);CHECK(ckfss_resolution_get_info_v1(job,&info)==CKFSS_OK&&info.generation==1&&info.protected_artifacts==2);CHECK(ckfss_resolution_finish_io_v1(job,&error)==CKFSS_OK);ckfss_resolution_destroy_v1(job);job=NULL;
    ckfe_engine* engine=NULL;ckfe_directory* directory=NULL;ckfe_error native_error={0};CHECK(ckfe_engine_create(&engine)==CKFE_API_OK);CHECK(ckfe_directory_open_utf8(engine,argv[1],0,&directory,&native_error)==CKFE_API_OK);
    ckfjr_options_v1 root_options;ckfjr_options_init_v1(&root_options);root_options.parent=directory;root_options.disposition=CKFJR_ADOPT_HELD;ckfjr_root* root=NULL;CHECK(ckfjr_start_v1(&root_options,&root)==CKFE_API_OK);ckfe_directory_destroy(directory);ckfe_engine_destroy(engine);ckfe_error_free(&native_error);
    ckfjr_snapshot_v1 root_state;ckfjr_snapshot_init_v1(&root_state);for(unsigned i=0;i<500;++i){CHECK(ckfjr_poll_v1(root,&root_state)==CKFE_API_OK);if(root_state.state!=CKFJR_PREPARING)break;CHECK(ckfjr_wait_v1(root,20)==CKFE_API_OK);}CHECK(root_state.state==CKFJR_READY);
    memset(&o.coordinator,0,sizeof(o.coordinator));CHECK(ckfss_resolution_open_with_journal_root_v1(&o,&m,&p,&limits,root,&job,&error)==CKFSS_OK);CHECK(ckfss_resolution_get_info_v1(job,&info)==CKFSS_OK&&info.generation==1&&info.protected_artifacts==2);
    CHECK(ckfjr_finish_v1(root)==CKFE_API_OK);CHECK(ckfss_resolution_finish_io_v1(job,&error)==CKFSS_OK);CHECK(ckfjr_poll_v1(root,&root_state)==CKFE_API_OK&&!root_state.worker_drained);ckfss_resolution_destroy_v1(job);
    for(unsigned i=0;i<500;++i){CHECK(ckfjr_poll_v1(root,&root_state)==CKFE_API_OK);if(root_state.worker_drained)break;CHECK(ckfjr_wait_v1(root,20)==CKFE_API_OK);}CHECK(root_state.worker_drained&&root_state.state==CKFJR_COMPLETE);ckfjr_release(root);
    puts("pure C resolution roundtrip + held Root drain PASS");return 0;
}
