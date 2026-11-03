// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_tree.h"
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <thread>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
namespace {thread_local bool polling=false;thread_local unsigned allocations=0,io=0;}
void* operator new(std::size_t n){if(polling){++allocations;throw std::bad_alloc();}if(void*p=std::malloc(n?n:1))return p;throw std::bad_alloc();}void* operator new[](std::size_t n){return ::operator new(n);}void operator delete(void*p)noexcept{std::free(p);}void operator delete[](void*p)noexcept{std::free(p);}void operator delete(void*p,std::size_t)noexcept{std::free(p);}void operator delete[](void*p,std::size_t)noexcept{std::free(p);}
extern "C" int __real_openat(int,const char*,int,...);extern "C" int __real_fstat(int,struct stat*);extern "C" int __real_statx(int,const char*,int,unsigned,struct statx*);extern "C" int __real_close(int);extern "C" ssize_t __real_pread(int,void*,size_t,off_t);
extern "C" int __wrap_openat(int d,const char*p,int flags,...){if(polling)++io;int mode=0;if((flags&O_CREAT)||((flags&O_TMPFILE)==O_TMPFILE)){va_list a;va_start(a,flags);mode=va_arg(a,int);va_end(a);}return __real_openat(d,p,flags,mode);}
extern "C" int __wrap_fstat(int fd,struct stat*s){if(polling)++io;return __real_fstat(fd,s);}extern "C" int __wrap_statx(int fd,const char*p,int f,unsigned mask,struct statx*s){if(polling)++io;return __real_statx(fd,p,f,mask,s);}extern "C" int __wrap_close(int fd){if(polling)++io;return __real_close(fd);}extern "C" ssize_t __wrap_pread(int fd,void*p,size_t n,off_t o){if(polling)++io;return __real_pread(fd,p,n,o);}
namespace {
ckfet_snapshot_v1 wait(ckfet_job*j,bool command=false){for(unsigned i=0;i<10000;++i){ckfet_snapshot_v1 s{};assert(ckfet_poll_v1(j,&s)==CKFE_API_OK);if(command?s.command_state>=CKFET_COMMAND_ACCEPTED:s.state!=CKFET_INVENTORY)return s;std::this_thread::sleep_for(std::chrono::milliseconds(1));}std::abort();}
void pause(ckfet_job*j,bool value){ckfet_request_pause(j,value);for(unsigned i=0;i<10000;++i){ckfet_snapshot_v1 s{};assert(ckfet_poll_v1(j,&s)==CKFE_API_OK);if(s.paused==unsigned(value))return;std::this_thread::sleep_for(std::chrono::milliseconds(1));}std::abort();}
void drain(ckfet_job*j){ckfet_request_cancel(j);for(unsigned i=0;i<10000;++i){uint32_t done=0;assert(ckfet_worker_drained_v1(j,&done)==CKFE_API_OK);if(done)return;std::this_thread::sleep_for(std::chrono::milliseconds(1));}std::abort();}
ckfet_name_feedback_v1 get(ckfet_job*j,uint64_t gen,uint64_t row,uint32_t choice){ckfet_name_feedback_v1 f{};assert(ckfet_name_feedback_get_v1(j,gen,row,choice,&f)==CKFE_API_OK);assert(f.version==1&&f.struct_size==sizeof(f)&&f.plan_generation==gen&&f.row_id==row);return f;}
}
int main(int argc,char**argv){
 assert(argc==2);ckfe_engine* e=nullptr;ckfe_directory* parent=nullptr;ckfe_entry *source=nullptr,*target=nullptr;ckfe_error err{};ckfe_error_init(&err);assert(ckfe_engine_create(&e)==CKFE_API_OK);assert(ckfe_directory_open_utf8(e,argv[1],0,&parent,&err)==CKFE_API_OK);assert(ckfe_entry_open_utf8(parent,"source",&source,&err)==CKFE_API_OK);assert(ckfe_entry_open_utf8(parent,"target",&target,&err)==CKFE_API_OK);
 ckfjr_options_v1 ro;ckfjr_options_init_v1(&ro);ro.parent=parent;ro.disposition=CKFJR_PROVISION_CHILD;ro.child.data="journal";ro.child.byte_count=7;ckfjr_root* root=nullptr;assert(ckfjr_start_v1(&ro,&root)==CKFE_API_OK);ckfjr_snapshot_v1 rs{};ckfjr_snapshot_init_v1(&rs);for(unsigned i=0;i<10000;++i){assert(ckfjr_poll_v1(root,&rs)==CKFE_API_OK);if(rs.state!=CKFJR_PREPARING)break;std::this_thread::sleep_for(std::chrono::milliseconds(1));}assert(rs.state==CKFJR_READY);
 ckfet_options_v1 options;ckfet_options_init_v1(&options);options.profile=CKFSP_COPY;options.allow_metadata_loss=1;options.operation_id[0]=94;ckfet_job* job=nullptr;assert(ckfet_start_with_journal_root_v1(source,target,&options,root,&job,&err)==CKFE_API_OK);ckfe_entry_destroy(source);ckfe_entry_destroy(target);ckfe_directory_destroy(parent);ckfe_engine_destroy(e);ckfe_error_free(&err);
 auto s=wait(job);assert(s.state==CKFET_AWAITING_REVIEW);ckfet_row_v1 rows[16]{};ckfet_page_v1 page{};assert(ckfet_page_v1_get(job,s.plan_generation,0,rows,16,&page)==CKFE_API_OK);uint64_t id=0;for(unsigned i=0;i<page.row_count;++i)if(rows[i].source.kind==CKFSP_REGULAR_FILE&&rows[i].source.presence==CKFET_PRESENCE_PRESENT&&rows[i].destination.presence==CKFET_PRESENCE_PRESENT)id=rows[i].row_id;assert(id);
 auto income=get(job,s.plan_generation,id,CKFET_KEEP_BOTH_INCOMING);assert(income.required_side==CKFET_NAME_INCOMING&&income.allowed_sides==CKFET_NAME_SIDE_INCOMING_BIT&&income.capability_reason==CKFET_NAME_REASON_NONE&&income.assessment_command_id==0);
 auto target_cap=get(job,s.plan_generation,id,CKFET_KEEP_BOTH_TARGET);assert(target_cap.required_side==CKFET_NAME_TARGET);if(!target_cap.retention_available)assert(target_cap.allowed_sides==0&&target_cap.capability_reason==CKFET_NAME_REASON_RETENTION_UNAVAILABLE);
 ckfet_rule_v1 rule{};rule.version=1;rule.struct_size=sizeof(rule);rule.kind=CKFET_CONFLICT_EXISTING_REGULAR;rule.scope=CKFET_SCOPE_ITEM;rule.protect_nonempty=1;rule.retain_replaced=1;rule.plan_generation=s.plan_generation;rule.selected_rows=&id;rule.selected_count=1;
 const char exact[]="alpha-variant";ckfet_name_choice_v1 name{};name.row_id=id;name.component={exact,sizeof(exact)-1,CKFET_POSIX_BYTES,0};
 auto review=[&](uint32_t choice,uint32_t side,bool supplied,uint32_t reason){rule.choice=choice;name.side=side;uint64_t command=0;assert(ckfet_review_names_v1(job,s.plan_generation,&rule,1,supplied?&name:nullptr,supplied?1:0,nullptr,0,&command)==CKFE_API_OK);s=wait(job,true);assert(s.command_id==command);auto f=get(job,s.plan_generation,id,CKFET_NAME_CHOICE_SELECTED);assert(f.assessment_command_id==command&&f.decision_choice==choice&&f.choice==choice&&f.selection_reason==reason);if(reason!=CKFET_NAME_REASON_NONE)assert(s.command_state==CKFET_COMMAND_REJECTED&&!s.receipt_id);else assert(s.command_state==CKFET_COMMAND_ACCEPTED&&s.receipt_id);assert(ckfet_acknowledge_command_v1(job,command)==CKFE_API_OK);return f;};
 auto bad=review(CKFET_KEEP_BOTH_INCOMING,CKFET_NAME_TARGET,true,CKFET_NAME_REASON_WRONG_SIDE);assert(bad.required_side==CKFET_NAME_INCOMING&&bad.submitted_side==CKFET_NAME_TARGET);
 review(CKFET_RENAME,CKFET_NAME_TARGET,true,CKFET_NAME_REASON_WRONG_SIDE);
 review(CKFET_KEEP_BOTH_INCOMING,CKFET_NAME_INCOMING,false,CKFET_NAME_REASON_AWAITING_NAME);
 auto retention=review(CKFET_KEEP_BOTH_TARGET,CKFET_NAME_INCOMING,true,CKFET_NAME_REASON_WRONG_SIDE);assert(retention.required_side==CKFET_NAME_TARGET);if(!retention.retention_available)assert(retention.capability_reason==CKFET_NAME_REASON_RETENTION_UNAVAILABLE);
 review(CKFET_KEEP_TARGET,CKFET_NAME_INCOMING,true,CKFET_NAME_REASON_NAME_NOT_ALLOWED);
 review(CKFET_KEEP_BOTH_INCOMING,CKFET_NAME_INCOMING,true,CKFET_NAME_REASON_NONE);
 pause(job,true);allocations=io=0;polling=true;for(unsigned i=0;i<1024;++i){ckfet_name_feedback_v1 f{};assert(ckfet_name_feedback_get_v1(job,s.plan_generation,id,CKFET_NAME_CHOICE_SELECTED,&f)==CKFE_API_OK&&f.selection_reason==CKFET_NAME_REASON_NONE);}ckfet_name_feedback_v1 stale;std::memset(&stale,0x55,sizeof(stale));assert(ckfet_name_feedback_get_v1(job,s.plan_generation+1,id,CKFET_RENAME,&stale)==CKFE_API_STALE_PLAN);ckfet_name_feedback_v1 invalid;std::memset(&invalid,0x55,sizeof(invalid));assert(ckfet_name_feedback_get_v1(job,s.plan_generation,id,12345,&invalid)==CKFE_API_INVALID_ARGUMENT);assert(ckfet_name_feedback_get_v1(job,s.plan_generation,UINT64_MAX,CKFET_RENAME,&invalid)==CKFE_API_INVALID_ARGUMENT);assert(ckfet_name_feedback_get_v1(nullptr,s.plan_generation,id,CKFET_RENAME,&invalid)==CKFE_API_INVALID_ARGUMENT);for(unsigned i=0;i<sizeof(invalid);++i)assert(reinterpret_cast<const unsigned char*>(&invalid)[i]==0);polling=false;assert(allocations==0&&io==0);const unsigned char* bytes=reinterpret_cast<const unsigned char*>(&stale);for(unsigned i=0;i<sizeof(stale);++i)assert(bytes[i]==0);
 drain(job);ckfet_release(job);assert(ckfjr_finish_v1(root)==CKFE_API_OK);for(unsigned i=0;i<10000;++i){assert(ckfjr_poll_v1(root,&rs)==CKFE_API_OK);if(rs.worker_drained)break;std::this_thread::sleep_for(std::chrono::milliseconds(1));}assert(rs.worker_drained);ckfjr_release(root);std::puts("native C name feedback: wrong sides, retention, missing/ignored name, accepted incoming, cached noIO/noalloc and stale generation PASS");
}
