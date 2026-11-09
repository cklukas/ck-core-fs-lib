// SPDX-License-Identifier: LGPL-2.0-or-later
// Genuine native C workers and private Roots; no mock topology/provider IDs.
#include "ck_fs_retry.h"
#include "native_handles.hpp"
#include "journal_root_handles.hpp"
#include "native_operation_recovery_evidence.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/mount.h>
#include <thread>
#include <unistd.h>
using namespace ck::files;
namespace {
#define CHECK(x) do {if(!(x)){std::fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);std::abort();}}while(false)
template<class T>T take(Observation<T> value){if(!value.value())std::fprintf(stderr,"native %s\n",value.unavailable_detail()->error.operation.c_str());CHECK(value.value());return std::move(value).take_value();}
NativeName name(const char*s){return *NativeName::from_posix(s);}
ckfer_native_v1 text(const char*s){ckfer_native_v1 n;ckfer_native_init_v1(&n);n.data=s;n.byte_count=std::strlen(s);return n;}
void file(const std::string&p,std::string_view bytes){int fd=open(p.c_str(),O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);CHECK(fd>=0);CHECK(write(fd,bytes.data(),bytes.size())==ssize_t(bytes.size()));CHECK(fsync(fd)==0);CHECK(close(fd)==0);}
std::string read(const std::string&p){int fd=open(p.c_str(),O_RDONLY|O_CLOEXEC);CHECK(fd>=0);std::string out;char b[4096];for(;;){auto n=::read(fd,b,sizeof b);CHECK(n>=0);if(!n)break;out.append(b,size_t(n));}CHECK(close(fd)==0);return out;}
bool absent(const std::string&p){struct stat s{};errno=0;return lstat(p.c_str(),&s)<0&&errno==ENOENT;}
ckfer_snapshot_v1 poll(ckfer_job*j){ckfer_snapshot_v1 s;ckfer_snapshot_init_v1(&s);CHECK(ckfer_poll_v1(j,&s)==CKFE_API_OK);return s;}
ckfer_snapshot_v1 await(ckfer_job*j,bool terminal){for(unsigned i=0;i<20000;++i){auto s=poll(j);if(s.worker_drained||(!terminal&&s.state==CKFER_AWAITING_REVIEW))return s;std::this_thread::sleep_for(std::chrono::milliseconds(1));}std::abort();}
ckfjr_snapshot_v1 poll(ckfjr_root*r){ckfjr_snapshot_v1 s;ckfjr_snapshot_init_v1(&s);CHECK(ckfjr_poll_v1(r,&s)==CKFE_API_OK);return s;}
ckfjr_root*cap(ckfe_directory*p,const char*child){ckfjr_options_v1 o;ckfjr_options_init_v1(&o);o.parent=p;o.disposition=CKFJR_ADOPT_CHILD;o.child.data=child;o.child.byte_count=std::strlen(child);ckfjr_root*r=nullptr;CHECK(ckfjr_start_v1(&o,&r)==CKFE_API_OK);for(unsigned i=0;i<20000;++i){auto s=poll(r);if(s.state==CKFJR_READY)return r;CHECK(!s.worker_drained);std::this_thread::sleep_for(std::chrono::milliseconds(1));}std::abort();}
void finish(ckfjr_root*r){CHECK(ckfjr_finish_v1(r)==CKFE_API_OK);for(unsigned i=0;i<20000;++i){auto s=poll(r);if(s.worker_drained){CHECK(s.state==CKFJR_COMPLETE);ckfjr_release(r);return;}std::this_thread::sleep_for(std::chrono::milliseconds(1));}std::abort();}
}
int main(int argc,char**argv){
 CHECK(argc==3);const std::string root=argv[1],mode=argv[2];
 const bool second=mode.find("second")!=mode.npos;const std::string backend=second?"k":"j";
 const bool source=mode.find("source")!=mode.npos,candidate=mode.find("candidate")!=mode.npos,destination=mode.find("destination")!=mode.npos;
 const bool bind=mode.find("bind")!=mode.npos;
 const bool alias=mode.find("alias")!=mode.npos,late=mode.find("late")!=mode.npos,positive=mode.starts_with("positive"),legacy=mode.find("legacy")!=mode.npos;
 for(const char*d:{"s","c","d","j","k","j/sub","k/sub"})CHECK(mkdir((root+"/"+d).c_str(),0700)==0);
 const std::string sp=root+"/"+((source&&!alias&&!late)?backend+"/sub":"s");
 const std::string cp=root+"/"+((candidate&&!alias&&!late)?backend+"/sub":"c");
 const std::string dp=root+"/"+((destination&&!late&&!bind)?backend+"/sub":"d");
 constexpr std::string_view content="actual native reviewed retry outside private storage";
 const auto source_file=bind&&source?root+"/"+backend+"/sub/source":sp+"/source";
 const auto candidate_file=bind&&candidate?root+"/"+backend+"/sub/candidate":cp+"/candidate";
 file(source_file,content);file(candidate_file,content.substr(0,13));
 std::string bind_target;
 if(bind){
  // The launcher created a fresh unprivileged user+mount namespace. Require
  // that identity proof before making any mount; never touch host mounts.
  CHECK(getuid()==0&&geteuid()==0);const char*host=std::getenv("CK_RETRY_SCOPE_HOST_UID");
  const char*host_user=std::getenv("CK_RETRY_SCOPE_HOST_USER_NS");const char*host_mount=std::getenv("CK_RETRY_SCOPE_HOST_MOUNT_NS");CHECK(host&&host_user&&host_mount);
  unsigned long inside=9,outside=0,count=0;auto map=read("/proc/self/uid_map");CHECK(std::sscanf(map.c_str(),"%lu %lu %lu",&inside,&outside,&count)==3);CHECK(inside==0&&outside==std::strtoul(host,nullptr,10)&&outside!=0&&count==1);
  struct stat u{},m{};CHECK(stat("/proc/self/ns/user",&u)==0&&stat("/proc/self/ns/mnt",&m)==0);CHECK(u.st_ino!=std::strtoull(host_user,nullptr,10)&&m.st_ino!=std::strtoull(host_mount,nullptr,10));
  CHECK(mount(nullptr,"/",nullptr,MS_REC|MS_PRIVATE,nullptr)==0);
  bind_target=source?sp:candidate?cp:dp;
  CHECK(mount((root+"/"+backend+"/sub").c_str(),bind_target.c_str(),nullptr,MS_BIND,nullptr)==0);
 }
 if(alias&&!late&&!positive&&!bind){const auto selected=(source?sp+"/source":cp+"/candidate");CHECK(link(selected.c_str(),(root+"/"+backend+"/private-alias").c_str())==0);}
 if(positive&&alias){CHECK(link((sp+"/source").c_str(),(root+"/s/external-source-alias").c_str())==0);CHECK(link((cp+"/candidate").c_str(),(root+"/s/external-candidate-alias").c_str())==0);}
 ckfe_engine*e=nullptr;ckfe_directory *p=nullptr,*s=nullptr,*c=nullptr,*d=nullptr;ckfe_entry *sf=nullptr,*cf=nullptr;ckfe_error error;ckfe_error_init(&error);CHECK(ckfe_engine_create(&e)==CKFE_API_OK);
 CHECK(ckfe_directory_open_utf8(e,root.c_str(),0,&p,&error)==CKFE_API_OK);CHECK(ckfe_directory_open_utf8(e,sp.c_str(),0,&s,&error)==CKFE_API_OK);CHECK(ckfe_directory_open_utf8(e,cp.c_str(),0,&c,&error)==CKFE_API_OK);CHECK(ckfe_directory_open_utf8(e,dp.c_str(),0,&d,&error)==CKFE_API_OK);
 CHECK(ckfe_entry_open_utf8(s,"source",&sf,&error)==CKFE_API_OK);CHECK(ckfe_entry_open_utf8(c,"candidate",&cf,&error)==CKFE_API_OK);
 auto*a=cap(p,"j"),*b=cap(p,"k");auto native=take(retain_prepared_journal_root(a));
 auto old=take(native->open_journal(name("origin"),true));auto journal=take(OperationJournal::create(FileOperation::Copy,OperationJournalId{std::byte{7}}));
 NativeOperationRecoveryEvidence evidence{name("old-stage"),name("output"),*NativeDurableIdentity::from_live(*sf->child->parent_identity().value()),*NativeDurableIdentity::from_live(*sf->child->metadata().identity.value()),*NativeDurableIdentity::from_live(*d->cursor->identity().value()),{},{},{},{}};
 for(auto state:{OperationJournalState::Planned,OperationJournalState::Prepared,OperationJournalState::Failed})CHECK(take(append_operation_journal_file(*old,*journal,{journal->records().size()+1,0,state,take(encode_native_operation_recovery_evidence(evidence))})));
 CHECK(take(old->finish_io()));old.reset();native.reset();const auto original=read(root+"/j/origin");
 ckfer_options_v1 o;ckfer_options_init_v1(&o);o.source=sf;o.candidate=cf;o.destination=d;o.prefix_bytes=13;o.original_journal_name=text("origin");o.attempt_journal_name=text("attempt");o.staging_hint=text("stage");o.destination_name=text("output");o.metadata_scope=CKFER_ORDINARY_METADATA_V1;o.metadata_ownership=CKFER_CURRENT_CALLER_OWNERSHIP;o.attempt_id[0]=8;
 const auto jp=root+"/j",kp=root+"/k";ckfer_job*job=nullptr;
 if(legacy){o.original_journal_root=text(jp.c_str());o.attempt_journal_root=text(kp.c_str());CHECK(ckfer_start_v1(&o,&job)==CKFE_API_OK);}else CHECK(ckfer_start_with_journal_roots_v1(&o,a,b,&job)==CKFE_API_OK);
 auto ready=await(job,false);
 if(positive||late){if(ready.state!=CKFER_AWAITING_REVIEW)std::fprintf(stderr,"unexpected %u %s\n",ready.state,ready.failure_operation);CHECK(ready.state==CKFER_AWAITING_REVIEW);
  if(late){if(destination)CHECK(rename(dp.c_str(),(root+"/"+backend+"/moved-destination").c_str())==0);else CHECK(link((source?sp+"/source":cp+"/candidate").c_str(),(root+"/"+backend+"/late-alias").c_str())==0);}
  CHECK(ckfer_execute_v1(job,ready.review_id)==CKFE_API_OK);ready=await(job,true);
 }
 CHECK(ready.worker_drained);
 if(positive){CHECK(ready.state==CKFER_COMPLETE);CHECK(read(dp+"/output")==content);CHECK(!absent(root+"/k/attempt"));}
 else {if(ready.state!=CKFER_REVIEW_REQUIRED)std::fprintf(stderr,"unexpected state %u\n",ready.state);CHECK(ready.state==CKFER_REVIEW_REQUIRED);std::fprintf(stderr,"refused %s %u/%lld/%s\n",mode.c_str(),ready.failure_state,(long long)ready.failure_code,ready.failure_operation);if(alias&&!late&&!bind)CHECK(std::string_view(ready.failure_operation)=="journal_membership.private_alias");else if(late&&!destination)CHECK(std::string_view(ready.failure_operation)=="journal_membership.source_changed");else CHECK(std::string_view(ready.failure_operation).starts_with("journal_scope."));CHECK(ready.failure_domain==unsigned(ErrorDomain::Adapter));CHECK(absent(root+"/k/attempt"));CHECK(absent(dp+"/output"));}
 CHECK(read(root+"/j/origin")==original);CHECK(read(sp+"/source")==content);CHECK(read(cp+"/candidate")==content.substr(0,13));
 for(unsigned i=0;i<32;++i){auto cached=poll(job);CHECK(cached.sequence==ready.sequence&&cached.failure_code==ready.failure_code);}ckfer_release(job);
 ckfe_entry_destroy(sf);ckfe_entry_destroy(cf);ckfe_directory_destroy(s);ckfe_directory_destroy(c);ckfe_directory_destroy(d);ckfe_directory_destroy(p);ckfe_engine_destroy(e);ckfe_error_free(&error);finish(a);finish(b);
 if(bind)CHECK(umount2(bind_target.c_str(),0)==0);
 std::printf("PASS scope %s state=%u failure=%s originalUnchanged=1 noAttemptOnRefusal=1\n",mode.c_str(),ready.state,ready.failure_operation);
}
