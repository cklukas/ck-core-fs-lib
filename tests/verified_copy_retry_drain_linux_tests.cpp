// SPDX-License-Identifier: LGPL-2.0-or-later
// Real exported C worker; no external cleanup observer assists production code.
#include "ck_fs_retry.h"
#include "verified_copy_retry.hpp"
#include "prepared_journal_directory.hpp"
#include "platform/journal_root_test_faults.hpp"
#include "native_handles.hpp"
#include "journal_root_handles.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "native_operation_recovery_evidence.hpp"
#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <new>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
using namespace ck::files;
extern "C" int __real_close(int);
extern "C" ssize_t __real_pread(int,void*,size_t,off_t);
extern "C" int __real_openat(int,const char*,int,...);
namespace {
#define CHECK(x) do{if(!(x)){std::fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);std::abort();}}while(false)
thread_local bool no_alloc=false;
std::atomic<unsigned> denied{0};
std::atomic<bool> pending_trigger{false},pending_paused{false},pending_release{false},retry_drain_returned{false},pending_after_drain{false};
thread_local bool pending_publisher=false;
void after_retry_drain()noexcept {
 retry_drain_returned.store(true,std::memory_order_release);
 if(!pending_after_drain.load(std::memory_order_acquire))return;
 pending_trigger.store(true,std::memory_order_release);pending_trigger.notify_all();
 while(!pending_paused.load(std::memory_order_acquire))pending_paused.wait(false,std::memory_order_acquire);
}
void pause_root_publication()noexcept {
 if(!pending_publisher)return;
 pending_paused.store(true,std::memory_order_release);pending_paused.notify_all();
 while(!pending_release.load(std::memory_order_acquire))pending_release.wait(false,std::memory_order_acquire);
}
std::optional<std::int64_t> pending_close_fault(detail::JournalRootFaultPoint point){
 return pending_publisher&&point==detail::JournalRootFaultPoint::DirectoryClose?std::optional<std::int64_t>{ENOSPC}:std::nullopt;
}
enum class Owner {Source,BaseSource,Candidate,Original,Attempt,Prior};
struct Id {dev_t dev=0;ino_t ino=0;};
bool same(const struct stat&s,Id i){return s.st_dev==i.dev&&s.st_ino==i.ino;}
struct Fd {int value=-1;Id id;Owner owner;unsigned closes=0;};
struct Control {
 std::mutex mutex;std::array<Fd,96> fds{};unsigned used=0;
 Id source,candidate,original;Owner inject=Owner::Source;
 bool active=false,arm=false,oom=false,injected=false,prior_arm=false,prior_injected=false,review_complete=false;
 bool reuse_guard=false,retried=false;std::array<int,96> reused{};unsigned reused_count=0;
} control;
void register_fd(int fd,const struct stat&s,Owner owner){
 for(unsigned i=0;i<control.used;++i)if(control.fds[i].value==fd&&control.fds[i].closes==0&&same(s,control.fds[i].id))return;
 CHECK(control.used<control.fds.size());control.fds[control.used++]={fd,{s.st_dev,s.st_ino},owner,0};
}
template<class T>T take(Observation<T> o){if(!o.value())std::fprintf(stderr,"native %u %lld %s\n",unsigned(o.state()),(long long)o.unavailable_detail()->error.code,o.unavailable_detail()->error.operation.c_str());CHECK(o.value());return std::move(o).take_value();}
NativeName name(const char*s){return *NativeName::from_posix(s);}
ckfer_native_v1 text(const char*s){ckfer_native_v1 n;ckfer_native_init_v1(&n);n.data=s;n.byte_count=std::strlen(s);return n;}
ckfer_snapshot_v1 poll(ckfer_job*j){ckfer_snapshot_v1 s;ckfer_snapshot_init_v1(&s);CHECK(ckfer_poll_v1(j,&s)==CKFE_API_OK);return s;}
ckfer_snapshot_v1 wait(ckfer_job*j,bool drain){
 for(unsigned i=0;i<20000;++i){auto s=poll(j);if(drain?s.worker_drained:s.state==CKFER_AWAITING_REVIEW||s.worker_drained)return s;std::this_thread::sleep_for(std::chrono::milliseconds(1));}
 const auto last=poll(j);
 std::fprintf(stderr,"RETRY_WAIT_TIMEOUT waitingFor=%s state=%u drained=%u sequence=%llu reviewed=%llu copied=%llu failure=%u/%lld/%s denied=%u\n",drain?"drain":"review",last.state,last.worker_drained,(unsigned long long)last.sequence,(unsigned long long)last.reviewed_bytes,(unsigned long long)last.copied_bytes,last.failure_domain,(long long)last.failure_code,last.failure_operation,denied.load());
 if(control.mutex.try_lock()){
  std::fprintf(stderr,"RETRY_CLOSE_STATUS injected=%d tracked=%u\n",int(control.injected),control.used);
  for(unsigned i=0;i<control.used;++i)std::fprintf(stderr,"RETRY_FD owner=%u fd=%d closes=%u\n",unsigned(control.fds[i].owner),control.fds[i].value,control.fds[i].closes);
  control.mutex.unlock();
 }else std::fprintf(stderr,"RETRY_CLOSE_STATUS mutex_busy=1\n");
 std::fflush(stderr);std::abort();
}
ckfjr_snapshot_v1 root_poll(ckfjr_root*r){ckfjr_snapshot_v1 s;ckfjr_snapshot_init_v1(&s);CHECK(ckfjr_poll_v1(r,&s)==CKFE_API_OK);return s;}
Id file_id(const std::string&path){struct stat s{};CHECK(lstat(path.c_str(),&s)==0);return {s.st_dev,s.st_ino};}
constexpr std::string_view bytes="real native prefix data and strict metadata";
void create_file(const std::string&path,std::string_view content){int fd=open(path.c_str(),O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC,0600);CHECK(fd>=0);CHECK(write(fd,content.data(),content.size())==ssize_t(content.size()));CHECK(fsync(fd)==0);CHECK(close(fd)==0);}
}
void* operator new(std::size_t n){if(no_alloc){++denied;throw std::bad_alloc();}if(void*p=std::malloc(n?n:1))return p;throw std::bad_alloc();}
void* operator new[](std::size_t n){return ::operator new(n);}void operator delete(void*p)noexcept{std::free(p);}void operator delete[](void*p)noexcept{std::free(p);}void operator delete(void*p,std::size_t)noexcept{std::free(p);}void operator delete[](void*p,std::size_t)noexcept{std::free(p);}
extern "C" ssize_t __wrap_pread(int fd,void*p,size_t n,off_t off){
 struct stat s{};if(fstat(fd,&s)==0){std::lock_guard lock(control.mutex);if(control.active){if(same(s,control.source))register_fd(fd,s,control.review_complete?Owner::BaseSource:Owner::Source);else if(same(s,control.candidate))register_fd(fd,s,Owner::Candidate);else if(same(s,control.original))register_fd(fd,s,Owner::Original);}}
 return __real_pread(fd,p,n,off);
}
extern "C" int __wrap_close(int fd){
 struct stat s{};const bool known=fstat(fd,&s)==0;std::lock_guard lock(control.mutex);
 if(control.reuse_guard)for(unsigned i=0;i<control.reused_count;++i)if(control.reused[i]==fd){control.retried=true;errno=EIO;return -1;}
 Fd* owner=nullptr;if(known)for(unsigned i=0;i<control.used;++i)if(control.fds[i].value==fd&&!control.fds[i].closes&&same(s,control.fds[i].id)){owner=&control.fds[i];break;}
 const int result=__real_close(fd),saved=errno;
 if(owner){++owner->closes;
  if(result==0&&control.prior_arm&&owner->owner==Owner::Prior&&!control.prior_injected){control.prior_injected=true;errno=ENOSPC;return -1;}
  if(result==0&&control.arm&&owner->owner==control.inject&&!control.injected){control.injected=true;no_alloc=control.oom;errno=EIO;return -1;}}
 errno=saved;return result;
}
// Native Root opens go through the same real openat. Classify actual inode,
// never a recovery hint or pointer address. No syscall is skipped.
#include <cstdarg>
extern "C" int __wrap_openat(int d,const char*p,int flags,...){
 int mode=0;if((flags&O_CREAT)||((flags&O_TMPFILE)==O_TMPFILE)){va_list a;va_start(a,flags);mode=va_arg(a,int);va_end(a);}
 const int fd=__real_openat(d,p,flags,mode);struct stat s{};
 if(fd>=0&&fstat(fd,&s)==0&&S_ISREG(s.st_mode)){
  std::lock_guard lock(control.mutex);if(control.active&&p){if(std::strcmp(p,"attempt")==0)register_fd(fd,s,Owner::Attempt);else if(std::strcmp(p,"prior")==0)register_fd(fd,s,Owner::Prior);}}
 return fd;
}
int main(int argc,char**argv){
 CHECK(argc==3);const std::string root=argv[1];const std::string_view mode=argv[2];
 const bool pending=mode.find("pending")!=mode.npos;
 const bool pending_before=mode.starts_with("pending-before-finish")||mode.starts_with("cpp-pending");
 const bool cpp_destructor=mode=="cpp-pending-destructor";
 const bool cpp=mode.starts_with("cpp-");
 const bool cancel=cpp||mode.starts_with("cancel")||mode.starts_with("prior")||pending_before;
 const bool fault=!pending&&mode!="success"&&mode!="cancel"&&mode!="cpp-finish";
 const bool oom=mode.find("oom")!=mode.npos;
 const bool prior=mode.starts_with("prior");
 const bool second=mode.find("second")!=mode.npos;
 control.inject=mode.find("candidate")!=mode.npos?Owner::Candidate:mode.find("journal")!=mode.npos?Owner::Original:mode.find("base")!=mode.npos?Owner::BaseSource:Owner::Source;
 CHECK(mkdir((root+"/s").c_str(),0700)==0);CHECK(mkdir((root+"/d").c_str(),0700)==0);
 create_file(root+"/s/source",bytes);create_file(root+"/s/candidate",bytes.substr(0,13));
 control.source=file_id(root+"/s/source");control.candidate=file_id(root+"/s/candidate");
 ckfe_engine*engine=nullptr;ckfe_directory *parent=nullptr,*src=nullptr,*dst=nullptr;ckfe_entry *source=nullptr,*candidate=nullptr;ckfe_error error{};ckfe_error_init(&error);
 CHECK(ckfe_engine_create(&engine)==CKFE_API_OK);CHECK(ckfe_directory_open_utf8(engine,root.c_str(),0,&parent,&error)==CKFE_API_OK);
 CHECK(ckfe_directory_open_utf8(engine,(root+"/s").c_str(),0,&src,&error)==CKFE_API_OK);CHECK(ckfe_directory_open_utf8(engine,(root+"/d").c_str(),0,&dst,&error)==CKFE_API_OK);
 CHECK(ckfe_entry_open_utf8(src,"source",&source,&error)==CKFE_API_OK);CHECK(ckfe_entry_open_utf8(src,"candidate",&candidate,&error)==CKFE_API_OK);
 ckfjr_options_v1 ro;ckfjr_options_init_v1(&ro);ro.parent=parent;ro.disposition=CKFJR_PROVISION_CHILD;ro.child.data="j";ro.child.byte_count=1;ckfjr_root*cap=nullptr;CHECK(ckfjr_start_v1(&ro,&cap)==CKFE_API_OK);
 for(unsigned n=0;n<20000;++n){auto s=root_poll(cap);if(s.state!=CKFJR_PREPARING){CHECK(s.state==CKFJR_READY);break;}std::this_thread::sleep_for(std::chrono::milliseconds(1));}
 ckfjr_root*attempt_cap=cap;
 if(second){ro.child.data="k";CHECK(ckfjr_start_v1(&ro,&attempt_cap)==CKFE_API_OK);for(unsigned n=0;n<20000;++n){auto s=root_poll(attempt_cap);if(s.state==CKFJR_READY)break;CHECK(!s.worker_drained);std::this_thread::sleep_for(std::chrono::milliseconds(1));}CHECK(root_poll(attempt_cap).state==CKFJR_READY);}
 auto initial_root=root_poll(cap);if(initial_root.state!=CKFJR_READY)std::fprintf(stderr,"ROOT prerequisite state=%u drained=%u failure=%u/%lld/%s\n",initial_root.state,initial_root.worker_drained,initial_root.failure_domain,(long long)initial_root.failure_code,initial_root.failure_operation);CHECK(initial_root.state==CKFJR_READY);
 auto native_root=take(retain_prepared_journal_root(cap));
 auto native_attempt=second?take(retain_prepared_journal_root(attempt_cap)):PreparedJournalRoot::Pointer{};
 auto journal=take(OperationJournal::create(FileOperation::Copy,OperationJournalId{std::byte{7}}));
 auto original=take(native_root->open_journal(name("origin"),true));
 NativeOperationRecoveryEvidence evidence{name("old-stage-hint"),name("output"),*NativeDurableIdentity::from_live(*source->child->parent_identity().value()),*NativeDurableIdentity::from_live(*source->child->metadata().identity.value()),*NativeDurableIdentity::from_live(*dst->cursor->identity().value()),{},{},{},{}};
 for(auto state:{OperationJournalState::Planned,OperationJournalState::Prepared,OperationJournalState::Failed})CHECK(take(append_operation_journal_file(*original,*journal,{journal->records().size()+1,0,state,take(encode_native_operation_recovery_evidence(evidence))})));
 CHECK(take(original->finish_io()));original.reset();control.original=file_id(root+"/j/origin");
 ckfer_options_v1 options;ckfer_options_init_v1(&options);options.source=source;options.candidate=candidate;options.destination=dst;options.prefix_bytes=13;options.original_journal_name=text("origin");options.attempt_journal_name=text("attempt");options.staging_hint=text("stage-hint");options.destination_name=text("output");options.metadata_scope=CKFER_ORDINARY_METADATA_V1;options.metadata_ownership=CKFER_CURRENT_CALLER_OWNERSHIP;options.attempt_id[0]=8;
 std::thread publisher;
 if(pending){
  CHECK(mode.starts_with("pending-before-finish")||mode=="pending-after-final-journal-check"||mode=="cpp-pending-finish"||mode=="cpp-pending-destructor");
  auto view=take(open_prepared_journal_directory(second?native_attempt:native_root));
  detail::journal_root_test_publication_pause=pause_root_publication;
  publisher=std::thread([view=std::move(view)]()mutable{
   while(!pending_trigger.load(std::memory_order_acquire))pending_trigger.wait(false,std::memory_order_acquire);
   pending_publisher=true;detail::journal_root_test_fault=pending_close_fault;
   auto closed=view->finish_io();CHECK(!closed.value()&&closed.unavailable_detail()->error.code==ENOSPC);
   detail::journal_root_test_fault=nullptr;pending_publisher=false;view.reset();
  });
 }
 control.active=true;ckfer_job*job=nullptr;VerifiedCopyRetryJob::Pointer core;
 if(cpp){VerifiedCopyRetryRequest input(native_root,name("origin"),native_root,name("attempt"),name("stage-hint"),name("output"));
  input.source=source->child;input.candidate=candidate->child;input.candidate_prefix_bytes=13;input.destination=dst->cursor;input.destination_address=dst->address;input.attempt_id.bytes[0]=std::byte{8};
  input.metadata_policy.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;input.metadata_policy.ownership=MetadataOwnership::CurrentCaller;
  core=take(VerifiedCopyRetryJob::create(std::move(input)));
 }else CHECK(ckfer_start_with_journal_roots_v1(&options,cap,attempt_cap,&job)==CKFE_API_OK);
 ckfe_entry_destroy(source);ckfe_entry_destroy(candidate);ckfe_directory_destroy(src);ckfe_directory_destroy(dst);ckfe_directory_destroy(parent);ckfe_engine_destroy(engine);ckfe_error_free(&error);
 ckfer_snapshot_v1 ready{};
 if(cpp){for(unsigned i=0;i<10000&&core->state()!=VerifiedCopyRetryState::AwaitingReview;++i){CHECK(core->advance()!=VerifiedCopyRetryState::ReviewRequired);}CHECK(core->state()==VerifiedCopyRetryState::AwaitingReview);}
 else{ready=wait(job,false);if(ready.state!=CKFER_AWAITING_REVIEW)std::fprintf(stderr,"preparation failed %u/%lld/%s\n",ready.state,(long long)ready.failure_code,ready.failure_operation);CHECK(ready.state==CKFER_AWAITING_REVIEW);}
 {std::lock_guard lock(control.mutex);control.review_complete=true;}
 if(cpp&&mode.find("copy")!=mode.npos){CHECK(take(core->approve()));for(unsigned i=0;i<10000&&core->state()!=VerifiedCopyRetryState::Copying;++i)CHECK(core->advance()!=VerifiedCopyRetryState::ReviewRequired);CHECK(core->state()==VerifiedCopyRetryState::Copying);}
 if(prior){control.prior_arm=true;auto first=take((second?native_attempt:native_root)->open_journal(name("prior"),true));auto closed=first->finish_io();CHECK(!closed.value()&&closed.unavailable_detail()->error.code==ENOSPC);first.reset();control.prior_arm=false;CHECK(control.prior_injected);}
 {std::lock_guard lock(control.mutex);control.arm=fault||pending_before;control.oom=oom;if(pending_before)control.inject=Owner::Original;}
 bool complete_while_pending=false,drained_while_pending=false;
 if(pending&&!cpp){pending_after_drain=!pending_before;detail::verified_copy_retry_test_after_drain=after_retry_drain;}
 if(pending_before){pending_trigger.store(true,std::memory_order_release);pending_trigger.notify_all();while(!pending_paused.load(std::memory_order_acquire))pending_paused.wait(false,std::memory_order_acquire);}

 ckfer_snapshot_v1 done{};
 bool cpp_returned_while_pending=true,cpp_provisional=true;
 if(cpp&&pending){
  std::atomic<bool> returned{false};
  // A separate caller observes return while the native Root writer is STILL
  // paused. A buggy blocking finalizer is released for cleanup and then fails
  // the assertion, rather than deadlocking this fixture indefinitely.
  std::thread finalizer([&]{
   if(cpp_destructor)core.reset();
   else {auto result=core->finish_io();cpp_provisional=!result.value()&&result.unavailable_detail()->error.operation=="copy_retry.root_failure_pending"&&!core->native_finish_failure().present;}
   returned.store(true,std::memory_order_release);
  });
  for(unsigned i=0;i<200&&!returned.load(std::memory_order_acquire);++i)std::this_thread::sleep_for(std::chrono::milliseconds(1));
  cpp_returned_while_pending=returned.load(std::memory_order_acquire);
  if(!cpp_returned_while_pending){pending_release.store(true,std::memory_order_release);pending_release.notify_all();}
  finalizer.join();
  if(cpp_returned_while_pending){std::lock_guard lock(control.mutex);for(unsigned i=0;i<control.used;++i)CHECK(control.fds[i].closes==1);}
  if(cpp_returned_while_pending&&!cpp_destructor){
   for(unsigned i=0;i<16;++i){auto result=core->finish_io();cpp_provisional&=!result.value()&&result.unavailable_detail()->error.operation=="copy_retry.root_failure_pending"&&!core->native_finish_failure().present;}
  }
  pending_release.store(true,std::memory_order_release);pending_release.notify_all();publisher.join();detail::journal_root_test_publication_pause=nullptr;
  if(!cpp_destructor){auto result=core->finish_io();CHECK(!result.value());CHECK(core->native_finish_failure().present&&core->native_finish_failure().code==ENOSPC);core.reset();}
 }else if(cpp){if(mode=="cpp-finish"){CHECK(take(core->finish_io()));CHECK(!core->approve().value());CHECK(core->advance()==VerifiedCopyRetryState::Cancelled);CHECK(take(core->finish_io()));}core.reset();}
 else{
  if(cancel)CHECK(ckfer_cancel_v1(job)==CKFE_API_OK);else CHECK(ckfer_execute_v1(job,ready.review_id)==CKFE_API_OK);
  if(pending){
   for(unsigned n=0;n<20000&&!pending_paused.load(std::memory_order_acquire);++n)std::this_thread::sleep_for(std::chrono::milliseconds(1));
   CHECK(pending_paused.load(std::memory_order_acquire));
   for(unsigned i=0;i<20000&&!retry_drain_returned.load(std::memory_order_acquire);++i)std::this_thread::sleep_for(std::chrono::milliseconds(1));
   CHECK(retry_drain_returned.load(std::memory_order_acquire));
   {std::lock_guard lock(control.mutex);for(unsigned i=0;i<control.used;++i)CHECK(control.fds[i].closes==1);}
   detail::PreparedJournalConsumerFailure slot;
   CHECK(detail::read_prepared_journal_consumer_failure(*(second?native_attempt:native_root),slot)&&slot.pending);
   for(unsigned n=0;n<200;++n){const auto sample=poll(job);complete_while_pending|=sample.state==CKFER_COMPLETE;drained_while_pending|=sample.worker_drained!=0;std::this_thread::sleep_for(std::chrono::milliseconds(1));}
   pending_release.store(true,std::memory_order_release);pending_release.notify_all();publisher.join();detail::journal_root_test_publication_pause=nullptr;detail::verified_copy_retry_test_after_drain=nullptr;
  }
  done=wait(job,true);
 }
 const auto expected=prior||pending?ENOSPC:EIO;
 if(pending){
  std::fprintf(stderr,"PENDING mode=%.*s CompleteWhilePending=%d DrainedWhilePending=%d FinalizerReturnedWhilePending=%d Provisional=%d laterConsumedEIO=%d final=%u/%u/%lld/%s expectedNative=%d\n",int(mode.size()),mode.data(),int(complete_while_pending),int(drained_while_pending),int(cpp_returned_while_pending),int(cpp_provisional),int(control.injected),done.state,done.failure_domain,(long long)done.failure_code,done.failure_operation,ENOSPC);
  CHECK(!complete_while_pending&&!drained_while_pending&&cpp_returned_while_pending&&cpp_provisional);
  if(!cpp){CHECK(done.state==CKFER_REVIEW_REQUIRED&&done.failure_domain==unsigned(ErrorDomain::Posix)&&done.failure_code==ENOSPC&&done.recovery_required);CHECK(std::string_view(done.failure_operation)=="journal_root.enumeration_close");}
  if(pending_before)CHECK(control.injected);
 }else if(fault){CHECK(control.injected);if(!cpp&&done.failure_code!=expected)std::fprintf(stderr,"terminal mode=%.*s state=%u domain=%u code=%lld op=%s expected=%d\n",int(mode.size()),mode.data(),done.state,done.failure_domain,(long long)done.failure_code,done.failure_operation,expected);
  if(!cpp)CHECK(done.state==CKFER_REVIEW_REQUIRED&&done.failure_domain==unsigned(ErrorDomain::Posix)&&done.failure_code==expected&&done.recovery_required);
  detail::PreparedJournalConsumerFailure failure;CHECK(detail::read_prepared_journal_consumer_failure(*native_root,failure)&&!failure.pending&&failure.code==(second?EIO:expected));
  if(second)CHECK(detail::read_prepared_journal_consumer_failure(*native_attempt,failure)&&!failure.pending&&failure.code==expected);
 }else if(!cpp)CHECK(done.state==(cancel?CKFER_CANCELLED:CKFER_COMPLETE));
 if(oom)CHECK(denied>0);
 {std::lock_guard lock(control.mutex);unsigned source_fds=0,candidate_fds=0,original_fds=0,attempt_fds=0;
  for(unsigned i=0;i<control.used;++i){const auto& f=control.fds[i];CHECK(f.closes==1);if(f.owner==Owner::Source)++source_fds;if(f.owner==Owner::Candidate)++candidate_fds;if(f.owner==Owner::Original)++original_fds;if(f.owner==Owner::Attempt)++attempt_fds;}
  CHECK(source_fds&&candidate_fds&&original_fds);if(!cancel)CHECK(attempt_fds);
  control.arm=false;control.active=false;
 }
 // Reuse every closed descriptor number, then exercise cached API/release.
 for(unsigned i=0;i<control.used;++i){const int old=control.fds[i].value;bool seen=false;for(unsigned j=0;j<control.reused_count;++j)seen|=control.reused[j]==old;if(seen)continue;errno=0;CHECK(fcntl(old,F_GETFD)<0&&errno==EBADF);int fd=open("/dev/null",O_RDONLY|O_CLOEXEC);CHECK(fd>=0);if(fd!=old){CHECK(dup2(fd,old)==old);CHECK(close(fd)==0);}control.reused[control.reused_count++]=old;}
 control.reuse_guard=true;
 if(!cpp){for(unsigned n=0;n<64;++n){auto cached=poll(job);CHECK(cached.worker_drained&&cached.state==done.state&&cached.failure_code==done.failure_code);}CHECK(ckfer_cancel_v1(job)==CKFE_API_OK);ckfer_release(job);}
 CHECK(!control.retried);control.reuse_guard=false;
 for(unsigned i=0;i<control.reused_count;++i)CHECK(close(control.reused[i])==0);
 if(second){native_attempt.reset();CHECK(ckfjr_finish_v1(attempt_cap)==CKFE_API_OK);for(unsigned n=0;n<20000&&!root_poll(attempt_cap).worker_drained;++n)std::this_thread::sleep_for(std::chrono::milliseconds(1));CHECK(root_poll(attempt_cap).worker_drained&&root_poll(attempt_cap).failure_code==expected);ckfjr_release(attempt_cap);}
 native_root.reset();CHECK(ckfjr_finish_v1(cap)==CKFE_API_OK);for(unsigned n=0;n<20000;++n){auto s=root_poll(cap);if(s.worker_drained)break;std::this_thread::sleep_for(std::chrono::milliseconds(1));}CHECK(root_poll(cap).worker_drained);if(fault||pending)CHECK(root_poll(cap).failure_code==(second?EIO:expected));ckfjr_release(cap);
 std::printf("PASS retry route=%s mode=%.*s actualConsumedClose=1 noExternalObserver=1 readersAndJournalsClosedBeforeDrained=1 RootCode=%lld noRetryAfterFDReuse=1 OOM=%u\n",cpp?(mode=="cpp-pending-finish"?"Cpp-explicit-finish":"Cpp-destructor"):"production-Cworker",int(mode.size()),mode.data(),(long long)(fault||pending?expected:done.failure_code),denied.load());
}
