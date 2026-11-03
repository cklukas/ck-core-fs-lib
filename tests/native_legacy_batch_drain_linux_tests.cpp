// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Native three-item batch regression. This deliberately uses the real legacy
// RegularMetadataPreservation factory, never injected no-op metadata phases.
#include "native_finalization_fixture_linux.hpp"
#include "native_operation_copy_job.hpp"
#include "native_filesystem.hpp"
#include "metadata_capture_job.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <climits>
#include <cstdarg>
#include <exception>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <filesystem>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
using namespace ck::files;

extern "C" {
int __real_close(int);
int __real_fstat(int,struct stat*);
int __real_fsync(int);
ssize_t __real_pread(int,void*,size_t,off_t);
ssize_t __real_pwrite(int,const void*,size_t,off_t);
int __real_openat(int,const char*,int,...);
int __real_statx(int,const char*,int,unsigned,struct statx*);
ssize_t __real_fgetxattr(int,const char*,void*,size_t);
ssize_t __real_flistxattr(int,char*,size_t);
}
namespace {
constexpr unsigned item_count=3;
struct Identity {dev_t device{};ino_t inode{};};
bool same(const struct stat& a,Identity b)noexcept{return a.st_dev==b.device&&a.st_ino==b.inode;}
Identity identity(const struct stat& s)noexcept{return {s.st_dev,s.st_ino};}
enum class Owner {LegacySource,BaseSource,Journal,JournalParent,Staging};
struct Descriptor {int fd=-1;Identity id{};Owner owner=Owner::LegacySource;unsigned item=0,closes=0;};
struct Control {
 PreparedJournalRoot* root=nullptr;
 std::array<Identity,item_count> sources{},journals{};
 std::array<unsigned,item_count> source_reads{},source_opens{};
 std::array<Descriptor,128> owners{};
 std::array<std::string,item_count> journal_names{};
 std::array<off_t,item_count> journal_sizes{};
 unsigned owner_count=0,journal_count=0,current_item=0;
 bool active=false,armed=false,inject_source=false,inject_journal=false,oom_on_fault=false,fault_consumed=false,repeat_guard=false,retried=false;
 unsigned io_calls=0,writes=0,allocation_failures=0;
 std::array<int,128> reused_slots{};unsigned reused_count=0;
 detail::PreparedJournalConsumerFailure first_allocation{};
};
thread_local Control* control=nullptr;
std::atomic<bool> deny_allocations=false;
void allocation_failed()noexcept {
 if(control&&!control->allocation_failures++)
  detail::read_prepared_journal_consumer_failure(*control->root,control->first_allocation);
}
void io()noexcept{if(control&&control->active)++control->io_calls;}
}
void* operator new(std::size_t n){if(deny_allocations){allocation_failed();throw std::bad_alloc();}if(void*p=std::malloc(n?n:1))return p;throw std::bad_alloc();}
void* operator new[](std::size_t n){return ::operator new(n);}
void operator delete(void*p)noexcept{std::free(p);}void operator delete[](void*p)noexcept{std::free(p);}
void operator delete(void*p,std::size_t)noexcept{std::free(p);}void operator delete[](void*p,std::size_t)noexcept{std::free(p);}
namespace {
#define CHECK(x) do{if(!(x)){deny_allocations=false;throw std::runtime_error(#x);}}while(false)
template<class T>T take(Observation<T> o){if(!o.value()){deny_allocations=false;const auto&e=*o.unavailable_detail();throw std::runtime_error(e.error.operation+":"+std::to_string(e.error.code));}return std::move(o).take_value();}
NativeName name(const std::string& s){auto n=NativeName::from_posix(s);CHECK(n);return *n;}
using Cursor=std::shared_ptr<const DirectoryCursor>;
struct Snapshot {int fd;struct stat metadata;};
std::vector<Snapshot> descriptors(){
 DIR* d=opendir("/proc/self/fd");CHECK(d);const int own=dirfd(d);std::vector<Snapshot> out;
 while(const auto* e=readdir(d)){
  char* end=nullptr;const long value=strtol(e->d_name,&end,10);
  if(end==e->d_name||*end||value<0||value>INT_MAX||value==own)continue;
  struct stat s{};if(__real_fstat(static_cast<int>(value),&s)==0)out.push_back({static_cast<int>(value),s});
 }
 CHECK(closedir(d)==0);return out;
}
Descriptor* watched(int fd,const struct stat& s)noexcept{
 if(!control)return nullptr;
 for(unsigned i=0;i<control->owner_count;++i){auto& o=control->owners[i];if(o.fd==fd&&same(s,o.id))return &o;}
 return nullptr;
}
void remember(int fd,const struct stat& s,Owner owner,unsigned item){
 CHECK(control&&control->owner_count<control->owners.size());
 CHECK(!watched(fd,s));control->owners[control->owner_count++]={fd,identity(s),owner,item,0};
}
unsigned count(Owner kind,unsigned item){unsigned n=0;for(unsigned i=0;i<control->owner_count;++i){const auto&o=control->owners[i];if(o.owner==kind&&o.item==item)++n;}return n;}
struct Fixture {
 std::string path;int root_fd=-1,source_fd=-1,target_fd=-1;Cursor parent,source,target;PreparedJournalRoot::Pointer root;
 std::array<std::string,item_count> input{},output{};std::array<bool,item_count> attributes{};
 std::array<std::byte,8193> bytes{};
 Fixture(){
  path=native_finalization_fixture::base()+"/legacy-batch-drain.XXXXXX";CHECK(mkdtemp(path.data()));
  root_fd=open(path.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);CHECK(root_fd>=0);
  NativeFileSystem fs;parent=Cursor(take(fs.open_directory(path)));
  source=Cursor(take(parent->create_child_directory(name("sources"))));target=Cursor(take(parent->create_child_directory(name("targets"))));
  source_fd=openat(root_fd,"sources",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);target_fd=openat(root_fd,"targets",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);CHECK(source_fd>=0&&target_fd>=0);
  PreparedJournalRootRequest request;request.parent=parent;request.child=name("journal");request.disposition=JournalRootDisposition::ProvisionChild;JournalRootPreparationProgress progress;root=take(prepare_native_journal_root(std::move(request),progress));
  bytes.fill(std::byte{0x63});
  for(unsigned i=0;i<item_count;++i){
   input[i]="source-"+std::to_string(i);output[i]="result-"+std::to_string(i);
   int fd=openat(source_fd,input[i].c_str(),O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0640);CHECK(fd>=0);
   CHECK(write(fd,bytes.data(),bytes.size())==static_cast<ssize_t>(bytes.size()));
   const unsigned char attribute[]={0x00,0x41,0xff,0x00,static_cast<unsigned char>(i)};
   if(fsetxattr(fd,"user.ckfs.batch",attribute,sizeof(attribute),0)==0)attributes[i]=true;
   else CHECK(errno==ENOTSUP||errno==EOPNOTSUPP||errno==EPERM);
   const timespec times[2]={{1600000000,123456789},{1600000100,987654321}};CHECK(fchmod(fd,0640)==0&&futimens(fd,times)==0&&fsync(fd)==0);
   CHECK(close(fd)==0);
  }
 }
 ~Fixture(){
  deny_allocations=false;control=nullptr;root.reset();source.reset();target.reset();parent.reset();
  if(source_fd>=0)close(source_fd);if(target_fd>=0)close(target_fd);if(root_fd>=0)close(root_fd);
  std::filesystem::remove_all(path);
 }
 void verify_payload(unsigned i,bool destination){
  const int parent_fd=destination?target_fd:source_fd;const auto& leaf=destination?output[i]:input[i];
  int fd=openat(parent_fd,leaf.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);CHECK(fd>=0);struct stat s{};CHECK(fstat(fd,&s)==0);
  if(destination){CHECK((s.st_mode&07777)==0640&&s.st_uid==geteuid()&&s.st_gid==getegid());CHECK(s.st_mtim.tv_sec==1600000100&&s.st_mtim.tv_nsec==987654321);}
  if(attributes[i]){unsigned char actual[16]{};const unsigned char expected[]={0x00,0x41,0xff,0x00,static_cast<unsigned char>(i)};CHECK(fgetxattr(fd,"user.ckfs.batch",actual,sizeof(actual))==ssize_t(sizeof(expected)));CHECK(std::memcmp(actual,expected,sizeof(expected))==0);}
  std::array<std::byte,8193> got{};std::size_t offset=0;while(offset<got.size()){const auto n=read(fd,got.data()+offset,got.size()-offset);CHECK(n>0);offset+=std::size_t(n);}CHECK(got==bytes);CHECK(close(fd)==0);
 }
};
OperationBatchJob::Pointer create_batch(Fixture& f,Control& c){
 NativeOperationCopyBatchRequest request;std::vector<HeldChild::Pointer> caller_sources;
 for(unsigned i=0;i<item_count;++i){
  auto h=take(HeldChild::observe_with_access(f.source,name(f.input[i]),EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity));
  caller_sources.push_back(h);request.sources.push_back(h);request.destination_names.push_back(name(f.output[i]));
  int fd=openat(f.source_fd,f.input[i].c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);CHECK(fd>=0);struct stat s{};CHECK(__real_fstat(fd,&s)==0);c.sources[i]=identity(s);CHECK(close(fd)==0);
 }
 request.destination=f.target;request.destination_address=take(NativeAbsolutePath::from_posix(f.path+"/targets"));request.journal_root=take(NativeAbsolutePath::from_posix(f.path+"/journal"));request.journal_id.bytes[0]=std::byte{91};request.policy.copy_limits.chunk_bytes=257;
 MetadataReplayPolicy policy;policy.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;policy.ownership=MetadataOwnership::CurrentCaller;request.policy.metadata_scope=policy.scope;request.policy.metadata_policy=policy;request.policy.allow_unhandled_metadata_loss=false;
 request.open_journal=[&](const NativeAbsolutePath&,const NativeName& leaf,bool fresh){
  CHECK(c.journal_count<item_count&&fresh&&leaf.posix_bytes());const auto before=descriptors();auto opened=f.root->open_journal(leaf,fresh);if(!opened.value())return opened;
  const unsigned item=c.journal_count++;c.journal_names[item]=*leaf.posix_bytes();unsigned files=0;
  for(const auto& entry:descriptors()){
   if(std::any_of(before.begin(),before.end(),[&](const Snapshot& old){return old.fd==entry.fd;}))continue;
   if(S_ISREG(entry.metadata.st_mode)){++files;c.journals[item]=identity(entry.metadata);remember(entry.fd,entry.metadata,Owner::Journal,item);}
   else if(S_ISDIR(entry.metadata.st_mode))remember(entry.fd,entry.metadata,Owner::JournalParent,item);
   else CHECK(false);
  }
  CHECK(files==1);return opened;
 };
 auto batch=take(create_native_operation_copy_batch(std::move(request)));
 // There must be no caller-owned source alias left to postpone the actual
 // native close. Parent directory cursors intentionally remain legitimate.
 request.sources.clear();caller_sources.clear();CHECK(c.journal_count==item_count);
 for(const auto& entry:descriptors())for(unsigned i=0;i<item_count;++i)if(same(entry.metadata,c.sources[i]))remember(entry.fd,entry.metadata,Owner::LegacySource,i);
 for(unsigned i=0;i<item_count;++i){CHECK(count(Owner::LegacySource,i)>0&&count(Owner::Journal,i)==1);for(unsigned j=0;j<c.owner_count;++j)if(c.owners[j].owner==Owner::Journal&&c.owners[j].item==i){struct stat s{};CHECK(__real_fstat(c.owners[j].fd,&s)==0);c.journal_sizes[i]=s.st_size;CHECK(s.st_size>0);}}
 return batch;
}
bool terminal(OperationBatchState s){return s!=OperationBatchState::Ready&&s!=OperationBatchState::Running;}
void run(std::string_view mode){
 const bool complete=mode=="complete"||mode=="complete-attrs";
 const bool started_cancel=mode=="started-cancel"||mode=="started-cancel-source-eio-oom";
 const bool uncertain=mode=="uncertain-first-source-eio";
 const bool prior=mode.find("prior-root")!=mode.npos;
 const bool source_error=mode.find("source-eio")!=mode.npos;
 const bool journal_error=mode.find("journal-eio")!=mode.npos;
 const bool oom=mode.find("oom")!=mode.npos;
 Fixture f;Control c;c.root=f.root.get();control=&c;auto job=create_batch(f,c);
 if(mode=="complete-attrs")for(bool present:f.attributes)CHECK(present);
 c.inject_source=source_error;c.inject_journal=journal_error;c.oom_on_fault=oom;c.armed=true;
 if(prior)CHECK(detail::record_prepared_journal_consumer_failure(*f.root,ObservationState::Failed,ErrorDomain::Posix,ENOSPC,"test.batch.prior_root"));
 std::stop_source stop;const bool pending_cancel=!complete&&!started_cancel&&!uncertain;if(pending_cancel)stop.request_stop();if(prior&&oom)deny_allocations=true;
 unsigned advances=0;
 for(;advances<20000&&!terminal(job->state());++advances){
  if(started_cancel&&c.source_reads[0])stop.request_stop();
  CHECK(detail::current_metadata_capture_cleanup()==nullptr);c.current_item=static_cast<unsigned>(job->current_item());c.active=true;job->advance(stop.get_token());c.active=false;
 }
 CHECK(advances<20000);const auto state=job->state();const auto terminal_io=c.io_calls,terminal_allocations=c.allocation_failures;
 // Poll while persistent allocation exhaustion is still active: no retry may
 // allocate diagnostics, reopen source objects, flush journals, or close again.
 for(unsigned i=0;i<3;++i){c.active=true;CHECK(job->advance(stop.get_token())==state);c.active=false;}
 CHECK(c.io_calls==terminal_io&&c.allocation_failures==terminal_allocations);
 const bool remained_oom=deny_allocations.exchange(false);CHECK(!oom||remained_oom);
 const bool fault=source_error||journal_error||prior;
 if(pending_cancel&&!fault)for(const auto& item:job->result().items)CHECK(item.outcome==OperationItemOutcome::Pending);
 CHECK(state==(fault?OperationBatchState::NeedsReconciliation:complete?OperationBatchState::Complete:OperationBatchState::Cancelled));
 const std::array<unsigned,item_count> no_source_io{};if(pending_cancel)CHECK(c.writes==0&&c.source_reads==no_source_io&&c.source_opens==no_source_io);
 if(started_cancel||uncertain)CHECK(c.source_reads[0]>0&&c.source_reads[1]==0&&c.source_reads[2]==0&&c.source_opens[1]==0&&c.source_opens[2]==0);
 detail::PreparedJournalConsumerFailure first{};const bool root_error=detail::read_prepared_journal_consumer_failure(*f.root,first);
 const int expected=prior?ENOSPC:EIO;
 if(fault){CHECK(root_error&&!first.pending&&first.domain==ErrorDomain::Posix&&first.code==expected);if(oom)CHECK(c.allocation_failures>0&&!c.first_allocation.pending&&c.first_allocation.domain==ErrorDomain::Posix&&c.first_allocation.code==expected);}
 else CHECK(!root_error);
 unsigned legacy_closes=0,base_closes=0,journal_closes=0,parent_closes=0,stage_closes=0;
 for(unsigned i=0;i<c.owner_count;++i){const auto&o=c.owners[i];CHECK(o.closes==1);if(o.owner==Owner::LegacySource)++legacy_closes;else if(o.owner==Owner::BaseSource)++base_closes;else if(o.owner==Owner::Journal)++journal_closes;else if(o.owner==Owner::JournalParent)++parent_closes;else ++stage_closes;}
 CHECK(journal_closes==item_count&&legacy_closes>=item_count&&!c.retried);
 for(const auto& fd:descriptors())for(unsigned i=0;i<item_count;++i)CHECK(!same(fd.metadata,c.sources[i])&&!same(fd.metadata,c.journals[i]));
 c.armed=false;
 for(unsigned i=0;i<item_count;++i){const bool published=complete||(uncertain&&i==0);CHECK(take(f.target->lookup_child(name(f.output[i]),ChildLookupMode::NativeDefault)).state()==(published?ChildLookupState::Found:ChildLookupState::Missing));if(published)f.verify_payload(i,true);f.verify_payload(i,false);
  if(pending_cancel||(i>0&&(started_cancel||uncertain))){struct stat s{};const auto exact="journal/"+c.journal_names[i];CHECK(fstatat(f.root_fd,exact.c_str(),&s,AT_SYMLINK_NOFOLLOW)==0&&same(s,c.journals[i])&&s.st_size==c.journal_sizes[i]);}
 }
 // Reuse every drained descriptor slot for a test-owned independent native
 // object. Never replace an occupied descriptor belonging to another owner.
 std::vector<int> reuse;for(unsigned i=0;i<c.owner_count;++i){const int old=c.owners[i].fd;if(std::find(reuse.begin(),reuse.end(),old)!=reuse.end())continue;errno=0;if(fcntl(old,F_GETFD)>=0)continue;CHECK(errno==EBADF);int fd=open("/dev/null",O_RDONLY|O_CLOEXEC);CHECK(fd>=0);if(fd!=old){CHECK(dup2(fd,old)==old);CHECK(close(fd)==0);}reuse.push_back(old);CHECK(c.reused_count<c.reused_slots.size());c.reused_slots[c.reused_count++]=old;}
 CHECK(!reuse.empty());c.repeat_guard=true;c.armed=true;job.reset();CHECK(!c.retried);c.armed=false;c.repeat_guard=false;for(int fd:reuse){CHECK(fcntl(fd,F_GETFD)>=0);CHECK(close(fd)==0);}c.armed=false;
 CHECK(f.root.use_count()==1);auto root_finished=f.root->finish_io();if(fault)CHECK(!root_finished.value()&&root_finished.unavailable_detail()->error.code==expected);else CHECK(take(std::move(root_finished)));
 std::printf("PASS legacy-native-batch mode=%.*s prepared=3 legacyClose=%u baseClose=%u journalClose=%u journalParentClose=%u stageClose=%u RootCode=%lld advanceWrites=%u OOM=%d sourceAliasesReleasedBeforeAdvance=1 sourceJournalAndObservedStageFDsClosedBeforeTerminal=1 repeatNoIO/noAlloc=1 noRetry=1\n",int(mode.size()),mode.data(),legacy_closes,base_closes,journal_closes,parent_closes,stage_closes,static_cast<long long>(first.code),c.writes,int(remained_oom));control=nullptr;
}
}
extern "C" int __wrap_close(int fd){
 io();struct stat s{};Descriptor* owned=nullptr;if(control&&control->armed&&__real_fstat(fd,&s)==0)owned=watched(fd,s);
 if(control&&control->armed&&control->repeat_guard)for(unsigned i=0;i<control->reused_count;++i)if(control->reused_slots[i]==fd)control->retried=true;
 const int result=__real_close(fd);const int saved=errno;
 if(owned){++owned->closes;const bool selected=owned->item==0&&((control->inject_source&&owned->owner==Owner::LegacySource)||(control->inject_journal&&owned->owner==Owner::Journal));if(result==0&&selected&&!control->fault_consumed){control->fault_consumed=true;deny_allocations=control->oom_on_fault;errno=EIO;return -1;}}
 errno=saved;return result;
}
extern "C" ssize_t __wrap_pread(int fd,void* p,size_t n,off_t off){io();if(control&&control->active&&n){struct stat s{};if(__real_fstat(fd,&s)==0)for(unsigned i=0;i<item_count;++i)if(same(s,control->sources[i])){++control->source_reads[i];if(!watched(fd,s)){if(control->owner_count==control->owners.size())std::abort();control->owners[control->owner_count++]={fd,identity(s),Owner::BaseSource,i,0};}}}return __real_pread(fd,p,n,off);}
extern "C" ssize_t __wrap_pwrite(int fd,const void* p,size_t n,off_t off){io();if(control&&control->active)++control->writes;return __real_pwrite(fd,p,n,off);}
extern "C" int __wrap_fstat(int fd,struct stat* s){io();return __real_fstat(fd,s);}
extern "C" int __wrap_fsync(int fd){io();return __real_fsync(fd);}
extern "C" int __wrap_openat(int parent,const char* p,int flags,...){
 mode_t mode=0;const bool creates=(flags&O_CREAT)||((flags&O_TMPFILE)==O_TMPFILE);
 if(creates){va_list args;va_start(args,flags);mode=static_cast<mode_t>(va_arg(args,int));va_end(args);}
 io();const int fd=__real_openat(parent,p,flags,mode);
 if(control&&control->active&&fd>=0){struct stat s{};if(__real_fstat(fd,&s)==0){
  for(unsigned i=0;i<item_count;++i)if(same(s,control->sources[i]))++control->source_opens[i];
  if(creates&&S_ISREG(s.st_mode)&&!watched(fd,s)){if(control->owner_count==control->owners.size()||control->current_item>=item_count)std::abort();control->owners[control->owner_count++]={fd,identity(s),Owner::Staging,control->current_item,0};}
 }}return fd;
}
extern "C" int __wrap_statx(int fd,const char* p,int flags,unsigned mask,struct statx* s){io();return __real_statx(fd,p,flags,mask,s);}
extern "C" ssize_t __wrap_fgetxattr(int fd,const char* n,void* p,size_t count){io();return __real_fgetxattr(fd,n,p,count);}
extern "C" ssize_t __wrap_flistxattr(int fd,char* p,size_t count){io();return __real_flistxattr(fd,p,count);}
int main(int argc,char** argv){std::set_terminate([]{deny_allocations=false;std::fputs("FAIL unexpected terminate in native legacy batch drain\n",stderr);std::_Exit(3);});try{auto mode=native_finalization_fixture::parse(argc,argv,{"cancel-before-start","cancel-source-eio","cancel-source-eio-oom","cancel-journal-eio-oom","cancel-prior-root-oom","cancel-prior-root-source-eio-oom","started-cancel","started-cancel-source-eio-oom","uncertain-first-source-eio","complete","complete-attrs"});run(mode);return 0;}catch(const std::exception& e){deny_allocations=false;std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
