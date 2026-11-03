// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_finalization_fixture_linux.hpp"
#include "native_operation_copy_job.hpp"
#include "native_filesystem.hpp"
#include "metadata_capture_job.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
using namespace ck::files;
namespace {
std::atomic<bool> deny_allocations=false;
struct Watch {
 dev_t dev=0,jdev=0,wdev=0;ino_t ino=0,jino=0,wino=0;int source=-1,writer=-1,journal_fd=-1;
 bool active=false,consumed=false,fault=false,oom=false,protocol=false,triggered=false,retry=false;
 unsigned reads=0,source_closes=0,writer_closes=0,journal_closes=0,metadata_finishes=0,allocations=0;
 PreparedJournalRoot* root=nullptr;OperationJournal* journal=nullptr;
 OperationJournalState state_at_close=OperationJournalState::Planned;
 detail::PreparedJournalConsumerFailure first_allocation{};
};
thread_local Watch* watch=nullptr;
void allocation()noexcept {if(watch&&!watch->allocations++)detail::read_prepared_journal_consumer_failure(*watch->root,watch->first_allocation);}
}
void* operator new(std::size_t n){if(deny_allocations){allocation();throw std::bad_alloc();}if(auto*p=std::malloc(n?n:1))return p;throw std::bad_alloc();}
void* operator new[](std::size_t n){return ::operator new(n);}void operator delete(void*p)noexcept{std::free(p);}void operator delete[](void*p)noexcept{std::free(p);}void operator delete(void*p,std::size_t)noexcept{std::free(p);}void operator delete[](void*p,std::size_t)noexcept{std::free(p);}
namespace {
#define CHECK(x) do{if(!(x)){deny_allocations=false;throw std::runtime_error(#x);}}while(false)
template<class T>T take(Observation<T> o){if(!o.value()){deny_allocations=false;const auto&e=*o.unavailable_detail();throw std::runtime_error(e.error.operation+":"+std::to_string(e.error.code));}return std::move(o).take_value();}
bool same(int fd,dev_t d,ino_t i)noexcept{struct stat s{};return !fstat(fd,&s)&&s.st_dev==d&&s.st_ino==i;}
struct Observer:MetadataCaptureFailureLatch {PreparedJournalRoot* root;mutable unsigned calls=0;explicit Observer(PreparedJournalRoot&r):root(&r){}void record_first(MetadataCaptureCleanupError e)const noexcept override{++calls;detail::record_prepared_journal_consumer_failure(*root,e.state,e.domain,e.code,e.operation);}};
NativeName name(const char*s){return *NativeName::from_posix(s);}
struct Fixture {
 std::string path;std::shared_ptr<const DirectoryCursor> parent;PreparedJournalRoot::Pointer root;
 Fixture(){path=native_finalization_fixture::base()+"/base-source.XXXXXX";CHECK(mkdtemp(path.data()));NativeFileSystem fs;parent=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(path)));PreparedJournalRootRequest r;r.parent=parent;r.child=name("journal");r.disposition=JournalRootDisposition::ProvisionChild;JournalRootPreparationProgress p;root=take(prepare_native_journal_root(std::move(r),p));}
 ~Fixture(){watch=nullptr;deny_allocations=false;root.reset();parent.reset();std::filesystem::remove_all(path);}
};
void native_case(std::string_view mode){
 const bool cancelled=mode.find("cancel")!=mode.npos,fault=mode.find("eio")!=mode.npos||mode.find("close-oom")!=mode.npos,oom=mode.find("oom")!=mode.npos,protocol=mode.find("protocol")!=mode.npos,prior=mode.find("prior")!=mode.npos;
 Fixture f;std::array<std::byte,8193> bytes{};bytes.fill(std::byte{0x53});
 {auto writer=take(f.parent->create_child_file(name("source")));CHECK(take(writer->write_content(0,bytes))==bytes.size());CHECK(take(writer->finish_content_writes()));}
 auto h=take(HeldChild::observe(f.parent,name("source")));const auto identity=*h->metadata().identity.value();h.reset();
 auto file=std::shared_ptr<OperationJournalFile>(take(f.root->open_journal(name("base.journal"),true)));
 OperationJournalId id{};id.bytes[0]=std::byte{84};auto journal=take(OperationJournal::create(FileOperation::Copy,id));CHECK(take(append_operation_journal_file(*file,*journal,{1,0,OperationJournalState::Planned,{}})));
 Watch w;w.root=f.root.get();w.journal=journal.get();w.fault=fault;w.oom=oom;w.protocol=protocol;
 struct stat s{};CHECK(!lstat((f.path+"/source").c_str(),&s));w.dev=s.st_dev;w.ino=s.st_ino;CHECK(!lstat((f.path+"/journal/base.journal").c_str(),&s));w.jdev=s.st_dev;w.jino=s.st_ino;
 auto parentid=take(f.parent->identity());NativeOperationCopyRequest r{.journal=journal,.journal_file=file,.item=0,.source_parent=f.parent,.source_parent_identity=parentid,.source_name=name("source"),.source_identity=identity,.destination=f.parent,.destination_identity=parentid,.destination_address=take(NativeAbsolutePath::from_posix(f.path)),.staging_name=name("private-stage"),.destination_name=name("published")};
 OpenedEntry* borrowed_source=nullptr;
 r.copy_limits.chunk_bytes=257;
 r.prepare_stream=[&](OpenedEntry& a,OpenedEntry& b,StreamCopyLimits l){borrowed_source=&a;return create_stream_copy_job(a,b,l);};
 // This focused base-owner test explicitly supplies no-op metadata phases and
 // creates NO MetadataCaptureJob/source proof: the selected FD can only be
 // NativeCopy's own source consumed by actual native pread.
 r.prepare_metadata=[](OpenedEntry&,std::stop_token){OperationMetadataRequest q;q.apply_traversal_metadata=q.apply_security_metadata=q.apply_final_times=q.flush_destination=[](std::stop_token){return Observation<bool>::available(true);};return OperationMetadataJob::create(std::move(q));};
 r.finish_metadata=[&]{++w.metadata_finishes;if(prior)detail::record_prepared_journal_consumer_failure(*f.root,ObservationState::Failed,ErrorDomain::Posix,ENOSPC,"test.prior_root_error");return Observation<bool>::available(true);};
 auto job=take(NativeOperationCopyJob::create(std::move(r)));Observer observer(*f.root);watch=&w;std::stop_source stop;unsigned advances=0;
 {detail::MetadataCaptureCleanupScope scope(&observer);for(;advances<4096&&job->state()<OperationExecutionState::Complete;++advances){if(cancelled&&w.reads)stop.request_stop();w.active=true;job->advance(stop.get_token());w.active=false;}}
 const bool was_oom=deny_allocations.exchange(false);w.active=false;
 detail::PreparedJournalConsumerFailure root_error;const bool root_failed=detail::read_prepared_journal_consumer_failure(*f.root,root_error);
 std::printf("OBS mode=%.*s state=%u reads=%u sourceFD=%d sourceClose=%u writerClose=%u journalClose=%u metadataFinish=%u retry=%d OOM=%d allocations=%u root=%d rootCode=%lld rootOp=%s firstAllocCode=%lld firstAllocPending=%d journalStateAtSourceClose=%u\n",int(mode.size()),mode.data(),unsigned(job->state()),w.reads,w.source,w.source_closes,w.writer_closes,w.journal_closes,w.metadata_finishes,int(w.retry),int(was_oom),w.allocations,int(root_failed),(long long)root_error.code,root_error.operation.data(),(long long)w.first_allocation.code,int(w.first_allocation.pending),unsigned(w.state_at_close));std::fflush(stdout);
 CHECK(advances<4096&&w.source>=0&&w.reads>0&&w.source_closes==1&&!w.retry&&w.metadata_finishes==1);
 CHECK(w.journal_closes==1);if(!cancelled)CHECK(w.writer_closes==1);
 if(oom)CHECK(was_oom&&w.allocations>0);
 if(fault){CHECK(job->state()==OperationExecutionState::NeedsReconciliation);CHECK(root_failed&&root_error.domain==ErrorDomain::Posix&&root_error.code==(prior?ENOSPC:EIO));CHECK(observer.calls>0);if(oom)CHECK(w.first_allocation.code==(prior?ENOSPC:EIO)&&!w.first_allocation.pending);}
 else if(protocol){CHECK(w.triggered&&job->state()==OperationExecutionState::NeedsReconciliation);}
 else CHECK(job->state()==(cancelled?OperationExecutionState::Cancelled:OperationExecutionState::Complete));
 CHECK(borrowed_source&&!borrowed_source->inspect_basic().value());
 // Root's current documented consumer-reference gate must remain fail-closed
 // while the job and separately held journal-file consumer still retain it.
 // The base source shell is already closed and remains safe to inspect above.
 auto before_destroy=f.root->finish_io();CHECK(!before_destroy.value()&&before_destroy.unavailable_detail()->error.operation=="journal_root.consumers_active");
 // Deliberately reuse the consumed source's exact numeric FD for an unrelated
 // native object. Terminal advance/destruction must not close that new owner.
 int reuse=static_cast<int>(syscall(SYS_openat,AT_FDCWD,"/dev/null",O_RDONLY|O_CLOEXEC,0));CHECK(reuse>=0);
 if(reuse!=w.source){CHECK(syscall(SYS_dup3,reuse,w.source,O_CLOEXEC)==w.source);CHECK(!syscall(SYS_close,reuse));reuse=w.source;}
 const auto terminal=job->state();const auto closes=w.source_closes,reads=w.reads;for(unsigned i=0;i<3;++i)CHECK(job->advance()==terminal);CHECK(closes==w.source_closes&&reads==w.reads&&!w.retry);job.reset();CHECK(closes==w.source_closes&&!w.retry&&fcntl(reuse,F_GETFD)>=0);CHECK(!syscall(SYS_close,reuse));watch=nullptr;
 if(!cancelled&&!protocol){CHECK(w.state_at_close==OperationJournalState::Complete);auto out=take(f.parent->open_child(name("published"),EntryAccess::ContentRead));auto content=take(out->read_content({16384}));CHECK(content.complete&&content.bytes.size()==bytes.size()&&std::equal(bytes.begin(),bytes.end(),content.bytes.begin()));}
 CHECK(take(f.parent->lookup_child(name("source"),ChildLookupMode::NativeDefault)).state()==ChildLookupState::Found);
 if(cancelled)CHECK(take(f.parent->lookup_child(name("published"),ChildLookupMode::NativeDefault)).state()==ChildLookupState::Missing);
 file.reset();
 auto finished=f.root->finish_io();if(fault)CHECK(!finished.value()&&finished.unavailable_detail()->error.code==(prior?ENOSPC:EIO));else CHECK(take(std::move(finished)));
 std::printf("PASS genuine Linux NativeCopy base-source mode=%.*s, all closes before terminal, source preserved, no close retry\n",int(mode.size()),mode.data());
}
unsigned finalizers=0;
void upstream(bool protocol){OperationJournalId id{};id.bytes[0]=std::byte{83};auto journal=take(OperationJournal::create(FileOperation::Copy,id));CHECK(journal->append({1,0,OperationJournalState::Planned,{}}).value());OperationCopyRequest c;c.journal=journal;c.revalidate_source=c.revalidate_destination=[](std::stop_token){return Observation<bool>::available(true);};c.prepare_copy=[](std::stop_token){return Observation<StreamCopyJob::Pointer>::unavailable(ObservationState::Unknown);};c.prepare_metadata=[](std::stop_token){return Observation<OperationMetadataJob::Pointer>::unavailable(ObservationState::Unknown);};c.verify_copy=[](std::stop_token){return Observation<bool>::available(true);};c.append_journal=[journal,protocol](OperationJournalRecord r){if(protocol){deny_allocations=true;throw std::bad_alloc();}return journal->append(std::move(r));};OperationExecutionRequest r;r.copy=take(OperationCopyJob::create(std::move(c)));r.prepare_commit=[](std::stop_token){return Observation<OperationCommitJob::Pointer>::unavailable(ObservationState::Unknown);};r.finish_io=[protocol]{++finalizers;if(!protocol){deny_allocations=true;throw std::bad_alloc();}return Observation<bool>::available(true);};auto j=take(OperationExecutionJob::create(std::move(r)));std::stop_source stop;stop.request_stop();auto state=j->advance(stop.get_token());deny_allocations=false;CHECK(state==OperationExecutionState::NeedsReconciliation&&finalizers==1);for(unsigned i=0;i<3;++i)CHECK(j->advance()==state);CHECK(finalizers==1);std::printf("PASS upstream persistent OOM protocol=%d finalizer exactly once\n",int(protocol));}
}
extern "C" ssize_t __wrap_pread(int fd,void* data,size_t n,off_t off){if(watch&&watch->active&&n&&same(fd,watch->dev,watch->ino)){if(watch->source>=0&&watch->source!=fd)std::abort();watch->source=fd;++watch->reads;}return syscall(SYS_pread64,fd,data,n,off);}
extern "C" ssize_t __wrap_pwrite(int fd,const void* data,size_t n,off_t off){auto*w=watch;if(w&&w->active){if(same(fd,w->jdev,w->jino))w->journal_fd=fd;else if(fd!=w->source){w->writer=fd;struct stat st{};if(!fstat(fd,&st)){w->wdev=st.st_dev;w->wino=st.st_ino;}}}auto result=syscall(SYS_pwrite64,fd,data,n,off);if(w&&w->active&&w->protocol&&w->reads&&fd==w->journal_fd&&!w->triggered){w->triggered=true;deny_allocations=true;throw std::bad_alloc();}return result;}
extern "C" int __wrap_close(int fd){auto*w=watch;const bool source=w&&fd==w->source&&same(fd,w->dev,w->ino),writer=w&&fd==w->writer&&same(fd,w->wdev,w->wino),journal=w&&same(fd,w->jdev,w->jino);if(w&&w->consumed&&fd==w->source){struct stat st{};if(fstat(fd,&st)&&errno==EBADF)w->retry=true;}const int rc=static_cast<int>(syscall(SYS_close,fd));const int saved=errno;if(w){if(writer)++w->writer_closes;if(journal)++w->journal_closes;if(source){++w->source_closes;w->consumed=true;if(const auto s=w->journal->state(0))w->state_at_close=*s;if(rc==0&&w->fault){deny_allocations=w->oom;errno=EIO;return -1;}}}errno=saved;return rc;}
int main(int argc,char**argv){std::set_terminate([]{deny_allocations=false;std::fprintf(stderr,"TERMINATE finalizers=%u\n",finalizers);if(watch){detail::PreparedJournalConsumerFailure e;const bool root_error=detail::read_prepared_journal_consumer_failure(*watch->root,e);std::fprintf(stderr,"FATAL sourceClose=%u writerClose=%u journalClose=%u metadataFinish=%u root=%d rootCode=%lld rootOp=%s\n",watch->source_closes,watch->writer_closes,watch->journal_closes,watch->metadata_finishes,int(root_error),(long long)e.code,e.operation.data());}std::_Exit(3);});try{const auto mode=native_finalization_fixture::parse(argc,argv,{"upstream-protocol-oom","upstream-finalizer-oom","success","cancel","eio","eio-cancel","eio-prior","close-oom","close-oom-cancel","protocol-oom"});if(mode=="upstream-protocol-oom")upstream(true);else if(mode=="upstream-finalizer-oom")upstream(false);else native_case(mode);return 0;}catch(const std::exception&e){deny_allocations=false;std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
