// SPDX-License-Identifier: LGPL-2.0-or-later
#define main foundation_hierarchy_regressions
#include "native_sync_hierarchy_binding_tests.cpp"
#undef main
#include <climits>
#include "sync_session_reader_epoch.hpp"
#include "native_sync_coordinator.hpp"
#include "native_sync_resolution.hpp"
namespace {
std::unique_ptr<SyncSession> session(Fixture& f,SyncSessionFaults faults={}){auto backend=get(open_native_sync_session_backend(f.journal,f.address("left"),f.address("right"),std::move(faults)));return get(SyncSession::open(std::move(backend),SyncDigest{}));}
unsigned selected_fds(const std::filesystem::path& path){struct stat target{};CHECK(lstat(path.c_str(),&target)==0);DIR* p=opendir("/proc/self/fd");CHECK(p);unsigned count=0;while(auto e=readdir(p)){char* end=nullptr;const long number=strtol(e->d_name,&end,10);if(end==e->d_name||*end||number<0||number>INT_MAX)continue;struct stat s{};if(fstat(static_cast<int>(number),&s)==0&&s.st_dev==target.st_dev&&s.st_ino==target.st_ino)++count;}CHECK(closedir(p)==0);return count;}
void shared_existing(){Fixture f;const auto before=fds();auto s=session(f);const auto generation=s->snapshot().generation;auto c=get(NativeHierarchyContext::borrow(*s));auto b=get(c->bind(false,path({"d","e","file"})));yes(b->revalidate());CHECK(s->snapshot().generation==generation);auto relock=NativeHierarchyContext::open(f.journal,f.address("left"),f.address("right"));CHECK(!relock.value()&&relock.unavailable_detail()->error.operation=="sync_session.overlap_lock");yes(c->finish_io());yes(s->revalidate());yes(s->finish_io());s.reset();CHECK(fds()==before);}
void finish_revokes(){Fixture f;const auto before=fds();bool saw=false;NativeHierarchyBinding::Pointer binding;auto faults=SyncSessionFaults{[&](SyncSessionIo io){if(io==SyncSessionIo::NativeHandleClose){saw=true;CHECK(selected_fds(f.root/"left/d/e/file")==0&&selected_fds(f.root/"left/d/e")==0);}return true;}};auto s=session(f,std::move(faults));auto c=get(NativeHierarchyContext::borrow(*s));binding=get(c->bind(false,path({"d","e","file"})));yes(s->finish_io());CHECK(saw&&!binding->revalidate().value());yes(binding->finish_io());yes(c->finish_io());s.reset();CHECK(fds()==before);auto next=f.context();yes(next->finish_io());}
void destruction_revokes(){Fixture f;auto s=session(f);auto c=get(NativeHierarchyContext::borrow(*s));auto b=get(c->bind(false,path({"d","e","file"})));s.reset();CHECK(!b->revalidate().value()&&!b->metadata().value());CHECK(selected_fds(f.root/"left/d/e/file")==0);yes(c->finish_io());}
void refresh_revokes(){Fixture f;auto s=session(f);auto c=get(NativeHierarchyContext::borrow(*s));auto b=get(c->bind(false,path({"d","e","file"})));const auto old=b->epoch();yes(s->refresh());CHECK(!b->revalidate().value());auto fresh=get(NativeHierarchyContext::borrow(*s));auto current=get(fresh->bind(false,path({"d","e","file"})));CHECK(current->epoch()!=old);yes(s->finish_io());CHECK(!current->revalidate().value());}
void commit_drains(bool oom){Fixture f;auto s=session(f);auto c=get(NativeHierarchyContext::borrow(*s));auto b=get(c->bind(false,path({"d","e","file"})));struct stat st{};CHECK(lstat((f.root/"left/d/e/file").c_str(),&st)==0);fault::dev=st.st_dev;fault::ino=st.st_ino;fault::hits=0;fault::oom_after_close=oom;fault::armed=true;const auto before=s->snapshot().generation;bool threw=false,unavailable=false;
 try{auto committed=s->commit(before,{},true);unavailable=!committed.value()&&committed.unavailable_detail()->error.domain==ErrorDomain::Posix&&committed.unavailable_detail()->error.code==EIO;}
 catch(const std::bad_alloc&){(void)c->drain();if(s->root_handle(false)!=-1)try{(void)s->finish_io();}catch(...){ }threw=true;}
 fault::fail_alloc=false;const auto raw=s->reader_failure();CHECK((oom?threw:unavailable)&&raw.failed&&raw.domain==ErrorDomain::Posix&&raw.code==EIO&&fault::hits==1);CHECK(s->snapshot().generation==before);
 if(!oom){auto again=s->commit(before,{},true);CHECK(!again.value()&&again.unavailable_detail()->error.code==EIO&&fault::hits==1);auto rejected=s->revalidate();CHECK(!rejected.value()&&rejected.unavailable_detail()->error.code==EIO);}
 CHECK(!b->revalidate().value()&&selected_fds(f.root/"left/d/e/file")==0);auto finished=s->finish_io();CHECK(!finished.value()&&finished.unavailable_detail()->error.code==EIO);finished=s->finish_io();CHECK(!finished.value()&&finished.unavailable_detail()->error.code==EIO&&fault::hits==1);}
void finish_close_fault(bool oom){Fixture f;auto s=session(f);auto c=get(NativeHierarchyContext::borrow(*s));auto b=get(c->bind(false,path({"d","e","file"})));struct stat st{};CHECK(lstat((f.root/"left/d/e/file").c_str(),&st)==0);fault::dev=st.st_dev;fault::ino=st.st_ino;fault::hits=0;fault::oom_after_close=oom;fault::armed=true;bool threw=false,unavailable=false;
 try{auto first=s->finish_io();unavailable=!first.value()&&first.unavailable_detail()->error.domain==ErrorDomain::Posix&&first.unavailable_detail()->error.code==EIO;}
 catch(const std::bad_alloc&){(void)c->drain();threw=true;}
 fault::fail_alloc=false;const auto raw=s->reader_failure();CHECK((oom?threw:unavailable)&&raw.failed&&raw.domain==ErrorDomain::Posix&&raw.code==EIO&&fault::hits==1);auto repeated=s->finish_io();CHECK(!repeated.value()&&repeated.unavailable_detail()->error.code==EIO&&fault::hits==1);CHECK(selected_fds(f.root/"left/d/e/file")==0&&!b->revalidate().value());}
NativeSyncCoordinatorRequest actual_request(Fixture& f){NativeSyncCoordinatorRequest r{f.address("store"),f.address("left"),f.address("right"),{},{},{},{},{},{},{}};r.prepared_journal_root=f.journal;r.metadata.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;r.metadata.ownership=MetadataOwnership::CurrentCaller;return r;}
void reset_flat_fixture(Fixture& f){std::filesystem::remove_all(f.root/"left/d");f.write("left/a");f.write("right/a");}
void add_actual_hierarchy(Fixture& f){CHECK(mkdir((f.root/"left/d").c_str(),0700)==0);CHECK(mkdir((f.root/"left/d/e").c_str(),0700)==0);f.write("left/d/e/file");}
void actual_coordinator(){Fixture f;reset_flat_fixture(f);auto worker=get(NativeSyncCoordinator::open(actual_request(f)));auto c=get(NativeHierarchyContext::borrow(*worker));add_actual_hierarchy(f);auto b=get(c->bind(false,path({"d","e","file"})));yes(b->revalidate());auto relock=NativeHierarchyContext::open(f.journal,f.address("left"),f.address("right"));CHECK(!relock.value()&&relock.unavailable_detail()->error.operation=="sync_session.overlap_lock");yes(worker->finish_io());CHECK(!b->revalidate().value()&&selected_fds(f.root/"left/d/e/file")==0);auto closed=NativeHierarchyContext::borrow(*worker);CHECK(!closed.value()&&closed.unavailable_detail()->error.operation=="hierarchy.worker_closed");}
void actual_resolution(){Fixture f;reset_flat_fixture(f);auto worker=get(NativeSyncResolution::open(actual_request(f)));auto c=get(NativeHierarchyContext::borrow(*worker));add_actual_hierarchy(f);auto b=get(c->bind(false,path({"d","e","file"})));yes(b->revalidate());yes(worker->finish_io());CHECK(!b->revalidate().value()&&selected_fds(f.root/"left/d/e/file")==0);auto closed=NativeHierarchyContext::borrow(*worker);CHECK(!closed.value()&&closed.unavailable_detail()->error.operation=="hierarchy.worker_closed");}
struct Facade final:SyncSessionBackend {
 std::unique_ptr<SyncSessionBackend> real;explicit Facade(std::unique_ptr<SyncSessionBackend> value):real(std::move(value)){}
 PreparedJournalRoot::Pointer storage_root()const noexcept override{return real->storage_root();}
 Observation<bool> finish_io()override{return real->finish_io();}
 const SyncDigest& left_identity()const noexcept override{return real->left_identity();}
 const SyncDigest& right_identity()const noexcept override{return real->right_identity();}
 Observation<bool> revalidate()override{return real->revalidate();}
 std::intptr_t root_handle(bool right)const noexcept override{return real->root_handle(right);}
 Observation<std::optional<std::vector<std::byte>>> read(std::string_view name,std::size_t limit)override{return real->read(name,limit);}
 Observation<bool> stage(std::string_view name,std::span<const std::byte> bytes)override{return real->stage(name,bytes);}
 Observation<bool> publish(std::string_view a,std::string_view b)override{return real->publish(a,b);}
 Observation<bool> remove(std::string_view name)override{return real->remove(name);}
 Observation<bool> flush_directory()override{return real->flush_directory();}
};
void fake_backend(){Fixture f;auto native=get(open_native_sync_session_backend(f.journal,f.address("left"),f.address("right")));auto s=get(SyncSession::open(std::make_unique<Facade>(std::move(native)),SyncDigest{}));auto c=NativeHierarchyContext::borrow(*s);CHECK(!c.value()&&c.state()==ObservationState::Unsupported&&c.unavailable_detail()->error.operation=="session_lease.native_backend_required");yes(s->finish_io());}
}
#ifndef CK_HIERARCHY_SESSION_LEASE_ENTRY
#define CK_HIERARCHY_SESSION_LEASE_ENTRY main
#endif
int CK_HIERARCHY_SESSION_LEASE_ENTRY(){try{CHECK(foundation_hierarchy_regressions()==0);shared_existing();finish_revokes();destruction_revokes();refresh_revokes();commit_drains(false);commit_drains(true);finish_close_fault(false);finish_close_fault(true);actual_coordinator();actual_resolution();fake_backend();std::printf("NATIVE_HIERARCHY_EXISTING_SESSION checks=%u PASS\n",checks);return 0;}catch(const std::exception& e){fault::armed=fault::fail_alloc=false;std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
