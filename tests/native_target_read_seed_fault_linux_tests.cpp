// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_capture_job.hpp"
#include "native_filesystem.hpp"
#include "prepared_journal_root.hpp"
#include "platform/native_target_read_seed.hpp"
#include "platform/prepared_journal_root_bridge.hpp"

#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <filesystem>
#include <new>
#include <span>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>

#if !defined(__linux__)
#error "native_target_read_seed_fault_linux_tests.cpp must be registered only for Linux"
#else
using namespace ck::files;

namespace fault {
std::atomic<bool> deny_allocations{false};
using RealClosedir = int (*)(DIR*);
RealClosedir real_closedir = nullptr;
struct Watch {
    dev_t device{};
    ino_t inode{};
    bool active=false;
    bool directory=false;
    bool oom=false;
    unsigned inject_after=1;
    unsigned selected_closes=0;
    unsigned injected=0;
    unsigned retries=0;
    int consumed_fd=-1;
    DIR* consumed_directory=nullptr;
};
thread_local Watch* watch=nullptr;
const MetadataCaptureBudget* budget_probe=nullptr;
std::size_t budget_before_close=0;
}

void* operator new(std::size_t size) {
    if (fault::deny_allocations.load(std::memory_order_relaxed)) throw std::bad_alloc();
    if (auto* value=std::malloc(size?size:1)) return value;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* value) noexcept { std::free(value); }
void operator delete[](void* value) noexcept { std::free(value); }
void operator delete(void* value,std::size_t) noexcept { std::free(value); }
void operator delete[](void* value,std::size_t) noexcept { std::free(value); }

namespace {
template<class T> T take(Observation<T> value) {
    assert(value.value());
    return std::move(value).take_value();
}
NativeName name(const char* text) { return *NativeName::from_posix(text); }

MetadataReplayPolicy policy() {
    MetadataReplayPolicy value;
    value.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;
    value.limits.max_records=256;
    value.limits.max_native_bytes=64*1024;
    return value;
}

class RootLatch final : public MetadataCaptureFailureLatch {
public:
    explicit RootLatch(PreparedJournalRoot& root):root_(&root) {}
    void record_first(MetadataCaptureCleanupError error) const noexcept override {
        ++calls;
        detail::record_prepared_journal_consumer_failure(*root_,error.state,error.domain,error.code,error.operation);
    }
    PreparedJournalRoot* root_;
    mutable unsigned calls=0;
};

struct Fixture {
    std::string path;
    std::shared_ptr<const DirectoryCursor> parent;
    PreparedJournalRoot::Pointer root;
    Fixture() {
        const char* temp=std::getenv("TMPDIR");
        assert(temp&&*temp);
        path=std::string(temp)+"/native-target-read-seed-fault-XXXXXX";
        assert(::mkdtemp(path.data()));
        NativeFileSystem filesystem;
        parent=std::shared_ptr<const DirectoryCursor>(take(filesystem.open_directory(path)));
        PreparedJournalRootRequest request;
        request.parent=parent;
        request.child=name("journal");
        request.disposition=JournalRootDisposition::ProvisionChild;
        JournalRootPreparationProgress progress;
        root=take(prepare_native_journal_root(std::move(request),progress));
    }
    ~Fixture() {
        fault::watch=nullptr;
        fault::deny_allocations.store(false);
        root.reset();
        parent.reset();
        std::filesystem::remove_all(path);
    }
};

std::shared_ptr<const NativeMetadataProof> capture_file(
    std::shared_ptr<const OpenedEntry> entry,const std::shared_ptr<const RootLatch>& latch,
    const std::shared_ptr<MetadataCaptureBudget>& budget) {
    auto job=take(MetadataCaptureJob::begin(entry,policy(),budget->limits(),budget,latch));
    for(unsigned i=0;i<10000&&job->progress().phase!=MetadataCapturePhase::Complete;++i) take(job->advance());
    assert(job->progress().phase==MetadataCapturePhase::Complete);
    auto proof=take(job->result());
    job.reset();
    return proof;
}
std::shared_ptr<const NativeMetadataProof> capture_directory(
    std::shared_ptr<const DirectoryCursor> entry,const std::shared_ptr<const RootLatch>& latch,
    const std::shared_ptr<MetadataCaptureBudget>& budget) {
    auto job=take(MetadataCaptureJob::begin_directory(std::move(entry),policy(),budget->limits(),budget,latch));
    for(unsigned i=0;i<10000&&job->progress().phase!=MetadataCapturePhase::Complete;++i) take(job->advance());
    assert(job->progress().phase==MetadataCapturePhase::Complete);
    auto proof=take(job->result());
    job.reset();
    return proof;
}

void arm(fault::Watch& watch,const BasicMetadata& metadata,unsigned after,bool directory,bool oom) {
    assert(metadata.identity.value());
    std::memcpy(&watch.device,metadata.identity.value()->volume.bytes.data(),sizeof(watch.device));
    std::memcpy(&watch.inode,metadata.identity.value()->object.bytes.data(),sizeof(watch.inode));
    watch.inject_after=after;
    watch.directory=directory;
    watch.oom=oom;
    watch.active=true;
    fault::watch=&watch;
}
bool selected(int fd) noexcept {
    if(!fault::watch||!fault::watch->active) return false;
    struct stat value{};
    return !fstat(fd,&value)&&value.st_dev==fault::watch->device&&value.st_ino==fault::watch->inode;
}
void reuse_consumed(int fd) {
    assert(fd>=0);
    const int replacement=static_cast<int>(syscall(SYS_openat,AT_FDCWD,"/dev/null",O_RDONLY|O_CLOEXEC,0));
    assert(replacement>=0);
    if(replacement!=fd) { assert(static_cast<int>(syscall(SYS_dup3,replacement,fd,O_CLOEXEC))==fd); assert(!syscall(SYS_close,replacement)); }
    assert(fcntl(fd,F_GETFD)>=0);
    assert(!syscall(SYS_close,fd));
}
void assert_root_error(PreparedJournalRoot& root,std::int64_t code) {
    detail::PreparedJournalConsumerFailure error{};
    assert(detail::read_prepared_journal_consumer_failure(root,error));
    assert(error.domain==ErrorDomain::Posix&&error.code==code&&!error.pending);
}

void source_close_case(bool oom,bool prior) {
    fault::deny_allocations.store(false);
    Fixture fixture;
    auto target=take(fixture.parent->create_child_file(name("target")));
    const std::array<std::byte,4> bytes{std::byte{'s'},std::byte{'e'},std::byte{'e'},std::byte{'d'}};
    assert(take(target->write_content(0,bytes))==bytes.size());
    auto reader=std::shared_ptr<const OpenedEntry>(take(fixture.parent->open_child(name("target"),EntryAccess::ContentRead)));
    MetadataCaptureLimits limits;
    limits.read.max_bytes=4096;
    auto budget=std::make_shared<MetadataCaptureBudget>(limits);
    auto latch=std::make_shared<RootLatch>(*fixture.root);
    auto proof=capture_file(reader,latch,budget);
    auto seed=take(detail::begin_native_target_read_seed(*target,proof,limits,budget,latch));
    assert(take(seed->advance()));
    auto source=take(seed->source());
    const auto source_metadata=take(source->inspect_basic());
    auto active_finish=seed->finish_io();
    assert(!active_finish.value() && active_finish.unavailable_detail()->error.operation=="seed.consumers_active");
    source.reset();
    fault::Watch watch;
    arm(watch,source_metadata,1,false,oom);
    if(prior) detail::record_prepared_journal_consumer_failure(*fixture.root,ObservationState::Failed,ErrorDomain::Posix,ENOSPC,"test.prior_root");
    bool threw=false;
    try {
        auto result=seed->finish_io();
        assert(!oom);
        assert(!result.value()&&result.unavailable_detail()->error.code==EIO);
    } catch(const std::bad_alloc&) { threw=true; }
    fault::watch=nullptr;
    fault::deny_allocations.store(false);
    assert(watch.injected==1&&watch.selected_closes==1&&watch.consumed_fd>=0&&!watch.retries);
    assert(!oom||threw);
    assert_root_error(*fixture.root,prior?ENOSPC:EIO);
    const unsigned closes=watch.selected_closes;
    auto cached=seed->finish_io();
    assert(!cached.value()&&cached.unavailable_detail()->error.code==EIO);
    assert(watch.selected_closes==closes);
    const int consumed=watch.consumed_fd;
    reuse_consumed(consumed);
    seed.reset();
    assert(take(proof->finish_io()));
    assert(take(target->finish_content_writes()));
    reader.reset();
    target.reset();
    assert_root_error(*fixture.root,prior?ENOSPC:EIO);
    assert(!fixture.root->finish_io().value());
    std::printf("PASS seed source close EIO mode=%s oom_model=%s prior=%d exact-close=1 no-retry fd-reuse-safe\n",
        oom?"persistent-new-denial":"eio",oom?"persistent_new_denial":"none",int(prior));
}

void capture_clone_case(bool oom) {
    fault::deny_allocations.store(false);
    Fixture fixture;
    auto target=take(fixture.parent->create_child_file(name("target")));
    const std::array<std::byte,4> bytes{std::byte{'c'},std::byte{'l'},std::byte{'o'},std::byte{'n'}};
    assert(take(target->write_content(0,bytes))==bytes.size());
    auto reader=std::shared_ptr<const OpenedEntry>(take(fixture.parent->open_child(name("target"),EntryAccess::ContentRead)));
    MetadataCaptureLimits limits;
    limits.read.max_bytes=4096;
    auto budget=std::make_shared<MetadataCaptureBudget>(limits);
    auto latch=std::make_shared<RootLatch>(*fixture.root);
    auto proof=capture_file(reader,latch,budget);
    auto seed=take(detail::begin_native_target_read_seed(*target,proof,limits,budget,latch));
    assert(take(seed->advance()));
    auto source=take(seed->source());
    auto clone=take(detail::open_native_metadata_capture_source(source,policy()));
    auto metadata=take(clone->inspect_basic());
    source.reset();
    auto active_finish=seed->finish_io();
    assert(!active_finish.value()&&active_finish.unavailable_detail()->error.operation=="seed.consumers_active");
    fault::Watch watch;
    arm(watch,metadata,1,false,oom);
    bool threw=false;
    try {
        detail::MetadataCaptureCleanupScope cleanup(latch.get());
        detail::finish_native_metadata_capture(clone.get(),proof->snapshot());
    } catch(const std::bad_alloc&) { threw=true; }
    fault::watch=nullptr;
    fault::deny_allocations.store(false);
    assert(!threw);
    assert(watch.injected==1&&watch.selected_closes==1&&watch.consumed_fd>=0&&!watch.retries);
    assert_root_error(*fixture.root,EIO);
    clone.reset();
    auto finished=seed->finish_io();
    assert(finished.value()&&*finished.value());
    reuse_consumed(watch.consumed_fd);
    seed.reset();
    assert(take(proof->finish_io()));
    assert(take(target->finish_content_writes()));
    reader.reset();
    target.reset();
    assert_root_error(*fixture.root,EIO);
    assert(!fixture.root->finish_io().value());
    std::printf("PASS actual capture clone close EIO mode=%s oom_model=%s exact-close=1 active-refusal budget-held POD-root\n",
        oom?"persistent-new-denial":"eio",oom?"persistent_new_denial":"none");
}

void clone_destructor_case() {
    fault::deny_allocations.store(false);
    Fixture fixture;
    auto target=take(fixture.parent->create_child_file(name("target")));
    const std::array<std::byte,4> bytes{std::byte{'d'},std::byte{'t'},std::byte{'o'},std::byte{'r'}};
    assert(take(target->write_content(0,bytes))==bytes.size());
    auto reader=std::shared_ptr<const OpenedEntry>(take(fixture.parent->open_child(name("target"),EntryAccess::ContentRead)));
    MetadataCaptureLimits limits;
    limits.read.max_bytes=4096;
    auto budget=std::make_shared<MetadataCaptureBudget>(limits);
    auto latch=std::make_shared<RootLatch>(*fixture.root);
    auto proof=capture_file(reader,latch,budget);
    auto seed=take(detail::begin_native_target_read_seed(*target,proof,limits,budget,latch));
    assert(take(seed->advance()));
    auto source=take(seed->source());
    auto clone=take(detail::open_native_metadata_capture_source(source,policy()));
    {
        detail::MetadataCaptureCleanupScope cleanup(latch.get());
        detail::finish_native_metadata_capture(source.get(),proof->snapshot());
    }
    source.reset();
    const auto expected=budget->retained_handle_reservations();
    {
        detail::MetadataCaptureCleanupScope cleanup(latch.get());
        fault::Watch watch;
        auto metadata=take(clone->inspect_basic());
        arm(watch,metadata,1,false,false);
        fault::budget_probe=budget.get();
        fault::budget_before_close=0;
        clone.reset();
        fault::budget_probe=nullptr;
        fault::watch=nullptr;
        assert(watch.injected==1&&watch.selected_closes==1&&watch.consumed_fd>=0&&!watch.retries);
        assert(fault::budget_before_close==expected);
        assert(budget->retained_handle_reservations()==expected-1);
        assert_root_error(*fixture.root,EIO);
        reuse_consumed(watch.consumed_fd);
    }
    assert(take(seed->finish_io()));
    seed.reset();
    assert(take(proof->finish_io()));
    assert(take(target->finish_content_writes()));
    reader.reset();
    target.reset();
    assert(!fixture.root->finish_io().value());
    std::printf("PASS actual capture clone destructor EIO reservation-held-during-close released-after-close\n");
}

void seed_close_case() {
    Fixture fixture;
    MetadataCaptureLimits limits;
    limits.read.max_bytes=4096;
    auto budget=std::make_shared<MetadataCaptureBudget>(limits);
    auto latch=std::make_shared<RootLatch>(*fixture.root);
    auto proof=capture_directory(fixture.parent,latch,budget);
    auto seed=take(detail::begin_native_directory_read_seed(fixture.parent,proof,limits,budget,latch));
    auto pending=seed->advance();
    assert(pending.value()&&!*pending.value());
    assert(take(seed->advance()));
    auto source=take(seed->source());
    auto metadata=take(source->inspect_basic());
    auto cursor=take(seed->directory_cursor());
    cursor.reset();
    source.reset();
    fault::Watch watch;
    arm(watch,metadata,2,false,false);
    auto result=seed->finish_io();
    fault::watch=nullptr;
    assert(!result.value()&&result.unavailable_detail()->error.code==EIO);
    assert(watch.injected==1&&watch.selected_closes==2&&!watch.retries);
    assert_root_error(*fixture.root,EIO);
    const unsigned closes=watch.selected_closes;
    assert(!seed->finish_io().value()&&watch.selected_closes==closes);
    reuse_consumed(watch.consumed_fd);
    seed.reset();
    assert(take(proof->finish_io()));
    assert_root_error(*fixture.root,EIO);
    assert(!fixture.root->finish_io().value());
    std::printf("PASS seed-owned enum close EIO exact-source+enum closes no-retry fd-reuse-safe\n");
}

void cursor_closedir_case() {
    Fixture fixture;
    MetadataCaptureLimits limits;
    limits.read.max_bytes=4096;
    auto budget=std::make_shared<MetadataCaptureBudget>(limits);
    auto latch=std::make_shared<RootLatch>(*fixture.root);
    auto proof=capture_directory(fixture.parent,latch,budget);
    auto seed=take(detail::begin_native_directory_read_seed(fixture.parent,proof,limits,budget,latch));
    auto pending=seed->advance();
    assert(pending.value()&&!*pending.value());
    assert(take(seed->advance()));
    auto source=take(seed->source());
    auto metadata=take(source->inspect_basic());
    auto cursor=take(seed->directory_cursor());
    auto active_finish=seed->finish_io();
    assert(!active_finish.value() && active_finish.unavailable_detail()->error.operation=="seed.consumers_active");
    fault::Watch watch;
    arm(watch,metadata,1,true,false);
    {
        detail::MetadataCaptureCleanupScope cleanup(latch.get());
        cursor.reset();
    }
    fault::watch=nullptr;
    assert(watch.injected==1&&watch.consumed_directory!=nullptr&&!watch.retries);
    assert_root_error(*fixture.root,EIO);
    source.reset();
    assert(take(seed->finish_io()));
    assert(take(seed->finish_io()));
    reuse_consumed(watch.consumed_fd);
    seed.reset();
    assert(take(proof->finish_io()));
    assert_root_error(*fixture.root,EIO);
    assert(!fixture.root->finish_io().value());
    std::printf("PASS cursor closedir EIO exact-close=1 root-first-error fd-reuse-safe\n");
}
}

extern "C" int __wrap_close(int fd) {
    auto* watch=fault::watch;
    const bool match=selected(fd);
    if(match&&watch->consumed_fd==fd) ++watch->retries;
    if(match&&fault::budget_probe)fault::budget_before_close=fault::budget_probe->retained_handle_reservations();
    const int result=static_cast<int>(syscall(SYS_close,fd));
    if(match&&result==0) {
        ++watch->selected_closes;
        if(watch->selected_closes==watch->inject_after) {
            watch->injected++;
            watch->consumed_fd=fd;
            if(watch->oom) fault::deny_allocations.store(true);
            errno=EIO;
            return -1;
        }
    }
    return result;
}

extern "C" int __wrap_closedir(DIR* directory) {
    auto* watch=fault::watch;
    if(watch&&watch->consumed_directory==directory) { ++watch->retries; errno=EBADF; return -1; }
    const int fd=directory?dirfd(directory):-1;
    const bool match=watch&&watch->active&&watch->directory&&fd>=0&&selected(fd);
    const int result=fault::real_closedir(directory);
    if(match&&result==0) {
        ++watch->selected_closes;
        if(watch->selected_closes==watch->inject_after) {
            watch->injected++;
            watch->consumed_fd=fd;
            watch->consumed_directory=directory;
            errno=EIO;
            return -1;
        }
    }
    return result;
}

int main(int argc,char** argv) {
    fault::real_closedir=reinterpret_cast<fault::RealClosedir>(dlsym(RTLD_NEXT,"closedir"));
    assert(fault::real_closedir);
    assert(argc==2);
    const std::string mode=argv[1];
    if(mode=="source-eio") source_close_case(false,false);
    else if(mode=="source-oom") source_close_case(true,false);
    else if(mode=="source-prior") source_close_case(false,true);
    else if(mode=="clone-eio") capture_clone_case(false);
    else if(mode=="clone-oom") capture_clone_case(true);
    else if(mode=="clone-dtor") clone_destructor_case();
    else if(mode=="seed-eio") seed_close_case();
    else if(mode=="cursor-eio") cursor_closedir_case();
    else return 2;
}
#endif
