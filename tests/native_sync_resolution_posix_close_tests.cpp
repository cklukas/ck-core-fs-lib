// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Linux native close regression; link the SAME static SDK as the 368-check suite.
#define main existing_resolution_regressions
#include "native_sync_resolution_tests.cpp"
#undef main
#include "native_filesystem.hpp"
#include "metadata_capture_job.hpp"
#include <bit>
#include <cerrno>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/syscall.h>

#ifndef __linux__
#error This native injected-consumed-close qualification requires Linux.
#endif
namespace close_watch {
enum class Mode { None, Query, HeldChild, Directory };
thread_local Mode mode=Mode::None;
thread_local dev_t device=0;
thread_local ino_t file_inode=0,directory_inode=0;
thread_local bool calibrate_query=false,calibrate_held=false,armed=false,saw_query=false;
thread_local void* query_site=nullptr;
thread_local void* held_site=nullptr;
thread_local unsigned query_calibrations=0,held_calibrations=0,hits=0,consumed_calls=0;
thread_local int consumed=-1;
thread_local bool retried=false;
bool file(const struct stat& s){return s.st_dev==device&&s.st_ino==file_inode&&S_ISREG(s.st_mode);}
int close_at(int fd,void* site) {
    struct stat s{};const bool selected=fstat(fd,&s)==0&&file(s);
    if(selected&&site==query_site)saw_query=true;
    const bool inject=selected&&armed&&((mode==Mode::Query&&site==query_site)||
        (mode==Mode::HeldChild&&saw_query&&site==held_site));
    if(selected&&armed&&fd==consumed)retried=true;
    const auto result=static_cast<int>(syscall(SYS_close,fd));const int saved=errno;
    if(selected&&result==0) {
        if(calibrate_query){query_site=site;++query_calibrations;}
        if(calibrate_held){held_site=site;++held_calibrations;}
        if(inject){armed=false;consumed=fd;++hits;++consumed_calls;errno=EIO;return -1;}
    }
    errno=saved;return result;
}
int close_directory(DIR* directory) {
    using Fn=int(*)(DIR*);
    static const auto real=std::bit_cast<Fn>(dlsym(RTLD_NEXT,"closedir"));
    if(!real)std::abort();
    const int fd=dirfd(directory);struct stat s{};
    const bool selected=fstat(fd,&s)==0&&s.st_dev==device&&s.st_ino==directory_inode;
    const bool inject=selected&&armed&&saw_query&&mode==Mode::Directory;
    const int result=real(directory);const int saved=errno;
    if(inject&&result==0){armed=false;consumed=fd;++hits;++consumed_calls;errno=EIO;return -1;}
    errno=saved;return result;
}
void reset(){armed=false;mode=Mode::None;saw_query=false;hits=consumed_calls=0;consumed=-1;retried=false;}
}
extern "C" int close(int fd){return close_watch::close_at(fd,__builtin_extract_return_addr(__builtin_return_address(0)));}
extern "C" int closedir(DIR* directory){return close_watch::close_directory(directory);}
namespace {
void calibrate(Fixture& f) {
    using namespace close_watch;
    struct stat s{};CHECK(lstat((f.root/"left"/"a").c_str(),&s)==0);device=s.st_dev;file_inode=s.st_ino;
    CHECK(lstat((f.root/"left").c_str(),&s)==0);directory_inode=s.st_ino;
    NativeFileSystem filesystem;
    auto parent=std::shared_ptr<const DirectoryCursor>(get(filesystem.open_native_directory(f.native("left"))));
    const auto access=EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity;
    auto original=std::shared_ptr<const OpenedEntry>(get(parent->open_child(name("a"),access)));
    MetadataCaptureLimits limits;limits.read={4096};
    auto capture=get(MetadataCaptureJob::begin(original,f.request().metadata,limits));
    for(unsigned i=0;i<10000&&capture->progress().phase!=MetadataCapturePhase::Complete;++i)get(capture->advance());
    auto proof=get(capture->result());
    query_calibrations=0;calibrate_query=true;CHECK(get(proof->finish_io()));calibrate_query=false;
    CHECK(query_calibrations==1&&query_site);
    CHECK(original->inspect_basic().value()&&parent->inspect_basic().value());
    CHECK(get(proof->finish_io())&&get(capture->finish_io()));CHECK(query_calibrations==1);
    auto held=get(HeldChild::observe_with_access(parent,name("a"),access));
    held_calibrations=0;calibrate_held=true;held.reset();calibrate_held=false;
    CHECK(held_calibrations==1&&held_site&&held_site!=query_site);
    CHECK(original->inspect_basic().value()&&parent->inspect_basic().value());
    // Both sites come from REAL native owners; no guessed hidden ELF symbols.
    reset();
}
std::string baseline_bytes(const Fixture& f) {
    std::string bytes;unsigned found=0;
    for(const auto& entry:std::filesystem::directory_iterator(f.root/"store"))if(entry.path().extension()==".baseline") {
        ++found;std::ifstream in(entry.path(),std::ios::binary);bytes.assign(std::istreambuf_iterator<char>(in),{});
    }
    CHECK(found==1&&!bytes.empty());return bytes;
}
unsigned publication_journals(const Fixture& f) {
    unsigned count=0;
    for(const auto& entry:std::filesystem::directory_iterator(f.root/"store"))
        if(entry.path().filename().string().starts_with(".ck-resolution-copy-"))++count;
    return count;
}
void injected_commit(close_watch::Mode mode) {
    using namespace close_watch;
    Fixture f;f.seed();calibrate(f);f.conflict();const auto before=baseline_bytes(f);
    auto request=f.request();request.before_event=[mode](auto event){
        if(event==NativeSyncCoordinatorEvent::BeforeBaselineCommit){reset();close_watch::mode=mode;armed=true;}
        return true;
    };
    auto job=get(NativeSyncResolution::open(std::move(request)));auto review=get(job->assess(choice()));CHECK(get(job->approve(*review)));
    for(unsigned i=0;i<3000&&job->result().state!=NativeSyncCoordinatorState::NeedsReview&&job->result().state!=NativeSyncCoordinatorState::Complete;++i)job->advance();
    armed=false;
    CHECK(hits==1&&consumed_calls==1&&!retried);
    CHECK(job->result().state==NativeSyncCoordinatorState::NeedsReview&&job->result().completed_operations==4);
    CHECK(job->snapshot().generation==1&&baseline_bytes(f)==before&&publication_journals(f)==4);
    CHECK(job->result().failure&&job->result().failure->error.domain==ErrorDomain::Posix&&job->result().failure->error.code==EIO);
    auto closed=job->finish_io();CHECK(!closed.value()&&closed.unavailable_detail()->error.code==EIO);
    const auto count=consumed_calls;closed=job->finish_io();CHECK(!closed.value()&&consumed_calls==count);
    job.reset();reset();
    job=get(NativeSyncResolution::open(f.request()));
    CHECK(job->snapshot().generation==2&&job->rows().size()==3&&job->protected_originals().size()==2);
    CHECK(job->result().completed_operations==0&&publication_journals(f)==4);CHECK(get(job->finish_io()));job.reset();
    job=get(NativeSyncResolution::open(f.request()));CHECK(job->snapshot().generation==2&&job->rows().size()==3);CHECK(get(job->finish_io()));
    std::cout<<"native POSIX pre-CAS consumed-close EIO mode="<<unsigned(mode)<<" generation unchanged + fresh recovery PASS\n";
}
void injected_recovery() {
    using namespace close_watch;
    Fixture f;f.seed();calibrate(f);f.conflict();auto request=f.request();
    request.before_event=[](auto event){return event!=NativeSyncCoordinatorEvent::BeforeBaselineCommit;};
    auto job=get(NativeSyncResolution::open(std::move(request)));auto review=get(job->assess(choice()));CHECK(get(job->approve(*review)));
    for(unsigned i=0;i<3000&&job->result().state!=NativeSyncCoordinatorState::NeedsReview;++i)job->advance();
    CHECK(job->snapshot().generation==1&&publication_journals(f)==4);CHECK(get(job->finish_io()));job.reset();
    const auto before=baseline_bytes(f);reset();mode=Mode::Query;armed=true;
    auto failed=NativeSyncResolution::open(f.request());armed=false;
    CHECK(!failed.value()&&hits==1&&consumed_calls==1&&failed.unavailable_detail()->error.domain==ErrorDomain::Posix&&failed.unavailable_detail()->error.code==EIO);
    CHECK(baseline_bytes(f)==before&&publication_journals(f)==4);reset();
    job=get(NativeSyncResolution::open(f.request()));CHECK(job->snapshot().generation==2&&job->rows().size()==3);
    CHECK(job->result().completed_operations==0&&publication_journals(f)==4);CHECK(get(job->finish_io()));
    std::cout<<"native POSIX recovery pre-CAS consumed-close EIO, no baseline effect/no publication replay PASS\n";
}
}
int main(){try{
    CHECK(existing_resolution_regressions()==0);
    injected_commit(close_watch::Mode::Query);
    injected_commit(close_watch::Mode::HeldChild);
    injected_commit(close_watch::Mode::Directory);
    injected_recovery();
    std::cout<<"native POSIX resolution close suite: "<<checks<<" checks PASS\n";return 0;
}catch(const std::exception& e){close_watch::reset();std::cerr<<e.what()<<'\n';return 1;}}
