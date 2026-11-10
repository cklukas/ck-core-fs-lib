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
#include <array>
#include <climits>
#include <cstdarg>

#ifndef __linux__
#error This native injected-consumed-close qualification requires Linux.
#endif
namespace close_watch {
enum class Mode { None, Query, HeldChild, Directory };
struct Fds {
    std::array<int,64> values{};unsigned size=0;
    bool contains(int fd)const{for(unsigned i=0;i<size;++i)if(values[i]==fd)return true;return false;}
    void add(int fd){CHECK(size<values.size()&&!contains(fd));values[size++]=fd;}
};
thread_local Mode mode=Mode::None;
thread_local dev_t device=0;
thread_local ino_t file_inode=0,directory_inode=0;
thread_local bool armed=false,tracking=false,acquiring=false,ordered=false,invalid_acquisition=false;
thread_local Fds files,directories;
thread_local int query_fd=-1,held_fd=-1,consumed=-1;
thread_local DIR* consumed_directory=nullptr;
thread_local unsigned file_closes=0,hits=0,consumed_calls=0;
thread_local bool retried=false,closed_once=false;
bool file(const struct stat& s){return s.st_dev==device&&s.st_ino==file_inode&&S_ISREG(s.st_mode);}
Fds snapshot(bool regular) {
    // Real current descriptors, not return addresses, symbol names or a guessed
    // descriptor-number ordering. The proc cursor is unrelated to our fixture.
    Fds out;DIR* proc=opendir("/proc/self/fd");CHECK(proc);
    int read_error=0;for(;;) {
        errno=0;auto* entry=readdir(proc);if(!entry){read_error=errno;break;}
        char* end=nullptr;const long number=strtol(entry->d_name,&end,10);
        if(end==entry->d_name||*end||number<0||number>INT_MAX)continue;
        struct stat s{};const int fd=static_cast<int>(number);
        if(fstat(fd,&s)!=0)continue;
        if(regular?file(s):(s.st_dev==device&&s.st_ino==directory_inode&&S_ISDIR(s.st_mode)))out.add(fd);
    }
    CHECK(closedir(proc)==0);CHECK(read_error==0);return out;
}
void acquisition_diagnostic(const char* point) {
    std::cerr<<"acquisition diagnostic "<<point
        <<" acquiring="<<acquiring<<" invalid="<<invalid_acquisition
        <<" tracked_size="<<files.size<<" query_fd="<<query_fd<<" held_fd="<<held_fd
        <<" file_closes="<<file_closes<<" hits="<<hits
        <<" consumed_calls="<<consumed_calls<<" consumed="<<consumed
        <<" retried="<<retried<<" closed_once="<<closed_once;
#ifdef _FORTIFY_SOURCE
    std::cerr<<" _FORTIFY_SOURCE="<<_FORTIFY_SOURCE;
#else
    std::cerr<<" _FORTIFY_SOURCE=undefined";
#endif
#ifdef __USE_FORTIFY_LEVEL
    std::cerr<<" __USE_FORTIFY_LEVEL="<<__USE_FORTIFY_LEVEL;
#endif
    std::cerr<<'\n';
    const auto dump=[](const char* label,int fd) {
        errno=0;const int status=fcntl(fd,F_GETFL);const int status_error=status<0?errno:0;
        errno=0;const int flags=fcntl(fd,F_GETFD);const int flags_error=flags<0?errno:0;
        struct stat s{};errno=0;const int stat_result=fstat(fd,&s);const int stat_error=stat_result<0?errno:0;
        std::cerr<<label<<" fd="<<fd<<" F_GETFL="<<status<<" errno="<<status_error
            <<" F_GETFD="<<flags<<" errno="<<flags_error
            <<" fstat="<<stat_result<<" errno="<<stat_error;
        if(stat_result==0)std::cerr<<" dev="<<s.st_dev<<" ino="<<s.st_ino<<" mode="<<s.st_mode<<" selected_inode="<<file(s);
        std::cerr<<'\n';
    };
    for(unsigned i=0;i<files.size;++i)dump("tracked",files.values[i]);
    dump("query",query_fd);dump("held",held_fd);
    try {
        const auto native=snapshot(true);std::cerr<<"native fixture inode snapshot size="<<native.size<<'\n';
        for(unsigned i=0;i<native.size;++i)dump("native",native.values[i]);
    }catch(const std::exception& error){std::cerr<<"diagnostic snapshot unavailable: "<<error.what()<<'\n';}
}
void reset(){armed=tracking=acquiring=ordered=invalid_acquisition=false;mode=Mode::None;files={};directories={};query_fd=held_fd=consumed=-1;consumed_directory=nullptr;file_closes=hits=consumed_calls=0;retried=closed_once=false;}
void acquired(int fd,int flags)noexcept {
    if(!acquiring||fd<0||files.size==2)return;
    struct stat s{};if(fstat(fd,&s)!=0||!file(s))return;
    // Native observer opens HeldChild, THEN its independent native_source.
    // qualify_owners below proves that assignment with actual independent
    // closes and live-owner checks; a changed acquisition contract fails.
    if((flags&O_ACCMODE)!=O_RDONLY||(flags&O_PATH)||files.contains(fd))invalid_acquisition=true;
    files.values[files.size++]=fd;
    if(files.size==2){held_fd=files.values[0];query_fd=files.values[1];acquiring=false;}
}
int opened_at(int parent,const char* path,int flags,mode_t permissions) {
    const int fd=static_cast<int>(syscall(SYS_openat,parent,path,flags,permissions));const int saved=errno;
    acquired(fd,flags);errno=saved;return fd;
}
int close_file(int fd) {
    if(tracking&&fd==consumed){retried=true;++consumed_calls;}
    struct stat s{};const bool selected=tracking&&files.contains(fd)&&fstat(fd,&s)==0&&file(s);
    if(selected&&ordered) {
        if(file_closes==0)query_fd=fd;
        else if(file_closes==1)held_fd=fd;
    }
    const bool inject=selected&&armed&&((mode==Mode::Query&&fd==query_fd&&file_closes==0)||
        (mode==Mode::HeldChild&&fd==held_fd&&file_closes==1&&query_fd!=held_fd));
    const auto result=static_cast<int>(syscall(SYS_close,fd));const int saved=errno;
    if(selected&&result==0){++file_closes;
        if(inject){armed=false;consumed=fd;++hits;consumed_calls=1;
            closed_once=fcntl(fd,F_GETFD)==-1&&errno==EBADF;errno=EIO;return -1;}
    }
    errno=saved;return result;
}
int close_directory(DIR* directory) {
    if(tracking&&directory==consumed_directory){retried=true;++consumed_calls;errno=EBADF;return -1;}
    using Fn=int(*)(DIR*);static const auto real=std::bit_cast<Fn>(dlsym(RTLD_NEXT,"closedir"));if(!real)std::abort();
    const int fd=dirfd(directory);struct stat s{};
    const bool selected=tracking&&directories.contains(fd)&&fstat(fd,&s)==0&&s.st_dev==device&&s.st_ino==directory_inode&&S_ISDIR(s.st_mode);
    const bool inject=selected&&armed&&mode==Mode::Directory&&file_closes==2&&query_fd!=held_fd;
    const int result=real(directory);const int saved=errno;
    if(inject&&result==0){armed=false;consumed=fd;consumed_directory=directory;++hits;consumed_calls=1;
        closed_once=fcntl(fd,F_GETFD)==-1&&errno==EBADF;errno=EIO;return -1;}
    errno=saved;return result;
}
void before_commit(Mode selected) {
    reset();files=snapshot(true);directories=snapshot(false);CHECK(files.size==2&&directories.size>0);
    for(unsigned i=0;i<files.size;++i){const int flags=fcntl(files.values[i],F_GETFL);CHECK(flags>=0&&(flags&O_ACCMODE)==O_RDONLY&&!(flags&O_PATH));const int fd_flags=fcntl(files.values[i],F_GETFD);CHECK(fd_flags>=0&&(fd_flags&FD_CLOEXEC));}
    // fresh() replaces this exact inventory: its drain closes native_source
    // first, then HeldChild, then DIR. New scan/transient FDs are NOT selected.
    mode=selected;tracking=ordered=armed=true;
}
const char* operation(Mode selected){return selected==Mode::Query?"metadata_capture.source_close":selected==Mode::HeldChild?"metadata_capture.temporary_close":"metadata_capture.temporary_closedir";}
}
extern "C" int close(int fd){return close_watch::close_file(fd);}
extern "C" int closedir(DIR* directory){return close_watch::close_directory(directory);}
extern "C" int openat(int parent,const char* path,int flags,...) {
    mode_t permissions=0;if((flags&O_CREAT)||((flags&O_TMPFILE)==O_TMPFILE)){va_list args;va_start(args,flags);permissions=va_arg(args,mode_t);va_end(args);}
    return close_watch::opened_at(parent,path,flags,permissions);
}
extern "C" int openat64(int parent,const char* path,int flags,...) {
    mode_t permissions=0;if((flags&O_CREAT)||((flags&O_TMPFILE)==O_TMPFILE)){va_list args;va_start(args,flags);permissions=va_arg(args,mode_t);va_end(args);}
    return close_watch::opened_at(parent,path,flags,permissions);
}
namespace {
void qualify_owners(Fixture& f) {
    using namespace close_watch;reset();
    struct stat s{};CHECK(lstat((f.root/"left"/"a").c_str(),&s)==0);device=s.st_dev;file_inode=s.st_ino;
    CHECK(lstat((f.root/"left").c_str(),&s)==0);directory_inode=s.st_ino;
    NativeFileSystem filesystem;auto parent=std::shared_ptr<const DirectoryCursor>(get(filesystem.open_native_directory(f.native("left"))));
    CHECK(snapshot(true).size==0);tracking=acquiring=true;
    NativeSyncProofBudget budget;auto proof=get(observe_native_sync_file(parent,name("a"),f.request().metadata,NativeSyncProofLimits{},budget));
    if(!(!acquiring&&!invalid_acquisition&&files.size==2&&query_fd>=0&&held_fd>=0&&query_fd!=held_fd&&file_closes==0))
        acquisition_diagnostic("qualify_owners.before_check");
    CHECK(!acquiring&&!invalid_acquisition&&files.size==2&&query_fd>=0&&held_fd>=0&&query_fd!=held_fd&&file_closes==0);
    const auto current=snapshot(true);CHECK(current.size==2&&current.contains(query_fd)&&current.contains(held_fd));
    for(int fd:{query_fd,held_fd}){struct stat owner{};CHECK(fstat(fd,&owner)==0&&file(owner));}
    detail::finish_native_metadata_capture(proof.native_source.get(),proof.metadata);
    CHECK(file_closes==1&&fcntl(query_fd,F_GETFD)==-1&&errno==EBADF);
    CHECK(proof.held->inspect_basic().value()&&parent->inspect_basic().value());
    detail::finish_native_metadata_capture(proof.native_source.get(),proof.metadata);CHECK(file_closes==1);
    proof.held.reset();CHECK(file_closes==2&&fcntl(held_fd,F_GETFD)==-1&&errno==EBADF);
    CHECK(snapshot(true).size==0&&parent->inspect_basic().value());reset();
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
    Fixture f;f.seed();qualify_owners(f);f.conflict();const auto before=baseline_bytes(f);
    auto request=f.request();request.before_event=[mode](auto event){
        if(event==NativeSyncCoordinatorEvent::BeforeBaselineCommit)before_commit(mode);
        return true;
    };
    auto job=get(NativeSyncResolution::open(std::move(request)));auto review=get(job->assess(choice()));CHECK(get(job->approve(*review)));
    for(unsigned i=0;i<3000&&job->result().state!=NativeSyncCoordinatorState::NeedsReview&&job->result().state!=NativeSyncCoordinatorState::Complete;++i)job->advance();
    armed=false;tracking=false;
    CHECK(hits==1&&consumed_calls==1&&!retried&&closed_once);
    CHECK(query_fd>=0&&held_fd>=0&&query_fd!=held_fd);
    CHECK(job->result().state==NativeSyncCoordinatorState::NeedsReview&&job->result().completed_operations==4);
    CHECK(job->snapshot().generation==1&&baseline_bytes(f)==before&&publication_journals(f)==4);
    CHECK(job->result().failure&&job->result().failure->error.domain==ErrorDomain::Posix&&job->result().failure->error.code==EIO&&job->result().failure->error.operation==operation(mode));
    tracking=true;auto closed=job->finish_io();CHECK(!closed.value()&&closed.unavailable_detail()->error.code==EIO);
    const auto count=consumed_calls;closed=job->finish_io();CHECK(!closed.value()&&consumed_calls==count&&!retried);
    job.reset();CHECK(consumed_calls==count&&!retried);reset();
    job=get(NativeSyncResolution::open(f.request()));
    CHECK(job->snapshot().generation==2&&job->rows().size()==3&&job->protected_originals().size()==2);
    CHECK(job->result().completed_operations==0&&publication_journals(f)==4);CHECK(get(job->finish_io()));job.reset();
    job=get(NativeSyncResolution::open(f.request()));CHECK(job->snapshot().generation==2&&job->rows().size()==3);CHECK(get(job->finish_io()));
    std::cout<<"native POSIX pre-CAS consumed-close EIO mode="<<unsigned(mode)<<" generation unchanged + fresh recovery PASS\n";
}
void injected_recovery() {
    using namespace close_watch;
    Fixture f;f.seed();qualify_owners(f);f.conflict();auto request=f.request();
    request.before_event=[](auto event){return event!=NativeSyncCoordinatorEvent::BeforeBaselineCommit;};
    auto job=get(NativeSyncResolution::open(std::move(request)));auto review=get(job->assess(choice()));CHECK(get(job->approve(*review)));
    for(unsigned i=0;i<3000&&job->result().state!=NativeSyncCoordinatorState::NeedsReview;++i)job->advance();
    CHECK(job->snapshot().generation==1&&publication_journals(f)==4);CHECK(get(job->finish_io()));job.reset();
    const auto before=baseline_bytes(f);reset();mode=Mode::Query;tracking=acquiring=armed=true;
    auto failed=NativeSyncResolution::open(f.request());armed=false;tracking=false;
    CHECK(!failed.value()&&hits==1&&consumed_calls==1&&failed.unavailable_detail()->error.domain==ErrorDomain::Posix&&failed.unavailable_detail()->error.code==EIO&&failed.unavailable_detail()->error.operation==operation(Mode::Query));
    CHECK(!acquiring&&!invalid_acquisition&&files.size==2&&query_fd!=held_fd&&closed_once&&!retried);
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
