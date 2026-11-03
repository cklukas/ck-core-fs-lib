// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_sync_resolution.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <cstdlib>
#ifndef _WIN32
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#endif
using namespace ck::files;
namespace {
unsigned checks=0;
#define CHECK(x) do{++checks;if(!(x))throw std::runtime_error(std::string("line ")+std::to_string(__LINE__)+": "+#x);}while(false)
template<class T>T get(Observation<T> o){if(!o.value()){auto& e=*o.unavailable_detail();throw std::runtime_error(e.error.operation+" code="+std::to_string(e.error.code));}return std::move(o).take_value();}
#ifndef _WIN32
struct Fixture {
    std::filesystem::path root;
    explicit Fixture(){const char* env=std::getenv("TMPDIR");CHECK(env&&*env);std::string pattern=std::string(env)+"/resolution.XXXXXX";char* p=mkdtemp(pattern.data());CHECK(p);root=p;
        for(const char* name:{"store","left","right"})CHECK(mkdir((root/name).c_str(),0700)==0);
        int fd=open(root.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);CHECK(fd>=0);CHECK(fsync(fd)==0);CHECK(close(fd)==0);
    }
    ~Fixture(){std::filesystem::remove_all(root);}
    NativeAbsolutePath native(const char* side){return get(NativeAbsolutePath::from_posix((root/side).string()));}
    NativeSyncCoordinatorRequest request(){NativeSyncCoordinatorRequest r{native("store"),native("left"),native("right"),{},{},{},{},{},{},{}};
        r.metadata.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;r.metadata.ownership=MetadataOwnership::CurrentCaller;r.proof_limits.max_total_bytes=4*1024*1024;return r;}
    void write(const char* side,const char* name,const char* data){auto path=root/side/name;{std::ofstream out(path,std::ios::binary|std::ios::trunc);out<<data;CHECK(out.good());}CHECK(chmod(path.c_str(),0644)==0);timespec times[2]{{1700000000,0},{1700000000,0}};CHECK(utimensat(AT_FDCWD,path.c_str(),times,0)==0);}
    std::string read(const char* side,const char* name){std::ifstream in(root/side/name,std::ios::binary);return {std::istreambuf_iterator<char>(in),{}};}
    ino_t inode(const char* side,const char* name){struct stat s{};CHECK(lstat((root/side/name).c_str(),&s)==0);return s.st_ino;}
    void seed(){write("left","a","old");write("right","a","old");auto worker=get(NativeSyncCoordinator::open(request()));std::vector<NativeSyncDecision> choices;
        for(const auto& row:worker->rows()){choices.push_back({row.exact_key,NativeSyncChoice::Proposal});}
        CHECK(get(worker->approve(choices,true)));
        for(unsigned i=0;i<1000&&worker->result().state!=NativeSyncCoordinatorState::Complete&&worker->result().state!=NativeSyncCoordinatorState::NeedsReview;++i){worker->advance();}
        if(worker->result().failure){throw std::runtime_error(worker->result().failure->error.operation);}
        CHECK(worker->result().state==NativeSyncCoordinatorState::Complete);CHECK(get(worker->finish_io()));
    }
    void conflict(){write("left","a","LEFT-VERSION");write("right","a","RIGHT-VERSION");}
};
NativeName name(const char* text){auto n=NativeName::from_posix(text);CHECK(n);return *n;}
std::vector<NativeSyncNamedResolution> choice(){return {{0,name("a.left"),name("a.right")}};}
void run(NativeSyncResolution& job){for(unsigned i=0;i<3000;++i){auto state=job.advance();if(state==NativeSyncCoordinatorState::Complete)return;if(state==NativeSyncCoordinatorState::NeedsReview||state==NativeSyncCoordinatorState::Cancelled){if(job.result().failure)throw std::runtime_error(job.result().failure->error.operation);throw std::runtime_error("resolution incomplete");}}throw std::runtime_error("step budget");}
void positive(){Fixture f;f.seed();f.conflict();auto left=f.inode("left","a"),right=f.inode("right","a");auto request=f.request();request.storage_faults.max_write_bytes=1;auto job=get(NativeSyncResolution::open(std::move(request)));auto old=*job->snapshot().baseline;CHECK(job->snapshot().generation==1);auto review=get(job->assess(choice()));CHECK(review->operations().size()==6);CHECK(get(job->approve(*review)));run(*job);
    CHECK(job->result().completed_operations==4);CHECK(job->snapshot().generation==2);CHECK(job->result().pending_keys.size()==1);CHECK(job->protected_originals().size()==2);
    CHECK(f.inode("left","a")==left);CHECK(f.inode("right","a")==right);CHECK(f.read("left","a")=="LEFT-VERSION");CHECK(f.read("right","a")=="RIGHT-VERSION");
    for(const char* side:{"left","right"}){CHECK(f.read(side,"a.left")=="LEFT-VERSION");CHECK(f.read(side,"a.right")=="RIGHT-VERSION");}
    CHECK(job->snapshot().baseline->rows.size()==3);const auto key=native_sync_key(std::array{name("a")});
    auto row=std::find_if(job->snapshot().baseline->rows.begin(),job->snapshot().baseline->rows.end(),[&](auto& r){return r.relative_path==key;});CHECK(row!=job->snapshot().baseline->rows.end());CHECK(*row==old.rows.front());
    CHECK(get(job->finish_io()));job.reset();job=get(NativeSyncResolution::open(f.request()));CHECK(job->snapshot().generation==2);CHECK(job->protected_originals().size()==2);CHECK(get(job->finish_io()));
}
void collision_and_stale(){Fixture f;f.seed();f.conflict();auto job=get(NativeSyncResolution::open(f.request()));
    std::vector<NativeSyncNamedResolution> duplicate{{0,name("same"),name("same")}};CHECK(!job->assess(duplicate).value());
    std::vector<NativeSyncNamedResolution> original{{0,name("a"),name("other")}};CHECK(!job->assess(original).value());
    auto first=get(job->assess(choice()));auto second=get(job->assess(choice()));CHECK(!job->approve(*first).value());CHECK(get(job->approve(*second)));CHECK(!job->approve(*second).value());CHECK(job->snapshot().generation==1);CHECK(get(job->finish_io()));
    // No ledger/effect before first advance: root locks can be reacquired.
    job.reset();job=get(NativeSyncResolution::open(f.request()));auto changed=get(job->assess(choice()));f.write("right","a.left","race");CHECK(!job->approve(*changed).value());CHECK(job->snapshot().generation==1);
}
void bounds_and_foreign(){Fixture f;f.seed();f.conflict();NativeSyncResolutionLimits limits;limits.max_transfer_bytes=1;
    auto job=get(NativeSyncResolution::open(f.request(),limits));CHECK(!job->assess(choice()).value());CHECK(get(job->finish_io()));job.reset();
    job=get(NativeSyncResolution::open(f.request()));auto review=get(job->assess(choice()));CHECK(get(job->finish_io()));job.reset();job=get(NativeSyncResolution::open(f.request()));CHECK(!job->approve(*review).value());CHECK(job->snapshot().generation==1);
}
void cancellation(){Fixture f;f.seed();f.conflict();auto job=get(NativeSyncResolution::open(f.request()));auto review=get(job->assess(choice()));CHECK(get(job->approve(*review)));
    for(unsigned i=0;i<2000&&job->result().completed_operations<1;++i){job->advance();}
    CHECK(job->result().completed_operations==1);std::stop_source stop;stop.request_stop();job->advance(stop.get_token());CHECK(job->snapshot().generation==1);CHECK(f.read("left","a")=="LEFT-VERSION");CHECK(f.read("right","a")=="RIGHT-VERSION");CHECK(get(job->finish_io()));job.reset();
    auto reopened=NativeSyncResolution::open(f.request());CHECK(!reopened.value());CHECK(reopened.unavailable_detail()->error.operation=="resolution.unresolved_intent");
}
void crash_recovery(){Fixture f;f.seed();f.conflict();auto pid=fork();CHECK(pid>=0);if(pid==0){try{auto request=f.request();request.before_event=[](NativeSyncCoordinatorEvent e){if(e==NativeSyncCoordinatorEvent::BeforeBaselineCommit)_Exit(75);return true;};auto job=get(NativeSyncResolution::open(std::move(request)));auto receipt=get(job->assess(choice()));get(job->approve(*receipt));run(*job);_Exit(3);}catch(...){_Exit(4);}}
    int status=0;CHECK(waitpid(pid,&status,0)==pid);CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==75);auto job=get(NativeSyncResolution::open(f.request()));CHECK(job->snapshot().generation==2);CHECK(job->protected_originals().size()==2);CHECK(job->snapshot().baseline->rows.size()==3);CHECK(get(job->finish_io()));job.reset();job=get(NativeSyncResolution::open(f.request()));CHECK(job->snapshot().generation==2);
}
void occupied_after_approval(){Fixture f;f.seed();f.conflict();auto job=get(NativeSyncResolution::open(f.request()));auto receipt=get(job->assess(choice()));CHECK(get(job->approve(*receipt)));job->advance();job->advance();f.write("left","a.left","INTRUDER");for(unsigned i=0;i<2000&&job->result().state!=NativeSyncCoordinatorState::NeedsReview;++i){job->advance();}
    CHECK(job->result().state==NativeSyncCoordinatorState::NeedsReview);CHECK(job->snapshot().generation==1);CHECK(f.read("left","a.left")=="INTRUDER");CHECK(f.read("left","a")=="LEFT-VERSION");CHECK(f.read("right","a")=="RIGHT-VERSION");CHECK(get(job->finish_io()));
}
void skipped_rows_and_failure(){Fixture f;f.write("left","other","same");f.write("right","other","same");f.seed();f.conflict();auto request=f.request();request.before_event=[](NativeSyncCoordinatorEvent event){return event!=NativeSyncCoordinatorEvent::BeforeLedgerClose;};auto job=get(NativeSyncResolution::open(std::move(request)));auto old=*job->snapshot().baseline;
    auto choices=choice();for(std::size_t i=0;i<job->rows().size();++i)if(job->components(i).front()==name("a"))choices.front().row=i;
    auto receipt=get(job->assess(choices));CHECK(get(job->approve(*receipt)));for(unsigned i=0;i<3000&&job->result().state!=NativeSyncCoordinatorState::NeedsReview;++i){job->advance();}
    CHECK(job->result().state==NativeSyncCoordinatorState::NeedsReview);CHECK(job->snapshot().generation==1);CHECK(*job->snapshot().baseline==old);CHECK(get(job->finish_io()));job.reset();job=get(NativeSyncResolution::open(f.request()));CHECK(job->snapshot().generation==2);CHECK(job->snapshot().baseline->rows.size()==4);
    for(const auto& row:old.rows){auto found=std::find_if(job->snapshot().baseline->rows.begin(),job->snapshot().baseline->rows.end(),[&](const auto& r){return r.relative_path==row.relative_path;});CHECK(found!=job->snapshot().baseline->rows.end()&&*found==row);}
}
void baseline_flush_failure(){Fixture f;f.seed();f.conflict();auto request=f.request();request.storage_faults.before=[](SyncSessionIo io){return io!=SyncSessionIo::FileFlush;};auto job=get(NativeSyncResolution::open(std::move(request)));auto before=*job->snapshot().baseline;auto receipt=get(job->assess(choice()));CHECK(get(job->approve(*receipt)));for(unsigned i=0;i<3000&&job->result().state!=NativeSyncCoordinatorState::NeedsReview;++i){job->advance();}
    CHECK(job->result().state==NativeSyncCoordinatorState::NeedsReview);CHECK(job->snapshot().generation==1);CHECK(*job->snapshot().baseline==before);CHECK(get(job->finish_io()));job.reset();job=get(NativeSyncResolution::open(f.request()));CHECK(job->snapshot().generation==2);CHECK(job->snapshot().baseline->rows.size()==3);
}
void native_close_failure(){Fixture f;f.seed();f.conflict();auto request=f.request();request.storage_faults.before=[](SyncSessionIo io){return io!=SyncSessionIo::NativeHandleClose;};auto job=get(NativeSyncResolution::open(std::move(request)));auto receipt=get(job->assess(choice()));CHECK(get(job->approve(*receipt)));CHECK(!job->finish_io().value());CHECK(!job->finish_io().value());CHECK(!job->assess(choice()).value());CHECK(job->snapshot().generation==1);job.reset();auto fresh=get(NativeSyncResolution::open(f.request()));CHECK(fresh->snapshot().generation==1);
}
void stale_recovery(){Fixture f;f.seed();f.conflict();auto request=f.request();request.before_event=[](NativeSyncCoordinatorEvent e){return e!=NativeSyncCoordinatorEvent::BeforeBaselineCommit;};auto job=get(NativeSyncResolution::open(std::move(request)));auto receipt=get(job->assess(choice()));CHECK(get(job->approve(*receipt)));for(unsigned i=0;i<3000&&job->result().state!=NativeSyncCoordinatorState::NeedsReview;++i){job->advance();}
    CHECK(job->snapshot().generation==1);CHECK(job->result().state==NativeSyncCoordinatorState::NeedsReview);CHECK(get(job->finish_io()));job.reset();f.write("right","a.left","CHANGED");auto reopen=NativeSyncResolution::open(f.request());CHECK(!reopen.value());
}
#endif
}
int main(){try{
#ifndef _WIN32
positive();collision_and_stale();bounds_and_foreign();cancellation();crash_recovery();stale_recovery();occupied_after_approval();skipped_rows_and_failure();baseline_flush_failure();native_close_failure();
#else
throw std::runtime_error("Windows runtime qualification required; no silent skip");
#endif
std::cout<<"native resolution: "<<checks<<" checks PASS\n";return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
