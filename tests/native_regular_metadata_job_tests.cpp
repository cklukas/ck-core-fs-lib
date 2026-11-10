// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Reuse the actual native capture fixture and read/close instrumentation.
#define main native_regular_capture_fixture_main
#include "metadata_capture_job_tests.cpp"
#undef main
#include "native_regular_metadata_job.hpp"
#include "staging_file.hpp"
#include "mac_capability_fixture.hpp"
#ifdef _WIN32
#include <malloc.h>
#endif
#include "platform/prepared_journal_root_bridge.hpp"

namespace {
thread_local bool persistent_final_diagnostic_failure=false;
thread_local unsigned persistent_diagnostic_attempts=0;
NativeName regular_name(const char* text) {
#ifdef _WIN32
    return *NativeName::from_windows(std::u16string(text,text+std::strlen(text)));
#else
    return *NativeName::from_posix(text);
#endif
}
class RegularTestLatch final:public MetadataCaptureFailureLatch {
public:
    explicit RegularTestLatch(PreparedJournalRoot::Pointer root):root_(std::move(root)){}
    void record_first(MetadataCaptureCleanupError e)const noexcept override {
        if(root_)detail::record_prepared_journal_consumer_failure(*root_,e.state,e.domain,e.code,e.operation);
    }
    void release()noexcept{root_.reset();}
private:PreparedJournalRoot::Pointer root_;
};
struct RegularState {
    Fixture& fixture;PreparedJournalRoot::Pointer root;
    explicit RegularState(Fixture& f):fixture(f) {
        PreparedJournalRootRequest request;request.parent=f.directory;
        request.disposition=JournalRootDisposition::ProvisionChild;request.child=regular_name(".regular-state");
        JournalRootPreparationProgress progress;root=take(prepare_native_journal_root(std::move(request),progress));
    }
    ~RegularState(){
        frame=false;close_watch=false;close_armed=false;
        if(root){try{(void)root->finish_io();}catch(...){}root.reset();}
#ifdef _WIN32
        if(!RemoveDirectoryW((fixture.root+L"\\.regular-state").c_str()))std::fputs("regular state cleanup failed\n",stderr);
#else
        if(rmdir((fixture.root+"/.regular-state").c_str()))std::fputs("regular state cleanup failed\n",stderr);
#endif
    }
};
struct RegularStage {
    Fixture& fixture;CreatedStagingFile file;ObjectIdentity identity;
    explicit RegularStage(Fixture& f):fixture(f),file(take(f.directory->create_staging_file(regular_name(".regular-stage")))),
        identity(*take(file.entry->inspect_basic()).identity.value()) {
        // The main-entry macro also renames the included fixture's data field.
        const auto& data=f.native_regular_capture_fixture_main;
        for(std::size_t at=0;at<data.size();) {
            const auto count=std::min<std::size_t>(4096,data.size()-at);
            const auto copied=take(file.entry->write_content(at,std::span(data).subspan(at,count)));
            check(copied>0&&copied<=count,"prepare private main data");at+=copied;
        }
    }
    ~RegularStage(){
        frame=false;close_watch=false;close_armed=false;
        try{(void)file.entry->finish_content_writes();}catch(...){}file.entry.reset();
        if(file.name){try{check(take(fixture.directory->retire_child(*file.name,identity)),"remove owned native staging");}
            catch(const std::exception& e){std::fprintf(stderr,"regular staging cleanup: %s\n",e.what());}}
    }
};
struct RegularSource {
    std::shared_ptr<const OpenedEntry> entry;
    std::shared_ptr<const NativeMetadataProof> proof;
    std::shared_ptr<MetadataCaptureBudget> budget;
    std::shared_ptr<RegularTestLatch> latch;
    std::unique_ptr<MetadataCaptureJob> capture,recheck;
    MetadataCaptureLimits bounds;
    bool finished=false;unsigned rechecks=0;
    RegularSource(Fixture& f,PreparedJournalRoot::Pointer root,MetadataOwnership ownership):entry(f.source()),
        latch(std::make_shared<RegularTestLatch>(std::move(root))),bounds(limits()) {
        bounds.read={4096};budget=std::make_shared<MetadataCaptureBudget>(bounds);
        auto p=policy();p.ownership=ownership;capture=take(MetadataCaptureJob::begin(entry,p,bounds,budget,latch));
        for(unsigned i=0;i<100000;++i){advance_reads=0;frame_limit=4096;frame=true;
            auto step=capture->advance();frame=false;take(std::move(step));
            check(advance_reads<=1,"initial native proof hid multiple reads");
            if(capture->progress().phase==MetadataCapturePhase::Complete){proof=take(capture->result());break;}}
        check(proof!=nullptr,"initial source proof did not complete");
    }
    ~RegularSource(){try{(void)finish();}catch(...){}}
    Observation<OperationMetadataStep> revalidate(bool begin,std::stop_token stop) {
        if(begin){check(!recheck,"overlapping native source verification");
            auto made=MetadataCaptureJob::verify(proof,bounds,budget,latch);
            if(!made.value())return Observation<OperationMetadataStep>::unavailable(made.state(),made.unavailable_detail()->error);
            recheck=std::move(made).take_value();}
        auto next=recheck->advance(stop);
        if(!next.value())return Observation<OperationMetadataStep>::unavailable(next.state(),next.unavailable_detail()->error);
        if(next.value()->phase!=MetadataCapturePhase::Complete)return Observation<OperationMetadataStep>::available(OperationMetadataStep::Pending);
        auto closed=recheck->finish_io();if(!closed.value())return Observation<OperationMetadataStep>::unavailable(closed.state(),closed.unavailable_detail()->error);
        check(*closed.value(),"native source verification close returned false");recheck.reset();++rechecks;
        check(!proof->io_finished(),"source verification consumed original proof");
        return Observation<OperationMetadataStep>::available(OperationMetadataStep::Complete);
    }
    Observation<bool> finish() {
        if(!finished){finished=true;detail::MetadataCaptureCleanupScope scope(latch.get());
            if(recheck){(void)recheck->finish_io();recheck.reset();}
            if(capture){(void)capture->finish_io();capture.reset();}
            if(proof)(void)proof->finish_io();entry.reset();latch->release();}
        if(proof){if(auto error=proof->cleanup_error()){const auto& e=*error;return Observation<bool>::unavailable(e.state,{e.domain,e.code,e.operation});}}
        return Observation<bool>::available(true);
    }
};
OperationMetadataStep regular_step(NativeRegularMetadataJob& job,OperationMetadataState state,std::stop_token token={}) {
    advance_reads=0;frame_limit=4096;frame=true;auto next=job.advance(state,token);frame=false;
    check(advance_reads<=1,"regular metadata step issued multiple native content reads");return take(std::move(next));
}
void regular_case(MetadataOwnership ownership,unsigned outcome) {
    Fixture fixture;RegularState state(fixture);auto source=std::make_shared<RegularSource>(fixture,state.root,ownership);
    RegularStage target(fixture);
    NativeRegularMetadataRequest request;request.target=target.file.entry.get();request.source=source->proof;
    request.journal_root=state.root;request.read_limits={4096};request.verify_membership=[root=state.root](std::stop_token){return root->revalidate();};
    request.revalidate_source=[source](bool begin,std::stop_token stop){return source->revalidate(begin,stop);};
    request.finish_source=[source,outcome]{
        auto closed=source->finish();
        if(outcome==3){check(source->budget->retained_handle_reservations()==0,"persistent injection before source closes");
            persistent_final_diagnostic_failure=true;}
        return closed;
    };auto job=take(NativeRegularMetadataJob::create(std::move(request)));
    if(outcome==1){std::stop_source stop;stop.request_stop();
        check(regular_step(*job,OperationMetadataState::ApplyingTraversal,stop.get_token())==OperationMetadataStep::Cancelled,"clean cancellation lost");
        check(job->progress().cancelled&&job->progress().worker_drained&&!job->progress().metadata_effects,"cancel did metadata work or retained consumers");
    }else {
        for(const auto phase:{OperationMetadataState::ApplyingTraversal,OperationMetadataState::ApplyingSecurity,
            OperationMetadataState::ApplyingTimes,OperationMetadataState::Flushing}) {
            bool done=false;for(unsigned i=0;i<100000;++i)if(regular_step(*job,phase)==OperationMetadataStep::Complete){done=true;break;}
            check(done,"regular metadata phase did not complete");
        }
        check(job->progress().complete&&source->rechecks==2,"missing independent source revalidation");
        const auto reads=native_reads.load();frame_limit=4096;advance_reads=0;frame=true;
        check(take(job->verify(*target.file.entry)),"native regular guard failed");frame=false;
        check(native_reads==reads,"prepublication guard hid a bulk content read");
        check(take(target.file.entry->finish_content_writes()),"base staging writer close failed");
        if(outcome>=2) {
#ifdef _WIN32
            close_target.VolumeSerialNumber=0;std::memcpy(close_target.FileId.Identifier,target.identity.object.bytes.data(),16);
            std::memcpy(&close_target.VolumeSerialNumber,target.identity.volume.bytes.data(),sizeof(close_target.VolumeSerialNumber));
#else
            struct stat native{};check(!stat((fixture.root+"/a").c_str(),&native),"select actual source close");
            close_device=native.st_dev;close_inode=native.st_ino;
#endif
            close_hits=0;selected_closes=0;close_watch=true;close_armed=true;
        }
    }
#ifdef _WIN32
    if(outcome==3){
        bool threw=false;try{(void)job->finish_io();}catch(const std::bad_alloc&){threw=true;}
        persistent_final_diagnostic_failure=false;close_watch=false;close_armed=false;
        check(threw&&persistent_diagnostic_attempts>0&&close_hits==1,"persistent diagnostic allocation was not exercised");
        check(job->progress().worker_drained&&!job->progress().complete,"persistent diagnostic OOM lost POD drain state");
        check(source->budget->retained_handle_reservations()==0,"persistent diagnostic OOM leaked native owners");
        const auto native_closed=selected_closes.load();const auto reads=native_reads.load();
        persistent_final_diagnostic_failure=true;threw=false;
        try{(void)job->finish_io();}catch(const std::bad_alloc&){threw=true;}
        persistent_final_diagnostic_failure=false;
        check(threw&&selected_closes==native_closed&&native_reads==reads,"persistent cached failure performed native I/O");
        const auto root_closed=state.root->finish_io();check(!root_closed.value()&&root_closed.unavailable_detail()->error.code==ERROR_READ_FAULT,
            "persistent diagnostic OOM lost exact consumed native close error");
        std::cout<<"native regular worker persistent all-allocation failure AFTER native closes; no MSVC proxy skipping PASS\n";return;
    }
#endif
    const auto closed=job->finish_io();close_watch=false;close_armed=false;
    if(outcome==2){check(!closed.value()&&close_hits==1,"consumed close error was lost");
        const auto reads=native_reads.load();check(!job->advance(OperationMetadataState::Flushing).value()&&native_reads==reads,"late failure became cached success or did I/O");
        check(!job->progress().complete&&!state.root->finish_io().value(),"late close error did not poison completion/Root");
    }else {check(closed.value()&&*closed.value(),"regular worker finalization failed");
        const auto reads=native_reads.load();check(take(job->finish_io())&&native_reads==reads,"cached finish did native reads");
        check(take(state.root->finish_io()),"regular worker retained Root consumers");}
    check(source->budget->retained_handle_reservations()==0,"source native reservations leaked");
    std::cout<<"native regular metadata ownership="<<unsigned(ownership)<<" outcome="<<outcome<<" PASS\n";
}
#if defined(__APPLE__)
void mac_staging_admission(MetadataOwnership ownership){
 Fixture fixture;RegularState state(fixture);
 auto source=std::make_shared<RegularSource>(fixture,state.root,ownership);
 const auto before=mac_capability_fixture::observe(fixture.root);
 const auto reads=native_reads.load();
 for(unsigned attempt=0;attempt<3;++attempt){
  const auto refused=fixture.directory->create_staging_file(regular_name(".regular-stage"));
  check(!refused.value()&&refused.state()==ObservationState::Unsupported&&refused.unavailable_detail()->error.domain==ErrorDomain::Adapter&&
    refused.unavailable_detail()->error.code==4&&refused.unavailable_detail()->error.operation=="create_staging_file.fd_publication_unqualified",
    "Mac regular writer needs a qualified staging provider");
 }
 check(native_reads==reads,"staging refusal read source content");
 check(mac_capability_fixture::observe(fixture.root)==before,"staging refusal modified source/state namespace");
 check(take(source->finish()),"fallible source proof drain");
 check(source->proof->io_finished()&&source->budget->retained_handle_reservations()==0,"refused staging leaked source proof readers");
 check(take(state.root->finish_io()),"refused staging lost Root close result");
 std::printf("Mac regular metadata prerequisite REFUSED ownership=%u; source proof/drain qualified, replay not entered\n",unsigned(ownership));
}
#endif

}
void* operator new(std::size_t size){
    if(persistent_final_diagnostic_failure){++persistent_diagnostic_attempts;throw std::bad_alloc();}
    if(auto* value=std::malloc(size?size:1))return value;throw std::bad_alloc();
}
void* operator new[](std::size_t size){return ::operator new(size);}
void operator delete(void* value)noexcept{std::free(value);}
void operator delete[](void* value)noexcept{std::free(value);}
void operator delete(void* value,std::size_t)noexcept{std::free(value);}
void operator delete[](void* value,std::size_t)noexcept{std::free(value);}
#ifdef _WIN32
void* operator new(std::size_t size,std::align_val_t alignment){
    if(persistent_final_diagnostic_failure){++persistent_diagnostic_attempts;throw std::bad_alloc();}
    if(auto* value=_aligned_malloc(size?size:1,static_cast<std::size_t>(alignment)))return value;throw std::bad_alloc();
}
void* operator new[](std::size_t size,std::align_val_t alignment){return ::operator new(size,alignment);}
void operator delete(void* value,std::align_val_t)noexcept{_aligned_free(value);}
void operator delete[](void* value,std::align_val_t)noexcept{_aligned_free(value);}
void operator delete(void* value,std::size_t,std::align_val_t)noexcept{_aligned_free(value);}
void operator delete[](void* value,std::size_t,std::align_val_t)noexcept{_aligned_free(value);}
#endif
int main(){try{
#ifdef __APPLE__
    mac_staging_admission(MetadataOwnership::Original);mac_staging_admission(MetadataOwnership::CurrentCaller);
#else
    regular_case(MetadataOwnership::Original,0);regular_case(MetadataOwnership::CurrentCaller,0);
    regular_case(MetadataOwnership::Original,1);regular_case(MetadataOwnership::Original,2);
#ifdef _WIN32
    regular_case(MetadataOwnership::Original,3);
#endif
#endif
    return 0;
}catch(const std::exception& e){persistent_final_diagnostic_failure=false;frame=false;close_watch=false;close_armed=false;std::fprintf(stderr,"native_regular_metadata_job: %s\n",e.what());return 1;}}
