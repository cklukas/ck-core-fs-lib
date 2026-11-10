// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#define main review_capture_fixture_main
#include "metadata_capture_job_tests.cpp"
#undef main
#include "native_regular_metadata_job.hpp"
#include "regular_metadata_preservation.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <string_view>
namespace {
NativeName review_name(const char* text) {
#ifdef _WIN32
 return *NativeName::from_windows(std::u16string(text,text+std::strlen(text)));
#else
 return *NativeName::from_posix(text);
#endif
}
struct ReviewLatch final:MetadataCaptureFailureLatch {
 PreparedJournalRoot::Pointer root;mutable std::optional<MetadataCaptureCleanupError> first;
 explicit ReviewLatch(PreparedJournalRoot::Pointer r):root(std::move(r)){}
 void record_first(MetadataCaptureCleanupError e)const noexcept override {
  if(!first)first=e;
  if(root)detail::record_prepared_journal_consumer_failure(*root,e.state,e.domain,e.code,e.operation);
 }
};
struct ReviewRoot {
 Fixture& fixture;PreparedJournalRoot::Pointer root;
 explicit ReviewRoot(Fixture& f):fixture(f) {
  PreparedJournalRootRequest r;r.parent=f.directory;r.child=review_name(".review-state");r.disposition=JournalRootDisposition::ProvisionChild;
  JournalRootPreparationProgress progress;root=take(prepare_native_journal_root(std::move(r),progress));
 }
 ~ReviewRoot(){close_watch=false;close_armed=false;frame=false;if(root){try{(void)root->finish_io();}catch(...){}root.reset();}
#ifdef _WIN32
  (void)RemoveDirectoryW((fixture.root+L"\\.review-state").c_str());
#else
  (void)rmdir((fixture.root+"/.review-state").c_str());
#endif
 }
};
struct ReviewSource {
 std::shared_ptr<const NativeMetadataProof> proof;std::unique_ptr<MetadataCaptureJob> capture;
 std::shared_ptr<ReviewLatch> latch;bool finished=false;unsigned finish_calls=0;
 ReviewSource(const HeldChild::Pointer& source,PreparedJournalRoot::Pointer root):latch(std::make_shared<ReviewLatch>(std::move(root))) {
  capture=take(MetadataCaptureJob::begin_held(source,policy(),limits(),{},latch));proof=drain(*capture);
 }
 Observation<bool> finish() {
  ++finish_calls;
  if(!finished){finished=true;detail::MetadataCaptureCleanupScope scope(latch.get());
   if(capture){auto r=capture->finish_io();if(!r.value()&&!latch->first){const auto&e=*r.unavailable_detail();latch->record_first({e.state,e.error.domain,e.error.code,"review.source.finish"});}capture.reset();}
   if(proof)(void)proof->finish_io();
  }
  if(latch->first){const auto&e=*latch->first;return Observation<bool>::unavailable(e.state,{e.domain,e.code,e.operation});}
  return Observation<bool>::available(true);
 }
};
HeldChild::Pointer held(Fixture& f){return take(HeldChild::observe_with_access(f.directory,review_name("a"),EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity));}
void select_source_close(Fixture& f) {
#ifdef _WIN32
 HANDLE h=CreateFileW((f.root+L"\\a").c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
 check(h!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(h,FileIdInfo,&close_target,sizeof(close_target)),"review close identity");check(CloseHandle(h)!=0,"review identity close");
#else
 struct stat s{};check(!stat((f.root+"/a").c_str(),&s),"review close identity");close_device=s.st_dev;close_inode=s.st_ino;
#endif
}
// This sentinel is deliberately NOT a native target. The tested cancellation
// and Root-failure gates must terminate before target preflight/any effects.
struct UntouchedTarget final:OpenedEntry {
 mutable unsigned touches=0;
 Observation<BasicMetadata> inspect_basic()const override{++touches;throw std::runtime_error("target reached before source gate");}
};
NativeRegularMetadataRequest request(ReviewRoot& root,const std::shared_ptr<ReviewSource>& source,OpenedEntry* target=nullptr) {
 NativeRegularMetadataRequest r;r.source=source->proof;r.journal_root=root.root;r.target=target;
 r.verify_membership=[](std::stop_token){return Observation<bool>::available(true);};
 r.revalidate_source=[](bool,std::stop_token){return Observation<OperationMetadataStep>::available(OperationMetadataStep::Pending);};
 r.finish_source=[source]{return source->finish();};return r;
}
void clean_callback_cancel(bool patched,bool close_fault) {
 Fixture f;ReviewRoot root(f);auto input=held(f);auto source=std::make_shared<ReviewSource>(input,root.root);UntouchedTarget target;
 auto r=request(root,source,&target);std::stop_source stop;
 r.revalidate_source=[&](bool,std::stop_token){stop.request_stop();return Observation<OperationMetadataStep>::available(OperationMetadataStep::Cancelled);};
 auto job=take(NativeRegularMetadataJob::create(std::move(r)));
 if(close_fault){select_source_close(f);close_hits=0;close_watch=true;close_armed=true;}
 frame=true;frame_limit=1024;advance_reads=0;auto result=job->advance(OperationMetadataState::ApplyingTraversal,stop.get_token());frame=false;
 close_watch=false;close_armed=false;check(target.touches==0&&!job->progress().metadata_effects&&job->progress().worker_drained,"cancellation gate touched target or retained worker");
 if(close_fault){check(!result.value()&&close_hits==1&&!job->progress().cancelled,"native close failure became clean cancellation");
  check(result.unavailable_detail()->error.domain!=ErrorDomain::Adapter,"actual native close domain lost");}
 else if(patched)check(result.value()&&*result.value()==OperationMetadataStep::Cancelled&&job->progress().cancelled,"explicit clean source cancellation rejected");
 else check(!result.value()&&!job->progress().cancelled,"baseline cancellation defect not reproduced");
 std::cout<<"clean source callback cancellation close_fault="<<close_fault<<" patched="<<patched<<" PASS\n";
}
void unrequested_callback_cancel() {
 Fixture f;ReviewRoot root(f);auto input=held(f);auto source=std::make_shared<ReviewSource>(input,root.root);UntouchedTarget target;
 auto r=request(root,source,&target);
 r.revalidate_source=[](bool,std::stop_token){return Observation<OperationMetadataStep>::available(OperationMetadataStep::Cancelled);};
 auto job=take(NativeRegularMetadataJob::create(std::move(r)));auto result=job->advance(OperationMetadataState::ApplyingTraversal);
 check(!result.value()&&!job->progress().cancelled&&job->progress().worker_drained&&target.touches==0,"unrequested source cancellation accepted");
 std::cout<<"unrequested cancellation remains an error PASS\n";
}
void root_after_membership(bool patched) {
 Fixture f;ReviewRoot root(f);auto input=held(f);auto source=std::make_shared<ReviewSource>(input,root.root);UntouchedTarget target;
 auto r=request(root,source,&target);unsigned revalidate_calls=0;select_source_close(f);close_hits=0;
 r.verify_membership=[&](std::stop_token){auto temporary=held(f);close_watch=true;close_armed=true;return Observation<bool>::available(true);};
 r.revalidate_source=[&](bool,std::stop_token){++revalidate_calls;return Observation<OperationMetadataStep>::available(OperationMetadataStep::Pending);};
 auto job=take(NativeRegularMetadataJob::create(std::move(r)));auto result=job->advance(OperationMetadataState::ApplyingTraversal);
 close_watch=false;close_armed=false;check(!result.value()&&close_hits==1&&job->progress().worker_drained&&target.touches==0,"membership consumed-close fixture failed");
 check(revalidate_calls==(patched?0u:1u),"membership close latch gate observation differs");
 detail::PreparedJournalConsumerFailure error;check(detail::read_prepared_journal_consumer_failure(*root.root,error)&&!error.pending,"membership close error absent from Root");
 std::cout<<"native callback-local consumed close before next callback calls="<<revalidate_calls<<" patched="<<patched<<" PASS\n";
}
void factory_source_drain(bool patched,bool close_fault) {
 Fixture f;ReviewRoot root(f);auto input=held(f);std::weak_ptr<const HeldChild> weak=input;
 auto source=std::make_shared<ReviewSource>(input,root.root);auto r=request(root,source);select_source_close(f);close_hits=0;
 r.finish_source=[source,close_fault]{auto done=source->finish();if(close_fault){close_watch=true;close_armed=true;}return done;};
 auto preservation=take(RegularMetadataPreservation::create_progressive(std::move(input),std::move(r)));r.finish_source={};r.verify_membership={};r.revalidate_source={};r.source.reset();r.journal_root.reset();
 auto done=preservation->finish_progressive_io();close_watch=false;close_armed=false;
 check(weak.expired()==patched,"original HeldChild retained past progressive finish");
 if(close_fault&&patched){check(!done.value()&&close_hits==1,"original held-source consumed close error lost");
  detail::PreparedJournalConsumerFailure error;check(detail::read_prepared_journal_consumer_failure(*root.root,error)&&!error.pending,"late source close not latched before return");
  check(!preservation->finish_progressive_io().value(),"cached close failure lost");}
 else check(done.value()&&*done.value()&&close_hits==0,"unexpected source drain result");
 std::cout<<"factory original native source drop close_fault="<<close_fault<<" expired="<<weak.expired()<<" patched="<<patched<<" PASS\n";
 preservation.reset();
}
}
int main(int argc,char** argv){
#ifdef _WIN32
    NativeCaptureFixtureScope native_capture_scope(capture_read_after,capture_close_before,capture_close_after);
#endif
    try {const bool patched=argc>1&&std::string_view(argv[1])=="--patched";
 clean_callback_cancel(patched,false);clean_callback_cancel(patched,true);unrequested_callback_cancel();root_after_membership(patched);
 factory_source_drain(patched,false);factory_source_drain(patched,true);std::cout<<"regular_metadata_review_tests passed\n";return 0;
}catch(const std::exception&e){frame=false;close_watch=false;close_armed=false;std::cerr<<e.what()<<'\n';return 1;}}
