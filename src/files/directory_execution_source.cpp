// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "directory_execution_source.hpp"
#include "metadata_semantic_digest.hpp"
#include "native_sync_observation.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "sha256.hpp"
#include <algorithm>
namespace ck::files {
namespace {
Observation<bool> refuse(const char* operation,ObservationState state=ObservationState::Changed,
    AdapterError code=AdapterError::PlanDecisionStale) {
    return Observation<bool>::unavailable(state,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),operation});
}
template<class T> Observation<bool> propagate(const Observation<T>& value) {
    const auto& error=*value.unavailable_detail();return Observation<bool>::unavailable(error.state,error.error);
}
std::array<std::byte,32> schema() {
    Sha256 hash;constexpr char domain[]="ck-core-fs-lib/native-preserved-metadata";
    hash.update(std::as_bytes(std::span(domain,sizeof(domain)-1)));std::array<std::byte,8> version{};
    for(unsigned i=0;i<version.size();++i)version[i]=std::byte((metadata_semantic_digest_version>>(8*i))&255);
    hash.update(version);return hash.digest();
}
std::array<std::byte,32> binding(const MetadataReplayPolicy& policy) {
    Sha256 hash;constexpr char domain[]="ck-core-fs-lib/reviewed-tree-preservation";
    hash.update(std::as_bytes(std::span(domain,sizeof(domain)-1)));return native_sync_policy_binding(hash.digest(),policy);
}
bool interrupted(const UnavailableObservation& error,std::stop_token stop)noexcept {
    return stop.stop_requested()&&error.error.domain==ErrorDomain::Adapter&&
        error.error.code==static_cast<std::int64_t>(AdapterError::InterruptedRead);
}
template<class T>bool equal(const Observation<T>& a,const Observation<T>& b) {
    return a.value()&&b.value()?*a.value()==*b.value():!a.value()&&!b.value()&&a.state()==b.state()&&a.unavailable_detail()->error==b.unavailable_detail()->error;
}
bool identity(const Observation<ObjectIdentity>& a,const Observation<ObjectIdentity>& b) {
    return a.value()&&b.value()&&compare_identity(*a.value(),*b.value())==IdentityComparison::Same;
}
}
class DirectoryExecutionSourceJob::Latch final:public MetadataCaptureFailureLatch {
public:
    explicit Latch(PreparedJournalRoot::Pointer root):root_(std::move(root)){}
    void record_first(MetadataCaptureCleanupError error)const noexcept override {
        if(!first)first=error;
        if(root_)detail::record_prepared_journal_consumer_failure(*root_,error.state,error.domain,error.code,error.operation);
    }
    void release()noexcept{root_.reset();}
    mutable std::optional<MetadataCaptureCleanupError> first;
private:PreparedJournalRoot::Pointer root_;
};
DirectoryExecutionSourceJob::DirectoryExecutionSourceJob(DirectoryExecutionSourceRequest request)
    :request_(std::move(request)),latch_(std::make_shared<Latch>(request_.journal_root)){}
Observation<DirectoryExecutionSourceJob::Pointer> DirectoryExecutionSourceJob::create(DirectoryExecutionSourceRequest request) {
    using R=Observation<Pointer>;
    auto invalid=[](const char* operation,ObservationState state,AdapterError code){return R::unavailable(state,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(code),operation});};
    if(!request.source||!request.journal_root||!request.verify_review||!request.policy.valid()||!request.limits.valid())
        return invalid("directory_source.request",ObservationState::Failed,AdapterError::InvalidIdentifier);
    if(request.policy.ownership!=MetadataOwnership::Original)
        return invalid("directory_source.current_caller_unqualified",ObservationState::Unsupported,AdapterError::ProviderReviewRequired);
    const auto& reviewed=request.reviewed;
    if(reviewed.state!=ComparisonDigestState::CompleteStable||reviewed.algorithm!=ComparisonDigestAlgorithm::Sha256||
       reviewed.schema!=schema()||reviewed.policy_binding!=binding(request.policy)||
       reviewed.ownership!=ComparisonMetadataOwnership::Original)
        return invalid("directory_source.review_schema_policy",ObservationState::Changed,AdapterError::PlanDecisionStale);
    if(!request.source->metadata().kind.value()||*request.source->metadata().kind.value()!=ObjectKind::Directory)
        return invalid("directory_source.kind",ObservationState::Unsupported,AdapterError::NotApplicable);
    if(!request.budget)request.budget=std::make_shared<MetadataCaptureBudget>(request.limits);
    return R::available(Pointer(new DirectoryExecutionSourceJob(std::move(request))));
}
void DirectoryExecutionSourceJob::remember(const UnavailableObservation& error,bool finish)noexcept {
    remember(error.state,error.error.domain,error.error.code,error.error.operation,finish);
}
void DirectoryExecutionSourceJob::remember(ObservationState state,ErrorDomain domain,std::int64_t code,
    std::string_view operation,bool finish)noexcept {
    auto& first=finish?progress_.finish_failure:progress_.failure;
    if(!first.present){first.present=true;first.state=state;first.domain=domain;first.code=code;
        const auto count=std::min(operation.size(),first.operation.size()-1);std::copy_n(operation.data(),count,first.operation.data());}
    if(finish&&request_.journal_root)detail::record_prepared_journal_consumer_failure(*request_.journal_root,state,domain,code,operation);
}
void DirectoryExecutionSourceJob::read_latch()noexcept {
    if(latch_&&latch_->first){const auto& error=*latch_->first;remember(error.state,error.domain,error.code,error.operation,true);}
    detail::PreparedJournalConsumerFailure root;
    if(request_.journal_root&&detail::read_prepared_journal_consumer_failure(*request_.journal_root,root))
        remember(root.state,root.domain,root.code,root.pending?"directory_source.pending_root_failure":root.operation.data(),true);
}
Observation<bool> DirectoryExecutionSourceJob::membership(std::stop_token stop) {
    auto valid=request_.journal_root->revalidate();if(!valid.value()||!*valid.value())return valid;
    valid=request_.verify_review(stop);if(!valid.value()||!*valid.value())return valid;
    if(scope_){valid=scope_->check_root(stop);if(!valid.value()||!*valid.value())return valid;}
    auto now=request_.source->refresh(stop);if(!now.value())return propagate(now);
    if(!(*now.value())->continues(*request_.source))return refuse("directory_source.membership");
    return scope_?scope_->check_entry(**now.value(),stop):Observation<bool>::available(true);
}
Observation<bool> DirectoryExecutionSourceJob::compare(const NativeMetadataProof& proof,std::stop_token stop)const {
    if(proof.io_finished())return refuse("directory_source.closed_proof");
    const auto& snapshot=proof.snapshot();const auto& metadata=snapshot.basic;
    if(!metadata.kind.value()||*metadata.kind.value()!=ObjectKind::Directory||
       !identity(metadata.identity,request_.source->metadata().identity))return refuse("directory_source.native_owner");
    const auto& held=request_.source->metadata();
    if(!equal(metadata.modified,held.modified)||!equal(metadata.changed,held.changed)||
       !equal(metadata.posix_permissions,held.posix_permissions)||!equal(metadata.posix_uid,held.posix_uid)||
       !equal(metadata.posix_gid,held.posix_gid)||!equal(metadata.link_count,held.link_count)||
       !equal(metadata.windows_attributes,held.windows_attributes)||!equal(metadata.bsd_flags,held.bsd_flags))
        return refuse("directory_source.review_version");
    for(const auto* object:{&request_.reviewed.before,&request_.reviewed.after}) {
        if(object->state!=ComparisonObjectState::Stable||object->kind!=ObjectKind::Directory||!object->identity||
           compare_identity(*object->identity,*metadata.identity.value())!=IdentityComparison::Same||
           !object->modified||!metadata.modified.value()||*object->modified!=*metadata.modified.value())
            return refuse("directory_source.review_object");
    }
    // V3 hashes canonical already-captured values. This helper performs no
    // content/native I/O and cannot silently refresh the reviewed digest.
    auto digest=detail::metadata_snapshot_semantic_digest(snapshot,stop);
    if(!digest.value())return propagate(digest);
    if(binding(snapshot.policy)!=request_.reviewed.policy_binding||*digest.value()!=request_.reviewed.bytes)
        return refuse("directory_source.review_metadata_changed");
    return Observation<bool>::available(true);
}
void DirectoryExecutionSourceJob::close_capture(std::unique_ptr<MetadataCaptureJob>& capture)noexcept {
    if(!capture)return;
    try{auto finished=capture->finish_io();if(!finished.value())remember(*finished.unavailable_detail(),true);
        else if(!*finished.value())remember(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"directory_source.finish_false",true);
    }catch(...){read_latch();if(!progress_.finish_failure.present)remember(ObservationState::Unknown,ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"directory_source.finish_exception",true);}
    read_latch();capture.reset();read_latch();
}
void DirectoryExecutionSourceJob::close_all(bool cancelled)noexcept {
    if(progress_.worker_drained)return;
    const auto ready=progress_.phase==DirectorySourcePhase::Ready;
    detail::MetadataCaptureCleanupScope cleanup(latch_.get());
    close_capture(recheck_);close_capture(capture_);
    if(proof_)try{auto finished=proof_->finish_io();if(!finished.value())remember(*finished.unavailable_detail(),true);
        else if(!*finished.value())remember(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"directory_source.proof_finish_false",true);
    }catch(...){read_latch();if(!progress_.finish_failure.present)remember(ObservationState::Unknown,ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"directory_source.proof_finish_exception",true);}
    proof_.reset();scope_.reset();request_.source.reset();request_.budget.reset();request_.verify_review={};read_latch();
    latch_->release();request_.journal_root.reset();progress_.worker_drained=true;
    progress_.phase=progress_.failure.present||progress_.finish_failure.present?DirectorySourcePhase::Failed:
        cancelled||!ready?DirectorySourcePhase::Cancelled:DirectorySourcePhase::Complete;
}
DirectoryExecutionSourceJob::~DirectoryExecutionSourceJob(){close_all(true);}
DirectorySourceProgress DirectoryExecutionSourceJob::advance(std::stop_token stop) {
    if(progress_.worker_drained)return progress_;
    if(stop.stop_requested()){close_all(true);return progress_;}
    if(progress_.phase==DirectorySourcePhase::Ready)return progress_;
    try{
        detail::MetadataCaptureCleanupScope cleanup(latch_.get());
        auto valid=membership(stop);
        if(!valid.value()||!*valid.value()){if(!valid.value()&&!interrupted(*valid.unavailable_detail(),stop))remember(*valid.unavailable_detail());
            else if(valid.value())remember(*refuse("directory_source.review_false").unavailable_detail());close_all(stop.stop_requested());return progress_;}
        if(progress_.phase==DirectorySourcePhase::Opening){
            auto guard=JournalScopeGuard::create_for_entry(request_.journal_root,*request_.source,stop);
            if(!guard.value()){if(!interrupted(*guard.unavailable_detail(),stop))remember(*guard.unavailable_detail());close_all(stop.stop_requested());return progress_;}
            scope_=std::move(guard).take_value();
            auto begun=MetadataCaptureJob::begin_held(request_.source,request_.policy,request_.limits,request_.budget,latch_);
            if(!begun.value()){remember(*begun.unavailable_detail());close_all(false);return progress_;}
            capture_=std::move(begun).take_value();progress_.phase=DirectorySourcePhase::Capturing;return progress_;
        }
        auto& capture=progress_.phase==DirectorySourcePhase::Rechecking?recheck_:capture_;
        const auto before=capture->progress();auto advanced=capture->advance(stop);const auto& after=capture->progress();
        progress_.read_calls+=after.read_calls-before.read_calls;progress_.read_bytes+=after.read_bytes-before.read_bytes;
        read_latch();
        if(!advanced.value()||progress_.finish_failure.present){if(!advanced.value()&&!interrupted(*advanced.unavailable_detail(),stop))remember(*advanced.unavailable_detail());close_all(stop.stop_requested());return progress_;}
        if(after.phase!=MetadataCapturePhase::Complete)return progress_;
        auto result=capture->result();if(!result.value()){remember(*result.unavailable_detail());close_all(false);return progress_;}
        valid=compare(**result.value(),stop);if(valid.value()&&*valid.value())valid=membership(stop);
        if(!valid.value()||!*valid.value()){if(!valid.value()&&!interrupted(*valid.unavailable_detail(),stop))remember(*valid.unavailable_detail());
            else if(valid.value())remember(*refuse("directory_source.final_membership_false").unavailable_detail());close_all(stop.stop_requested());return progress_;}
        if(progress_.phase==DirectorySourcePhase::Rechecking)close_capture(recheck_);else proof_=*result.value();
        read_latch();if(progress_.finish_failure.present){close_all(false);return progress_;}
        progress_.phase=DirectorySourcePhase::Ready;
    }catch(...){remember(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"directory_source.worker_exception");close_all(stop.stop_requested());}
    return progress_;
}
Observation<std::shared_ptr<const NativeMetadataProof>> DirectoryExecutionSourceJob::proof()const {
    if(progress_.phase!=DirectorySourcePhase::Ready||!proof_||proof_->io_finished())
        return Observation<std::shared_ptr<const NativeMetadataProof>>::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"directory_source.proof_not_ready"});
    return Observation<std::shared_ptr<const NativeMetadataProof>>::available(proof_);
}
Observation<bool> DirectoryExecutionSourceJob::start_revalidation() {
    if(progress_.phase!=DirectorySourcePhase::Ready||!proof_||proof_->io_finished())return refuse("directory_source.recheck_not_ready");
    auto begun=MetadataCaptureJob::verify(proof_,request_.limits,request_.budget,latch_);
    if(!begun.value()){remember(*begun.unavailable_detail());close_all(false);return propagate(begun);}
    recheck_=std::move(begun).take_value();progress_.phase=DirectorySourcePhase::Rechecking;return Observation<bool>::available(true);
}
Observation<bool> DirectoryExecutionSourceJob::finish_io() {
    close_all(false);const auto& failure=progress_.finish_failure;
    return failure.present?Observation<bool>::unavailable(failure.state,{failure.domain,failure.code,failure.operation.data()}):
        Observation<bool>::available(true);
}
} // namespace ck::files
