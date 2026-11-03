// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "regular_execution_source.hpp"
#include "metadata_semantic_digest.hpp"
#include "metadata_ownership_digest.hpp"
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
bool reviewed_object(const ComparisonObject& object,const BasicMetadata& metadata) noexcept {
    return object.state==ComparisonObjectState::Stable && object.kind==ObjectKind::RegularFile &&
        object.identity && metadata.identity.value() &&
        compare_identity(*object.identity,*metadata.identity.value())==IdentityComparison::Same &&
        object.size && metadata.logical_size.value() && *object.size==*metadata.logical_size.value() &&
        object.modified && metadata.modified.value() && *object.modified==*metadata.modified.value() &&
        object.timestamp_quantum_ns==1 && !object.change_cookie;
}
}
class RegularExecutionSourceJob::Latch final:public MetadataCaptureFailureLatch {
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
RegularExecutionSourceJob::RegularExecutionSourceJob(RegularExecutionSourceRequest request)
    :request_(std::move(request)),latch_(std::make_shared<Latch>(request_.journal_root)){}
Observation<RegularExecutionSourceJob::Pointer> RegularExecutionSourceJob::create(RegularExecutionSourceRequest request) {
    using R=Observation<Pointer>;
    // Even a rejected/moved request may be the last native owner. Its release
    // belongs inside the same first-error scope, before constructing a result.
    Latch cleanup(request.journal_root);
    detail::MetadataCaptureCleanupScope cleanup_scope(&cleanup);
    auto release=[&]() noexcept {
        request.source.reset();request.budget.reset();request.verify_review={};
        request.journal_root.reset();
    };
    auto invalid=[&](const char* operation,ObservationState state,AdapterError code) {
        release();
        if(cleanup.first){const auto& e=*cleanup.first;
            return R::unavailable(e.state,{e.domain,e.code,e.operation});}
        return R::unavailable(state,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),operation});
    };
    try {
        if(!request.source||!request.journal_root||!request.verify_review||
           !request.policy.valid()||!request.limits.valid()||
           (request.budget&&!request.budget->limits().valid()))
            return invalid("regular_source.request",ObservationState::Failed,AdapterError::InvalidIdentifier);
        detail::PreparedJournalConsumerFailure failure;
        if(detail::read_prepared_journal_consumer_failure(*request.journal_root,failure)) {
            release();
            return R::unavailable(failure.state,{failure.domain,failure.code,
                failure.pending?"regular_source.pending_root_failure":failure.operation.data()});
        }
        const auto ownership=request.policy.ownership==MetadataOwnership::Original?
            ComparisonMetadataOwnership::Original:ComparisonMetadataOwnership::CurrentCaller;
        const auto& reviewed=request.reviewed;
        if(metadata_semantic_digest_version!=3 || reviewed.state!=ComparisonDigestState::CompleteStable ||
           reviewed.algorithm!=ComparisonDigestAlgorithm::Sha256 || reviewed.schema!=schema() ||
           reviewed.policy_binding!=binding(request.policy) || reviewed.ownership!=ownership ||
           (ownership==ComparisonMetadataOwnership::CurrentCaller&&!reviewed.canonical_owner_digest))
            return invalid("regular_source.review_schema_policy_owner",ObservationState::Changed,AdapterError::PlanDecisionStale);
        const auto& held=request.source->metadata();
        if(!held.kind.value()||*held.kind.value()!=ObjectKind::RegularFile)
            return invalid("regular_source.kind",ObservationState::Unsupported,AdapterError::NotApplicable);
        if(!requests_content_read(request.source->access()))
            return invalid("regular_source.content_access",ObservationState::Unsupported,AdapterError::InvalidAccess);
        const auto& main=request.reviewed_main;
        if(main.state!=ComparisonDigestState::CompleteStable || main.algorithm!=ComparisonDigestAlgorithm::Sha256 ||
           !held.logical_size.value() || main.bytes_read!=*held.logical_size.value())
            return invalid("regular_source.review_main",ObservationState::Changed,AdapterError::PlanDecisionStale);
        for(const auto* object:{&reviewed.before,&reviewed.after,&main.before,&main.after})
            if(!reviewed_object(*object,held))
                return invalid("regular_source.review_object",ObservationState::Changed,AdapterError::PlanDecisionStale);
        if(!request.budget)request.budget=std::make_shared<MetadataCaptureBudget>(request.limits);
        return R::available(Pointer(new RegularExecutionSourceJob(std::move(request))));
    } catch(...) {
        // Allocation exceptions may propagate through this C++ worker API, but
        // no transferred native consumer can escape the cleanup/latch boundary.
        release();throw;
    }
}
void RegularExecutionSourceJob::remember(const UnavailableObservation& error,bool finish)noexcept {
    remember(error.state,error.error.domain,error.error.code,error.error.operation,finish);
}
void RegularExecutionSourceJob::remember(ObservationState state,ErrorDomain domain,std::int64_t code,
    std::string_view operation,bool finish)noexcept {
    auto& first=finish?progress_.finish_failure:progress_.failure;
    if(!first.present){first.present=true;first.state=state;first.domain=domain;first.code=code;
        const auto count=std::min(operation.size(),first.operation.size()-1);std::copy_n(operation.data(),count,first.operation.data());}
    if(finish&&request_.journal_root)detail::record_prepared_journal_consumer_failure(*request_.journal_root,state,domain,code,operation);
}
void RegularExecutionSourceJob::read_latch()noexcept {
    if(latch_&&latch_->first){const auto& error=*latch_->first;remember(error.state,error.domain,error.code,error.operation,true);}
    detail::PreparedJournalConsumerFailure root;
    if(request_.journal_root&&detail::read_prepared_journal_consumer_failure(*request_.journal_root,root))
        remember(root.state,root.domain,root.code,root.pending?"regular_source.pending_root_failure":root.operation.data(),true);
}
Observation<bool> RegularExecutionSourceJob::membership(std::stop_token stop) {
    auto latched=[&]() {read_latch();return progress_.finish_failure.present;};
    if(latched())return refuse("regular_source.root_failure");
    auto valid=request_.journal_root->revalidate();
    if(!valid.value()||!*valid.value())return valid;
    if(latched())return refuse("regular_source.root_failure");
    valid=request_.verify_review(stop);if(!valid.value()||!*valid.value())return valid;
    if(latched())return refuse("regular_source.root_failure");
    if(scope_) {
        valid=scope_->check_root(stop);if(!valid.value()||!*valid.value())return valid;
        if(latched())return refuse("regular_source.root_failure");
    }
    auto now=request_.source->refresh(stop);if(!now.value())return propagate(now);
    if(latched())return refuse("regular_source.root_failure");
    if(!(*now.value())->continues(*request_.source) ||
       !native_sync_same_version((*now.value())->metadata(),request_.source->metadata()))
        return refuse("regular_source.membership_version");
    valid=scope_?scope_->check_entry(**now.value(),stop):Observation<bool>::available(true);
    if(latched())return refuse("regular_source.root_failure");
    return valid;
}
Observation<bool> RegularExecutionSourceJob::compare(const NativeMetadataProof& proof,std::stop_token stop)const {
    if(proof.io_finished())return refuse("regular_source.closed_proof");
    if(auto error=proof.cleanup_error())
        return Observation<bool>::unavailable(error->state,{error->domain,error->code,error->operation});
    const auto& snapshot=proof.snapshot();const auto& metadata=snapshot.basic;
    if(!native_sync_same_version(metadata,request_.source->metadata()))
        return refuse("regular_source.native_owner_version");
    for(const auto* object:{&request_.reviewed.before,&request_.reviewed.after,
                            &request_.reviewed_main.before,&request_.reviewed_main.after})
        if(!reviewed_object(*object,metadata))return refuse("regular_source.review_object");
    if(!proof.main_digest() || *proof.main_digest()!=request_.reviewed_main.bytes ||
       !proof.progress().main_logical_bytes ||
       *proof.progress().main_logical_bytes!=request_.reviewed_main.bytes_read)
        return refuse("regular_source.review_main_changed");
    // These helpers encode only the bounded already-captured native values.
    // Neither performs reads, bulk capture, or refreshes the reviewed facts.
    auto digest=native_metadata_proof_digest(proof,stop);
    if(!digest.value())return propagate(digest);
    if(binding(snapshot.policy)!=request_.reviewed.policy_binding ||
       *digest.value()!=request_.reviewed.bytes)
        return refuse("regular_source.review_metadata_changed");
    if(request_.reviewed.ownership==ComparisonMetadataOwnership::CurrentCaller ||
       request_.reviewed.canonical_owner_digest) {
        auto owner=metadata_ownership_digest(snapshot);if(!owner.value())return propagate(owner);
        if(!request_.reviewed.canonical_owner_digest || *owner.value()!=*request_.reviewed.canonical_owner_digest)
            return refuse("regular_source.review_owner_changed");
    }
    return Observation<bool>::available(true);
}
void RegularExecutionSourceJob::close_capture(std::unique_ptr<MetadataCaptureJob>& capture)noexcept {
    if(!capture)return;
    try{auto finished=capture->finish_io();if(!finished.value())remember(*finished.unavailable_detail(),true);
        else if(!*finished.value())remember(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"regular_source.finish_false",true);
    }catch(...){read_latch();if(!progress_.finish_failure.present)remember(ObservationState::Unknown,ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"regular_source.finish_exception",true);}
    read_latch();capture.reset();read_latch();
}
void RegularExecutionSourceJob::close_all(bool cancelled)noexcept {
    if(progress_.worker_drained)return;
    const auto ready=progress_.phase==RegularSourcePhase::Ready;
    detail::MetadataCaptureCleanupScope cleanup(latch_.get());
    close_capture(recheck_);close_capture(capture_);
    if(proof_)try{auto finished=proof_->finish_io();if(!finished.value())remember(*finished.unavailable_detail(),true);
        else if(!*finished.value())remember(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"regular_source.proof_finish_false",true);
    }catch(...){read_latch();if(!progress_.finish_failure.present)remember(ObservationState::Unknown,ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"regular_source.proof_finish_exception",true);}
    proof_.reset();scope_.reset();request_.source.reset();request_.budget.reset();request_.verify_review={};read_latch();
    latch_->release();request_.journal_root.reset();
    if(latch_->first){const auto& error=*latch_->first;remember(error.state,error.domain,error.code,error.operation,true);}
    progress_.worker_drained=true;
    progress_.phase=progress_.failure.present||progress_.finish_failure.present?RegularSourcePhase::Failed:
        cancelled||!ready?RegularSourcePhase::Cancelled:RegularSourcePhase::Complete;
}
RegularExecutionSourceJob::~RegularExecutionSourceJob(){close_all(true);}
RegularSourceProgress RegularExecutionSourceJob::advance(std::stop_token stop) {
    if(progress_.worker_drained)return progress_;
    if(stop.stop_requested()){close_all(true);return progress_;}
    if(progress_.phase==RegularSourcePhase::Ready) {
        read_latch();
        if(!proof_||proof_->io_finished())remember(ObservationState::Changed,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::PlanDecisionStale),"regular_source.closed_proof");
        if(progress_.failure.present||progress_.finish_failure.present)close_all(false);
        return progress_;
    }
    try{
        detail::MetadataCaptureCleanupScope cleanup(latch_.get());
        read_latch();
        if(progress_.finish_failure.present){close_all(false);return progress_;}
        if(progress_.phase==RegularSourcePhase::Opening) {
            auto guard=JournalScopeGuard::create_for_entry(request_.journal_root,*request_.source,stop);
            if(!guard.value()){if(!interrupted(*guard.unavailable_detail(),stop))remember(*guard.unavailable_detail());close_all(stop.stop_requested());return progress_;}
            scope_=std::move(guard).take_value();
        }
        auto valid=membership(stop);read_latch();
        if(progress_.finish_failure.present){close_all(false);return progress_;}
        if(!valid.value()||!*valid.value()){if(!valid.value()&&!interrupted(*valid.unavailable_detail(),stop))remember(*valid.unavailable_detail());
            else if(valid.value()) {
                remember(*refuse("regular_source.review_false").unavailable_detail());
            }
            close_all(stop.stop_requested());return progress_;
        }
        if(progress_.phase==RegularSourcePhase::Opening){
            auto begun=MetadataCaptureJob::begin_held(request_.source,request_.policy,request_.limits,request_.budget,latch_);
            if(!begun.value()){remember(*begun.unavailable_detail());close_all(false);return progress_;}
            capture_=std::move(begun).take_value();progress_.phase=RegularSourcePhase::Capturing;return progress_;
        }
        auto& capture=progress_.phase==RegularSourcePhase::Rechecking?recheck_:capture_;
        const auto before=capture->progress();auto advanced=capture->advance(stop);const auto& after=capture->progress();
        progress_.read_calls+=after.read_calls-before.read_calls;progress_.read_bytes+=after.read_bytes-before.read_bytes;
        read_latch();
        if(!advanced.value()||progress_.finish_failure.present){if(!advanced.value()&&!interrupted(*advanced.unavailable_detail(),stop))remember(*advanced.unavailable_detail());close_all(stop.stop_requested());return progress_;}
        if(after.phase!=MetadataCapturePhase::Complete)return progress_;
        auto result=capture->result();if(!result.value()){remember(*result.unavailable_detail());close_all(false);return progress_;}
        valid=compare(**result.value(),stop);if(valid.value()&&*valid.value())valid=membership(stop);
        read_latch();if(progress_.finish_failure.present){close_all(false);return progress_;}
        if(!valid.value()||!*valid.value()){if(!valid.value()&&!interrupted(*valid.unavailable_detail(),stop))remember(*valid.unavailable_detail());
            else if(valid.value()) {
                remember(*refuse("regular_source.final_membership_false").unavailable_detail());
            }
            close_all(stop.stop_requested());return progress_;
        }
        if(progress_.phase==RegularSourcePhase::Rechecking)close_capture(recheck_);else proof_=*result.value();
        read_latch();if(progress_.finish_failure.present){close_all(false);return progress_;}
        progress_.phase=RegularSourcePhase::Ready;
    }catch(...){remember(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"regular_source.worker_exception");close_all(stop.stop_requested());}
    return progress_;
}
Observation<std::shared_ptr<const NativeMetadataProof>> RegularExecutionSourceJob::proof()const {
    if(progress_.phase!=RegularSourcePhase::Ready||!proof_||proof_->io_finished())
        return Observation<std::shared_ptr<const NativeMetadataProof>>::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"regular_source.proof_not_ready"});
    return Observation<std::shared_ptr<const NativeMetadataProof>>::available(proof_);
}
Observation<bool> RegularExecutionSourceJob::start_revalidation() {
    auto failed=[&](const UnavailableObservation& error) {
        remember(error);close_all(false);return Observation<bool>::unavailable(error.state,error.error);
    };
    if(progress_.worker_drained)return refuse("regular_source.recheck_after_drain");
    try {
        detail::MetadataCaptureCleanupScope cleanup(latch_.get());
        read_latch();
        if(progress_.finish_failure.present) {
            close_all(false);const auto& error=progress_.finish_failure;
            return Observation<bool>::unavailable(error.state,{error.domain,error.code,error.operation.data()});
        }
        if(progress_.phase!=RegularSourcePhase::Ready||!proof_||proof_->io_finished())
            return failed(*refuse("regular_source.recheck_not_ready").unavailable_detail());
        auto valid=membership({});read_latch();
        if(progress_.finish_failure.present) {
            close_all(false);const auto& error=progress_.finish_failure;
            return Observation<bool>::unavailable(error.state,{error.domain,error.code,error.operation.data()});
        }
        if(!valid.value())return failed(*valid.unavailable_detail());
        if(!*valid.value())return failed(*refuse("regular_source.review_false").unavailable_detail());
        auto begun=MetadataCaptureJob::verify(proof_,request_.limits,request_.budget,latch_);
        if(!begun.value())return failed(*begun.unavailable_detail());
        recheck_=std::move(begun).take_value();
        read_latch();
        if(progress_.finish_failure.present) {
            close_all(false);const auto& error=progress_.finish_failure;
            return Observation<bool>::unavailable(error.state,{error.domain,error.code,error.operation.data()});
        }
        progress_.phase=RegularSourcePhase::Rechecking;
        return Observation<bool>::available(true);
    } catch(...) {
        remember(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"regular_source.recheck_exception");
        close_all(false);throw;
    }
}
Observation<bool> RegularExecutionSourceJob::finish_io() {
    close_all(false);const auto& failure=progress_.finish_failure;
    return failure.present?Observation<bool>::unavailable(failure.state,{failure.domain,failure.code,failure.operation.data()}):
        Observation<bool>::available(true);
}
} // namespace ck::files
