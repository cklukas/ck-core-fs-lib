// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "regular_metadata_preservation.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <algorithm>
#include <cstring>

namespace ck::files {
namespace {
template<class T> Observation<T> review(const char* operation) {
    return Observation<T>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::ProviderReviewRequired), operation});
}
template<class T> Observation<T> unavailable(const UnavailableObservation& error) {
    return Observation<T>::unavailable(error.state, error.error);
}
Observation<bool> cancelled() {
    return Observation<bool>::unavailable(ObservationState::Unknown,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InterruptedRead),
         "regular_metadata.cancelled"});
}
template<class T> bool equal(const Observation<T>& a, const Observation<T>& b) {
    return a.value() && b.value() && *a.value() == *b.value();
}
bool same_object(const BasicMetadata& a, const BasicMetadata& b) {
    return a.identity.value() && b.identity.value() &&
        compare_identity(*a.identity.value(), *b.identity.value()) == IdentityComparison::Same;
}

}

Observation<RegularMetadataPreservation::Pointer> RegularMetadataPreservation::create(
    HeldChild::Pointer source, bool allow_loss, RegularMetadataScope scope, std::stop_token stop) {
    MetadataReplayPolicy policy;
    policy.scope=scope;
    policy.ownership=scope==RegularMetadataScope::CompleteMetadataV1 ? MetadataOwnership::Original : MetadataOwnership::CurrentCaller;
    return create_with_policy(std::move(source),allow_loss,policy,stop);
}

Observation<RegularMetadataPreservation::Pointer> RegularMetadataPreservation::create_with_policy(
    HeldChild::Pointer source, bool allow_loss, MetadataReplayPolicy policy, std::stop_token stop) {
    if (!source) return review<Pointer>("regular_metadata.source_missing");
    if (!policy.valid()) return review<Pointer>("regular_metadata.invalid_policy_version");
    if (stop.stop_requested()) return unavailable<Pointer>(*cancelled().unavailable_detail());
    auto metadata=source->inspect_basic();
    if (!metadata.value()) return unavailable<Pointer>(*metadata.unavailable_detail());
    if (!same_object(source->metadata(),*metadata.value())) return review<Pointer>("regular_metadata.source_identity");
    auto preservation=Pointer(new RegularMetadataPreservation(source,*metadata.value(),allow_loss,policy.scope));
    preservation->policy_=policy;
    if (!allow_loss) {
        auto replay=source->capture_metadata(policy,stop);
        if (!replay.value()) return unavailable<Pointer>(*replay.unavailable_detail());
        if (!same_object(source->metadata(),replay.value()->basic)) return review<Pointer>("regular_metadata.capture_identity");
        preservation->metadata_=replay.value()->basic;
        preservation->replay_=std::move(replay).take_value();
        auto verified=source->verify_metadata_source(*preservation->replay_,stop);
        if (!verified.value()) return unavailable<Pointer>(*verified.unavailable_detail());
        if (!*verified.value()) return Observation<Pointer>::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged),
             "regular_metadata.capture_verification_false"});
    }
    return Observation<Pointer>::available(std::move(preservation));
}

Observation<OperationMetadataJob::Pointer> RegularMetadataPreservation::prepare(OpenedEntry& staging,
                                                                              std::stop_token stop) {
    if (stop.stop_requested()) return unavailable<OperationMetadataJob::Pointer>(*cancelled().unavailable_detail());
    if(progressive_finished_)return review<OperationMetadataJob::Pointer>("regular_metadata.progressive_finished");
    if(progressive_) {
        if(progressive_job_)return review<OperationMetadataJob::Pointer>("regular_metadata.already_prepared");
        auto request=*progressive_;request.target=&staging;
        auto job=NativeRegularMetadataJob::create(std::move(request));
        if(!job.value())return unavailable<OperationMetadataJob::Pointer>(*job.unavailable_detail());
        progressive_job_=std::move(job).take_value();
        OperationMetadataRequest metadata;
        metadata.advance_phase=[lifetime=shared_from_this()](OperationMetadataState state,std::stop_token token){
            return lifetime->progressive_job_->advance(state,token);
        };
        return OperationMetadataJob::create(std::move(metadata));
    }
    OperationMetadataRequest request;
    request.apply_traversal_metadata = [this, lifetime = shared_from_this()](std::stop_token stop) {
        if (stop.stop_requested()) return cancelled();
        if (replay_) return source_->verify_metadata_source(*replay_,stop);
        return Observation<bool>::available(true);
    };
    request.apply_security_metadata = [this, lifetime=shared_from_this(), &staging](std::stop_token stop) {
        if (stop.stop_requested()) return cancelled();
        return replay_ ? apply_metadata_replay(staging,*replay_,stop) : Observation<bool>::available(true);
    };
    // All data verification reads have finished before this phase. The native
    // setter masks privilege-affecting bits even with explicit loss consent.
    request.apply_final_times = [this, lifetime = shared_from_this(), &staging](std::stop_token stop) {
        if (stop.stop_requested()) return cancelled();
        auto safe = metadata_;
        if (safe.posix_permissions.value()) safe.posix_permissions =
            Observation<std::uint32_t>::available(*safe.posix_permissions.value() & 0777U);
        auto applied = replay_ ? staging.apply_replay_basic(metadata_,replay_->policy) : staging.apply_portable_basic_metadata(safe);
        if (!applied.value() || !*applied.value()) return applied;
        auto current = staging.inspect_basic();
        if (!current.value()) return unavailable<bool>(*current.unavailable_detail());
        applied_ = *current.value();
        return verify(staging, stop);
    };
    request.flush_destination = [this, lifetime = shared_from_this(), &staging](std::stop_token stop) {
        auto flushed = staging.flush_content();
        if (!flushed.value() || !*flushed.value()) return flushed;
        return verify(staging, stop);
    };
    return OperationMetadataJob::create(std::move(request));
}

Observation<bool> RegularMetadataPreservation::verify(OpenedEntry& staging, std::stop_token stop) const {
    if (stop.stop_requested()) return cancelled();
    if(progressive_)return progressive_job_?progressive_job_->verify(staging,stop):review<bool>("regular_metadata.progressive_not_prepared");
    if (!applied_) return review<bool>("regular_metadata.not_applied");
    if (replay_) {
        auto source=source_->verify_metadata_source(*replay_,stop);
        if (!source.value() || !*source.value()) return source;
        return verify_metadata_replay(staging,*replay_,*applied_,stop);
    }
    auto target = staging.inspect_basic();
    if (!target.value()) return unavailable<bool>(*target.unavailable_detail());
    const auto& current = *target.value();
    if (!same_object(*applied_, current) || !equal(metadata_.kind, current.kind) ||
        !equal(metadata_.logical_size, current.logical_size) ||
        !equal(metadata_.accessed, current.accessed) || !equal(metadata_.modified, current.modified))
        return review<bool>("regular_metadata.basic_verification");
    if (metadata_.posix_permissions.value() && (!current.posix_permissions.value() ||
        *current.posix_permissions.value() != (*metadata_.posix_permissions.value() & 0777U)))
        return review<bool>("regular_metadata.mode_verification");
    return Observation<bool>::available(true);
}

Observation<RegularMetadataPreservation::Pointer> RegularMetadataPreservation::create_progressive(
    HeldChild::Pointer source,NativeRegularMetadataRequest binding) {
    if(!source||binding.target||!binding.source||!binding.journal_root||!binding.verify_membership||
       !binding.revalidate_source||!binding.finish_source||!binding.read_limits.valid())
        return review<Pointer>("regular_metadata.progressive_binding");
    auto qualified=NativeRegularMetadataJob::qualify_source(*binding.source);
    if(!qualified.value())return unavailable<Pointer>(*qualified.unavailable_detail());
    if(!*qualified.value())return review<Pointer>("regular_metadata.progressive_source_false");
    const auto& snapshot=binding.source->snapshot();
    auto now=source->inspect_basic();if(!now.value())return unavailable<Pointer>(*now.unavailable_detail());
    if(!same_object(source->metadata(),snapshot.basic)||!same_object(*now.value(),snapshot.basic)||
       !equal(now.value()->kind,snapshot.basic.kind)||!equal(now.value()->logical_size,snapshot.basic.logical_size)||
       !equal(now.value()->modified,snapshot.basic.modified)||!equal(now.value()->changed,snapshot.basic.changed))
        return review<Pointer>("regular_metadata.progressive_source_changed");
    auto result=Pointer(new RegularMetadataPreservation(std::move(source),snapshot.basic,false,snapshot.policy.scope));
    result->policy_=snapshot.policy;result->replay_=snapshot;result->progressive_=std::move(binding);
    return Observation<Pointer>::available(std::move(result));
}

Observation<bool> RegularMetadataPreservation::finish_io() {
    if(progressive_||progressive_finished_)return finish_progressive_io();
    struct LegacyClose final:MetadataCaptureFailureLatch {
        LegacyClose(std::optional<MetadataCaptureCleanupError>& error,std::array<char,128>& operation,
            const MetadataCaptureFailureLatch* previous):error(error),operation(operation),previous(previous){}
        std::optional<MetadataCaptureCleanupError>& error;
        std::array<char,128>& operation;
        const MetadataCaptureFailureLatch* previous;
        void record_first(MetadataCaptureCleanupError value)const noexcept override {
            if(!error) {
                const std::string_view tag=value.operation?value.operation:"regular_metadata.legacy_close";
                const auto count=std::min(tag.size(),operation.size()-1);
                if(count)std::memcpy(operation.data(),tag.data(),count);operation[count]=0;
                error=MetadataCaptureCleanupError{value.state,value.domain,value.code,operation.data()};
            }
            if(previous)previous->record_first(value);
        }
    } latch(progressive_finish_error_,progressive_finish_operation_,detail::current_metadata_capture_cleanup());
    {
        detail::MetadataCaptureCleanupScope scope(&latch);
        // Explicitly invalidate native channel readers even when their shared
        // immutable snapshot values outlive this preservation operation.
        if(replay_)detail::finish_native_metadata_capture(nullptr,*replay_);
        replay_.reset();source_.reset();
    }
    progressive_finished_=true;
    if(progressive_finish_error_) {
        const auto& error=*progressive_finish_error_;
        return Observation<bool>::unavailable(error.state,{error.domain,error.code,error.operation});
    }
    return Observation<bool>::available(true);
}

Observation<bool> RegularMetadataPreservation::finish_progressive_io() {
    auto result=[&] {
        if(!progressive_finish_error_)return Observation<bool>::available(true);
        const auto& e=*progressive_finish_error_;
        // Native drains precede diagnostic publication. Even an empty string
        // can allocate in the MSVC Debug runtime, so let OOM propagate without
        // constructing a second diagnostic; the Root retains its POD error.
        return Observation<bool>::unavailable(e.state,{e.domain,e.code,e.operation});
    };
    if(progressive_finished_)return result();
    if(!progressive_)return review<bool>("regular_metadata.progressive_binding_missing");
    struct Latch final:MetadataCaptureFailureLatch {
        Latch(PreparedJournalRoot::Pointer root,std::optional<MetadataCaptureCleanupError>& error,std::array<char,128>& operation)
            :root(std::move(root)),error(error),operation(operation){}
        PreparedJournalRoot::Pointer root;
        std::optional<MetadataCaptureCleanupError>& error;
        std::array<char,128>& operation;
        void save(ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view op,bool replace=false)const noexcept {
            if(error&&!replace)return;
            const auto n=std::min(op.size(),operation.size()-1);
            if(n)std::memcpy(operation.data(),op.data(),n);operation[n]=0;
            error=MetadataCaptureCleanupError{state,domain,code,operation.data()};
        }
        void record_first(MetadataCaptureCleanupError e)const noexcept override {
            save(e.state,e.domain,e.code,e.operation);
            detail::record_prepared_journal_consumer_failure(*root,e.state,e.domain,e.code,e.operation);
        }
        void read_root()const noexcept {
            detail::PreparedJournalConsumerFailure first;
            if(detail::read_prepared_journal_consumer_failure(*root,first))
                save(first.state,first.domain,first.code,first.pending?"regular_metadata.pending_root_failure":first.operation.data(),true);
        }
        void observe(const Observation<bool>& value)const noexcept {
            if(const auto* e=value.unavailable_detail()) {
                save(e->state,e->error.domain,e->error.code,e->error.operation);
                detail::record_prepared_journal_consumer_failure(*root,e->state,e->error.domain,e->error.code,e->error.operation);
            }else if(!*value.value())record_first({ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"regular_metadata.finish_false"});
        }
    } latch(progressive_->journal_root,progressive_finish_error_,progressive_finish_operation_);
    {
        detail::MetadataCaptureCleanupScope scope(&latch);
        auto close=[&](auto&& callback)noexcept {
            try{latch.observe(callback());}catch(...){
                latch.read_root();
                if(!progressive_finish_error_)latch.record_first({ObservationState::Unknown,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"regular_metadata.finish_exception"});
            }
        };
        if(progressive_job_)close([&]{return progressive_job_->finish_io();});
        else {
            close([&]{return progressive_->finish_source();});
            close([&]{return progressive_->source->finish_io();});
        }
        // Drop duplicate callback/proof/Root references while the close
        // observer is still active. The replay values contain closed evidence.
        // The preservation object can outlive terminal execution through the
        // enclosing copy callbacks. Consume its original held source and drop
        // closed native evidence here, while Root still observes every close.
        source_.reset();replay_.reset();progressive_job_.reset();
        progressive_.reset();latch.read_root();
    }
    progressive_finished_=true;return result();
}
} // namespace ck::files
