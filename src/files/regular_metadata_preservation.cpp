// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "regular_metadata_preservation.hpp"

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
} // namespace ck::files
