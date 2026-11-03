// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "held_child.hpp"
#include "operation_metadata_job.hpp"
#include "native_regular_metadata_job.hpp"

namespace ck::files {

struct RegularMetadataScopeReport final {
    std::uint32_t version = 1;
    RegularMetadataScope requested = RegularMetadataScope::CompleteMetadataV1;
    // Unknown remains unknown even after successful ordinary-subset copying.
    ObservationState arbitrary_hidden_attributes = ObservationState::Unknown;
    MetadataOwnership ownership_policy = MetadataOwnership::Original;
    bool privilege_metadata_opted_in = false;
    ObservationState attributes_captured = ObservationState::Unknown;
    ObservationState security_captured = ObservationState::Unknown;
};


// Held-source capture, staged replay and final pre-publication verification.
// Explicit loss consent is a separate portable-basic-only operation and never
// establishes complete metadata preservation. No native privilege escalation.
class RegularMetadataPreservation final : public std::enable_shared_from_this<RegularMetadataPreservation> {
public:
    using Pointer = std::shared_ptr<RegularMetadataPreservation>;
    static Observation<Pointer> create(HeldChild::Pointer source, bool allow_unhandled_metadata_loss,
        RegularMetadataScope scope = RegularMetadataScope::CompleteMetadataV1, std::stop_token stop = {});
    static Observation<Pointer> create_with_policy(HeldChild::Pointer source, bool allow_unhandled_metadata_loss,
        MetadataReplayPolicy policy, std::stop_token stop = {});
    // Strict native worker binding. Fresh proof/review membership belongs to
    // the enclosing reviewed executor; target must be null until prepare().
    // This never substitutes a weaker preservation policy or caller digest.
    static Observation<Pointer> create_progressive(HeldChild::Pointer,NativeRegularMetadataRequest);
    Observation<bool> finish_progressive_io();
    RegularMetadataScopeReport scope_report() const noexcept {
        return {1, scope_, !allow_loss_ && scope_ == RegularMetadataScope::CompleteMetadataV1 ?
            ObservationState::Available : ObservationState::Unknown, policy_.ownership,
            policy_.allow_privilege_metadata, replay_ ? ObservationState::Available : ObservationState::Unknown,
            replay_ ? ObservationState::Available : ObservationState::Unknown};
    }
    const MetadataReplaySnapshot* captured_metadata() const noexcept { return replay_ ? &*replay_ : nullptr; }
    Observation<OperationMetadataJob::Pointer> prepare(OpenedEntry& staging, std::stop_token stop = {});
    Observation<bool> verify(OpenedEntry& staging, std::stop_token stop = {}) const;
private:
    RegularMetadataPreservation(HeldChild::Pointer source, BasicMetadata metadata, bool loss, RegularMetadataScope scope)
        : source_(std::move(source)), metadata_(std::move(metadata)), allow_loss_(loss), scope_(scope) {}
    HeldChild::Pointer source_;
    BasicMetadata metadata_;
    bool allow_loss_ = false;
    RegularMetadataScope scope_ = RegularMetadataScope::CompleteMetadataV1;
    std::optional<BasicMetadata> applied_;
    std::optional<MetadataReplaySnapshot> replay_;
    MetadataReplayPolicy policy_;
    std::optional<NativeRegularMetadataRequest> progressive_;
    NativeRegularMetadataJob::Pointer progressive_job_;
    bool progressive_finished_=false;
    std::optional<MetadataCaptureCleanupError> progressive_finish_error_;
    std::array<char,128> progressive_finish_operation_{};
};

} // namespace ck::files
