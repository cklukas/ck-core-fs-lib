// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "held_child.hpp"
#include "operation_metadata_job.hpp"

namespace ck::files {

// Versioned requested scope, independent of blanket metadata-loss consent.
// CompleteMetadataV1 remains refused until every relevant namespace/class can
// be qualified. OrdinaryCallerVisibleV1 explicitly excludes arbitrary hidden
// xattr namespaces, birth/ctime, original ownership, physical allocation/clone
// identity and provider semantics outside the audited local-file adapter.
// It requires absent visible attributes and explicit absent ACL / known Linux
// labels, integrity xattrs and file capabilities, plus ordinary dense storage.
enum class RegularMetadataScope : std::uint32_t {
    CompleteMetadataV1 = 0,
    OrdinaryCallerVisibleV1 = 1
};
struct RegularMetadataScopeReport final {
    std::uint32_t version = 1;
    RegularMetadataScope requested = RegularMetadataScope::CompleteMetadataV1;
    // Unknown remains unknown even after successful ordinary-subset copying.
    ObservationState arbitrary_hidden_attributes = ObservationState::Unknown;
};


// Worker-owned, deliberately narrow preservation contract: ordinary regular
// files, mode 0777, atime/mtime, and explicitly current-caller ownership.
// Birth/ctime, hard-link topology, physical allocation/clone identity and
// arbitrary provider semantics are not represented by this contract. Known
// unsupported metadata and insufficient query coverage refuse strict copies.
// A held object is not a snapshot or writer exclusion.
class RegularMetadataPreservation final : public std::enable_shared_from_this<RegularMetadataPreservation> {
public:
    using Pointer = std::shared_ptr<RegularMetadataPreservation>;
    static Observation<Pointer> create(HeldChild::Pointer source, bool allow_unhandled_metadata_loss,
        RegularMetadataScope scope = RegularMetadataScope::CompleteMetadataV1, std::stop_token stop = {});
    RegularMetadataScopeReport scope_report() const noexcept { return {1, scope_, ObservationState::Unknown}; }
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
};

} // namespace ck::files
