// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "opened_entry.hpp"

namespace ck::files {
enum class RegularMetadataScope : std::uint32_t {
    CompleteMetadataV1 = 0, OrdinaryCallerVisibleV1 = 1
};
enum class MetadataOwnership : std::uint32_t { Original = 0, CurrentCaller = 1 };
// V1 replays regular-file logical metadata, not inode identity, ctime, link
// topology or physical allocation. Ordinary scope leaves arbitrary hidden
// POSIX namespaces unknown; complete scope must qualify their visibility.
struct MetadataReplayPolicy final {
    std::uint32_t version = 1;
    RegularMetadataScope scope = RegularMetadataScope::CompleteMetadataV1;
    MetadataOwnership ownership = MetadataOwnership::Original;
    bool allow_privilege_metadata = false;
    InventoryLimits limits{};
    bool valid() const noexcept;
};
struct MetadataReplaySnapshot final {
    MetadataReplayPolicy policy;
    BasicMetadata basic;
    AttributeCoverage attribute_coverage = AttributeCoverage::Unknown;
    std::vector<AttributeValue> attributes;
    std::vector<NativeSecurityValue> security;
};
// Bounded inventory through the retained native object. Capture twice and
// compare before use; a held handle alone does not exclude concurrent writers.
Observation<MetadataReplaySnapshot> capture_metadata_replay(const OpenedEntry&, MetadataReplayPolicy,
                                                            std::stop_token = {});
Observation<bool> verify_metadata_replay_source(const OpenedEntry&, const MetadataReplaySnapshot&,
                                               std::stop_token = {});
Observation<bool> apply_metadata_replay(OpenedEntry&, const MetadataReplaySnapshot&, std::stop_token = {});
Observation<bool> verify_metadata_replay(const OpenedEntry&, const MetadataReplaySnapshot&,
                                        const BasicMetadata& applied, std::stop_token = {});
} // namespace ck::files
