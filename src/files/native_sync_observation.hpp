// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "held_child.hpp"
#include "metadata_replay.hpp"
#include "metadata_semantic_digest.hpp"
#include "sync_baseline.hpp"
#include <map>
#include <memory>
namespace ck::files {
struct NativeSyncProofLimits final {
    std::uint64_t max_file_bytes=64*1024*1024;
    std::uint64_t max_total_bytes=512*1024*1024;
    std::size_t max_entries=128;
    std::size_t max_metadata_bytes=16*1024*1024;
    std::size_t chunk_bytes=64*1024;
    SyncBaselineLimits baseline{};
};
struct NativeSyncProofBudget final { std::uint64_t bytes=0,metadata=0;std::size_t entries=0; };
inline constexpr std::uint64_t native_sync_metadata_digest_version=metadata_semantic_digest_version;
// Shared by verified receipts, the two-way coordinator and named resolution.
// A semantic-schema change must never silently reuse an older baseline policy.
SyncDigest native_sync_policy_binding(const SyncDigest&,const MetadataReplayPolicy&) noexcept;
struct NativeSyncChannelFacts final {
    DataChannelCoverage coverage=DataChannelCoverage::Unknown;
    std::uint64_t named_stream_count=0;
    // Available only for qualified Windows FileStreamInfo logical DATA scope.
    // POSIX ordinary preservation does not prove every hidden provider stream.
    std::optional<std::uint64_t> all_stream_logical_bytes;
    SyncDigest semantic_digest{};
};
struct NativeSyncFileProof final {
    std::vector<NativeName> components;
    HeldChild::Pointer held;
    MetadataReplaySnapshot metadata;
    SyncEntryStatus status;
    // Independent native query handle, opened under the retained parent and
    // compared to held BEFORE catalog/capture; no caller reader/hash authority.
    std::shared_ptr<const OpenedEntry> native_source;
    NativeSyncChannelFacts channel_facts;
};
struct NativeSyncInventory final {
    std::shared_ptr<const DirectoryCursor> root;
    BasicMetadata root_metadata;
    std::map<std::string,NativeSyncFileProof> files;
};
bool native_sync_same_ownership(const MetadataReplaySnapshot&,const MetadataReplaySnapshot&);
bool native_sync_same_version(const BasicMetadata&,const BasicMetadata&) noexcept;
std::string native_sync_key(std::span<const NativeName>);
// Requires an actual native source. Authenticates native stream/security
// evidence and rehashes source metadata with cancellation before digesting it.
Observation<SyncDigest> native_sync_metadata_digest(const OpenedEntry&,const MetadataReplaySnapshot&,std::stop_token={});
// Root-level file executor has no directory-ADS replay/convergence contract.
// Qualified empty directory catalog (zero unnamed main) only; never path reopen.
Observation<bool> qualify_native_sync_root_channels(const DirectoryCursor&,InventoryLimits={});
Observation<NativeSyncFileProof> observe_native_sync_file(std::shared_ptr<const DirectoryCursor>,NativeName,
    MetadataReplayPolicy,const NativeSyncProofLimits&,NativeSyncProofBudget&,std::stop_token={});
// Fresh exact root enumeration is bracketed by native directory versions. V1
// admits ordinary regular files only; structural directory metadata is not
// manufactured from mode bits. Unsupported kinds fail before execution.
// The map's move constructor may allocate on MSVC. Transfer a unique owner
// through Observation instead of asserting a false noexcept payload contract.
Observation<std::unique_ptr<NativeSyncInventory>> observe_native_sync_root(std::shared_ptr<const DirectoryCursor>,
    MetadataReplayPolicy,const NativeSyncProofLimits&,NativeSyncProofBudget&,std::stop_token={});
Observation<bool> compare_native_sync_inventories(const NativeSyncInventory&,const NativeSyncInventory&);
} // namespace ck::files
