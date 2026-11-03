// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "native_sync_coordinator.hpp"
namespace ck::files {
// 0.5 worker-only, root-flat KEEP_BOTH_NAMED. Original objects remain in
// place and visibly protected/pending; this is not canonical-name convergence.
// Qualified Linux main DATA and native Windows NTFS/ReFS logical DATA families.
// Windows admission requires native metadata/security/channel evidence and
// identity-bound no-replace publication; Mac remains typed Unsupported.
struct NativeSyncResolutionLimits final {
    std::size_t max_resolutions=16,max_added_paths=32,max_protected_objects=32;
    std::uint64_t max_name_bytes=64*1024,max_transfer_bytes=512*1024*1024;
    std::uint64_t max_proof_bytes=8ULL*1024*1024*1024;
};
struct NativeSyncNamedResolution final {
    std::size_t row;
    NativeName left_version_name,right_version_name;
};
enum class NativeSyncResolutionOperationKind { ProtectOriginal, PublishVersion };
struct NativeSyncResolutionOperation final {
    NativeSyncResolutionOperationKind kind;
    std::size_t source_row;
    bool source_right,destination_right;
    std::vector<NativeName> components;
    // Unnamed main DATA only; never an all-stream progress counter. Transfer
    // admission separately includes every qualified named DATA stream.
    std::uint64_t main_data_bytes;
};
// Additive worker API; the existing operation layout and main-data meaning
// remain unchanged. This is admission evidence, not completed transfer work.
struct NativeSyncResolutionStreamFactsV1 final {
    std::uint32_t version=1;
    DataChannelCoverage coverage=DataChannelCoverage::Unknown;
    std::uint64_t named_stream_count=0;
    std::optional<std::uint64_t> all_stream_logical_bytes;
};
struct NativeSyncResolutionReceiptState;
class NativeSyncResolutionReceipt final {
public:
    using Pointer=std::shared_ptr<const NativeSyncResolutionReceipt>;
    const std::vector<NativeSyncResolutionOperation>& operations() const noexcept;
    const SyncDigest& digest() const noexcept;
    const NativeSyncResolutionStreamFactsV1& stream_facts_v1(std::size_t operation) const;
private:
    std::shared_ptr<NativeSyncResolutionReceiptState> state_;
    explicit NativeSyncResolutionReceipt(std::shared_ptr<NativeSyncResolutionReceiptState> s):state_(std::move(s)){}
    friend class NativeSyncResolution;
};
class NativeSyncResolution final {
public:
    using Pointer=std::unique_ptr<NativeSyncResolution>;
    static Observation<Pointer> open(NativeSyncCoordinatorRequest,NativeSyncResolutionLimits={},std::stop_token={});
    ~NativeSyncResolution();
    const std::vector<NativeSyncReviewedRow>& rows() const noexcept;
    const std::vector<NativeName>& components(std::size_t row) const;
    const std::vector<NativeSyncProtectedEvidence>& protected_originals() const noexcept;
    const NativeSyncCoordinatorResult& result() const noexcept;
    const SyncSessionSnapshot& snapshot() const noexcept;
    Observation<NativeSyncResolutionReceipt::Pointer> assess(std::span<const NativeSyncNamedResolution>,std::stop_token={});
    Observation<bool> approve(const NativeSyncResolutionReceipt&,bool approve_first_run=false,std::stop_token={});
    NativeSyncCoordinatorState advance(std::stop_token={});
    Observation<bool> finish_io();
private:
    struct State;
    std::unique_ptr<State> state_;
    explicit NativeSyncResolution(std::unique_ptr<State>);
};
} // namespace ck::files
