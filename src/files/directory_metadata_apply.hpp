// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "directory_execution_source.hpp"
namespace ck::files {
class NativeDirectoryReplayJob;
// Nonmutating qualification of an OPEN native source proof. This is separate
// from destination access and native directory creation qualification.
Observation<bool> qualify_directory_metadata_source(const NativeMetadataProof&);
enum class DirectoryApplyPhase { Preflight, ChannelCatalog, RemoveChannels, OpenChannel, ReadChannel,
    WriteChannel, CloseChannel, AwaitingVerifier, AttributeCatalog, RemoveAttributes, OrdinaryAttributes,
    Ownership, InitialBasic, Security, PrivilegedAttributes, FinalBasic, Complete, Cancelled, Failed };
struct DirectoryApplyProgress final {
    DirectoryApplyPhase phase=DirectoryApplyPhase::Preflight;
    std::uint64_t read_calls=0,read_bytes=0,write_calls=0,write_bytes=0;
    bool effects=false,worker_drained=false;
    DirectorySourceFailure failure,finish_failure;
};
// Borrowed native base writer, owned incremental stream writers. The enclosing
// executor journals metadata intent BEFORE constructing this job. Exactly one
// bounded source read or target write occurs in an advance; no bulk ADS helper.
class DirectoryMetadataApplyJob final {
public:
    using Pointer=std::unique_ptr<DirectoryMetadataApplyJob>;
    ~DirectoryMetadataApplyJob();
    const DirectoryApplyProgress& progress()const noexcept;
    const BasicMetadata& applied_basic()const noexcept;
    DirectoryApplyProgress advance(std::stop_token={});
    Observation<bool> finish_io();
private:
    friend class NativeDirectoryReplayJob;
    static Observation<Pointer> create(OpenedEntry&,HeldChild::Pointer,
        std::shared_ptr<const DirectoryCursor>,std::shared_ptr<const NativeMetadataProof>,
        PreparedJournalRoot::Pointer,ContentReadLimits,std::function<Observation<bool>(std::stop_token)>);
    // The executor opens its independent target readers here, before final
    // security. No further stream effects occur once this gate is reached.
    Observation<bool> continue_metadata();
    struct Impl;
    explicit DirectoryMetadataApplyJob(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
} // namespace ck::files
