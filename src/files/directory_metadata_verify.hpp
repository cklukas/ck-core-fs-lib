// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "directory_execution_source.hpp"
#include "sha256.hpp"
namespace ck::files {
class NativeDirectoryReplayJob;
// Execution ledger component, NOT the reviewed V3 digest or mutation authority.
// Only directory mtime may change when already-verified children are published.
// All other canonical metadata/ADS remain bound to the pre-effects proof.
Observation<std::array<std::byte,32>> directory_metadata_payload_digest(const NativeMetadataProof&);
// Pure value hashing. Neither the snapshot nor its coverage-family marker is
// native replay evidence, and no channel/source/target handles are retained.
Observation<std::array<std::byte,32>> directory_metadata_payload_digest_values(const MetadataReplaySnapshot&);
enum class DirectoryVerifyPhase { Preflight, Basic, AttributeCatalog, Attributes, Security,
    ChannelCatalog, OpenChannel, ReadChannel, Postflight, Complete, Cancelled, Failed };
struct DirectoryVerifyProgress final {
    DirectoryVerifyPhase phase=DirectoryVerifyPhase::Preflight;
    std::uint64_t read_calls=0,read_bytes=0;
    DirectorySourceFailure failure;
};
// The owning native directory executor preopens independent target readers
// before applying restrictive security, closes its writer, then constructs this
// verifier. No public factory accepts a caller-created OpenedEntry as native
// target evidence. Its borrowed reader owners finish in the enclosing job.
class DirectoryMetadataVerifyJob final {
public:
    using Pointer=std::unique_ptr<DirectoryMetadataVerifyJob>;
    const DirectoryVerifyProgress& progress()const noexcept{return progress_;}
    DirectoryVerifyProgress advance(std::stop_token={});
    void release_readers()noexcept;
    // Actual target query results, available only after independent data hashes
    // and final version checks succeed. This is NOT a NativeMetadataProof.
    const MetadataReplaySnapshot* observed_values()const noexcept {
        return progress_.phase==DirectoryVerifyPhase::Complete?&observed_:nullptr;
    }
private:
    friend class NativeDirectoryReplayJob;
    static Observation<Pointer> create(const OpenedEntry&,std::shared_ptr<const NativeMetadataProof>,
        BasicMetadata applied,ContentReadLimits,std::function<Observation<bool>(std::stop_token)>);
    DirectoryMetadataVerifyJob(const OpenedEntry&,std::shared_ptr<const NativeMetadataProof>,BasicMetadata,
        ContentReadLimits,std::function<Observation<bool>(std::stop_token)>);
    Observation<bool> basic(bool final)const;
    Observation<bool> native_evidence()const;
    void fail(const UnavailableObservation&)noexcept;
    void fail(ObservationState,ErrorDomain,std::int64_t,std::string_view)noexcept;
    const OpenedEntry* target_;
    std::shared_ptr<const NativeMetadataProof> source_;
    BasicMetadata applied_,before_;
    MetadataReplaySnapshot observed_;
    ContentReadLimits limits_;
    std::function<Observation<bool>(std::stop_token)> membership_;
    DirectoryVerifyProgress progress_;
    std::size_t index_=0;
    std::uint64_t offset_=0;
    Sha256 hash_;
    std::shared_ptr<const MetadataReplayChannelSource> reader_;
};
} // namespace ck::files
