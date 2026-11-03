// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "opened_entry.hpp"
#include <array>

namespace ck::files {
enum class RegularMetadataScope : std::uint32_t {
    CompleteMetadataV1 = 0, OrdinaryCallerVisibleV1 = 1
};
enum class MetadataOwnership : std::uint32_t { Original = 0, CurrentCaller = 1 };
// V1 replays regular-file and directory logical metadata, not inode identity, ctime, link
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
struct MetadataReplayChannelState final {
    NativeFeatureIdentifier identifier;
    ObjectIdentity owner;
    std::uint64_t logical_size=0;
};
// A held logical data stream, distinct from a directory entry. Its identity
// is the base-object identity plus the exact native stream identifier. These
// readers belong to one native worker; they do not promise immutable data.
class MetadataReplayChannelSource {
public:
    virtual ~MetadataReplayChannelSource()=default;
    virtual Observation<MetadataReplayChannelState> inspect() const=0;
    virtual Observation<ContentRead> read_content(ContentReadLimits,std::uint64_t,std::stop_token = {}) const=0;
};
struct MetadataReplayChannelSnapshot final {
    NativeFeatureIdentifier identifier;
    std::uint64_t logical_size=0;
    std::array<std::byte,32> digest{};
    std::shared_ptr<const MetadataReplayChannelSource> source;
};
enum class MetadataSecurityCoverage { Unknown, WindowsPersistentSecurityV1, LinuxPersistentSecurityV1 };
// Evidence is produced after native queries, not selected by policy. Native
// target adapters validate their own evidence type and recheck the held source
// before replay and publication. Coverage excludes OS-derived transient trust
// caches; protected EAs that cannot be replayed still refuse the operation.
class MetadataSecurityCoverageEvidence {
public:
    virtual ~MetadataSecurityCoverageEvidence()=default;
    virtual MetadataSecurityCoverage family() const noexcept=0;
    virtual Observation<bool> recheck(const MetadataReplaySnapshot&) const=0;
};
// Opaque adapter-issued binding of the complete stream set and native readers.
// Native validation, not a caller-created implementation, authorizes replay.
class MetadataReplayChannelEvidence {
public:
    virtual ~MetadataReplayChannelEvidence()=default;
};
struct MetadataReplaySnapshot final {
    MetadataReplayPolicy policy;
    BasicMetadata basic;
    AttributeCoverage attribute_coverage = AttributeCoverage::Unknown;
    std::vector<AttributeValue> attributes;
    std::vector<NativeSecurityValue> security;
    std::shared_ptr<const MetadataSecurityCoverageEvidence> security_coverage;
    DataChannelCoverage channel_coverage=DataChannelCoverage::Unknown;
    std::vector<MetadataReplayChannelSnapshot> channels;
    std::shared_ptr<const MetadataReplayChannelEvidence> channel_evidence;
};
Observation<std::shared_ptr<const MetadataReplayChannelEvidence>> issue_native_metadata_replay_channels(
    const OpenedEntry&,const MetadataReplaySnapshot&,std::stop_token = {});
// Rechecks private native issuer identity, policy, limits, exact manifest and
// held readers/catalog. It does not freeze bytes; use source verification with
// cancellation to rehash before publication. Do not hash evidence addresses.
Observation<bool> verify_native_metadata_replay_channels(const MetadataReplaySnapshot&);
Observation<std::array<std::byte,32>> digest_metadata_replay_channel(const MetadataReplayChannelSource&,
    const NativeFeatureIdentifier&,const ObjectIdentity&,std::uint64_t,std::stop_token = {});
// Bounded inventory through the retained native object. Capture twice and
// compare before use; a held handle alone does not exclude concurrent writers.
Observation<MetadataReplaySnapshot> capture_metadata_replay(const OpenedEntry&, MetadataReplayPolicy,
                                                            std::stop_token = {});
Observation<bool> verify_metadata_replay_source(const OpenedEntry&, const MetadataReplaySnapshot&,
                                               std::stop_token = {});
Observation<bool> apply_metadata_replay(OpenedEntry&, const MetadataReplaySnapshot&, std::stop_token = {});
Observation<bool> verify_metadata_replay(const OpenedEntry&, const MetadataReplaySnapshot&,
                                        const BasicMetadata& applied, std::stop_token = {});
// Metadata values and exact stream manifest only: NO stream-content proof.
// A cooperative executor must separately hash every independent native target
// reader and compare to its open source proof before claiming preservation.
// This primitive grants neither mutation nor publication authority.
Observation<bool> verify_metadata_replay_values(const OpenedEntry&, const MetadataReplaySnapshot&,
                                               const BasicMetadata& applied, std::stop_token = {});
// Native creation authority is separate from momentary access and rename
// capabilities. Qualification never creates a directory. The factory is
// no-replace, retains the actual created object, and never adopts a name reopen.
class NativeCreatedDirectory;
Observation<bool> qualify_native_directory_creation(const DirectoryCursor&,const MetadataReplayPolicy&);
Observation<std::unique_ptr<NativeCreatedDirectory>> create_native_directory(
    std::shared_ptr<const DirectoryCursor> parent,NativeName name,const MetadataReplayPolicy&);
// Worker-only live authority; never reconstructed from journal bytes. Creation
// or barrier failure can have effects: callers must journal intent first and
// must not perform path cleanup or assume an unavailable result means absent.
class NativeCreatedDirectory final {
public:
    ~NativeCreatedDirectory()=default;
    NativeCreatedDirectory(const NativeCreatedDirectory&)=delete;
    NativeCreatedDirectory& operator=(const NativeCreatedDirectory&)=delete;
    const std::shared_ptr<const DirectoryCursor>& cursor() const noexcept{return cursor_;}
    OpenedEntry& metadata_writer() noexcept{return *writer_;}
    const BasicMetadata& created_metadata() const noexcept{return created_;}
    // Fully closes the actual creation/metadata writer, retaining the result.
    // The cursor and verifier own independent read-only file descriptions.
    Observation<bool> finish_io();
    // Independent held-object metadata verification after successful close.
    // Namespace membership is a separate executor responsibility.
    Observation<bool> verify_metadata(const MetadataReplaySnapshot&,const BasicMetadata& applied,
        std::stop_token = {}) const;
private:
    friend Observation<std::unique_ptr<NativeCreatedDirectory>> create_native_directory(
        std::shared_ptr<const DirectoryCursor>,NativeName,const MetadataReplayPolicy&);
    NativeCreatedDirectory(std::shared_ptr<const DirectoryCursor> parent,NativeName name,
        std::shared_ptr<const DirectoryCursor> cursor,std::unique_ptr<OpenedEntry> writer,
        std::unique_ptr<OpenedEntry> verifier,BasicMetadata created,MetadataReplayPolicy policy)
        :parent_(std::move(parent)),name_(std::move(name)),cursor_(std::move(cursor)),writer_(std::move(writer)),
         verifier_(std::move(verifier)),created_(std::move(created)),policy_(policy){}
    std::shared_ptr<const DirectoryCursor> parent_;
    NativeName name_;
    std::shared_ptr<const DirectoryCursor> cursor_;
    std::unique_ptr<OpenedEntry> writer_,verifier_;
    BasicMetadata created_;
    MetadataReplayPolicy policy_;
    std::optional<Observation<bool>> finish_result_;
};

} // namespace ck::files
