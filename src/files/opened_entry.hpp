// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "file_metadata.hpp"
#include "data_channels.hpp"
#include "attributes.hpp"
#include "security.hpp"
#include "storage_info.hpp"
#include "link_metadata.hpp"
#include "data_layout.hpp"
#include "file_limits.hpp"
#include "integrity_info.hpp"
#include "inode_flags.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <stop_token>
#include <vector>

namespace ck::files {

class DirectoryCursor;
class NativeName;
struct MetadataReplayPolicy;
struct MetadataReplaySnapshot;
class MetadataSecurityCoverageEvidence;
class MetadataReplayChannelSource;

// Requested OS access only; never authority for mutation, loss or hydration.
// Layout is an explicit regular-file query opt-in and can require data-read
// permission on platforms that need an additional readable handle.
// InodeFlags independently requests a Linux regular-file readable handle.
enum class EntryAccess : unsigned {
    MetadataOnly = 0, MetadataAndAttributes = 1, MetadataAndSecurity = 2,
    MetadataAndFullSecurity = 6, MetadataAndLayout = 8, MetadataAndInodeFlags = 16, ContentRead = 32,
    // Windows-only source exclusion for cross-filesystem moves. POSIX
    // adapters refuse this request rather than imply writer exclusion.
    MoveSource = 64,
    // Windows rename guard: requests DELETE and denies WRITE/DELETE sharing.
    // Only this exact held handle may rename the object. Sharing alone does
    // not freeze preexisting writable mappings; qualify_stable_content must
    // separately succeed before relying on a digest for retention.
    RenameSource = 128
};
constexpr EntryAccess operator|(EntryAccess left, EntryAccess right) noexcept {
    return static_cast<EntryAccess>(static_cast<unsigned>(left) | static_cast<unsigned>(right));
}
constexpr bool valid_entry_access(EntryAccess access) noexcept {
    const auto bits = static_cast<unsigned>(access);
    return (bits & ~255U) == 0 && ((bits & 4U) == 0 || (bits & 2U) != 0) && (bits & 192U) != 192U;
}
constexpr bool requests_attributes(EntryAccess access) noexcept { return (static_cast<unsigned>(access) & 1U) != 0; }
constexpr bool requests_security(EntryAccess access) noexcept { return (static_cast<unsigned>(access) & 2U) != 0; }
constexpr bool requests_audit_security(EntryAccess access) noexcept { return (static_cast<unsigned>(access) & 4U) != 0; }
constexpr bool requests_inode_flags(EntryAccess access) noexcept { return (static_cast<unsigned>(access) & 16U) != 0; }
constexpr bool requests_content_read(EntryAccess access) noexcept { return (static_cast<unsigned>(access) & 32U) != 0; }
constexpr bool requests_move_source(EntryAccess access) noexcept { return (static_cast<unsigned>(access) & 64U) != 0; }
constexpr bool requests_rename_source(EntryAccess access) noexcept { return (static_cast<unsigned>(access) & 128U) != 0; }
constexpr bool requests_layout(EntryAccess access) noexcept { return (static_cast<unsigned>(access) & 8U) != 0; }

struct ContentReadLimits {
    std::size_t max_bytes = 64 * 1024;
    static constexpr std::size_t hard_max_bytes = 4 * 1024 * 1024;
    bool valid() const noexcept { return max_bytes > 0 && max_bytes <= hard_max_bytes; }
};
struct ContentRead {
    std::vector<std::byte> bytes;
    bool complete = false;
};

struct ContentWriteLimits {
    std::size_t max_bytes = 4 * 1024 * 1024;
    static constexpr std::size_t hard_max_bytes = 4 * 1024 * 1024;
    bool valid() const noexcept { return max_bytes > 0 && max_bytes <= hard_max_bytes; }
};

// Owns the opened object, independently of the original parent/name. Queries
// use that object even if its entry is renamed, replaced or unlinked. This does
// not freeze content, prove continued parent membership, or authorize mutation.
// Opening and inspecting belong to workers; native calls can block. This initial
// boundary has no write, shell or elevation API. Attribute values can themselves
// carry data/security information; reads are explicit and bounded.
class OpenedEntry {
public:
    virtual ~OpenedEntry() = default;
    OpenedEntry(const OpenedEntry&) = delete;
    OpenedEntry& operator=(const OpenedEntry&) = delete;
    virtual Observation<BasicMetadata> inspect_basic() const = 0;
    // Directory objects only. Opens a metadata-only parent reference through
    // the held object. No original path reopen or enumeration; native support
    // and permissions may refuse. A live edge observation, not a stable path.
    virtual Observation<std::unique_ptr<OpenedEntry>> open_parent_directory() const;
    // Bound for this held inode only. On a directory this concerns the
    // directory itself, never prospective child files. No content access.
    virtual Observation<FileLinkLimits> inspect_link_limits() const;
    // Fixed read-only integrity configuration query through the retained
    // object. Does not enable/disable integrity or read/verify any content.
    virtual Observation<FileIntegrityInfo> inspect_integrity(InventoryLimits limits = {}) const;
    // Linux regular-file FS_IOC_GETFLAGS. Explicit independent read-access
    // opt-in; no content reads or setters. Other platforms are Unsupported.
    virtual Observation<FileInodeFlags> inspect_inode_flags(InventoryLimits limits = {}) const;
    virtual Observation<StorageInfo> inspect_storage() const;
    // Explicit opt-in layout access can require native data-read permission;
    // this query seeks/queries metadata and never reads file content. Main data
    // only, regular files only. No hydration consent or dense-file fallback.
    virtual Observation<FileDataLayout> inspect_data_layout(InventoryLimits limits = {}, std::stop_token stop = {}) const;
    virtual Observation<LinkMetadata> read_link_metadata(InventoryLimits limits = {}) const;
    // Native channel identifiers and sizes only; no channel content is read.
    // Coverage is explicit. Unsupported is not evidence that channels are absent.
    // This live query does not establish complete metadata or snapshot stability.
    virtual Observation<DataChannelCatalog> inspect_data_channels(InventoryLimits limits = {}) const;
    virtual Observation<AttributeCatalog> inspect_attributes(InventoryLimits limits = {}) const;
    virtual Observation<AttributeValue> read_attribute(const NativeFeatureIdentifier& identifier, InventoryLimits limits = {}) const;
    virtual Observation<NativeSecurityValue> read_security(SecurityPart part, InventoryLimits limits = {}) const;
    virtual Observation<ContentRead> read_content(ContentReadLimits limits = {}, std::uint64_t offset = 0,
                                                   std::stop_token stop = {}) const;
    // Explicit staging-file write boundary. The object must have been created
    // by the worker's held parent with write access; this is not a path-based
    // replacement API and does not publish a destination name.
    virtual Observation<std::size_t> write_content(std::uint64_t offset, std::span<const std::byte> bytes,
                                                    ContentWriteLimits limits = {}, std::stop_token stop = {});
    virtual Observation<bool> flush_content();
    // Worker-only terminal boundary for operation-owned writable handles.
    // Flushes and closes them, retaining the result for idempotent calls. Native
    // adapters detach handles before close and never retry a consumed close,
    // including EINTR. No live inspection or further writes are available
    // afterward: capture qualified committed evidence before calling this.
    // The default succeeds only for portable fakes with no native handles;
    // every native writable adapter must override it.
    virtual Observation<bool> finish_content_writes();
    // Worker-only proof for the lifetime of this held guard, checked before
    // and after data verification and immediately before mutation. Ordinary
    // share exclusion does not qualify preexisting writable mappings. Default
    // refuses; no provider or oplock-break proof may be inferred from an ID.
    virtual Observation<bool> qualify_stable_content() const;
    // Strict ordinary-file qualification through this held object. Success
    // requires an audited local filesystem, caller-visible attribute inventory,
    // explicit ACL / known label/capability absence, ordinary storage flags and
    // dense main-data layout. Arbitrary hidden attribute namespaces remain
    // UNKNOWN: success qualifies only OrdinaryCallerVisibleV1. May acquire metadata-query read rights through
    // the held descriptor; never reopens the original source name.
    virtual Observation<bool> qualify_ordinary_regular_metadata() const;
    // Staging-only explicit current effective uid/gid policy; never adopts
    // source ownership. Default refuses (including Windows).
    virtual Observation<bool> apply_current_caller_ownership();
    // Apply only the platform's explicitly qualified portable-basic metadata
    // subset to this worker-created staging object. This is not a complete
    // preservation operation: callers must account separately for ownership,
    // ACL/security, channels, attributes/xattrs, flags, provider state and any
    // timestamp field outside the adapter's documented subset.
    virtual Observation<bool> apply_portable_basic_metadata(const BasicMetadata& source);
    // Apply one already-inventoried non-security attribute to this held
    // staging object. Security/ACL attributes have a separate adapter
    // contract and are refused here; the caller must bind the value to its
    // reviewed source identity before invoking this worker-only boundary.
    virtual Observation<bool> apply_nonsecurity_attribute(const AttributeValue& source);
    // Worker-only staging replay. Native adapters qualify provider coverage,
    // never elevate, and retain native Denied/Unsupported results.
    virtual Observation<bool> qualify_metadata_replay(const MetadataReplayPolicy&) const;
    // Policy-specific read rights acquired through the retained native
    // identity, never the source basename. A returned entry owns a per-capture
    // query handle, avoiding shared mutable access state. Available(nullptr)
    // explicitly uses the existing object (POSIX); denial never weakens capture.
    virtual Observation<std::unique_ptr<OpenedEntry>> open_metadata_replay_view(const MetadataReplayPolicy&) const;
    // Worker-only independent metadata writer for this held directory. No
    // basename reopen, data writes, or publication authority is conferred.
    // Apply after descendants; finish_content_writes closes only this view.
    virtual Observation<std::unique_ptr<OpenedEntry>> open_directory_metadata_target(const MetadataReplayPolicy&) const;
    virtual Observation<bool> apply_replay_ownership(const BasicMetadata&, const MetadataReplayPolicy&);
    virtual Observation<bool> apply_replay_attribute(const AttributeValue&, const MetadataReplayPolicy&);
    virtual Observation<bool> remove_replay_attribute(const NativeFeatureIdentifier&, const MetadataReplayPolicy&);
    virtual Observation<bool> apply_replay_security(const NativeSecurityValue&, const MetadataReplayPolicy&);
    virtual Observation<bool> verify_replay_security(const NativeSecurityValue&, const MetadataReplayPolicy&) const;
    virtual Observation<bool> apply_replay_basic(const BasicMetadata&, const MetadataReplayPolicy&);
    // Publish this worker-created staging object under a new destination name
    // relative to a held directory. The default refuses the operation; a
    // platform adapter must provide an atomic no-replace primitive and retain
    // an ambiguous native outcome for reconciliation.
    virtual Observation<bool> publish_noreplace(const DirectoryCursor& destination, const NativeName& name);
    // Exact held-source rename, never a source-basename reopen. Requires a
    // RenameSource handle and qualified source/destination adapters. Does not
    // prove that the original parent/name still refers to this held inode.
    virtual Observation<bool> rename_noreplace(const DirectoryCursor& source_parent,
        const DirectoryCursor& destination, const NativeName& name) const;
    virtual Observation<std::shared_ptr<const MetadataSecurityCoverageEvidence>> issue_metadata_security_coverage(
        const MetadataReplaySnapshot&) const;
    virtual Observation<bool> preflight_metadata_security_coverage(const MetadataReplaySnapshot&);
    virtual Observation<bool> verify_metadata_security_coverage(const MetadataReplaySnapshot&) const;
    virtual Observation<std::shared_ptr<const MetadataReplayChannelSource>> open_metadata_replay_channel_read(
        const NativeFeatureIdentifier&) const;
    virtual Observation<bool> apply_replay_channels(const MetadataReplaySnapshot&,std::stop_token = {});
protected:
    OpenedEntry() = default;
};

} // namespace ck::files
