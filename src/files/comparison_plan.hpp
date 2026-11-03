// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "file_metadata.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ck::files {

// Pure comparison/planning, main-data only unless explicitly opted into
// preserved-metadata comparison. No native I/O, mutation, consent, or
// preservation authorization. Adapter facts are claims to compare, never
// authority to execute an action. Executors must acquire held native evidence,
// validate topology/preservation, obtain review receipts, and revalidate again.
enum class ComparisonProfile { Copy, Move, Update, MissingOnly, Sync, Mirror, Compare };
enum class ComparisonMode { SizeAndMtime, Size, CompleteDigest };
enum class ComparisonTopology { Unknown, Disjoint, SameRoot, Overlap };
enum class ComparisonInventoryState { Unknown, CompleteStable, Incomplete, Denied, Changed, Failed };
enum class ComparisonObjectState { Unknown, Stable, Denied, Gone, Changed, Failed };
enum class ComparisonDigestState { Unknown, CompleteStable, Incomplete, Denied, Changed, Failed };
enum class ComparisonDigestAlgorithm { Unknown, Sha256 };

struct ComparisonObject final {
    ComparisonObjectState state = ComparisonObjectState::Unknown;
    std::optional<ObjectIdentity> identity;
    std::optional<ObjectKind> kind;
    std::optional<std::uint64_t> size;
    std::optional<FileTimestamp> modified;
    // Zero means unknown. A quantum is either a divisor of 1 second in ns,
    // or an integral number of seconds (at most 1 day). No inferred skew/DST.
    std::uint64_t timestamp_quantum_ns = 0;
    std::optional<std::uint64_t> change_cookie;
};

struct ComparisonDigest final {
    ComparisonDigestState state = ComparisonDigestState::Unknown;
    ComparisonDigestAlgorithm algorithm = ComparisonDigestAlgorithm::Unknown;
    std::array<std::byte, 32> bytes{};
    std::uint64_t bytes_read = 0;
    // CompleteStable is an adapter assertion about a full stable read, not a
    // conclusion from matching stat values. Both observations must also match
    // the entry exactly, including identity, size, and observed version fields.
    ComparisonObject before;
    ComparisonObject after;
};

enum class ComparisonMetadataOwnership { Unknown, Original, CurrentCaller };
struct ComparisonMetadataDigest final {
    ComparisonDigestState state = ComparisonDigestState::Unknown;
    ComparisonDigestAlgorithm algorithm = ComparisonDigestAlgorithm::Unknown;
    // Opaque canonical metadata schema and preservation-policy identifiers.
    // All-zero identifiers mean unknown. Equal hashes are comparable only
    // under the same qualified schema, policy and ownership interpretation.
    std::array<std::byte, 32> schema{}, policy_binding{}, bytes{};
    ComparisonMetadataOwnership ownership = ComparisonMetadataOwnership::Unknown;
    // Required and compared under CurrentCaller, whose preservation hash may
    // omit actual ownership. Original includes ownership in bytes' schema.
    // These are declarative canonical facts, never native issuer authority.
    std::optional<std::array<std::byte, 32>> canonical_owner_digest;
    // CompleteStable asserts a full stable metadata observation; matching
    // timestamps alone cannot establish it. Bind both observations exactly to
    // the entry, just as for a main-data digest. Main data is NOT in bytes.
    ComparisonObject before, after;
};

// Declarative execution contract facts, never native mutation authority.
// Version1 requires an executor that performs fresh review-bound capture,
// native creation/held-target binding and journaled postorder verification.
// The generic planner and every legacy C adapter default to Unknown.
enum class ComparisonDirectoryMetadataContract { Unknown, NativeOriginalPostorderV1 };
struct ComparisonEntry final {
    // Exact, lossless adapter comparison key, '/' separated relative components.
    // No empty, '.', '..', NUL or backslash components, absolute/drive paths.
    // Adapters must encode otherwise unrepresentable native names losslessly
    // and report case/normalization aliases via name_collision. No folding here.
    std::string relative_path;
    ComparisonObject object;
    std::optional<ComparisonDigest> digest;
    bool excluded = false;       // protects this path and its entire subtree
    bool name_collision = false;
    std::optional<ComparisonMetadataDigest> metadata_digest;
    ComparisonDirectoryMetadataContract directory_metadata_contract=ComparisonDirectoryMetadataContract::Unknown;
};

struct ComparisonInventory final {
    // CompleteStable qualifies the ENTIRE supplied tree, including absence.
    // A partial page must never be labeled CompleteStable. Entries may explicitly
    // represent unreadable objects. Excluded subtrees need not be enumerated.
    ComparisonInventoryState state = ComparisonInventoryState::Unknown;
    std::optional<ObjectIdentity> root;
    std::span<const ComparisonEntry> entries;
};

struct ComparisonFilters final {
    std::optional<std::uint64_t> minimum_size;
    std::optional<std::uint64_t> maximum_size;
    std::optional<FileTimestamp> modified_not_before; // inclusive
    std::optional<FileTimestamp> modified_before;     // exclusive
    // ObjectKind enum ordinal bits. Size/date filters apply to regular files;
    // directories remain traversable unless excluded by type/depth/path.
    std::uint64_t allowed_kind_mask = (1ULL << 10) - 1;
    std::size_t maximum_depth = 1024; // top-level entries have depth 1
};

struct ComparisonOptions final {
    ComparisonProfile profile = ComparisonProfile::Compare;
    ComparisonMode mode = ComparisonMode::SizeAndMtime;
    ComparisonTopology topology = ComparisonTopology::Unknown;
    std::uint64_t timestamp_quantum_ns = 1;
    ComparisonFilters filters;
    // Require qualified stable metadata for EVERY observed, nonprotected
    // regular file, including one-sided copy/removal candidates. Directories
    // remain unresolved until directory metadata has a preservation contract.
    // Byte-count completeness continues to describe main-data byte counts.
    bool compare_preserved_metadata = false;
    ComparisonDirectoryMetadataContract directory_metadata_contract=ComparisonDirectoryMetadataContract::Unknown;
};

struct ComparisonLimits final {
    std::size_t max_entries = 100'000; // combined source + destination
    std::size_t max_path_bytes = 4096;
    std::size_t max_total_path_bytes = 16 * 1024 * 1024; // includes exclusions
    std::size_t max_exclusions = 10'000;
    std::size_t max_page_rows = 256;
    std::uint64_t max_aggregate_bytes = 1ULL << 60; // each byte aggregate
    static constexpr std::size_t hard_max_entries = 1'000'000;
    static constexpr std::size_t hard_max_path_bytes = 65'536;
    static constexpr std::size_t hard_max_total_path_bytes = 256 * 1024 * 1024;
    static constexpr std::size_t hard_max_exclusions = 100'000;
    static constexpr std::size_t hard_max_page_rows = 4096;
};

enum class ComparisonRelation {
    Unknown, SourceOnly, DestinationOnly, SameSize, SameSizeAndMtime, Identical,
    SourceNewer, DestinationNewer, SizeDifferent, ContentDifferent, TypeConflict,
    DirectoryPair, Protected, MetadataDifferent
};
enum class ComparisonReason {
    UnknownObject, IncompleteInventory, UnqualifiedIdentity, MissingSize,
    MissingTimestamp, PrecisionUnavailable, DigestUnavailable, DigestIncomplete,
    DigestChanged, DigestBindingMismatch, SourceMissing, DestinationMissing,
    SameSize, SameSizeAndMtime, SameContent, SourceNewer, DestinationNewer,
    SizeMismatch, DigestMismatch, TypeMismatch, UnsupportedKind, DirectoryPair,
    Excluded, Filtered, FilterUnknown, ProtectedDescendant, NameCollision,
    ExistingDestination, EqualTimeConflict, AncestorConflict, SameObject,
    MetadataDigestUnavailable, MetadataDigestIncomplete, MetadataDigestChanged,
    MetadataDigestBindingMismatch, MetadataSchemaMismatch, MetadataPolicyMismatch,
    MetadataOwnerUnavailable, MetadataMismatch, DirectoryMetadataUnsupported
};
// Declarative proposals only. MoveAfterCommit requires verified publication of
// the whole affected subtree before source retirement; directory removal means
// EMPTY directory removal, never recursive deletion. No action authorizes I/O.
enum class ComparisonAction {
    Report, Skip, Review, CopyToDestination, MoveAfterCommit,
    CreateDestinationDirectory, MergeDirectories, ReplaceDestination,
    RemoveDestinationFile, RemoveDestinationDirectory
};

struct ComparisonIdentityState;
class ComparisonPlanIdentity final {
public:
    ComparisonPlanIdentity() = default;
    bool is_valid() const noexcept { return state_ != nullptr; }
    friend bool operator==(const ComparisonPlanIdentity&, const ComparisonPlanIdentity&) = default;
private:
    explicit ComparisonPlanIdentity(std::shared_ptr<const ComparisonIdentityState> state)
        : state_(std::move(state)) {}
    std::shared_ptr<const ComparisonIdentityState> state_;
    friend class ComparisonPlan;
};

class ComparisonDecisionToken final {
public:
    ComparisonDecisionToken() = default;
    bool is_valid() const noexcept { return plan_.is_valid() && row_id_ != 0; }
    ComparisonPlanIdentity plan_identity() const noexcept { return plan_; }
    std::uint64_t row_id() const noexcept { return row_id_; }
    friend bool operator==(const ComparisonDecisionToken&, const ComparisonDecisionToken&) = default;
private:
    ComparisonDecisionToken(ComparisonPlanIdentity plan, std::uint64_t row_id)
        : plan_(std::move(plan)), row_id_(row_id) {}
    ComparisonPlanIdentity plan_;
    std::uint64_t row_id_ = 0;
    friend class ComparisonPlan;
};

struct ComparisonRow final {
    std::uint64_t id = 0; // stable only within this plan; sorted by exact key
    std::string relative_path;
    std::optional<std::size_t> source_index;
    std::optional<std::size_t> destination_index;
    ComparisonRelation relation = ComparisonRelation::Unknown;
    ComparisonReason reason = ComparisonReason::UnknownObject;
    ComparisonAction action = ComparisonAction::Review;
    bool destination_protected = false;
    bool requires_review = false;
    ComparisonDecisionToken token;
};

struct ComparisonAggregate final {
    std::uint64_t rows = 0;
    std::uint64_t unknown_rows = 0;
    std::uint64_t protected_rows = 0;
    std::uint64_t review_rows = 0;
    std::uint64_t proposed_writes = 0;
    std::uint64_t proposed_removals = 0;
    std::uint64_t source_bytes = 0;
    std::uint64_t destination_bytes = 0;
    std::uint64_t proposed_copy_bytes = 0;
    // False means byte counts are known subtotals, never asserted totals.
    bool source_bytes_complete = true;
    bool destination_bytes_complete = true;
    bool proposed_copy_bytes_complete = true;
};

struct ComparisonPage final {
    ComparisonPlanIdentity identity;
    std::vector<ComparisonRow> rows; // bounded copies; no borrowed lifetimes
    std::size_t total_rows = 0;
    std::optional<std::size_t> next_offset;
};

enum class ComparisonRevalidation { Matches, ForeignToken, EvidenceChanged, InvalidInput };

class ComparisonPlan final {
public:
    using Pointer = std::shared_ptr<const ComparisonPlan>;
    ComparisonPlan(const ComparisonPlan&) = delete;
    ComparisonPlan& operator=(const ComparisonPlan&) = delete;

    // Fails closed (no partial plan) for invalid limits/options/keys, duplicate
    // keys, impossible tree structure, unsafe topology, or aggregate overflow.
    // Allocation failures may throw at this internal C++ boundary; C adapters
    // must translate exceptions. No C ABI or platform dependency is introduced.
    static Observation<Pointer> create(const ComparisonOptions& options,
        const ComparisonInventory& source, const ComparisonInventory& destination,
        std::span<const std::string> excluded_paths = {}, ComparisonLimits limits = {});

    ComparisonPlanIdentity identity() const noexcept { return identity_; }
    const ComparisonOptions& options() const noexcept { return options_; }
    const ComparisonAggregate& aggregate() const noexcept { return aggregate_; }
    const std::vector<ComparisonEntry>& source_entries() const noexcept { return source_; }
    const std::vector<ComparisonEntry>& destination_entries() const noexcept { return destination_; }
    const std::vector<std::string>& excluded_paths() const noexcept { return exclusions_; }
    // offset == total_rows returns an empty terminal page; zero/oversize limits
    // and offsets beyond the end fail. No cursor is valid across plan identities.
    Observation<ComparisonPage> page(std::size_t offset, std::size_t limit) const;

    // Compares the WHOLE frozen evidence set, including absences, exact object
    // identity/version, digest qualification, exclusions, roots and options.
    // Entry/exclusion input order is irrelevant. A match is NOT mutation consent.
    // Tokens are opaque, process-local identities, not serializable credentials.
    ComparisonRevalidation revalidate(const ComparisonDecisionToken& token,
        const ComparisonOptions& options, const ComparisonInventory& source,
        const ComparisonInventory& destination,
        std::span<const std::string> excluded_paths = {}) const;

private:
    ComparisonPlan() = default;
    ComparisonOptions options_;
    ComparisonLimits limits_;
    ComparisonPlanIdentity identity_;
    ComparisonInventoryState source_state_ = ComparisonInventoryState::Unknown;
    ComparisonInventoryState destination_state_ = ComparisonInventoryState::Unknown;
    std::optional<ObjectIdentity> source_root_;
    std::optional<ObjectIdentity> destination_root_;
    std::vector<ComparisonEntry> source_;
    std::vector<ComparisonEntry> destination_;
    std::vector<std::string> exclusions_;
    std::vector<ComparisonRow> rows_;
    ComparisonAggregate aggregate_;
};

} // namespace ck::files
