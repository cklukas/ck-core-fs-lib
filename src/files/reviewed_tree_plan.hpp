// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "comparison_plan.hpp"
#include "conflict_rules.hpp"
#include "metadata_capture_job.hpp"
#include "native_operation_copy_job.hpp"
#include <stop_token>

namespace ck::files {

// Worker-only inputs. Roots must be held directory children, not namespace
// roots. All enumeration, reads and writes resolve exact NativeName components
// through these owners. Addresses are journal recovery/navigation values only.
struct ReviewedTreePlanRequest final {
    HeldChild::Pointer source_root, destination_root;
    std::optional<NativeAbsolutePath> destination_address;
    ComparisonOptions comparison{}; // topology is derived; CompleteDigest required
    ComparisonLimits limits{};
    NativeOperationCopyBatchPolicy copy_policy{};
    std::optional<NativeAbsolutePath> journal_root;
    OperationJournalId journal_id{}; // caller supplies a unique operation ID
    std::function<Observation<std::unique_ptr<OperationJournalFile>>(
        const NativeAbsolutePath&, const NativeName&, bool)> open_journal;
    std::size_t digest_chunk_bytes = 64 * 1024;
    // Typed native authority; journal_root remains a navigation/encoding hint.
    std::shared_ptr<PreparedJournalRoot> prepared_journal_root = {};
    // Cumulative native metadata/data-stream admission for each independent
    // scan; read.max_bytes is always replaced by digest_chunk_bytes.
    MetadataCaptureLimits metadata_limits{};
};

enum class ReviewedTreeState {
    Inventory, AwaitingReview, Revalidating, Executing, Complete,
    Failed, Cancelled, Partial, NeedsReconciliation
};
enum class ReviewedTreeAction { Report, Skip, Copy, CreateDirectory, MergeDirectory, Replace, RemoveFile, RemoveDirectory };
enum class ReviewedTreeItemState { Pending, Skipped, Complete, Failed, Cancelled, NeedsReconciliation };
enum class ReviewedTreeNameSide { Incoming, Target };
struct ReviewedTreeNameChoice final {
    ComparisonDecisionToken token;
    NativeName name;
    ReviewedTreeNameSide side = ReviewedTreeNameSide::Incoming;
};
struct ReviewedTreeFacts final {
    bool source_present = false, destination_present = false;
    std::optional<ObjectKind> source_kind, destination_kind;
    std::optional<std::uint64_t> source_size, destination_size;
    std::optional<FileTimestamp> source_modified, destination_modified;
    std::uint64_t timestamp_quantum_ns = 0;
    // ConflictChoice ordinal bits: eligibility in this frozen plan, never
    // execution authority or a promise that a subsequent native call succeeds.
    std::uint64_t allowed_choices = 0;
    bool retained_target_available = false;
    ConflictClass conflict_class = ConflictClass::Unavailable;
    // Closed native source observations, value facts only. Unknown metadata
    // never grants strict mutation authority. Main data has a separate digest.
    std::optional<ComparisonMetadataDigest> source_metadata, destination_metadata;
    std::optional<UnavailableObservation> source_metadata_failure, destination_metadata_failure;
};
struct ReviewedTreeItem final {
    ComparisonRow row;
    std::vector<NativeName> relative_components; // exact native values for presentation; never parsed keys
    ReviewedTreeAction action = ReviewedTreeAction::Report;
    ReviewedTreeItemState state = ReviewedTreeItemState::Pending;
    std::optional<ConflictRuleResult> decision;
    std::optional<UnavailableObservation> failure;
    std::optional<OperationJournalId> journal_id;
    std::optional<NativeName> journal_name, staging_name;
    std::optional<NativeName> retained_name;
    std::optional<OperationJournalId> retention_journal_id;
    bool recovery_required = false;
    ReviewedTreeFacts facts;
    std::optional<NativeName> proposed_name, resulting_name;
    std::optional<ReviewedTreeNameSide> name_side;
    bool target_retained = false;
};
struct ReviewedTreePage final {
    ComparisonPlanIdentity identity;
    std::vector<ReviewedTreeItem> items;
    std::size_t total_rows = 0;
    std::optional<std::size_t> next_offset;
};
struct ReviewedTreeProgress final {
    ReviewedTreeState state = ReviewedTreeState::Inventory;
    std::uint64_t known_items = 0, completed_items = 0, skipped_items = 0, failed_items = 0;
    std::uint64_t known_copy_bytes = 0, copied_bytes = 0;
    bool counts_complete = false;
    bool partial = false, recovery_required = false;
    std::optional<std::uint64_t> current_row;
    std::optional<UnavailableObservation> failure;
};

// Worker-only native binding for composition with retained replacement. It is
// evidence, never independent execution consent; the receipt must still pass
// begin_execution and whole-tree revalidation. Missing target parents remain
// unavailable until the reviewed directory creation has actually completed.
struct ReviewedTreeNativeBinding final {
    ComparisonDecisionToken token;
    std::vector<NativeName> relative_components;
    HeldChild::Pointer source, destination;
    std::shared_ptr<const DirectoryCursor> source_parent, destination_parent;
    std::optional<std::array<std::byte, 32>> source_digest, destination_digest;
};

struct ReviewedTreeReceiptState;
class ReviewedTreeReceipt final {
public:
    ReviewedTreeReceipt() = default;
    bool is_valid() const noexcept { return state_ != nullptr; }
private:
    std::shared_ptr<const ReviewedTreeReceiptState> state_;
    friend class ReviewedTreePlanJob;
};
struct ReviewedTreeDeletionState;
class ReviewedTreeDeletionReceipt final {
public:
    ReviewedTreeDeletionReceipt() = default;
    bool is_valid() const noexcept { return state_ != nullptr; }
private:
    std::shared_ptr<const ReviewedTreeDeletionState> state_;
    friend class ReviewedTreePlanJob;
};

// Single worker. Native inventory/hash steps and copy-job steps are bounded;
// pure plan freezing is bounded by the configured inventory limits. Native calls can block. No UI callback
// or display path is execution authority. Internal allocation may throw; C
// wrappers translate exceptions. Preview remains the very same immutable plan.
class ReviewedTreePlanJob final {
public:
    using Pointer = std::unique_ptr<ReviewedTreePlanJob>;
    static Observation<Pointer> create(ReviewedTreePlanRequest request);
    ~ReviewedTreePlanJob();
    ReviewedTreePlanJob(const ReviewedTreePlanJob&) = delete;
    ReviewedTreePlanJob& operator=(const ReviewedTreePlanJob&) = delete;

    ReviewedTreeState advance(std::stop_token stop = {});
    ReviewedTreeState state() const noexcept;
    ReviewedTreeProgress progress() const;
    ComparisonPlan::Pointer preview() const noexcept;
    Observation<ReviewedTreePage> page(std::size_t offset, std::size_t limit) const;
    // Worker-only assessment: exposes unresolved/invalid decisions and reasons
    // without authorizing execution. Changed rules invalidate older receipts.
    Observation<ReviewedTreePage> assess_rules(std::span<const ConflictRule> rules,
        std::size_t offset, std::size_t limit) const;
    Observation<ReviewedTreePage> assess_rules(std::span<const ConflictRule> rules,
        std::span<const ReviewedTreeNameChoice> names, std::size_t offset, std::size_t limit) const;
    // Bounded copies from the last assessment, including a rejected review.
    // No native queries, rule evaluation, or full-vector copies on this path.
    Observation<ReviewedTreePage> assessment_page(std::size_t offset, std::size_t limit) const;
    Observation<ReviewedTreePage> reviewed_page(const ReviewedTreeReceipt& receipt,
        std::size_t offset, std::size_t limit) const;
    Observation<ReviewedTreeNativeBinding> native_binding(const ComparisonDecisionToken& token) const;
    Observation<std::vector<NativeName>> native_components(std::uint64_t row_id, bool source) const;

    // Exact full deletion set, no implicit recursive authorization. Empty is
    // valid only when this preview proposes no removals. Receipts are opaque,
    // process-local and tied to this plan and its frozen native evidence.
    Observation<ReviewedTreeDeletionReceipt> review_deletions(
        std::span<const ComparisonDecisionToken> exact_rows) const;
    // Evaluate scoped rules ONCE against frozen facts. Unresolved choices fail
    // closed. No second rules pass during begin/advance. Unsupported actions
    // remain visible and are refused before any mutation at begin_execution.
    Observation<ReviewedTreeReceipt> review(std::span<const ConflictRule> rules,
        const ReviewedTreeDeletionReceipt& deletion = {}) const;
    Observation<ReviewedTreeReceipt> review(std::span<const ConflictRule> rules,
        std::span<const ReviewedTreeNameChoice> names, const ReviewedTreeDeletionReceipt& deletion = {}) const;
    Observation<bool> begin_execution(const ReviewedTreeReceipt& receipt);

private:
    struct Impl;
    explicit ReviewedTreePlanJob(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};
} // namespace ck::files
