// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "native_sync_observation.hpp"
#include "native_sync_ledger.hpp"
#include "native_operation_copy_job.hpp"
#include "conflict_rules.hpp"
#include <functional>
namespace ck::files {
class NativeHierarchyContext;
enum class NativeSyncCoordinatorEvent { BeforeLedgerClose, BeforeBaselineCommit, AfterBaselineCommit };
struct NativeSyncCoordinatorRequest final {
    std::optional<NativeAbsolutePath> coordinator;
    NativeAbsolutePath left,right;
    SyncDigest application_policy{};
    MetadataReplayPolicy metadata;
    NativeSyncProofLimits proof_limits;
    NativeSyncLedgerLimits ledger_limits;
    SyncDeletionGuard deletion_guard;
    // Internal deterministic crash/fault seam. Never supplied by the C facade.
    std::function<bool(NativeSyncCoordinatorEvent)> before_event;
    SyncSessionFaults storage_faults;
    PreparedJournalRoot::Pointer prepared_journal_root={};
};
enum class NativeSyncChoice { Proposal, Skip, LeftWins, RightWins };
struct NativeSyncDecision final {std::string exact_key;NativeSyncChoice choice=NativeSyncChoice::Skip;};
struct NativeSyncReviewedRow final {
    std::string exact_key;
    SyncEntryStatus left,right;
    SyncAction proposal=SyncAction::Blocked;
    SyncReason reason=SyncReason::UnknownStatus;
};
struct NativeSyncObservedFacts final {
    SyncEntryStatus status;
    std::optional<ObjectKind> kind;
    std::optional<std::uint64_t> size;
    std::optional<FileTimestamp> modified;
    // size remains unnamed main data. These are observations, not progress or
    // an immutable all-stream content guarantee.
    std::optional<std::uint64_t> all_stream_size;
    std::optional<std::uint64_t> named_stream_count;
    DataChannelCoverage channel_coverage=DataChannelCoverage::Unknown;
};
struct NativeSyncRawFacts final {
    ComparisonDecisionToken token;
    ComparisonRelation relation=ComparisonRelation::Unknown;
    ConflictClass conflict_class=ConflictClass::Unavailable;
    NativeSyncObservedFacts left,right;
    // Snapshot eligibility, not a retained mutation capability. Execution
    // reacquires the exact held-object guard and fails if it cannot qualify.
    Observation<bool> left_retention,right_retention;
    std::uint64_t allowed_choices=0;
};
struct NativeSyncRuleRow final {
    ConflictRuleResult decision;
    NativeSyncDecision selected;
};
struct NativeSyncRuleAssessmentState;
class NativeSyncRuleAssessment final {
public:
    using Pointer=std::shared_ptr<NativeSyncRuleAssessment>;
    const std::vector<NativeSyncRuleRow>& rows() const noexcept;
    bool consumed() const noexcept;
private:
    explicit NativeSyncRuleAssessment(std::shared_ptr<NativeSyncRuleAssessmentState> s):state_(std::move(s)) {}
    std::shared_ptr<NativeSyncRuleAssessmentState> state_;
    friend class NativeSyncCoordinator;
};
enum class NativeSyncProtection { RetainedProtected };
struct NativeSyncProtectedEvidence final {
    NativeSyncArtifact artifact;
    BasicMetadata fresh_observation;
    NativeSyncProtection protection=NativeSyncProtection::RetainedProtected;
    // Fresh ID/content/semantic-metadata match; no live continuity across
    // restart and NO authority to clean, rename, or otherwise mutate artifact.
};
enum class NativeSyncCoordinatorState { AwaitingReview, Executing, Verifying, Committing, Complete, Cancelled, NeedsReview };
struct NativeSyncCoordinatorResult final {
    NativeSyncCoordinatorState state=NativeSyncCoordinatorState::AwaitingReview;
    std::uint64_t generation=0;
    std::size_t completed_operations=0;
    std::vector<std::string> pending_keys;
    std::optional<UnavailableObservation> failure;
};
// Entirely worker-owned. The factory acquires BOTH root locks and retains them
// through review/execution/verification/baseline commit, released by terminal
// worker finish_io or destruction. The private Root owner survives until destroy.
// No frontend callbacks, supplied digests, opposing jobs, or cross-root atomicity
// claim. Each side is observed at a verified version; subsequent external edits
// are detected on the next scan. V1 supports root-level regular files only.
class NativeSyncCoordinator final {
public:
    using Pointer=std::unique_ptr<NativeSyncCoordinator>;
    static Observation<Pointer> open(NativeSyncCoordinatorRequest,std::stop_token={});
    ~NativeSyncCoordinator();
    // Worker-only terminal consumer close, not baseline completion/recovery.
    // Stops further execution, closes journals/native session locks, and keeps
    // the shared private-root lifecycle owner until worker-side destruction.
    Observation<bool> finish_io();
    const SyncSessionIdentity& identity() const noexcept;
    const std::vector<NativeSyncReviewedRow>& rows() const noexcept;
    const NativeSyncCoordinatorResult& result() const noexcept;
    const std::vector<NativeSyncProtectedEvidence>& protected_artifacts() const noexcept;
    const std::vector<NativeName>& components(std::size_t reviewed_row) const;
    // Decisions must cover every reviewed row exactly once. A skip preserves
    // old baseline evidence. Conflict overrides select a native side, never a
    // caller content assertion. An explicit first-run approval is separate.
    Observation<bool> approve(std::span<const NativeSyncDecision>,bool approve_first_run=false,std::stop_token={});
    // GetFacts is frozen native evidence. Rules never accept caller facts or
    // digests. SourceToTarget means left/source -> right/target (KeepTarget is
    // a nonmutating skip); two-way Left/Right choices require explicit direction.
    Observation<NativeSyncRawFacts> facts(std::size_t row);
    void invalidate_rule_receipts() noexcept;
    Observation<ComparisonPlanIdentity> rule_plan_identity();
    Observation<NativeSyncRuleAssessment::Pointer> assess_rules(std::span<const ConflictRule>,
        std::uint64_t timestamp_quantum_ns=1,std::stop_token={});
    Observation<bool> approve_rules(const NativeSyncRuleAssessment&,bool approve_first_run=false,std::stop_token={});
    // May block in native filesystem calls, bounded by configured byte/entry
    // limits. Sticky cancellation is accepted before baseline durable intent;
    // a committed baseline intent is finished idempotently by SyncSession.
    NativeSyncCoordinatorState advance(std::stop_token={});
private:
    friend class NativeHierarchyContext;
    struct State;
    explicit NativeSyncCoordinator(std::unique_ptr<State> s);
    std::unique_ptr<State> state_;
};
} // namespace ck::files
