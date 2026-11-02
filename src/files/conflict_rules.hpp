// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "comparison_plan.hpp"

namespace ck::files {
enum class ConflictClass {
    ExistingRegular, BothEdited, DeleteEdit, DirectoryDeleteEditedChild,
    TypeMismatch, LinkMismatch, NameCollision, RequiredMetadata,
    Unavailable, StalePlan, AmbiguousCommit, DirectoryPair,
    HardLinkEffects, AccessFailure, CapacityFailure
};
enum class ConflictChoice {
    Ask, UseSource, KeepTarget, Newest, SourceIfNewer, NewerOrDifferentSizeAtEqualTime,
    SizeDiffers, PreferLarger, PreferSmaller, KeepBothIncoming, KeepBothTarget,
    Rename, Compare, MergeFolders, Retry, Cancel, Skip,
    KeepLeft, KeepRight, KeepBoth, RestoreDeleted, KeepEdited, DeleteEdited
};
enum class ConflictScope { Item, Selected, Subtree, MatchingClassInJob };
enum class ConflictDirection { SourceToTarget, LeftToRight, RightToLeft };
// Worker-qualified ordering, independent of a size/digest comparison relation.
// Equal means equal at the declared comparison precision; precision ambiguity,
// missing timestamps and unqualified ordering remain Unknown/Ambiguous.
enum class ConflictTimeOrder { Unknown, SourceNewer, TargetNewer, Equal, Ambiguous };
struct ConflictRule {
    ComparisonPlanIdentity plan;
    ConflictClass kind = ConflictClass::ExistingRegular;
    ConflictChoice choice = ConflictChoice::Ask;
    // Only Ask, KeepTarget/left/right, or a KeepBoth variant. Missing evidence
    // and equal values use this visible fallback; no claim of content equality.
    ConflictChoice tie = ConflictChoice::Ask;
    ConflictScope scope = ConflictScope::Item;
    std::vector<std::uint64_t> selected_rows;
    std::string subtree;
    bool protect_nonempty = true;
    bool retain_replaced = false;
    ConflictDirection direction = ConflictDirection::SourceToTarget;
};
struct ConflictFacts {
    ComparisonDecisionToken token;
    std::string relative_path; // exact lossless comparison key, not a native path
    ConflictClass kind = ConflictClass::ExistingRegular;
    ComparisonRelation relation = ComparisonRelation::Unknown;
    std::optional<std::uint64_t> source_size, target_size;
    bool evidence_current = false;
    bool compatible_regular_files = false;
    bool compatible_directories = false;
    // True only for a qualified retention capability, including chosen storage,
    // space/quota and preservation requirements; never just a configured path.
    bool retention_available = false;
    // Includes bounded attempt/backoff eligibility and proof that retry cannot
    // replay an ambiguous publication. Retry never overrides Stale/Ambiguous.
    bool retry_qualified = false;
    ConflictDirection direction = ConflictDirection::SourceToTarget;
    ConflictTimeOrder time_order = ConflictTimeOrder::Unknown;
    // Explicit equal-time evidence is required for the rsync variant. Must
    // agree with time_order == Equal. SizeDifferent alone never sets this.
    bool equal_time = false;
};
enum class ConflictRuleState { NoMatch, Apply, NeedsReview, Stale, Invalid };
enum class ConflictRuleReason {
    None, NoMatchingRule, InvalidRule, StaleEvidence, ContradictoryRules,
    UnqualifiedObjects, SeparatePolicyRequired, AwaitingChoice,
    ZeroLengthProtection, RetentionUnavailable, RetryNotQualified
};
struct ConflictRuleResult {
    ConflictRuleState state = ConflictRuleState::NeedsReview;
    ConflictChoice choice = ConflictChoice::Ask;
    bool retain_replaced = false;
    bool used_fallback = false;
    // Rename requests still need a reviewed native component, exact collision
    // allocation/preview and alias checks. No name is synthesized here.
    bool requires_native_name_allocation = false;
    ConflictRuleReason reason = ConflictRuleReason::None;
    std::optional<std::size_t> rule_index;
};
// Pure proposals, never publication, deletion, retirement or retry authority.
// Adapters must bind facts to this exact token/row and use whole-plan
// revalidation before setting evidence_current. No native I/O or receipt here.
// Ask stays unresolved. Compare requests inspection/staged merge review only.
// Edit/delete actions require a separate deletion/retention contract and remain
// review-needed here. Skips retain move sources and pending two-way baselines.
ConflictRuleResult evaluate_conflict_rule(const ConflictRule&, const ConflictFacts&);
// Precedence: Item > Selected > Subtree > MatchingClassInJob. Contradictory
// matching rules at the winning priority are invalid, regardless of input order.
// A narrower subtree is not an implicit tiebreaker. Empty rule sets do not match.
ConflictRuleResult evaluate_conflict_rules(std::span<const ConflictRule>, const ConflictFacts&);
} // namespace ck::files
