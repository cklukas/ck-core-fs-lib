// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "conflict_rules.hpp"

#include <algorithm>
#include <string_view>

namespace ck::files {
namespace {
using S = ConflictRuleState;
using C = ConflictChoice;
using K = ConflictClass;
using R = ConflictRuleReason;

template<class E> bool valid_enum(E value, E last) noexcept {
    return static_cast<unsigned>(value) <= static_cast<unsigned>(last);
}

bool valid_path(std::string_view path) noexcept {
    if (path.empty() || path.size() > ComparisonLimits::hard_max_path_bytes || path.front() == '/' ||
        path.back() == '/' || path.find('\0') != path.npos || path.find('\\') != path.npos ||
        (path.size() > 1 && path[1] == ':')) return false;
    std::size_t begin = 0, depth = 0;
    for (;;) {
        const auto end = path.find('/', begin);
        const auto part = path.substr(begin, end == path.npos ? path.npos : end - begin);
        if (part.empty() || part == "." || part == ".." || ++depth > 1024) return false;
        if (end == path.npos) return true;
        begin = end + 1;
    }
}

bool prefix(std::string_view path, std::string_view subtree) noexcept {
    return path == subtree || (path.size() > subtree.size() && path.starts_with(subtree) && path[subtree.size()] == '/');
}

bool two_way(ConflictDirection direction) noexcept { return direction != ConflictDirection::SourceToTarget; }
bool left_is_source(ConflictDirection direction) noexcept { return direction == ConflictDirection::LeftToRight; }
bool names_needed(C choice) noexcept {
    return choice == C::KeepBothIncoming || choice == C::KeepBothTarget || choice == C::KeepBoth || choice == C::Rename;
}
bool fallback(C choice, ConflictDirection direction) noexcept {
    if (choice == C::Ask || choice == C::KeepBothIncoming || choice == C::KeepBothTarget || choice == C::KeepBoth) return true;
    return two_way(direction) ? choice == C::KeepLeft || choice == C::KeepRight : choice == C::KeepTarget;
}

ConflictRuleResult result(S state, C choice = C::Ask, R reason = R::None) {
    ConflictRuleResult out;
    out.state = state; out.choice = choice; out.reason = reason;
    return out;
}

bool valid_rule(const ConflictRule& rule) {
    if (!valid_enum(rule.choice, C::DeleteEdited) || !valid_enum(rule.scope, ConflictScope::MatchingClassInJob) ||
        !valid_enum(rule.kind, K::CapacityFailure) || !valid_enum(rule.direction, ConflictDirection::RightToLeft) ||
        !fallback(rule.tie, rule.direction) || rule.selected_rows.size() > 100'000) return false;
    if (rule.scope == ConflictScope::Item || rule.scope == ConflictScope::Selected) {
        if (rule.selected_rows.empty() || !rule.subtree.empty() ||
            (rule.scope == ConflictScope::Item && rule.selected_rows.size() != 1)) return false;
        auto ids = rule.selected_rows;
        std::sort(ids.begin(), ids.end());
        if (ids.front() == 0 || std::adjacent_find(ids.begin(), ids.end()) != ids.end()) return false;
    } else if (!rule.selected_rows.empty() ||
        (rule.scope == ConflictScope::Subtree ? !valid_path(rule.subtree) : !rule.subtree.empty())) return false;
    return true;
}

bool valid_facts(const ConflictFacts& facts) noexcept {
    return valid_enum(facts.kind, K::CapacityFailure) &&
        valid_enum(facts.relation, ComparisonRelation::MetadataDifferent) &&
        valid_enum(facts.direction, ConflictDirection::RightToLeft) &&
        valid_enum(facts.time_order, ConflictTimeOrder::Ambiguous) && valid_path(facts.relative_path) &&
        facts.equal_time == (facts.time_order == ConflictTimeOrder::Equal) &&
        !(facts.compatible_regular_files && facts.compatible_directories);
}

bool matches(const ConflictRule& rule, const ConflictFacts& facts) noexcept {
    if (rule.kind != facts.kind || rule.direction != facts.direction) return false;
    if (rule.scope == ConflictScope::Item || rule.scope == ConflictScope::Selected)
        return std::find(rule.selected_rows.begin(), rule.selected_rows.end(), facts.token.row_id()) != rule.selected_rows.end();
    return rule.scope != ConflictScope::Subtree || prefix(facts.relative_path, rule.subtree);
}

bool content_class(K kind) noexcept { return kind == K::ExistingRegular || kind == K::BothEdited; }
bool failure_class(K kind) noexcept {
    return kind == K::Unavailable || kind == K::AccessFailure || kind == K::CapacityFailure;
}

C source_wins(ConflictDirection direction) noexcept {
    if (!two_way(direction)) return C::UseSource;
    return left_is_source(direction) ? C::KeepLeft : C::KeepRight;
}
C target_wins(ConflictDirection direction) noexcept {
    if (!two_way(direction)) return C::KeepTarget;
    return left_is_source(direction) ? C::KeepRight : C::KeepLeft;
}

bool same_rule_decision(const ConflictRule& a, const ConflictRule& b) noexcept {
    // Compare preferences, not just the coincidentally equal outcome for this
    // row; a later tie must not make traversal order determine the policy.
    return a.choice == b.choice && a.tie == b.tie && a.protect_nonempty == b.protect_nonempty &&
        a.retain_replaced == b.retain_replaced;
}
int priority(ConflictScope scope) noexcept {
    switch (scope) {
    case ConflictScope::Item: return 3;
    case ConflictScope::Selected: return 2;
    case ConflictScope::Subtree: return 1;
    case ConflictScope::MatchingClassInJob: return 0;
    }
    return -1;
}
} // namespace

ConflictRuleResult evaluate_conflict_rule(const ConflictRule& rule, const ConflictFacts& facts) {
    if (!rule.plan.is_valid() || !facts.token.is_valid() || rule.plan != facts.token.plan_identity() ||
        !facts.evidence_current || facts.kind == K::StalePlan)
        return result(S::Stale, C::Ask, R::StaleEvidence);
    if (!valid_rule(rule) || !valid_facts(facts)) return result(S::Invalid, C::Ask, R::InvalidRule);
    if (!matches(rule, facts)) return result(S::NoMatch, C::Ask, R::NoMatchingRule);
    C choice = rule.choice;
    if (choice == C::Cancel || choice == C::Skip || choice == C::KeepTarget)
        // KeepTarget is a one-way non-mutating skip; two-way uses explicit sides.
        return choice == C::KeepTarget && two_way(facts.direction)
            ? result(S::NeedsReview, C::Ask, R::SeparatePolicyRequired) : result(S::Apply, choice);
    if (choice == C::Ask) return result(S::NeedsReview, choice, R::AwaitingChoice);
    if (choice == C::Retry)
        return failure_class(facts.kind) && facts.retry_qualified
            ? result(S::Apply, choice) : result(S::NeedsReview, C::Ask, R::RetryNotQualified);
    if (choice == C::Compare) return result(S::Apply, choice);
    if (choice == C::MergeFolders)
        return facts.kind == K::DirectoryPair && facts.compatible_directories &&
            facts.relation == ComparisonRelation::DirectoryPair
            ? result(S::Apply, choice) : result(S::NeedsReview, C::Ask, R::SeparatePolicyRequired);
    if (!content_class(facts.kind)) return result(S::NeedsReview, C::Ask, R::SeparatePolicyRequired);
    if (!facts.compatible_regular_files || facts.relation == ComparisonRelation::Unknown ||
        facts.relation == ComparisonRelation::Protected || facts.relation == ComparisonRelation::TypeConflict ||
        facts.relation == ComparisonRelation::DirectoryPair || facts.relation == ComparisonRelation::SourceOnly ||
        facts.relation == ComparisonRelation::DestinationOnly)
        return result(S::NeedsReview, C::Ask, R::UnqualifiedObjects);
    if ((two_way(facts.direction) && (choice == C::UseSource || choice == C::SourceIfNewer ||
            choice == C::NewerOrDifferentSizeAtEqualTime)) ||
        (!two_way(facts.direction) && (choice == C::KeepLeft || choice == C::KeepRight)))
        return result(S::NeedsReview, C::Ask, R::SeparatePolicyRequired);
    bool used_fallback = false;
    if (choice == C::Newest || choice == C::SourceIfNewer || choice == C::NewerOrDifferentSizeAtEqualTime) {
        if (facts.time_order == ConflictTimeOrder::SourceNewer) choice = source_wins(facts.direction);
        else if (facts.time_order == ConflictTimeOrder::TargetNewer) choice = target_wins(facts.direction);
        else if (choice == C::NewerOrDifferentSizeAtEqualTime && facts.equal_time &&
                 facts.source_size && facts.target_size && *facts.source_size != *facts.target_size)
            choice = C::UseSource;
        else { choice = rule.tie; used_fallback = true; }
    } else if (choice == C::SizeDiffers || choice == C::PreferLarger || choice == C::PreferSmaller) {
        if (!facts.source_size || !facts.target_size || *facts.source_size == *facts.target_size) {
            choice = rule.tie; used_fallback = true;
        } else if (choice == C::SizeDiffers) choice = source_wins(facts.direction);
        else if (choice == C::PreferLarger) choice = *facts.source_size > *facts.target_size
            ? source_wins(facts.direction) : target_wins(facts.direction);
        else choice = *facts.source_size < *facts.target_size ? source_wins(facts.direction) : target_wins(facts.direction);
    }
    auto out = result(S::Apply, choice);
    out.used_fallback = used_fallback;
    if (choice == C::Ask) { out.state = S::NeedsReview; out.reason = R::AwaitingChoice; return out; }
    if (choice == C::RestoreDeleted || choice == C::KeepEdited || choice == C::DeleteEdited)
        return result(S::NeedsReview, C::Ask, R::SeparatePolicyRequired);
    const bool source_replaces = choice == C::UseSource || choice == C::KeepBothTarget ||
        (choice == C::KeepLeft && left_is_source(facts.direction)) ||
        (choice == C::KeepRight && !left_is_source(facts.direction));
    const bool target_replaces = two_way(facts.direction) &&
        ((choice == C::KeepLeft && !left_is_source(facts.direction)) ||
         (choice == C::KeepRight && left_is_source(facts.direction)));
    if (rule.protect_nonempty && (source_replaces || target_replaces)) {
        const auto& incoming = source_replaces ? facts.source_size : facts.target_size;
        const auto& existing = source_replaces ? facts.target_size : facts.source_size;
        if (!incoming || !existing || (*incoming == 0 && *existing != 0)) {
            out.state = S::NeedsReview; out.reason = R::ZeroLengthProtection; return out;
        }
    }
    // Renaming the old target also replaces its original name, and requires
    // qualified retention when requested. Renaming incoming does not replace.
    const bool replaces = source_replaces || target_replaces || choice == C::KeepBothTarget;
    out.retain_replaced = rule.retain_replaced && replaces;
    if (out.retain_replaced && !facts.retention_available) {
        out.state = S::NeedsReview; out.reason = R::RetentionUnavailable; return out;
    }
    out.requires_native_name_allocation = names_needed(choice);
    return out;
}

ConflictRuleResult evaluate_conflict_rules(std::span<const ConflictRule> rules, const ConflictFacts& facts) {
    if (rules.size() > 100'000) return result(S::Invalid, C::Ask, R::InvalidRule);
    if (!facts.token.is_valid() || !facts.evidence_current || facts.kind == K::StalePlan)
        return result(S::Stale, C::Ask, R::StaleEvidence);
    if (!valid_facts(facts)) return result(S::Invalid, C::Ask, R::InvalidRule);
    std::optional<std::size_t> winner;
    int winning_priority = -1;
    bool contradictory = false;
    for (std::size_t index = 0; index < rules.size(); ++index) {
        const auto& rule = rules[index];
        if (!rule.plan.is_valid() || rule.plan != facts.token.plan_identity())
            return result(S::Stale, C::Ask, R::StaleEvidence);
        if (!valid_rule(rule)) return result(S::Invalid, C::Ask, R::InvalidRule);
        if (!matches(rule, facts)) continue;
        const auto p = priority(rule.scope);
        if (p > winning_priority) { winner = index; winning_priority = p; contradictory = false; }
        else if (p == winning_priority && !same_rule_decision(rules[*winner], rule)) contradictory = true;
    }
    if (!winner) return result(S::NoMatch, C::Ask, R::NoMatchingRule);
    if (contradictory) return result(S::Invalid, C::Ask, R::ContradictoryRules);
    auto out = evaluate_conflict_rule(rules[*winner], facts);
    out.rule_index = winner;
    return out;
}
} // namespace ck::files
