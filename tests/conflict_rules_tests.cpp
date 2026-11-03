// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
/* Standalone, one compile slot:
   c++ -std=c++20 tests/conflict_rules_tests.cpp src/files/conflict_rules.cpp
       src/files/comparison_plan.cpp src/files/file_metadata.cpp
       -o "$TMPDIR/conflict_rules_tests"
*/
#include "../src/files/conflict_rules.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>

using namespace ck::files;
namespace {
unsigned checks = 0;
void check(bool ok, const char* expression, int line) {
    ++checks;
    if (ok) return;
    std::fprintf(stderr, "line %d: %s\n", line, expression);
    std::exit(1);
}
#define CHECK(expression) check((expression), #expression, __LINE__)
using C = ConflictChoice;
using K = ConflictClass;
using S = ConflictRuleState;
using R = ConflictRuleReason;

struct Fixture {
    AdapterScope scope;
    ComparisonOptions options;
    std::vector<ComparisonEntry> source, target;
    ComparisonPlan::Pointer plan;

    ObjectIdentity identity(std::uint64_t id) const {
        return {scope, IdentityScheme::PosixDeviceInode,
            NativeIdentifier::from_u64(1), NativeIdentifier::from_u64(id), {}};
    }
    ComparisonEntry entry(std::string path, std::uint64_t id, ObjectKind kind) const {
        ComparisonEntry out;
        out.relative_path = std::move(path);
        out.object.state = ComparisonObjectState::Stable;
        out.object.identity = identity(id);
        out.object.kind = kind;
        out.object.size = 10;
        out.object.modified = FileTimestamp::from_unix(1, 0);
        out.object.timestamp_quantum_ns = 1;
        return out;
    }
    ComparisonInventory inventory(bool incoming) const {
        return {ComparisonInventoryState::CompleteStable, identity(incoming ? 100 : 200),
            incoming ? std::span<const ComparisonEntry>(source) : std::span<const ComparisonEntry>(target)};
    }
    Fixture() {
        options.topology = ComparisonTopology::Disjoint;
        options.mode = ComparisonMode::Size;
        unsigned id = 1;
        for (const auto* path : {"folder", "folder/a", "folder/b", "folderish", "folderish/a", "z"}) {
            const auto kind = std::string_view(path) == "folder" || std::string_view(path) == "folderish"
                ? ObjectKind::Directory : ObjectKind::RegularFile;
            source.push_back(entry(path, id, kind));
            target.push_back(entry(path, id + 1000, kind));
            ++id;
        }
        auto made = ComparisonPlan::create(options, inventory(true), inventory(false));
        CHECK(made.value() != nullptr);
        plan = *made.value();
    }
    ConflictFacts facts(std::string_view path = "folder/a") const {
        const auto page = plan->page(0, 32);
        CHECK(page.value() != nullptr);
        const auto it = std::find_if(page.value()->rows.begin(), page.value()->rows.end(),
            [path](const auto& row) { return row.relative_path == path; });
        CHECK(it != page.value()->rows.end());
        CHECK(plan->revalidate(it->token, options, inventory(true), inventory(false)) == ComparisonRevalidation::Matches);
        ConflictFacts out;
        out.token = it->token;
        out.relative_path = it->relative_path;
        out.kind = path == "folder" || path == "folderish" ? K::DirectoryPair : K::ExistingRegular;
        out.relation = it->relation;
        out.evidence_current = true;
        out.compatible_directories = out.kind == K::DirectoryPair;
        out.compatible_regular_files = !out.compatible_directories;
        out.source_size = 10; out.target_size = 10;
        return out;
    }
    ConflictRule rule(const ConflictFacts& facts, C choice = C::UseSource) const {
        ConflictRule out;
        out.plan = plan->identity(); out.kind = facts.kind; out.choice = choice;
        out.selected_rows = {facts.token.row_id()};
        return out;
    }
};

void stale_and_invalid() {
    Fixture fixture, foreign;
    auto facts = fixture.facts();
    auto rule = fixture.rule(facts);
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Apply);
    auto changed = fixture.source;
    changed[1].object.size = 99;
    auto altered_inventory = fixture.inventory(true);
    altered_inventory.entries = changed;
    CHECK(fixture.plan->revalidate(facts.token, fixture.options, altered_inventory, fixture.inventory(false)) ==
        ComparisonRevalidation::EvidenceChanged);
    facts.evidence_current = false;
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Stale);
    facts = foreign.facts();
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Stale);
    facts = fixture.facts();
    facts.token = {};
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Stale);
    facts = fixture.facts();
    rule.plan = {};
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Stale);
    rule = fixture.rule(facts);
    rule.choice = static_cast<C>(-1);
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Invalid);
    rule = fixture.rule(facts);
    rule.tie = C::UseSource;
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Invalid);
    rule = fixture.rule(facts);
    facts.time_order = ConflictTimeOrder::Equal;
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Invalid);
    facts.equal_time = true;
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Apply);
    facts.equal_time = false;
    facts.time_order = ConflictTimeOrder::Unknown;
    facts.kind = static_cast<K>(999);
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Invalid);
    for (const auto& path : {std::string{}, std::string{"/a"}, std::string{"a/"}, std::string{"a//b"},
             std::string{"a/../b"}, std::string{"a/./b"}, std::string{"C:a"}, std::string{"a\\b"},
             std::string{"a\0b", 3}}) {
        facts = fixture.facts(); facts.relative_path = path;
        CHECK(evaluate_conflict_rule(rule, facts).state == S::Invalid);
    }
    facts = fixture.facts();
    facts.relative_path = "folder/a:stream-key"; // same lossless-key contract as comparison
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Apply);
}

void scopes_and_precedence() {
    Fixture fixture;
    auto a = fixture.facts(), b = fixture.facts("folder/b"), unrelated = fixture.facts("folderish/a");
    auto rule = fixture.rule(a);
    CHECK(evaluate_conflict_rule(rule, b).state == S::NoMatch);
    rule.scope = ConflictScope::Selected;
    rule.selected_rows.push_back(b.token.row_id());
    CHECK(evaluate_conflict_rule(rule, b).state == S::Apply);
    CHECK(evaluate_conflict_rule(rule, unrelated).state == S::NoMatch);
    rule.selected_rows.push_back(b.token.row_id());
    CHECK(evaluate_conflict_rule(rule, a).state == S::Invalid);
    rule.selected_rows = {0};
    CHECK(evaluate_conflict_rule(rule, a).state == S::Invalid);
    rule.selected_rows.clear();
    CHECK(evaluate_conflict_rule(rule, a).state == S::Invalid);
    rule.scope = ConflictScope::Subtree; rule.subtree = "folder";
    CHECK(evaluate_conflict_rule(rule, a).state == S::Apply);
    CHECK(evaluate_conflict_rule(rule, b).state == S::Apply);
    CHECK(evaluate_conflict_rule(rule, unrelated).state == S::NoMatch);
    rule.subtree = "folder/../folder";
    CHECK(evaluate_conflict_rule(rule, a).state == S::Invalid);
    rule.subtree.clear(); rule.scope = ConflictScope::MatchingClassInJob;
    CHECK(evaluate_conflict_rule(rule, unrelated).state == S::Apply);
    rule.kind = K::BothEdited;
    CHECK(evaluate_conflict_rule(rule, a).state == S::NoMatch);
    rule.kind = K::ExistingRegular;
    rule.direction = ConflictDirection::LeftToRight; rule.tie = C::KeepLeft;
    CHECK(evaluate_conflict_rule(rule, a).state == S::NoMatch);

    auto job = fixture.rule(a, C::KeepTarget);
    job.scope = ConflictScope::MatchingClassInJob; job.selected_rows.clear();
    auto subtree = job; subtree.scope = ConflictScope::Subtree; subtree.subtree = "folder"; subtree.choice = C::Compare;
    auto selected = fixture.rule(a, C::Skip); selected.scope = ConflictScope::Selected;
    auto item = fixture.rule(a, C::KeepBothIncoming);
    std::array rules{job, subtree, selected, item};
    auto out = evaluate_conflict_rules(rules, a);
    CHECK(out.state == S::Apply && out.choice == C::KeepBothIncoming && out.rule_index == 3);
    std::reverse(rules.begin(), rules.end());
    out = evaluate_conflict_rules(rules, a);
    CHECK(out.state == S::Apply && out.choice == C::KeepBothIncoming && out.rule_index == 0);
    CHECK(evaluate_conflict_rules(std::span(rules).subspan(1), a).choice == C::Skip);
    CHECK(evaluate_conflict_rules(std::array{job, subtree}, a).choice == C::Compare);
    CHECK(evaluate_conflict_rules(std::array{job, subtree}, unrelated).choice == C::KeepTarget);
    CHECK(evaluate_conflict_rules({}, a).state == S::NoMatch);
    auto contradictory = item; contradictory.choice = C::UseSource;
    out = evaluate_conflict_rules(std::array{item, contradictory}, a);
    CHECK(out.state == S::Invalid && out.reason == R::ContradictoryRules);
    CHECK(evaluate_conflict_rules(std::array{contradictory, item}, a).state == S::Invalid);
    CHECK(evaluate_conflict_rules(std::array{item, item}, a).state == S::Apply);
    // Conflicts below the winner cannot override an item choice.
    auto other_job = job; other_job.choice = C::UseSource;
    CHECK(evaluate_conflict_rules(std::array{job, other_job, item}, a).choice == C::KeepBothIncoming);
    CHECK(evaluate_conflict_rules(std::array{item, job, other_job}, a).choice == C::KeepBothIncoming);
}

void qualified_times_and_fallbacks() {
    Fixture fixture;
    auto facts = fixture.facts();
    for (const auto choice : {C::Newest, C::SourceIfNewer, C::NewerOrDifferentSizeAtEqualTime}) {
        auto rule = fixture.rule(facts, choice);
        facts.relation = ComparisonRelation::SizeDifferent;
        facts.source_size = 3; facts.target_size = 9;
        facts.time_order = ConflictTimeOrder::SourceNewer;
        CHECK(evaluate_conflict_rule(rule, facts).choice == C::UseSource);
        facts.time_order = ConflictTimeOrder::TargetNewer;
        CHECK(evaluate_conflict_rule(rule, facts).choice == C::KeepTarget);
        for (const auto unqualified : {ConflictTimeOrder::Unknown, ConflictTimeOrder::Ambiguous}) {
            facts.time_order = unqualified;
            auto out = evaluate_conflict_rule(rule, facts);
            CHECK(out.state == S::NeedsReview && out.choice == C::Ask && out.used_fallback);
            rule.tie = C::KeepTarget;
            out = evaluate_conflict_rule(rule, facts);
            CHECK(out.state == S::Apply && out.choice == C::KeepTarget && out.used_fallback);
            rule.tie = C::KeepBothIncoming;
            out = evaluate_conflict_rule(rule, facts);
            CHECK(out.state == S::Apply && out.requires_native_name_allocation && out.used_fallback);
            rule.tie = C::Ask;
        }
        facts.time_order = ConflictTimeOrder::Equal; facts.equal_time = true;
        auto out = evaluate_conflict_rule(rule, facts);
        CHECK(out.choice == (choice == C::NewerOrDifferentSizeAtEqualTime ? C::UseSource : C::Ask));
        CHECK(out.used_fallback == (choice != C::NewerOrDifferentSizeAtEqualTime));
        facts.source_size = 9;
        CHECK(evaluate_conflict_rule(rule, facts).choice == C::Ask);
        facts.source_size.reset();
        CHECK(evaluate_conflict_rule(rule, facts).choice == C::Ask);
        facts.equal_time = false; facts.time_order = ConflictTimeOrder::Unknown;
    }
    // A comparison relation alone cannot choose a winner without qualified time.
    auto rule = fixture.rule(facts, C::Newest);
    facts.relation = ComparisonRelation::SourceNewer;
    CHECK(evaluate_conflict_rule(rule, facts).choice == C::Ask);
}

void size_rules_and_protections() {
    Fixture fixture;
    auto facts = fixture.facts();
    for (const auto choice : {C::SizeDiffers, C::PreferLarger, C::PreferSmaller}) {
        auto rule = fixture.rule(facts, choice);
        facts.source_size = 20; facts.target_size = 10;
        CHECK(evaluate_conflict_rule(rule, facts).choice == (choice == C::PreferSmaller ? C::KeepTarget : C::UseSource));
        facts.source_size = 5;
        CHECK(evaluate_conflict_rule(rule, facts).choice == (choice == C::PreferLarger ? C::KeepTarget : C::UseSource));
        facts.source_size = 10;
        CHECK(evaluate_conflict_rule(rule, facts).state == S::NeedsReview);
        rule.tie = C::KeepBothTarget;
        CHECK(evaluate_conflict_rule(rule, facts).requires_native_name_allocation);
        facts.source_size.reset();
        CHECK(evaluate_conflict_rule(rule, facts).used_fallback);
    }
    for (const auto choice : {C::UseSource, C::KeepBothTarget, C::PreferSmaller, C::SizeDiffers,
             C::Newest, C::NewerOrDifferentSizeAtEqualTime}) {
        auto rule = fixture.rule(facts, choice);
        facts.source_size = 0; facts.target_size = 10;
        facts.time_order = ConflictTimeOrder::SourceNewer;
        auto out = evaluate_conflict_rule(rule, facts);
        CHECK(out.state == S::NeedsReview && out.reason == R::ZeroLengthProtection);
        rule.protect_nonempty = false;
        CHECK(evaluate_conflict_rule(rule, facts).state == S::Apply);
    }
    facts = fixture.facts();
    for (const auto choice : {C::UseSource, C::KeepBothTarget}) {
        auto rule = fixture.rule(facts, choice); rule.retain_replaced = true;
        auto out = evaluate_conflict_rule(rule, facts);
        CHECK(out.state == S::NeedsReview && out.reason == R::RetentionUnavailable && out.retain_replaced);
        facts.retention_available = true;
        out = evaluate_conflict_rule(rule, facts);
        CHECK(out.state == S::Apply && out.retain_replaced);
        facts.retention_available = false;
    }
    auto rule = fixture.rule(facts, C::KeepBothIncoming); rule.retain_replaced = true;
    auto out = evaluate_conflict_rule(rule, facts);
    CHECK(out.state == S::Apply && !out.retain_replaced && out.requires_native_name_allocation);
    rule.choice = C::UseSource; facts.source_size.reset();
    CHECK(evaluate_conflict_rule(rule, facts).reason == R::ZeroLengthProtection);
}

void classes_and_common_choices() {
    Fixture fixture;
    auto facts = fixture.facts();
    for (const auto choice : {C::UseSource, C::KeepTarget, C::KeepBothIncoming, C::KeepBothTarget,
             C::Rename, C::Compare, C::Skip, C::Cancel, C::KeepBoth}) {
        const auto out = evaluate_conflict_rule(fixture.rule(facts, choice), facts);
        CHECK(out.state == S::Apply && out.choice == choice);
        CHECK(out.requires_native_name_allocation == (choice == C::KeepBothIncoming || choice == C::KeepBothTarget ||
            choice == C::Rename || choice == C::KeepBoth));
    }
    CHECK(evaluate_conflict_rule(fixture.rule(facts, C::Ask), facts).state == S::NeedsReview);
    for (const auto kind : {K::TypeMismatch, K::LinkMismatch, K::NameCollision, K::RequiredMetadata,
             K::DeleteEdit, K::DirectoryDeleteEditedChild, K::HardLinkEffects, K::Unavailable,
             K::AmbiguousCommit, K::AccessFailure, K::CapacityFailure}) {
        facts.kind = kind;
        for (const auto choice : {C::UseSource, C::Newest, C::SizeDiffers, C::MergeFolders, C::KeepBothIncoming,
                 C::RestoreDeleted, C::KeepEdited, C::DeleteEdited}) {
            CHECK(evaluate_conflict_rule(fixture.rule(facts, choice), facts).state == S::NeedsReview);
        }
        CHECK(evaluate_conflict_rule(fixture.rule(facts, C::KeepTarget), facts).state == S::Apply);
        CHECK(evaluate_conflict_rule(fixture.rule(facts, C::Skip), facts).state == S::Apply);
        facts.retry_qualified = true;
        const auto retry = evaluate_conflict_rule(fixture.rule(facts, C::Retry), facts);
        CHECK(retry.state == (kind == K::Unavailable || kind == K::AccessFailure || kind == K::CapacityFailure
            ? S::Apply : S::NeedsReview));
    }
    facts = fixture.facts("folder");
    auto rule = fixture.rule(facts, C::MergeFolders);
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Apply);
    facts.compatible_directories = false;
    CHECK(evaluate_conflict_rule(rule, facts).state == S::NeedsReview);
    facts.compatible_directories = true; facts.kind = K::TypeMismatch; rule.kind = facts.kind;
    CHECK(evaluate_conflict_rule(rule, facts).state == S::NeedsReview);
    facts = fixture.facts(); facts.compatible_regular_files = false;
    CHECK(evaluate_conflict_rule(fixture.rule(facts), facts).state == S::NeedsReview);
    facts = fixture.facts();
    for (const auto relation : {ComparisonRelation::Unknown, ComparisonRelation::Protected,
             ComparisonRelation::SourceOnly, ComparisonRelation::DestinationOnly, ComparisonRelation::TypeConflict}) {
        facts.relation = relation;
        CHECK(evaluate_conflict_rule(fixture.rule(facts), facts).state == S::NeedsReview);
    }
}

void explicit_two_way_sides() {
    Fixture fixture;
    for (const auto direction : {ConflictDirection::LeftToRight, ConflictDirection::RightToLeft}) {
        auto facts = fixture.facts(); facts.direction = direction; facts.kind = K::BothEdited;
        auto rule = fixture.rule(facts, C::Newest); rule.direction = direction;
        facts.time_order = ConflictTimeOrder::SourceNewer;
        CHECK(evaluate_conflict_rule(rule, facts).choice ==
            (direction == ConflictDirection::LeftToRight ? C::KeepLeft : C::KeepRight));
        facts.time_order = ConflictTimeOrder::TargetNewer;
        CHECK(evaluate_conflict_rule(rule, facts).choice ==
            (direction == ConflictDirection::LeftToRight ? C::KeepRight : C::KeepLeft));
        rule.choice = C::UseSource;
        CHECK(evaluate_conflict_rule(rule, facts).state == S::NeedsReview);
        rule.choice = C::KeepLeft; rule.retain_replaced = true;
        CHECK(evaluate_conflict_rule(rule, facts).reason == R::RetentionUnavailable);
        facts.retention_available = true;
        CHECK(evaluate_conflict_rule(rule, facts).state == S::Apply);
        if (direction == ConflictDirection::LeftToRight) facts.source_size = 0;
        else facts.target_size = 0;
        CHECK(evaluate_conflict_rule(rule, facts).reason == R::ZeroLengthProtection);
        facts.time_order = ConflictTimeOrder::Unknown;
        rule.choice = C::Newest; rule.tie = C::KeepRight;
        CHECK(evaluate_conflict_rule(rule, facts).used_fallback);
    }
}
void preserved_metadata_conflicts() {
    Fixture fixture;
    fixture.source = {fixture.entry("a", 1, ObjectKind::RegularFile)};
    fixture.target = {fixture.entry("a", 2, ObjectKind::RegularFile)};
    fixture.options.compare_preserved_metadata = true;
    auto attach = [](ComparisonEntry& entry, unsigned value) {
        ComparisonMetadataDigest digest;
        digest.state = ComparisonDigestState::CompleteStable;
        digest.algorithm = ComparisonDigestAlgorithm::Sha256;
        digest.schema[0] = std::byte{1};
        digest.policy_binding[0] = std::byte{2};
        digest.bytes[0] = std::byte(value);
        digest.ownership = ComparisonMetadataOwnership::Original;
        digest.before = digest.after = entry.object;
        entry.metadata_digest = digest;
    };
    attach(fixture.source.front(), 3);
    attach(fixture.target.front(), 4);
    auto made = ComparisonPlan::create(fixture.options, fixture.inventory(true), fixture.inventory(false));
    CHECK(made.value());
    fixture.plan = *made.value();
    auto facts = fixture.facts("a");
    CHECK(facts.relation == ComparisonRelation::MetadataDifferent);
    for (auto choice : {C::UseSource, C::KeepTarget, C::KeepBothIncoming}) {
        auto rule = fixture.rule(facts, choice);
        const auto result = evaluate_conflict_rule(rule, facts);
        CHECK(result.state == S::Apply && result.choice == choice);
        CHECK(result.requires_native_name_allocation == (choice == C::KeepBothIncoming));
    }
    auto rule = fixture.rule(facts, C::Newest);
    facts.time_order = ConflictTimeOrder::Equal;
    facts.equal_time = true;
    auto result = evaluate_conflict_rule(rule, facts);
    CHECK(result.state == S::NeedsReview && result.used_fallback && result.choice == C::Ask);
    rule.tie = C::KeepTarget;
    result = evaluate_conflict_rule(rule, facts);
    CHECK(result.state == S::Apply && result.used_fallback && result.choice == C::KeepTarget);
    rule.choice = C::UseSource;
    rule.retain_replaced = true;
    CHECK(evaluate_conflict_rule(rule, facts).reason == R::RetentionUnavailable);
    facts.retention_available = true;
    CHECK(evaluate_conflict_rule(rule, facts).retain_replaced);
    facts.relation = ComparisonRelation::Unknown;
    CHECK(evaluate_conflict_rule(rule, facts).reason == R::UnqualifiedObjects);
    facts.kind = K::RequiredMetadata;
    rule.kind = K::RequiredMetadata;
    CHECK(evaluate_conflict_rule(rule, facts).reason == R::SeparatePolicyRequired);
    facts.evidence_current = false;
    CHECK(evaluate_conflict_rule(rule, facts).state == S::Stale);
}
} // namespace

int main() {
    stale_and_invalid();
    scopes_and_precedence();
    qualified_times_and_fallbacks();
    size_rules_and_protections();
    classes_and_common_choices();
    explicit_two_way_sides();
    preserved_metadata_conflicts();
    std::printf("conflict_rules_tests: %u checks passed\n", checks);
}
