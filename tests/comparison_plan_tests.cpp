// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "comparison_plan.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <limits>
#include <utility>

#ifdef NDEBUG
#error "comparison_plan_tests requires enabled assertions"
#endif

using namespace ck::files;
namespace {
AdapterScope scope;
ObjectIdentity identity(std::uint64_t id) {
    return {scope, IdentityScheme::PosixDeviceInode, NativeIdentifier::from_u64(1), NativeIdentifier::from_u64(id), 1};
}
FileTimestamp time_at(std::int64_t seconds, std::uint32_t ns = 0) {
    auto value = FileTimestamp::from_unix(seconds, ns);
    assert(value); return *value;
}
ComparisonEntry file(std::string key, std::uint64_t id, std::uint64_t size = 10, std::int64_t seconds = 100) {
    ComparisonEntry e;
    e.relative_path = std::move(key);
    e.object = {ComparisonObjectState::Stable, identity(id), ObjectKind::RegularFile, size, time_at(seconds), 1, 1};
    return e;
}
ComparisonEntry directory(std::string key, std::uint64_t id) {
    auto e = file(std::move(key), id);
    e.object.kind = ObjectKind::Directory;
    e.object.size.reset();
    return e;
}
void digest(ComparisonEntry& e, unsigned value = 1) {
    e.digest = ComparisonDigest{ComparisonDigestState::CompleteStable, ComparisonDigestAlgorithm::Sha256, {}, *e.object.size, e.object, e.object};
    e.digest->bytes[0] = static_cast<std::byte>(value);
}
struct Fixture {
    ComparisonOptions options;
    std::vector<ComparisonEntry> source, destination;
    std::vector<std::string> exclusions;
    ComparisonLimits limits;
    ComparisonInventoryState ss = ComparisonInventoryState::CompleteStable, ds = ComparisonInventoryState::CompleteStable;
    std::optional<ObjectIdentity> sr = identity(1000), dr = identity(2000);
    Fixture() { options.topology = ComparisonTopology::Disjoint; }
    ComparisonInventory s() const { return {ss, sr, source}; }
    ComparisonInventory d() const { return {ds, dr, destination}; }
    Observation<ComparisonPlan::Pointer> build() const { return ComparisonPlan::create(options, s(), d(), exclusions, limits); }
    ComparisonPlan::Pointer plan() const { auto r = build(); assert(r.value()); return *r.value(); }
};
std::vector<ComparisonRow> rows(const ComparisonPlan::Pointer& p) {
    std::vector<ComparisonRow> result;
    std::size_t offset = 0;
    do {
        auto page = p->page(offset, 1);
        assert(page.value() && page.value()->identity == p->identity());
        result.insert(result.end(), page.value()->rows.begin(), page.value()->rows.end());
        if (!page.value()->next_offset) break;
        offset = *page.value()->next_offset;
    } while (true);
    return result;
}
ComparisonRow row(Fixture& f) { auto r = rows(f.plan()); assert(r.size() == 1); return r.front(); }
void assert_safe_unknown(const ComparisonRow& r) {
    assert(r.relation == ComparisonRelation::Unknown);
    assert(r.destination_protected);
    assert(r.action == ComparisonAction::Review || r.action == ComparisonAction::Report);
}
void profiles() {
    constexpr ComparisonProfile profiles[] = {ComparisonProfile::Copy, ComparisonProfile::Move, ComparisonProfile::Update,
        ComparisonProfile::MissingOnly, ComparisonProfile::Sync, ComparisonProfile::Mirror, ComparisonProfile::Compare};
    for (auto profile : profiles) {
        Fixture f; f.options.profile = profile; f.source = {file("a", 1)};
        const auto r = row(f);
        assert(r.relation == ComparisonRelation::SourceOnly);
        assert(r.action == (profile == ComparisonProfile::Compare ? ComparisonAction::Report :
            profile == ComparisonProfile::Move ? ComparisonAction::MoveAfterCommit : ComparisonAction::CopyToDestination));
        f.destination = {file("a", 2, 20, 99)};
        const auto conflict = row(f);
        const auto expected = profile == ComparisonProfile::Compare ? ComparisonAction::Report :
            profile == ComparisonProfile::Copy || profile == ComparisonProfile::Move ? ComparisonAction::Review :
            profile == ComparisonProfile::MissingOnly ? ComparisonAction::Skip : ComparisonAction::ReplaceDestination;
        assert(conflict.action == expected);
        assert(conflict.requires_review == (expected == ComparisonAction::Review));
        f.source.clear();
        const auto only_dest = row(f);
        assert(only_dest.action == (profile == ComparisonProfile::Mirror ? ComparisonAction::RemoveDestinationFile :
            profile == ComparisonProfile::Compare ? ComparisonAction::Report : ComparisonAction::Skip));
    }
    Fixture f; f.options.profile = ComparisonProfile::Update;
    f.source = {file("a", 1, 10, 99)}; f.destination = {file("a", 2, 20, 100)};
    assert(row(f).action == ComparisonAction::Skip);
    f.source[0].object.modified = time_at(100);
    assert(row(f).reason == ComparisonReason::EqualTimeConflict);
    f.options.profile = ComparisonProfile::Copy;
    f.destination[0].object.size = 10;
    assert(row(f).action == ComparisonAction::Skip);
    f.options.profile = ComparisonProfile::Move;
    assert(row(f).action == ComparisonAction::Review); // never retire source on a quick match
    f.options.profile = ComparisonProfile::MissingOnly;
    f.destination[0].object.kind = ObjectKind::Directory;
    assert(row(f).action == ComparisonAction::Skip);
}
void comparison_modes() {
    Fixture f; f.options.profile = ComparisonProfile::Sync;
    f.source = {file("a", 1)}; f.destination = {file("a", 2)};
    assert(row(f).relation == ComparisonRelation::SameSizeAndMtime);
    f.options.mode = ComparisonMode::Size;
    f.source[0].object.modified.reset();
    assert(row(f).relation == ComparisonRelation::SameSize);
    f.source[0].object.size = 11;
    assert(row(f).relation == ComparisonRelation::SizeDifferent);
    f.options.mode = ComparisonMode::CompleteDigest;
    assert_safe_unknown(row(f));
    f.source[0].object.modified = time_at(100);
    digest(f.source[0]); digest(f.destination[0]);
    assert(row(f).relation == ComparisonRelation::SizeDifferent);
    f.source[0].object.size = 10; digest(f.source[0]);
    assert(row(f).relation == ComparisonRelation::Identical);
    assert(row(f).reason == ComparisonReason::SameContent);
    f.destination[0].digest->bytes[0] = std::byte{2};
    assert(row(f).relation == ComparisonRelation::ContentDifferent);
    assert(row(f).action == ComparisonAction::ReplaceDestination);
    for (auto state : {ComparisonDigestState::Unknown, ComparisonDigestState::Incomplete, ComparisonDigestState::Denied,
        ComparisonDigestState::Changed, ComparisonDigestState::Failed}) {
        f.destination[0].digest->state = state;
        assert_safe_unknown(row(f));
    }
    digest(f.destination[0]); f.destination[0].digest->bytes_read = 9;
    assert(row(f).reason == ComparisonReason::DigestIncomplete);
    digest(f.destination[0]); f.destination[0].digest->after.change_cookie = 2;
    assert(row(f).reason == ComparisonReason::DigestBindingMismatch);
    digest(f.destination[0]); f.destination[0].digest->before.identity = identity(999);
    assert_safe_unknown(row(f));
    digest(f.destination[0]); f.destination[0].digest->algorithm = ComparisonDigestAlgorithm::Unknown;
    assert(row(f).reason == ComparisonReason::DigestUnavailable);
    f.source.clear(); f.options.profile = ComparisonProfile::Mirror;
    assert_safe_unknown(row(f)); // missing digest cannot authorize deletion
    f.source = {file("a", 1, 0)}; f.destination = {file("a", 2, 0)};
    digest(f.source[0]); digest(f.destination[0]);
    assert(row(f).relation == ComparisonRelation::Identical); // complete empty reads
}
void timestamp_precision() {
    Fixture f; f.source = {file("a", 1)}; f.destination = {file("a", 2)};
    f.source[0].object.modified = time_at(100, 999);
    f.destination[0].object.modified = time_at(100, 1);
    assert(row(f).relation == ComparisonRelation::SourceNewer);
    f.options.timestamp_quantum_ns = 1000;
    assert(row(f).relation == ComparisonRelation::SameSizeAndMtime);
    f.destination[0].object.timestamp_quantum_ns = 1'000'000'000;
    assert(row(f).reason == ComparisonReason::PrecisionUnavailable);
    f.options.timestamp_quantum_ns = 1'000'000'000;
    assert(row(f).relation == ComparisonRelation::SameSizeAndMtime);
    f.source[0].object.modified = time_at(3700);
    assert(row(f).relation == ComparisonRelation::SourceNewer); // no DST forgiveness
    f.source[0].object.modified = time_at(-1, 999'999'999);
    f.destination[0].object.modified = time_at(0);
    f.options.timestamp_quantum_ns = 2'000'000'000;
    assert(row(f).relation == ComparisonRelation::DestinationNewer); // floor before epoch
    f.source[0].object.modified = time_at(std::numeric_limits<std::int64_t>::min());
    f.destination[0].object.modified = time_at(std::numeric_limits<std::int64_t>::max(), 999'999'999);
    assert(row(f).relation == ComparisonRelation::DestinationNewer);
    f.options.timestamp_quantum_ns = 3;
    assert(!f.build().value());
    f.options.timestamp_quantum_ns = 1;
    f.destination[0].object.timestamp_quantum_ns = 0;
    assert_safe_unknown(row(f));
}
void unknown_evidence() {
    Fixture f; f.options.profile = ComparisonProfile::Mirror;
    f.source = {file("a", 1)}; f.destination = {file("a", 2)};
    for (auto state : {ComparisonObjectState::Unknown, ComparisonObjectState::Denied, ComparisonObjectState::Gone,
        ComparisonObjectState::Changed, ComparisonObjectState::Failed}) {
        f.source[0].object.state = state; assert_safe_unknown(row(f));
    }
    f.source[0] = file("a", 1);
    f.source[0].object.identity.reset(); assert_safe_unknown(row(f));
    f.source[0] = file("a", 1); f.source[0].object.identity->object = {};
    assert_safe_unknown(row(f));
    f.source[0] = file("a", 1); f.source[0].object.size.reset();
    assert(row(f).reason == ComparisonReason::MissingSize);
    f.source[0] = file("a", 1); f.source[0].object.modified.reset();
    assert_safe_unknown(row(f));
    f.source.clear();
    for (auto state : {ComparisonInventoryState::Unknown, ComparisonInventoryState::Incomplete, ComparisonInventoryState::Denied,
        ComparisonInventoryState::Changed, ComparisonInventoryState::Failed}) {
        f.ss = state; assert_safe_unknown(row(f));
    }
    f.ss = ComparisonInventoryState::CompleteStable; f.sr.reset(); assert_safe_unknown(row(f));
    f.sr = identity(1000); f.destination[0].object.kind = ObjectKind::SymbolicLink;
    assert(row(f).reason == ComparisonReason::UnsupportedKind);
    f.destination[0] = file("a", 1); f.source = {file("a", 1)};
    assert(row(f).reason == ComparisonReason::SameObject);
}
void exclusions_and_trees() {
    Fixture f; f.options.profile = ComparisonProfile::Mirror;
    f.destination = {directory("tree", 5), file("tree/keep", 6), file("tree/remove", 7)};
    f.exclusions = {"tree/keep"};
    auto r = rows(f.plan());
    assert(r[0].reason == ComparisonReason::ProtectedDescendant);
    assert(r[1].action == ComparisonAction::Skip);
    assert(r[2].action == ComparisonAction::RemoveDestinationFile);
    f.exclusions = {"tree/omitted/nested"}; // absent exclusion still protects its parents
    assert(rows(f.plan())[0].destination_protected);
    f.exclusions.clear(); f.source = {directory("tree", 10)}; f.source[0].excluded = true;
    r = rows(f.plan()); for (const auto& e : r) assert(e.action == ComparisonAction::Skip);
    f.source.clear(); f.destination[0].name_collision = true;
    r = rows(f.plan()); for (const auto& e : r) assert_safe_unknown(e);
    f.destination[0].name_collision = false;
    f.destination[1].object.state = ComparisonObjectState::Denied;
    r = rows(f.plan()); assert(r[0].reason == ComparisonReason::ProtectedDescendant); assert_safe_unknown(r[1]);
    f.destination[1] = file("tree/keep", 6);
    f.source = {directory("tree", 10), file("tree/new", 11)};
    f.destination = {file("tree", 12)};
    r = rows(f.plan()); assert(r[0].relation == ComparisonRelation::TypeConflict); assert_safe_unknown(r[1]);
    f.destination = {directory("tree", 12)};
    r = rows(f.plan()); assert(r[0].action == ComparisonAction::MergeDirectories);
    assert(r[1].action == ComparisonAction::CopyToDestination);
    f.options.profile = ComparisonProfile::Move;
    r = rows(f.plan()); assert(r[0].action == ComparisonAction::MoveAfterCommit);
    f.source.clear(); f.destination = {directory("empty", 1)};
    f.options.profile = ComparisonProfile::Mirror;
    assert(row(f).action == ComparisonAction::RemoveDestinationDirectory);
}
void filters() {
    Fixture f; f.options.profile = ComparisonProfile::Mirror;
    f.destination = {file("a", 1, 10, 100)};
    f.options.filters.minimum_size = 11;
    assert(row(f).reason == ComparisonReason::Filtered);
    f.options.filters.minimum_size = 10; f.options.filters.maximum_size = 10;
    assert(row(f).action == ComparisonAction::RemoveDestinationFile);
    f.options.filters.modified_not_before = time_at(100);
    f.options.filters.modified_before = time_at(101);
    assert(row(f).relation == ComparisonRelation::DestinationOnly);
    f.options.filters.modified_before = time_at(100);
    assert(!f.build().value()); // empty/reversed date interval
    f.options.filters.modified_not_before.reset();
    assert(row(f).relation == ComparisonRelation::Protected); // upper bound exclusive
    f.destination[0].object.modified.reset();
    assert_safe_unknown(row(f));
    f.options.filters = {};
    f.options.filters.allowed_kind_mask = 1ULL << static_cast<unsigned>(ObjectKind::Directory);
    assert(row(f).destination_protected);
    f.options.filters = {}; f.options.filters.maximum_depth = 1;
    f.destination = {directory("a", 1), file("a/b", 2)};
    auto r = rows(f.plan()); assert(r[0].destination_protected); assert(r[1].reason == ComparisonReason::Filtered);
    f.options.filters = {}; f.options.filters.minimum_size = 10;
    f.destination[1].object.size.reset();
    r = rows(f.plan()); assert_safe_unknown(r[1]); assert(r[0].destination_protected);
}
void bounds_and_structure() {
    Fixture f; auto p = f.plan(); assert(p->aggregate().rows == 0);
    assert(p->page(0, 1).value()->rows.empty());
    for (const auto* key : {"", "/a", "a/", "../a", "a/..", "a//b", "a/./b", "a\\b", "C:/a"}) {
        f.source = {file(key, 1)}; assert(!f.build().value());
    }
    f.source = {file(std::string("a\0b", 3), 1)}; assert(!f.build().value());
    f.source = {file("a", 1), file("a", 2)}; assert(!f.build().value());
    f.source = {file("a/b", 1)}; assert(!f.build().value());
    f.source = {file("a", 1), file("a/b", 2)}; assert(!f.build().value());
    f.source = {file("a", 1)}; f.options.topology = ComparisonTopology::Unknown; assert(!f.build().value());
    f.options.topology = ComparisonTopology::Overlap; assert(!f.build().value());
    f.options.topology = ComparisonTopology::SameRoot; assert(!f.build().value());
    f.options.topology = ComparisonTopology::Disjoint; f.dr = f.sr; assert(!f.build().value());
    f.dr = identity(2000);
    f.limits.max_entries = 1; f.destination = {file("a", 2)}; assert(!f.build().value());
    f.limits = {}; f.limits.max_total_path_bytes = 1; assert(!f.build().value());
    f.destination.clear(); f.limits = {}; f.limits.max_path_bytes = 1; f.source[0].relative_path = "aa"; assert(!f.build().value());
    f.source[0].relative_path = "a"; f.limits = {}; f.limits.max_page_rows = 0; assert(!f.build().value());
    f.limits = {}; f.limits.max_entries = ComparisonLimits::hard_max_entries + 1; assert(!f.build().value());
    f.limits = {}; f.limits.max_exclusions = 0; f.exclusions = {"a"}; assert(!f.build().value());
    f.exclusions.clear(); f.options.profile = static_cast<ComparisonProfile>(999); assert(!f.build().value());
    f.options.profile = ComparisonProfile::Mirror; f.source[0].object.timestamp_quantum_ns = 3; assert(!f.build().value());
}
void aggregates() {
    Fixture f; f.options.profile = ComparisonProfile::Sync;
    f.source = {file("b", 2, 20), file("a", 1, 10)};
    auto p = f.plan(); const auto a = p->aggregate();
    assert(a.rows == 2 && a.source_bytes == 30 && a.destination_bytes == 0);
    assert(a.proposed_copy_bytes == 30 && a.proposed_writes == 2 && a.proposed_removals == 0);
    assert(a.source_bytes_complete && a.destination_bytes_complete && a.proposed_copy_bytes_complete);
    f.limits.max_aggregate_bytes = 29; assert(!f.build().value());
    f.limits.max_aggregate_bytes = std::numeric_limits<std::uint64_t>::max();
    f.source[0].object.size = std::numeric_limits<std::uint64_t>::max();
    assert(!f.build().value()); // checked addition, not wraparound
    f.source[0].object.size = 20; f.source[1].object.size.reset();
    p = f.plan(); assert(!p->aggregate().source_bytes_complete); assert(p->aggregate().source_bytes == 20);
    assert(p->aggregate().unknown_rows == 1 && p->aggregate().review_rows == 1);
    f.source[1] = file("a", 1); f.ss = ComparisonInventoryState::Incomplete;
    assert(!f.plan()->aggregate().source_bytes_complete);
    f.ss = ComparisonInventoryState::CompleteStable; f.exclusions = {"omitted"};
    assert(!f.plan()->aggregate().source_bytes_complete);
}
void tokens_and_paging() {
    Fixture f; f.source = {file("c", 3), file("b", 2), file("a", 1)}; f.limits.max_page_rows = 2;
    auto p = f.plan();
    auto first = p->page(0, 2); assert(first.value());
    assert(first.value()->rows[0].relative_path == "a" && first.value()->rows[1].relative_path == "b");
    assert(first.value()->total_rows == 3 && first.value()->next_offset == 2);
    assert(p->page(2, 2).value()->rows.size() == 1 && !p->page(2, 2).value()->next_offset);
    assert(p->page(3, 2).value()->rows.empty());
    assert(!p->page(4, 1).value() && !p->page(0, 0).value() && !p->page(0, 3).value());
    const auto token = first.value()->rows[0].token;
    assert(token.is_valid() && token.plan_identity() == p->identity() && token.row_id() == 1);
    assert(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::Matches);
    std::reverse(f.source.begin(), f.source.end());
    assert(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::Matches);
    assert(f.plan()->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::ForeignToken);
    assert(p->revalidate({}, f.options, f.s(), f.d()) == ComparisonRevalidation::ForeignToken);
    f.source[2].object.size = 11; // change another row invalidates whole evidence set
    assert(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::EvidenceChanged);
    f.source[2].object.size = 10;
    f.source.push_back(file("d", 4));
    assert(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::EvidenceChanged);
    f.source.pop_back(); f.sr = identity(3000);
    assert(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::EvidenceChanged);
    f.sr = identity(1000); f.options.profile = ComparisonProfile::Mirror;
    assert(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::EvidenceChanged);
    f.options.profile = ComparisonProfile::Compare; f.options.filters.maximum_size = 20;
    assert(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::EvidenceChanged);
    f.options.filters = {}; f.exclusions = {"a"};
    assert(p->revalidate(token, f.options, f.s(), f.d(), f.exclusions) == ComparisonRevalidation::EvidenceChanged);
    f.exclusions.clear(); f.source[0].relative_path = "../invalid";
    assert(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::InvalidInput);
    // Page copies can be changed/destroyed without changing the frozen plan.
    first.value(); auto copied = *first.value(); copied.rows[0].action = ComparisonAction::RemoveDestinationFile;
    assert(p->page(0, 1).value()->rows[0].action == ComparisonAction::Report);
    p.reset(); assert(copied.identity.is_valid() && copied.rows[0].token == token);
}
void digest_revalidation() {
    Fixture f; f.options.mode = ComparisonMode::CompleteDigest;
    f.source = {file("a", 1)}; f.destination = {file("a", 2)};
    digest(f.source[0]); digest(f.destination[0]); auto p = f.plan(); auto token = rows(p)[0].token;
    assert(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::Matches);
    f.source[0].digest->state = ComparisonDigestState::Incomplete;
    assert(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::EvidenceChanged);
    digest(f.source[0]); f.destination[0].object.identity->generation = 2;
    assert(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::EvidenceChanged);
}
}
int main() {
    profiles(); comparison_modes(); timestamp_precision(); unknown_evidence(); exclusions_and_trees();
    filters(); bounds_and_structure(); aggregates(); tokens_and_paging(); digest_revalidation();
    std::cout << "comparison_plan_tests: all assertions passed\n";
}
