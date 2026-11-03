// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "comparison_plan.hpp"
#include <cstdio>
#include <functional>
#include <stdexcept>
#include <string>
#include <utility>

using namespace ck::files;
namespace {
unsigned checks = 0;
void check(bool value, const char* expression, int line) {
    ++checks;
    if (!value) throw std::runtime_error(std::to_string(line) + ": " + expression);
}
#define CHECK(x) check(bool(x), #x, __LINE__)
AdapterScope scope;
ObjectIdentity identity(std::uint64_t id) {
    return {scope, IdentityScheme::PosixDeviceInode, NativeIdentifier::from_u64(1), NativeIdentifier::from_u64(id), 1};
}
ComparisonEntry entry(std::uint64_t id) {
    ComparisonEntry e;
    e.relative_path = "file";
    e.object = {ComparisonObjectState::Stable, identity(id), ObjectKind::RegularFile, 7,
        FileTimestamp::from_unix(100, 0), 1, 1};
    e.digest = ComparisonDigest{ComparisonDigestState::CompleteStable, ComparisonDigestAlgorithm::Sha256,
        {}, 7, e.object, e.object};
    e.digest->bytes[0] = std::byte{1};
    return e;
}
void metadata(ComparisonEntry& e, ComparisonMetadataOwnership ownership = ComparisonMetadataOwnership::CurrentCaller) {
    ComparisonMetadataDigest m;
    m.state = ComparisonDigestState::CompleteStable;
    m.algorithm = ComparisonDigestAlgorithm::Sha256;
    m.schema[0] = std::byte{1}; m.policy_binding[0] = std::byte{2}; m.bytes[0] = std::byte{3};
    m.ownership = ownership;
    if (ownership == ComparisonMetadataOwnership::CurrentCaller) {
        m.canonical_owner_digest.emplace(); (*m.canonical_owner_digest)[0] = std::byte{4};
    }
    m.before = m.after = e.object;
    e.metadata_digest = m;
}
struct Fixture {
    ComparisonOptions options;
    std::vector<ComparisonEntry> source{entry(1)}, destination{entry(2)};
    Fixture() {
        options.topology = ComparisonTopology::Disjoint; options.mode = ComparisonMode::CompleteDigest;
        options.profile = ComparisonProfile::Copy; options.compare_preserved_metadata = true;
        metadata(source[0]); metadata(destination[0]);
    }
    ComparisonInventory s() const { return {ComparisonInventoryState::CompleteStable, identity(100), source}; }
    ComparisonInventory d() const { return {ComparisonInventoryState::CompleteStable, identity(200), destination}; }
    Observation<ComparisonPlan::Pointer> build() const { return ComparisonPlan::create(options, s(), d()); }
    ComparisonPlan::Pointer plan() const { auto p = build(); CHECK(p.value()); return *p.value(); }
    ComparisonRow row() const {
        auto p = plan(); auto page = p->page(0, 8); CHECK(page.value() && page.value()->rows.size() == 1);
        return page.value()->rows.front();
    }
};
void unresolved(const Fixture& f, ComparisonReason reason) {
    const auto r = f.row(); CHECK(r.relation == ComparisonRelation::Unknown && r.reason == reason);
    CHECK(r.destination_protected && r.action == ComparisonAction::Review && r.requires_review);
}
void qualified_comparisons() {
    Fixture f;
    auto r = f.row(); CHECK(r.relation == ComparisonRelation::Identical && r.action == ComparisonAction::Skip);
    f.destination[0].metadata_digest->bytes[1] = std::byte{9};
    r = f.row(); CHECK(r.relation == ComparisonRelation::MetadataDifferent && r.reason == ComparisonReason::MetadataMismatch);
    CHECK(r.action == ComparisonAction::Review && r.requires_review);
    metadata(f.destination[0]); (*f.destination[0].metadata_digest->canonical_owner_digest)[1] = std::byte{1};
    r = f.row(); CHECK(r.relation == ComparisonRelation::MetadataDifferent && r.reason == ComparisonReason::MetadataMismatch);
    // CurrentCaller preservation hashes are identical: observed owner equality
    // remains an independent requirement for an equality/Noop conclusion.
    CHECK(f.source[0].metadata_digest->bytes == f.destination[0].metadata_digest->bytes);
    f.options.compare_preserved_metadata = false;
    CHECK(f.row().relation == ComparisonRelation::Identical);
    f.source[0].metadata_digest.reset(); f.destination[0].metadata_digest.reset();
    CHECK(f.row().relation == ComparisonRelation::Identical); // Existing main-only contract.
    f.options.compare_preserved_metadata = true;
    unresolved(f, ComparisonReason::MetadataDigestUnavailable);
    metadata(f.source[0]); metadata(f.destination[0]);
    f.destination[0].digest->bytes[0] = std::byte{8};
    CHECK(f.row().relation == ComparisonRelation::ContentDifferent);
    f.destination[0].digest.reset();
    unresolved(f, ComparisonReason::DigestUnavailable); // Metadata hash never substitutes for main data.
    f = Fixture{};
    metadata(f.source[0], ComparisonMetadataOwnership::Original);
    metadata(f.destination[0], ComparisonMetadataOwnership::Original);
    CHECK(f.row().relation == ComparisonRelation::Identical); // Original's schema includes ownership.
    f.destination[0].metadata_digest->bytes[2] = std::byte{2};
    CHECK(f.row().relation == ComparisonRelation::MetadataDifferent);
}
void qualification_failures() {
    for (bool source : {false, true}) {
        Fixture f; auto& e = source ? f.source[0] : f.destination[0];
        for (auto state : {ComparisonDigestState::Unknown, ComparisonDigestState::Incomplete,
             ComparisonDigestState::Denied, ComparisonDigestState::Failed}) {
            e.metadata_digest->state = state; unresolved(f, ComparisonReason::MetadataDigestIncomplete);
        }
        e.metadata_digest->state = ComparisonDigestState::Changed;
        unresolved(f, ComparisonReason::MetadataDigestChanged); metadata(e);
        e.metadata_digest->algorithm = ComparisonDigestAlgorithm::Unknown;
        unresolved(f, ComparisonReason::MetadataDigestUnavailable); metadata(e);
        e.metadata_digest->schema = {};
        unresolved(f, ComparisonReason::MetadataSchemaMismatch); metadata(e);
        e.metadata_digest->schema[1] = std::byte{1};
        unresolved(f, ComparisonReason::MetadataSchemaMismatch); metadata(e);
        e.metadata_digest->policy_binding = {};
        unresolved(f, ComparisonReason::MetadataPolicyMismatch); metadata(e);
        e.metadata_digest->policy_binding[1] = std::byte{1};
        unresolved(f, ComparisonReason::MetadataPolicyMismatch); metadata(e);
        e.metadata_digest->ownership = ComparisonMetadataOwnership::Unknown;
        unresolved(f, ComparisonReason::MetadataPolicyMismatch); metadata(e);
        e.metadata_digest->ownership = ComparisonMetadataOwnership::Original;
        unresolved(f, ComparisonReason::MetadataPolicyMismatch); metadata(e);
        e.metadata_digest->canonical_owner_digest.reset();
        unresolved(f, ComparisonReason::MetadataOwnerUnavailable);
    }
    using Change = std::function<void(ComparisonObject&)>;
    const Change changes[] = {
        [](auto& o) { o.state = ComparisonObjectState::Changed; },
        [](auto& o) { o.identity->scope = AdapterScope{}; },
        [](auto& o) { o.identity->generation = 2; },
        [](auto& o) { o.identity->object = NativeIdentifier::from_u64(999); },
        [](auto& o) { o.kind = ObjectKind::Directory; },
        [](auto& o) { o.size = 8; },
        [](auto& o) { o.modified = FileTimestamp::from_unix(101, 0); },
        [](auto& o) { o.timestamp_quantum_ns = 1000; },
        [](auto& o) { o.change_cookie = 2; }
    };
    for (bool source : {false, true}) for (bool before : {false, true}) for (const auto& change : changes) {
        Fixture f; auto& m = *(source ? f.source[0] : f.destination[0]).metadata_digest;
        change(before ? m.before : m.after); unresolved(f, ComparisonReason::MetadataDigestBindingMismatch);
    }
    Fixture no_version; no_version.options.mode = ComparisonMode::Size;
    no_version.source[0].object.modified.reset(); no_version.source[0].object.change_cookie.reset();
    metadata(no_version.source[0]); unresolved(no_version, ComparisonReason::MetadataDigestBindingMismatch);
}
void profile_matrix() {
    for (auto mode : {ComparisonMode::SizeAndMtime, ComparisonMode::Size, ComparisonMode::CompleteDigest})
        for (auto profile : {ComparisonProfile::Copy, ComparisonProfile::Move, ComparisonProfile::Update,
             ComparisonProfile::MissingOnly, ComparisonProfile::Sync, ComparisonProfile::Mirror, ComparisonProfile::Compare}) {
            Fixture f; f.options.mode = mode; f.options.profile = profile;
            CHECK(f.row().relation != ComparisonRelation::MetadataDifferent);
            f.destination[0].metadata_digest->bytes[0] = std::byte{4};
            const auto r = f.row(); CHECK(r.relation == ComparisonRelation::MetadataDifferent);
            CHECK(r.reason == ComparisonReason::MetadataMismatch);
            const auto action = profile == ComparisonProfile::Compare ? ComparisonAction::Report :
                profile == ComparisonProfile::MissingOnly ? ComparisonAction::Skip :
                profile == ComparisonProfile::Sync || profile == ComparisonProfile::Mirror ?
                    ComparisonAction::ReplaceDestination : ComparisonAction::Review;
            CHECK(r.action == action && r.requires_review == (action == ComparisonAction::Review));
        }
    Fixture update; update.options.profile = ComparisonProfile::Update;
    update.destination[0].object.modified = FileTimestamp::from_unix(101, 0);
    update.destination[0].digest->before = update.destination[0].digest->after = update.destination[0].object;
    metadata(update.destination[0]); update.destination[0].metadata_digest->bytes[0] = std::byte{9};
    const auto r = update.row(); CHECK(r.relation == ComparisonRelation::MetadataDifferent);
    CHECK(r.action == ComparisonAction::Skip && r.reason == ComparisonReason::MetadataMismatch);
}
void frozen_evidence() {
    for (bool enabled : {false, true}) {
        Fixture f; f.options.compare_preserved_metadata = enabled;
        auto p = f.plan(); const auto token = f.row().token; // Deliberately another plan.
        CHECK(p->revalidate(token, f.options, f.s(), f.d()) == ComparisonRevalidation::ForeignToken);
        const auto own = p->page(0, 1).value()->rows.front().token;
        CHECK(p->revalidate(own, f.options, f.s(), f.d()) == ComparisonRevalidation::Matches);
        auto changed = [&](const std::function<void(Fixture&)>& mutate) {
            Fixture copy = f; mutate(copy);
            CHECK(p->revalidate(own, copy.options, copy.s(), copy.d()) == ComparisonRevalidation::EvidenceChanged);
        };
        changed([](auto& c) { c.options.compare_preserved_metadata = !c.options.compare_preserved_metadata; });
        for (bool source : {false, true}) {
            auto mutate = [&](const std::function<void(ComparisonMetadataDigest&)>& action) {
                changed([&](auto& c) { action(*(source ? c.source[0] : c.destination[0]).metadata_digest); });
            };
            changed([&](auto& c) { (source ? c.source[0] : c.destination[0]).metadata_digest.reset(); });
            mutate([](auto& m) { m.state = ComparisonDigestState::Changed; });
            mutate([](auto& m) { m.algorithm = ComparisonDigestAlgorithm::Unknown; });
            mutate([](auto& m) { m.ownership = ComparisonMetadataOwnership::Original; });
            mutate([](auto& m) { m.canonical_owner_digest.reset(); });
            mutate([](auto& m) { m.before.change_cookie = 3; });
            mutate([](auto& m) { m.after.identity->generation = 3; });
            for (std::size_t n = 0; n < 32; ++n) {
                mutate([&](auto& m) { m.schema[n] ^= std::byte{1}; });
                mutate([&](auto& m) { m.policy_binding[n] ^= std::byte{1}; });
                mutate([&](auto& m) { m.bytes[n] ^= std::byte{1}; });
                mutate([&](auto& m) { (*m.canonical_owner_digest)[n] ^= std::byte{1}; });
            }
        }
        // Caller edits cannot alter an existing plan's copied evidence/page.
        f.source[0].metadata_digest->bytes[0] = std::byte{99};
        CHECK(p->source_entries()[0].metadata_digest->bytes[0] == std::byte{3});
        CHECK(p->page(0, 1).value()->rows.front().relation == ComparisonRelation::Identical);
    }
}
void invalid_and_structural() {
    static_assert(static_cast<unsigned>(ComparisonRelation::Protected) == 12);
    static_assert(static_cast<unsigned>(ComparisonReason::SameObject) == 30);
    using Change = std::function<void(ComparisonMetadataDigest&)>;
    const Change invalid[] = {
        [](auto& m) { m.state = static_cast<ComparisonDigestState>(-1); },
        [](auto& m) { m.state = static_cast<ComparisonDigestState>(6); },
        [](auto& m) { m.algorithm = static_cast<ComparisonDigestAlgorithm>(2); },
        [](auto& m) { m.ownership = static_cast<ComparisonMetadataOwnership>(-1); },
        [](auto& m) { m.ownership = static_cast<ComparisonMetadataOwnership>(3); },
        [](auto& m) { m.before.state = static_cast<ComparisonObjectState>(6); },
        [](auto& m) { m.after.timestamp_quantum_ns = 3; }
    };
    for (bool source : {false, true}) for (const auto& action : invalid) {
        Fixture f; auto p = f.plan(); auto own = p->page(0, 1).value()->rows.front().token;
        action(*(source ? f.source[0] : f.destination[0]).metadata_digest);
        CHECK(!f.build().value()); CHECK(p->revalidate(own, f.options, f.s(), f.d()) == ComparisonRevalidation::InvalidInput);
    }
    Fixture directory;
    for (auto* e : {&directory.source[0], &directory.destination[0]}) {
        e->object.kind = ObjectKind::Directory; e->object.size.reset(); e->digest.reset(); e->metadata_digest.reset();
    }
    unresolved(directory, ComparisonReason::DirectoryMetadataUnsupported);
    auto child_s = entry(3), child_d = entry(4); child_s.relative_path = child_d.relative_path = "file/child";
    metadata(child_s); metadata(child_d); directory.source.push_back(child_s); directory.destination.push_back(child_d);
    auto rows = directory.plan()->page(0, 8); CHECK(rows.value() && rows.value()->rows.size() == 2);
    CHECK(rows.value()->rows[1].reason == ComparisonReason::AncestorConflict && rows.value()->rows[1].destination_protected);
    directory.options.compare_preserved_metadata = false;
    CHECK(directory.plan()->page(0, 8).value()->rows[0].action == ComparisonAction::MergeDirectories);
    Fixture excluded; excluded.source[0].excluded = true; excluded.source[0].metadata_digest.reset();
    CHECK(excluded.row().action == ComparisonAction::Skip && excluded.row().destination_protected);
}
void one_sided_metadata() {
    for (auto mode : {ComparisonMode::Size, ComparisonMode::SizeAndMtime, ComparisonMode::CompleteDigest})
        for (bool source : {false, true}) {
            Fixture f; f.options.mode = mode; f.options.profile = ComparisonProfile::Mirror;
            if (source) f.destination.clear(); else f.source.clear();
            auto& e = (source ? f.source : f.destination).front();
            const auto expected = source ? ComparisonAction::CopyToDestination : ComparisonAction::RemoveDestinationFile;
            CHECK(f.row().action == expected);
            e.metadata_digest.reset(); unresolved(f, ComparisonReason::MetadataDigestUnavailable);
            metadata(e); e.metadata_digest->state = ComparisonDigestState::Incomplete;
            unresolved(f, ComparisonReason::MetadataDigestIncomplete);
            metadata(e); e.metadata_digest->state = ComparisonDigestState::Changed;
            unresolved(f, ComparisonReason::MetadataDigestChanged);
            metadata(e); e.metadata_digest->canonical_owner_digest.reset();
            unresolved(f, ComparisonReason::MetadataOwnerUnavailable);
            metadata(e); e.metadata_digest->before.change_cookie = 2;
            unresolved(f, ComparisonReason::MetadataDigestBindingMismatch);
            metadata(e, ComparisonMetadataOwnership::Original); CHECK(f.row().action == expected);
            metadata(e); CHECK(f.row().action == expected);
            e.metadata_digest.reset(); f.options.compare_preserved_metadata = false;
            CHECK(f.row().action == expected); // Legacy main-only behavior stays intact.
            f.options.compare_preserved_metadata = true; e.object.kind = ObjectKind::Directory;
            e.object.size.reset(); e.digest.reset();
            unresolved(f, ComparisonReason::DirectoryMetadataUnsupported);
            f.options.compare_preserved_metadata = false;
            CHECK(f.row().action == (source ? ComparisonAction::CreateDestinationDirectory : ComparisonAction::RemoveDestinationDirectory));
        }
}
}
int main() {
    try {
        qualified_comparisons(); qualification_failures(); profile_matrix(); frozen_evidence(); invalid_and_structural();
        one_sided_metadata();
        std::printf("preserved metadata planner: %u checks passed\n", checks); return 0;
    } catch (const std::exception& e) { std::fprintf(stderr, "%s\n", e.what()); return 1; }
}
