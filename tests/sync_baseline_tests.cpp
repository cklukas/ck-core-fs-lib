// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Standalone, one compiler process:
// c++ -std=c++20 tests/sync_baseline_tests.cpp src/files/sync_baseline.cpp \
//     src/files/sha256.cpp -o "$TMPDIR/sync_baseline_tests"
#include "../src/files/sync_baseline.hpp"
#include "../src/files/sha256.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace {
using namespace ck::files;
unsigned checks = 0;
void check(bool condition, const char* expression, int line) {
    ++checks;
    if (!condition) {
        std::fprintf(stderr, "line %d: %s\n", line, expression);
        std::exit(1);
    }
}
#define CHECK(expression) check((expression), #expression, __LINE__)
SyncDigest digest(unsigned char n) { SyncDigest d{}; d[0] = std::byte{n}; return d; }
const auto policy = digest(55);
const SyncEntryStatus unknown{};
const SyncEntryStatus absent{SyncPresence::Absent};
SyncEntryStatus file(unsigned char content, unsigned char metadata = 1) {
    return {SyncPresence::Present, SyncKind::File, digest(content), digest(metadata)};
}
SyncEntryStatus directory(unsigned char metadata = 1) {
    return {SyncPresence::Present, SyncKind::Directory, digest(100), digest(metadata)};
}
SyncBaseline baseline(std::vector<SyncBaselineRow> rows) { return {policy, std::move(rows)}; }
SyncReconcilePlan plan(const SyncBaseline* old, std::span<const SyncBaselineRow> now,
    SyncDeletionGuard guard = {1000, 10'000}, SyncDigest fingerprint = policy,
    bool complete = true) {
    auto p = reconcile_sync(old, {complete, complete, now}, fingerprint, guard);
    CHECK(p.value());
    return std::move(p).take_value();
}
void decision_table() {
    const std::array statuses{unknown, absent, file(1), file(2)};
    for (const auto& l : statuses) for (const auto& r : statuses) {
        const std::array now{SyncBaselineRow{"f", l, r}};
        auto p = plan(nullptr, now);
        CHECK(p.rows.size() == 1);
        const auto a = p.rows[0].action;
        CHECK(a != SyncAction::DeleteLeft && a != SyncAction::DeleteRight);
        if (l == unknown || r == unknown) CHECK(a == SyncAction::Blocked);
        else if (l == r) CHECK(a == SyncAction::Unchanged);
        else if (r == absent) CHECK(a == SyncAction::CopyLeftToRight);
        else if (l == absent) CHECK(a == SyncAction::CopyRightToLeft);
        else CHECK(a == SyncAction::Conflict);
    }
    auto old = baseline({{"f", file(1), file(1)}});
    for (const auto& l : statuses) for (const auto& r : statuses) {
        const std::array now{SyncBaselineRow{"f", l, r}};
        const auto p = plan(&old, now);
        const auto a = p.rows[0].action;
        if (l == unknown || r == unknown) CHECK(a == SyncAction::Blocked);
        else if (l == r) CHECK(a == SyncAction::Unchanged);
        else if (l == file(1)) CHECK(a == (r == absent ? SyncAction::DeleteLeft : SyncAction::CopyRightToLeft));
        else if (r == file(1)) CHECK(a == (l == absent ? SyncAction::DeleteRight : SyncAction::CopyLeftToRight));
        else {
            CHECK(a == SyncAction::Conflict);
            CHECK(p.rows[0].reason == SyncReason::DeleteEdit);
        }
    }
    std::array now{SyncBaselineRow{"f", file(2), file(3)}};
    CHECK(plan(&old, now).rows[0].reason == SyncReason::ConcurrentEdit);
    now[0] = {"f", file(1, 2), file(1)}; // one-sided chmod, same content
    CHECK(plan(&old, now).rows[0].action == SyncAction::CopyLeftToRight);
    now[0] = {"f", file(1), file(1, 2)};
    CHECK(plan(&old, now).rows[0].action == SyncAction::CopyRightToLeft);
    now[0] = {"f", file(1, 2), file(1, 3)};
    CHECK(plan(&old, now).rows[0].reason == SyncReason::RequiredMetadataDifference);
    CHECK(plan(nullptr, now).rows[0].reason == SyncReason::RequiredMetadataDifference);
    now[0] = {"f", file(1, 2), file(1, 2)};
    CHECK(plan(&old, now).rows[0].action == SyncAction::Unchanged);
    CHECK(plan(&old, {}).rows[0].action == SyncAction::Blocked); // omission is not absence
    old.rows[0].left = unknown;
    now[0] = {"f", absent, file(1)};
    CHECK(plan(&old, now).rows[0].reason == SyncReason::UnknownStatus);
    old.rows[0] = {"f", file(2), file(3)};
    CHECK(plan(&old, now).rows[0].reason == SyncReason::BaselineDiverged);
}
void policy_and_guards() {
    auto old = baseline({{"a", file(1), file(1)}, {"b", file(1), file(1)}});
    std::array now{SyncBaselineRow{"a", absent, file(1)}, SyncBaselineRow{"b", file(1), file(1)}};
    CHECK(plan(&old, now, {1, 5000}).state == SyncReconcileState::Ready);
    auto p = plan(&old, now, {1, 4999});
    CHECK(p.state == SyncReconcileState::DeletionGuardExceeded);
    CHECK(p.proposed_deletions_right == 1 && p.proposed_deletions_left == 0);
    CHECK(p.rows[0].action == SyncAction::Blocked && p.rows[0].reason == SyncReason::DeletionGuard);
    CHECK(plan(&old, now, {0, 10'000}).state == SyncReconcileState::DeletionGuardExceeded);
    CHECK(plan(&old, now, {1, 0}).state == SyncReconcileState::DeletionGuardExceeded);
    auto no_permission = reconcile_sync(&old, {true, true, now}, policy);
    CHECK(no_permission.value() && no_permission.value()->state == SyncReconcileState::DeletionGuardExceeded);
    now[1] = {"b", file(1), absent};
    CHECK(plan(&old, now, {1, 10'000}).state == SyncReconcileState::DeletionGuardExceeded);
    CHECK(plan(&old, now, {2, 5000}).state == SyncReconcileState::Ready);
    // A left-only baseline row increases only the left denominator.
    old.rows.push_back({"c", file(1), absent});
    std::vector<SyncBaselineRow> asymmetric(now.begin(), now.end());
    asymmetric.push_back(old.rows.back());
    CHECK(plan(&old, asymmetric, {2, 4999}).state == SyncReconcileState::DeletionGuardExceeded);
    p = plan(&old, asymmetric, {1000, 10'000}, digest(56));
    CHECK(p.state == SyncReconcileState::ReconcileRequired);
    CHECK(p.proposed_deletions_left + p.proposed_deletions_right == 0);
    for (const auto& row : p.rows) CHECK(row.action == SyncAction::Blocked && row.reason == SyncReason::PolicyChanged);
    p = plan(&old, asymmetric, {1000, 10'000}, policy, false);
    CHECK(p.state == SyncReconcileState::Blocked);
    for (const auto& row : p.rows) CHECK(row.reason == SyncReason::IncompleteInventory);
    CHECK(plan(nullptr, {}, {0, 0}, policy, false).state == SyncReconcileState::Blocked);
}
void subtree_conflicts() {
    // The intervening sibling makes naive lexical stack ancestry incorrect.
    auto old = baseline({{"a", directory(), directory()}, {"a-", file(1), file(1)},
        {"a/b", directory(), directory()}, {"a/b/c", file(1), file(1)}});
    std::vector<SyncBaselineRow> now{{"a", absent, directory()}, {"a-", file(1), file(1)},
        {"a/b", absent, directory()}, {"a/b/c", absent, file(2)}};
    auto p = plan(&old, now);
    CHECK(p.rows[0].action == SyncAction::Conflict);
    CHECK(p.rows[0].reason == SyncReason::DirectoryDeleteChangedSubtree);
    CHECK(p.rows[1].action == SyncAction::Unchanged);
    CHECK(p.rows[2].reason == SyncReason::AncestorConflict);
    CHECK(p.rows[3].reason == SyncReason::AncestorConflict);
    // A newly added child also conflicts with deletion of the other directory.
    now[3] = {"a/b/c", absent, file(1)};
    now.push_back({"a/b/new", absent, file(3)});
    CHECK(plan(&old, now).rows[0].reason == SyncReason::DirectoryDeleteChangedSubtree);
    now.pop_back();
    now[3].left = unknown;
    CHECK(plan(&old, now).rows[0].reason == SyncReason::UnknownStatus);
    now[3].left = absent;
    p = plan(&old, now);
    CHECK(p.rows[0].action == SyncAction::DeleteRight);
    CHECK(p.rows[2].action == SyncAction::DeleteRight);
    CHECK(p.rows[3].action == SyncAction::DeleteRight);
    CHECK(p.proposed_deletions_right == 3);
    for (auto& r : now) std::swap(r.left, r.right);
    CHECK(plan(&old, now).rows[0].action == SyncAction::DeleteLeft);
    now[3].left = file(2);
    CHECK(plan(&old, now).rows[0].reason == SyncReason::DirectoryDeleteChangedSubtree);
}
void pending_advancement() {
    auto old = baseline({{"a", file(1), file(1)}, {"b", file(1), file(1)}});
    std::vector<SyncBaselineUpdate> updates{{{"a", absent, file(1)}, SyncBaselineUpdateState::Pending},
        {{"c", file(3), file(3)}, SyncBaselineUpdateState::ConfirmedEqual},
        {{"d", absent, file(1)}, SyncBaselineUpdateState::Pending}};
    auto result = advance_sync_baseline(&old, updates, policy);
    CHECK(result.value());
    const auto& value = *result.value();
    CHECK(value.baseline.rows.size() == 3);
    CHECK(value.baseline.rows[0] == old.rows[0]); // skipped delete keeps prior digest
    CHECK(value.baseline.rows[1] == old.rows[1]); // omission remains pending
    CHECK(value.baseline.rows[2] == updates[1].observed);
    CHECK(value.pending_paths == std::vector<std::string>({"a", "b", "d"}));
    const std::array now{updates[0].observed, old.rows[1], updates[1].observed};
    CHECK(plan(&value.baseline, now).rows[0].action == SyncAction::DeleteRight);
    updates[0].state = SyncBaselineUpdateState::ConfirmedEqual;
    CHECK(!advance_sync_baseline(&old, updates, policy).value());
    updates[0].observed.right = absent;
    result = advance_sync_baseline(&old, updates, policy);
    CHECK(result.value() && result.value()->baseline.rows[0].left == absent);
    CHECK(!advance_sync_baseline(&old, updates, digest(99)).value());
    updates[0].observed.left = unknown; updates[0].observed.right = unknown;
    CHECK(!advance_sync_baseline(&old, updates, policy).value());
    result = advance_sync_baseline(nullptr, {}, policy);
    CHECK(result.value() && result.value()->baseline.rows.empty());
}
void reseal(std::vector<std::byte>& bytes) {
    Sha256 h; h.update(std::span<const std::byte>(bytes).first(bytes.size() - 32));
    const auto sum = h.digest();
    std::copy(sum.begin(), sum.end(), bytes.end() - 32);
}
void put(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value, unsigned count) {
    for (unsigned n = 0; n < count; ++n) bytes[offset+n] = std::byte((value >> (8*n)) & 0xff);
}
void codec() {
    auto old = baseline({{"a", unknown, absent}, {"b", file(1), file(2)},
        {"dir", directory(), directory()}, {"dir/file", file(3, 7), file(3, 7)}});
    auto encoded = encode_sync_baseline(old);
    CHECK(encoded.value());
    const auto bytes = *encoded.value();
    CHECK(bytes.size() == 64 + 32 + 4 * 140 + 1 + 1 + 3 + 8);
    auto decoded = decode_sync_baseline(bytes);
    CHECK(decoded.value() && *decoded.value() == old);
    CHECK(*encode_sync_baseline(*decoded.value()).value() == bytes);
    // Every byte position, every truncation and an appended byte fail closed.
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        auto bad = bytes; bad[i] ^= std::byte{1};
        CHECK(!decode_sync_baseline(bad).value());
        CHECK(!decode_sync_baseline(std::span<const std::byte>(bytes).first(i)).value());
    }
    auto bad = bytes; bad.push_back(std::byte{0});
    CHECK(!decode_sync_baseline(bad).value());
    // Recomputed checksums cannot make structurally invalid schemas acceptable.
    for (const auto offset : {std::size_t{0}, std::size_t{8}, std::size_t{12}, std::size_t{16},
        std::size_t{24}, std::size_t{68}, std::size_t{69}, std::size_t{70}}) {
        bad = bytes; bad[offset] = std::byte{0xff}; reseal(bad);
        CHECK(!decode_sync_baseline(bad).value());
    }
    bad = bytes; put(bad, 64, 0xffffffff, 4); reseal(bad);
    CHECK(!decode_sync_baseline(bad).value());
    bad = bytes; bad[72] = std::byte{1}; reseal(bad); // digest on Unknown
    CHECK(!decode_sync_baseline(bad).value());
    bad = bytes; bad[204] = std::byte{'/'}; reseal(bad); // unsafe first key
    CHECK(!decode_sync_baseline(bad).value());
    bad = bytes; bad[345] = std::byte{'a'}; reseal(bad); // duplicate second key
    CHECK(!decode_sync_baseline(bad).value());
    bad = bytes; bad.insert(bad.end()-32, std::byte{0}); put(bad,16,bad.size(),8); reseal(bad);
    CHECK(!decode_sync_baseline(bad).value());
    auto empty = encode_sync_baseline(baseline({}));
    CHECK(empty.value() && empty.value()->size() == 96);
    CHECK(decode_sync_baseline(*empty.value()).value());
    SyncBaselineLimits l;
    l.max_wire_bytes = bytes.size();
    CHECK(encode_sync_baseline(old,l).value() && decode_sync_baseline(bytes,l).value());
    --l.max_wire_bytes;
    CHECK(!encode_sync_baseline(old,l).value() && !decode_sync_baseline(bytes,l).value());
    l = {}; l.max_rows = 3;
    CHECK(!encode_sync_baseline(old,l).value() && !decode_sync_baseline(bytes,l).value());
    l = {}; l.max_path_bytes = 7;
    CHECK(!encode_sync_baseline(old,l).value() && !decode_sync_baseline(bytes,l).value());
    l = {}; l.max_total_path_bytes = 12;
    CHECK(!encode_sync_baseline(old,l).value() && !decode_sync_baseline(bytes,l).value());
}
void invalid_input() {
    for (const auto& key : std::vector<std::string>{"", "/a", "a/", "a//b", "a/./b", "a/../b", "a\\b", "C:a", ".", "..", std::string("a\0b",3)}) {
        const auto old = baseline({{key, file(1), file(1)}});
        CHECK(!encode_sync_baseline(old).value());
        CHECK(!reconcile_sync(&old, {true,true,old.rows}, policy).value());
    }
    auto old = baseline({{"b", file(1), file(1)}, {"a", file(1), file(1)}});
    CHECK(!encode_sync_baseline(old).value());
    old.rows[1].relative_path = "b";
    CHECK(!encode_sync_baseline(old).value());
    old = baseline({{"p", absent, directory()}, {"p/c", file(1), file(1)}});
    CHECK(!encode_sync_baseline(old).value());
    old.rows[0].left = file(1);
    CHECK(!encode_sync_baseline(old).value());
    old = baseline({{"a", file(1), file(1)}});
    SyncBaselineLimits limits; limits.max_rows = 0;
    CHECK(!encode_sync_baseline(old,limits).value());
    CHECK(!decode_sync_baseline({},limits).value());
    CHECK(!reconcile_sync(&old,{true,true,old.rows},policy,{},limits).value());
    CHECK(!advance_sync_baseline(&old,{},policy,limits).value());
    CHECK(!reconcile_sync(&old,{true,true,old.rows},policy,{1,10001}).value());
    std::array now{SyncBaselineRow{"b",file(1),absent}};
    limits = {}; limits.max_rows = 1;
    CHECK(!reconcile_sync(&old,{true,true,now},policy,{},limits).value());
    const std::array updates{SyncBaselineUpdate{now[0],SyncBaselineUpdateState::Pending}};
    CHECK(!advance_sync_baseline(&old,updates,policy,limits).value());
}
} // namespace
int main() {
    decision_table(); policy_and_guards(); subtree_conflicts();
    pending_advancement(); codec(); invalid_input();
    std::printf("sync_baseline_tests: %u checks passed\n", checks);
}
