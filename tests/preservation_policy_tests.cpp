// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Standalone (one compile slot):
// c++ -std=c++20 -DCK_FS_POLICY_STATIC tests/preservation_policy_tests.cpp \
//     src/files/preservation_policy.cpp src/c-api/preservation_policy_c.cpp \
//     -o "$TMPDIR/preservation_policy_tests"
#include "../src/files/preservation_policy.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <type_traits>

namespace {

unsigned checks = 0;
void check(bool condition, const char* text, int line) {
    ++checks;
    if (condition) return;
    std::fprintf(stderr, "line %d: %s\n", line, text);
    std::exit(1);
}
#define CHECK(condition) check((condition), #condition, __LINE__)

constexpr std::uint64_t bit(unsigned index) { return UINT64_C(1) << index; }

ckfe_preservation_inventory_v1 complete_inventory() {
    auto inventory = ck::files::empty_preservation_inventory();
    inventory.state = CKFE_POLICY_INVENTORY_COMPLETE;
    inventory.flags = CKFE_POLICY_INVENTORY_SECURITY_CLASSIFIED;
    for (auto& evidence : inventory.classes) {
        evidence.source = CKFE_POLICY_SOURCE_ABSENT;
        evidence.flags = CKFE_POLICY_EVIDENCE_COMPLETE;
        evidence.destination = CKFE_POLICY_SUPPORT_SUPPORTED;
    }
    inventory.classes[CKFE_POLICY_ORDINARY_PERMISSIONS].source = CKFE_POLICY_SOURCE_PRESENT;
    inventory.classes[CKFE_POLICY_TIMESTAMPS].source = CKFE_POLICY_SOURCE_PRESENT;
    inventory.classes[CKFE_POLICY_OWNERSHIP].source = CKFE_POLICY_SOURCE_PRESENT;
    return inventory;
}

ckfe_preservation_assessment_v1 assess(const ckfe_preservation_policy_v1& policy,
    const ckfe_preservation_inventory_v1& inventory) {
    ckfe_preservation_assessment_v1 out{};
    const auto result = ckfe_preservation_assess_v1(&policy, &inventory, &out, sizeof(out));
    CHECK(result == out.result);
    CHECK(out.version == CKFE_PRESERVATION_POLICY_VERSION);
    CHECK(out.struct_size == sizeof(out));
    CHECK(out.reserved == 0);
    const auto internal = ck::files::assess_preservation_inventory(policy, inventory);
    CHECK(std::memcmp(&internal, &out, sizeof(out)) == 0);
    if (out.result == CKFE_POLICY_RESULT_SUPPORTED) {
        CHECK(out.validation == CKFE_POLICY_VALID);
        CHECK(out.inventory_complete == 1);
        CHECK(out.needs_review_classes == 0);
        CHECK(out.incomplete_classes == 0);
        CHECK(out.unsupported_classes == 0);
        CHECK(out.denied_classes == 0);
        CHECK(out.changed_classes == 0);
        CHECK((out.supported_classes | out.discarded_classes) == CKFE_POLICY_ALL_CLASSES);
        CHECK((out.supported_classes & out.discarded_classes) == 0);
    }
    return out;
}

void defaults_and_mode_separation() {
    ckfe_preservation_policy_v1 policy;
    std::memset(&policy, 0xff, sizeof(policy));
    CHECK(ckfe_preservation_policy_init_v1(&policy) == CKFE_POLICY_VALID);
    CHECK(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_VALID);
    CHECK(policy.flags == 0);
    CHECK(policy.dispositions[CKFE_POLICY_OWNERSHIP] == CKFE_POLICY_CURRENT_CALLER);
    CHECK(policy.dispositions[CKFE_POLICY_PRIVILEGE_BITS] == CKFE_POLICY_DISCARD_SOURCE);
    CHECK(policy.dispositions[CKFE_POLICY_CAPABILITIES] == CKFE_POLICY_REVIEW);
    CHECK(policy.dispositions[CKFE_POLICY_ACCESS_ACL] == CKFE_POLICY_REVIEW);
    CHECK(policy.dispositions[CKFE_POLICY_DEFAULT_ACL] == CKFE_POLICY_REVIEW);
    CHECK(policy.dispositions[CKFE_POLICY_XATTRS] == CKFE_POLICY_REVIEW);
    CHECK(policy.dispositions[CKFE_POLICY_SECURITY_LABELS] == CKFE_POLICY_REVIEW);
    CHECK(policy.dispositions[CKFE_POLICY_STORAGE] == CKFE_POLICY_REVIEW);
    CHECK(policy.dispositions[CKFE_POLICY_PROVIDER] == CKFE_POLICY_REVIEW);
    for (std::uint32_t mode = 0; mode <= 0177777u; ++mode) {
        const auto bits = ck::files::split_preservation_permissions(mode);
        CHECK((bits.ordinary & 07000u) == 0);
        CHECK(bits.ordinary == (mode & 0777u));
        CHECK(bits.privilege == (mode & 07000u));
        CHECK((bits.ordinary | bits.privilege) == (mode & 07777u));
    }
    auto inventory = complete_inventory();
    CHECK(assess(policy, inventory).result == CKFE_POLICY_RESULT_SUPPORTED);
    inventory.classes[CKFE_POLICY_PRIVILEGE_BITS].source = CKFE_POLICY_SOURCE_PRESENT;
    auto out = assess(policy, inventory);
    CHECK(out.result == CKFE_POLICY_RESULT_SUPPORTED);
    CHECK(out.discarded_classes == bit(CKFE_POLICY_PRIVILEGE_BITS));
    CHECK(!(out.supported_classes & bit(CKFE_POLICY_PRIVILEGE_BITS)));
    inventory.classes[CKFE_POLICY_CAPABILITIES].source = CKFE_POLICY_SOURCE_PRESENT;
    out = assess(policy, inventory);
    CHECK(out.result == CKFE_POLICY_RESULT_NEEDS_REVIEW);
    CHECK(out.needs_review_classes == bit(CKFE_POLICY_CAPABILITIES));
}

void policy_validation() {
    const auto good = ck::files::default_preservation_policy();
    auto policy = good;
    policy.version = 0;
    CHECK(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_INVALID_VERSION);
    policy.version = 2;
    CHECK(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_INVALID_VERSION);
    for (auto size : {0u, 8u, static_cast<unsigned>(sizeof(policy) - 1),
             static_cast<unsigned>(sizeof(policy) + 1), std::numeric_limits<unsigned>::max()}) {
        policy = good;
        policy.struct_size = size;
        CHECK(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_INVALID_STRUCT_SIZE);
        CHECK(assess(policy, complete_inventory()).result == CKFE_POLICY_RESULT_INVALID);
    }
    for (unsigned flag = 2; flag < 32; ++flag) {
        policy = good;
        policy.flags = std::uint32_t{1} << flag;
        CHECK(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_UNKNOWN_FIELD);
    }
    policy = good;
    policy.reserved = 1;
    CHECK(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_UNKNOWN_FIELD);
    for (unsigned index = 0; index < 3; ++index) {
        policy = good;
        policy.reserved_words[index] = 1;
        CHECK(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_UNKNOWN_FIELD);
    }
    for (unsigned index = 0; index < CKFE_POLICY_CLASS_COUNT; ++index) {
        for (auto disposition : {0u, 5u, std::numeric_limits<unsigned>::max()}) {
            policy = good;
            policy.dispositions[index] = disposition;
            CHECK(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_INVALID_DISPOSITION);
        }
        policy = good;
        policy.dispositions[index] = CKFE_POLICY_CURRENT_CALLER;
        CHECK(ckfe_preservation_policy_validate_v1(&policy) ==
            (index == CKFE_POLICY_OWNERSHIP ? CKFE_POLICY_VALID : CKFE_POLICY_INVALID_DISPOSITION));
    }
    for (auto index : {CKFE_POLICY_PRIVILEGE_BITS, CKFE_POLICY_CAPABILITIES}) {
        policy = good;
        policy.dispositions[index] = CKFE_POLICY_REQUIRE_SOURCE;
        CHECK(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_PRIVILEGE_OPT_IN_REQUIRED);
        policy.flags = index == CKFE_POLICY_PRIVILEGE_BITS ? CKFE_POLICY_ALLOW_CAPABILITY_REPLAY
                                                        : CKFE_POLICY_ALLOW_PRIVILEGE_REPLAY;
        CHECK(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_PRIVILEGE_OPT_IN_REQUIRED);
        policy.flags = CKFE_POLICY_ALLOW_CAPABILITY_REPLAY | CKFE_POLICY_ALLOW_PRIVILEGE_REPLAY;
        CHECK(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_VALID);
        auto inventory = complete_inventory();
        inventory.classes[index].source = CKFE_POLICY_SOURCE_PRESENT;
        inventory.classes[index].destination = CKFE_POLICY_SUPPORT_UNSUPPORTED;
        CHECK(assess(policy, inventory).result == CKFE_POLICY_RESULT_UNSUPPORTED);
    }
}

void inventory_validation() {
    const auto policy = ck::files::default_preservation_policy();
    const auto good = complete_inventory();
    auto inventory = good;
    inventory.version = 2;
    CHECK(ckfe_preservation_inventory_validate_v1(&inventory) == CKFE_POLICY_INVALID_VERSION);
    CHECK(assess(policy, inventory).result == CKFE_POLICY_RESULT_INVALID);
    for (auto size : {0u, 8u, static_cast<unsigned>(sizeof(inventory) - 1),
             static_cast<unsigned>(sizeof(inventory) + 1)}) {
        inventory = good;
        inventory.struct_size = size;
        CHECK(ckfe_preservation_inventory_validate_v1(&inventory) == CKFE_POLICY_INVALID_STRUCT_SIZE);
    }
    inventory = good;
    inventory.state = 6;
    CHECK(ckfe_preservation_inventory_validate_v1(&inventory) == CKFE_POLICY_INVALID_EVIDENCE);
    for (unsigned flag = 1; flag < 32; ++flag) {
        inventory = good;
        inventory.flags |= std::uint32_t{1} << flag;
        CHECK(ckfe_preservation_inventory_validate_v1(&inventory) == CKFE_POLICY_UNKNOWN_FIELD);
    }
    for (unsigned index = 0; index < 4; ++index) {
        inventory = good;
        inventory.reserved_words[index] = 1;
        CHECK(ckfe_preservation_inventory_validate_v1(&inventory) == CKFE_POLICY_UNKNOWN_FIELD);
    }
    for (unsigned index = 0; index < CKFE_POLICY_CLASS_COUNT; ++index) {
        inventory = good;
        inventory.classes[index].source = 7;
        CHECK(ckfe_preservation_inventory_validate_v1(&inventory) == CKFE_POLICY_INVALID_EVIDENCE);
        inventory = good;
        inventory.classes[index].destination = 6;
        CHECK(ckfe_preservation_inventory_validate_v1(&inventory) == CKFE_POLICY_INVALID_EVIDENCE);
        inventory = good;
        inventory.classes[index].reserved = 1;
        CHECK(ckfe_preservation_inventory_validate_v1(&inventory) == CKFE_POLICY_UNKNOWN_FIELD);
        for (unsigned flag = 1; flag < 32; ++flag) {
            inventory = good;
            inventory.classes[index].flags |= std::uint32_t{1} << flag;
            CHECK(ckfe_preservation_inventory_validate_v1(&inventory) == CKFE_POLICY_UNKNOWN_FIELD);
        }
    }
}

void coverage_and_aggregate_findings() {
    const auto policy = ck::files::default_preservation_policy();
    auto inventory = ck::files::empty_preservation_inventory();
    auto out = assess(policy, inventory);
    CHECK(out.result == CKFE_POLICY_RESULT_NEEDS_REVIEW);
    CHECK(out.inventory_complete == 0);
    CHECK(out.incomplete_classes == CKFE_POLICY_ALL_CLASSES);
    inventory = complete_inventory();
    inventory.flags = 0;
    out = assess(policy, inventory);
    CHECK(out.result == CKFE_POLICY_RESULT_NEEDS_REVIEW);
    CHECK(out.incomplete_classes == CKFE_POLICY_ALL_CLASSES);
    for (unsigned index = 0; index < CKFE_POLICY_CLASS_COUNT; ++index) {
        inventory = complete_inventory();
        inventory.classes[index].flags = 0;
        out = assess(policy, inventory);
        CHECK(out.result == CKFE_POLICY_RESULT_NEEDS_REVIEW);
        CHECK(out.incomplete_classes == bit(index));
        CHECK(out.inventory_complete == 0);
        inventory.classes[index].flags = CKFE_POLICY_EVIDENCE_COMPLETE;
        inventory.classes[index].source = CKFE_POLICY_SOURCE_UNKNOWN;
        out = assess(policy, inventory);
        CHECK(out.result == CKFE_POLICY_RESULT_NEEDS_REVIEW);
        CHECK(out.incomplete_classes == bit(index));
    }
    const std::array<ckfe_policy_result, 6> expected{
        CKFE_POLICY_RESULT_NEEDS_REVIEW, CKFE_POLICY_RESULT_SUPPORTED, CKFE_POLICY_RESULT_UNSUPPORTED,
        CKFE_POLICY_RESULT_DENIED, CKFE_POLICY_RESULT_CHANGED, CKFE_POLICY_RESULT_NEEDS_REVIEW};
    for (unsigned state = 0; state < expected.size(); ++state) {
        inventory = complete_inventory();
        inventory.state = state;
        out = assess(policy, inventory);
        CHECK(out.result == expected[state]);
        CHECK(out.inventory_complete == (state == CKFE_POLICY_INVENTORY_COMPLETE ? 1u : 0u));
    }
    inventory = complete_inventory();
    inventory.state = CKFE_POLICY_INVENTORY_UNKNOWN;
    inventory.classes[CKFE_POLICY_ORDINARY_PERMISSIONS].destination = CKFE_POLICY_SUPPORT_DENIED;
    out = assess(policy, inventory);
    CHECK(out.result == CKFE_POLICY_RESULT_DENIED);
    CHECK(out.denied_classes == bit(CKFE_POLICY_ORDINARY_PERMISSIONS));
    CHECK(out.incomplete_classes == CKFE_POLICY_ALL_CLASSES);

    inventory = complete_inventory();
    inventory.classes[CKFE_POLICY_ORDINARY_PERMISSIONS].destination = CKFE_POLICY_SUPPORT_UNSUPPORTED;
    inventory.classes[CKFE_POLICY_ACCESS_ACL].source = CKFE_POLICY_SOURCE_DENIED;
    inventory.classes[CKFE_POLICY_CAPABILITIES].source = CKFE_POLICY_SOURCE_CHANGED;
    out = assess(policy, inventory);
    CHECK(out.result == CKFE_POLICY_RESULT_CHANGED);
    CHECK(out.unsupported_classes == bit(CKFE_POLICY_ORDINARY_PERMISSIONS));
    CHECK(out.denied_classes == bit(CKFE_POLICY_ACCESS_ACL));
    CHECK(out.changed_classes == bit(CKFE_POLICY_CAPABILITIES));
    CHECK(out.needs_review_classes == (out.unsupported_classes | out.denied_classes | out.changed_classes));
    CHECK(out.inventory_complete == 0);
}

void disposition_matrix() {
    const std::array<ckfe_policy_result, 7> source_results{
        CKFE_POLICY_RESULT_NEEDS_REVIEW, CKFE_POLICY_RESULT_SUPPORTED, CKFE_POLICY_RESULT_SUPPORTED,
        CKFE_POLICY_RESULT_UNSUPPORTED, CKFE_POLICY_RESULT_DENIED, CKFE_POLICY_RESULT_CHANGED,
        CKFE_POLICY_RESULT_NEEDS_REVIEW};
    const std::array<ckfe_policy_result, 6> destination_results{
        CKFE_POLICY_RESULT_NEEDS_REVIEW, CKFE_POLICY_RESULT_SUPPORTED, CKFE_POLICY_RESULT_UNSUPPORTED,
        CKFE_POLICY_RESULT_DENIED, CKFE_POLICY_RESULT_CHANGED, CKFE_POLICY_RESULT_NEEDS_REVIEW};
    // Every family must refuse unreadable/unsupported source observations,
    // even when a caller explicitly discards the source class.
    for (unsigned index = 0; index < CKFE_POLICY_CLASS_COUNT; ++index) {
        for (unsigned disposition = CKFE_POLICY_REQUIRE_SOURCE; disposition <= CKFE_POLICY_CURRENT_CALLER;
             ++disposition) {
            if (disposition == CKFE_POLICY_CURRENT_CALLER && index != CKFE_POLICY_OWNERSHIP) continue;
            auto policy = ck::files::default_preservation_policy();
            policy.flags = CKFE_POLICY_ALLOW_CAPABILITY_REPLAY | CKFE_POLICY_ALLOW_PRIVILEGE_REPLAY;
            policy.dispositions[index] = disposition;
            for (unsigned source = 0; source < source_results.size(); ++source) {
                auto inventory = complete_inventory();
                inventory.classes[index].source = source;
                auto expected = source_results[source];
                if (source == CKFE_POLICY_SOURCE_PRESENT && disposition == CKFE_POLICY_REVIEW)
                    expected = CKFE_POLICY_RESULT_NEEDS_REVIEW;
                CHECK(assess(policy, inventory).result == expected);
            }
            for (unsigned support = 0; support < destination_results.size(); ++support) {
                auto inventory = complete_inventory();
                inventory.classes[index].source = CKFE_POLICY_SOURCE_PRESENT;
                inventory.classes[index].destination = support;
                const auto out = assess(policy, inventory);
                if (disposition == CKFE_POLICY_REQUIRE_SOURCE || disposition == CKFE_POLICY_CURRENT_CALLER) {
                    CHECK(out.result == destination_results[support]);
                } else if (disposition == CKFE_POLICY_REVIEW) {
                    CHECK(out.result == CKFE_POLICY_RESULT_NEEDS_REVIEW);
                    CHECK(out.needs_review_classes == bit(index));
                } else {
                    CHECK(out.result == CKFE_POLICY_RESULT_SUPPORTED);
                    CHECK(out.discarded_classes == bit(index));
                }
                // Qualified absence does not require replay support, except
                // establishing current-caller ownership remains mandatory.
                inventory.classes[index].source = CKFE_POLICY_SOURCE_ABSENT;
                CHECK(assess(policy, inventory).result ==
                    (disposition == CKFE_POLICY_CURRENT_CALLER ? destination_results[support]
                                                             : CKFE_POLICY_RESULT_SUPPORTED));
            }
        }
    }
}

void c_boundary_and_rejection_reset() {
    CHECK(ckfe_preservation_policy_init_v1(nullptr) == CKFE_POLICY_INVALID_ARGUMENT);
    CHECK(ckfe_preservation_inventory_init_v1(nullptr) == CKFE_POLICY_INVALID_ARGUMENT);
    CHECK(ckfe_preservation_policy_validate_v1(nullptr) == CKFE_POLICY_INVALID_ARGUMENT);
    CHECK(ckfe_preservation_inventory_validate_v1(nullptr) == CKFE_POLICY_INVALID_ARGUMENT);
    const auto policy = ck::files::default_preservation_policy();
    auto inventory = complete_inventory();
    ckfe_preservation_assessment_v1 out;
    std::memset(&out, 0x55, sizeof(out));
    const auto sentinel = out;
    for (auto size : {std::size_t{0}, sizeof(out) - 1, sizeof(out) + 1}) {
        CHECK(ckfe_preservation_assess_v1(&policy, &inventory, &out, size) == CKFE_POLICY_RESULT_INVALID);
        CHECK(std::memcmp(&sentinel, &out, sizeof(out)) == 0);
    }
    CHECK(ckfe_preservation_assess_v1(&policy, &inventory, nullptr, sizeof(out)) == CKFE_POLICY_RESULT_INVALID);
    for (unsigned missing = 0; missing < 3; ++missing) {
        CHECK(ckfe_preservation_assess_v1(missing == 0 ? &policy : nullptr,
                  missing == 1 ? &inventory : nullptr, &out, sizeof(out)) == CKFE_POLICY_RESULT_INVALID);
        CHECK(out.result == CKFE_POLICY_RESULT_INVALID);
        CHECK(out.validation == CKFE_POLICY_INVALID_ARGUMENT);
        CHECK(out.inventory_complete == 0);
        CHECK(out.supported_classes == 0);
        CHECK(out.discarded_classes == 0);
    }
    out = assess(policy, inventory);
    CHECK(out.result == CKFE_POLICY_RESULT_SUPPORTED);
    inventory.classes[CKFE_POLICY_XATTRS].reserved = 1;
    CHECK(ckfe_preservation_assess_v1(&policy, &inventory, &out, sizeof(out)) == CKFE_POLICY_RESULT_INVALID);
    CHECK(out.validation == CKFE_POLICY_UNKNOWN_FIELD);
    CHECK(out.supported_classes == 0);
    CHECK(out.inventory_complete == 0);
    ckfe_preservation_inventory_v1 uninitialized;
    std::memset(&uninitialized, 0xff, sizeof(uninitialized));
    CHECK(ckfe_preservation_inventory_init_v1(&uninitialized) == CKFE_POLICY_VALID);
    CHECK(assess(policy, uninitialized).result == CKFE_POLICY_RESULT_NEEDS_REVIEW);
}

} // namespace

int main() {
    static_assert(std::is_standard_layout_v<ckfe_preservation_assessment_v1>);
    static_assert(std::is_trivially_copyable_v<ckfe_preservation_inventory_v1>);
    defaults_and_mode_separation();
    policy_validation();
    inventory_validation();
    coverage_and_aggregate_findings();
    disposition_matrix();
    c_boundary_and_rejection_reset();
    std::printf("preservation_policy_tests: %u checks passed\n", checks);
}
