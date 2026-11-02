// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "preservation_policy.hpp"

#include <type_traits>

namespace ck::files {
namespace {

static_assert(std::is_standard_layout_v<ckfe_preservation_policy_v1>);
static_assert(std::is_trivially_copyable_v<ckfe_preservation_policy_v1>);
static_assert(sizeof(ckfe_preservation_policy_v1) == 80);
static_assert(sizeof(ckfe_preservation_inventory_v1) == 240);
static_assert(sizeof(ckfe_preservation_assessment_v1) == 80);

template <class T>
ckfe_policy_validation header(const T& value) noexcept {
    if (value.version != CKFE_PRESERVATION_POLICY_VERSION) return CKFE_POLICY_INVALID_VERSION;
    if (value.struct_size != sizeof(T)) return CKFE_POLICY_INVALID_STRUCT_SIZE;
    return CKFE_POLICY_VALID;
}

void summarize(ckfe_preservation_assessment_v1& out) noexcept {
    out.needs_review_classes |= out.incomplete_classes | out.unsupported_classes | out.denied_classes |
        out.changed_classes;
    if (out.changed_classes) out.result = CKFE_POLICY_RESULT_CHANGED;
    else if (out.denied_classes) out.result = CKFE_POLICY_RESULT_DENIED;
    else if (out.unsupported_classes) out.result = CKFE_POLICY_RESULT_UNSUPPORTED;
    else if (out.needs_review_classes) out.result = CKFE_POLICY_RESULT_NEEDS_REVIEW;
    else out.result = CKFE_POLICY_RESULT_SUPPORTED;
}

bool source_known(ckfe_policy_source_state state) noexcept {
    return state == CKFE_POLICY_SOURCE_PRESENT || state == CKFE_POLICY_SOURCE_ABSENT;
}

void assess_source(const ckfe_preservation_class_evidence_v1& evidence, std::uint64_t bit,
    ckfe_preservation_assessment_v1& out) noexcept {
    if (!(evidence.flags & CKFE_POLICY_EVIDENCE_COMPLETE) || !source_known(evidence.source))
        out.incomplete_classes |= bit;
    switch (evidence.source) {
    case CKFE_POLICY_SOURCE_UNSUPPORTED: out.unsupported_classes |= bit; break;
    case CKFE_POLICY_SOURCE_DENIED: out.denied_classes |= bit; break;
    case CKFE_POLICY_SOURCE_CHANGED: out.changed_classes |= bit; break;
    case CKFE_POLICY_SOURCE_UNKNOWN:
    case CKFE_POLICY_SOURCE_NEEDS_REVIEW: out.needs_review_classes |= bit; break;
    default: break;
    }
}

void assess_destination(ckfe_policy_support support, std::uint64_t bit,
    ckfe_preservation_assessment_v1& out) noexcept {
    switch (support) {
    case CKFE_POLICY_SUPPORT_SUPPORTED: out.supported_classes |= bit; break;
    case CKFE_POLICY_SUPPORT_UNSUPPORTED: out.unsupported_classes |= bit; break;
    case CKFE_POLICY_SUPPORT_DENIED: out.denied_classes |= bit; break;
    case CKFE_POLICY_SUPPORT_CHANGED: out.changed_classes |= bit; break;
    default: out.needs_review_classes |= bit; break;
    }
}

} // namespace

ckfe_preservation_policy_v1 default_preservation_policy() noexcept {
    ckfe_preservation_policy_v1 policy{};
    policy.version = CKFE_PRESERVATION_POLICY_VERSION;
    policy.struct_size = sizeof(policy);
    for (auto& disposition : policy.dispositions) disposition = CKFE_POLICY_REVIEW;
    policy.dispositions[CKFE_POLICY_ORDINARY_PERMISSIONS] = CKFE_POLICY_REQUIRE_SOURCE;
    policy.dispositions[CKFE_POLICY_TIMESTAMPS] = CKFE_POLICY_REQUIRE_SOURCE;
    policy.dispositions[CKFE_POLICY_OWNERSHIP] = CKFE_POLICY_CURRENT_CALLER;
    policy.dispositions[CKFE_POLICY_PRIVILEGE_BITS] = CKFE_POLICY_DISCARD_SOURCE;
    policy.dispositions[CKFE_POLICY_ADDITIONAL_DATA] = CKFE_POLICY_REQUIRE_SOURCE;
    policy.dispositions[CKFE_POLICY_LINKS] = CKFE_POLICY_REQUIRE_SOURCE;
    return policy;
}

ckfe_preservation_inventory_v1 empty_preservation_inventory() noexcept {
    ckfe_preservation_inventory_v1 inventory{};
    inventory.version = CKFE_PRESERVATION_POLICY_VERSION;
    inventory.struct_size = sizeof(inventory);
    return inventory;
}

ckfe_policy_validation validate_preservation_policy(const ckfe_preservation_policy_v1& policy) noexcept {
    if (const auto status = header(policy); status != CKFE_POLICY_VALID) return status;
    constexpr std::uint32_t flags = CKFE_POLICY_ALLOW_PRIVILEGE_REPLAY | CKFE_POLICY_ALLOW_CAPABILITY_REPLAY;
    if (policy.flags & ~flags || policy.reserved) return CKFE_POLICY_UNKNOWN_FIELD;
    for (auto reserved : policy.reserved_words) if (reserved) return CKFE_POLICY_UNKNOWN_FIELD;
    for (std::uint32_t index = 0; index < CKFE_POLICY_CLASS_COUNT; ++index) {
        const auto disposition = policy.dispositions[index];
        if (disposition < CKFE_POLICY_REQUIRE_SOURCE || disposition > CKFE_POLICY_CURRENT_CALLER ||
            (disposition == CKFE_POLICY_CURRENT_CALLER && index != CKFE_POLICY_OWNERSHIP))
            return CKFE_POLICY_INVALID_DISPOSITION;
        if (disposition == CKFE_POLICY_REQUIRE_SOURCE &&
            ((index == CKFE_POLICY_PRIVILEGE_BITS && !(policy.flags & CKFE_POLICY_ALLOW_PRIVILEGE_REPLAY)) ||
             (index == CKFE_POLICY_CAPABILITIES && !(policy.flags & CKFE_POLICY_ALLOW_CAPABILITY_REPLAY))))
            return CKFE_POLICY_PRIVILEGE_OPT_IN_REQUIRED;
    }
    return CKFE_POLICY_VALID;
}

ckfe_policy_validation validate_preservation_inventory(const ckfe_preservation_inventory_v1& inventory) noexcept {
    if (const auto status = header(inventory); status != CKFE_POLICY_VALID) return status;
    if (inventory.flags & ~std::uint32_t{CKFE_POLICY_INVENTORY_SECURITY_CLASSIFIED})
        return CKFE_POLICY_UNKNOWN_FIELD;
    for (auto reserved : inventory.reserved_words) if (reserved) return CKFE_POLICY_UNKNOWN_FIELD;
    if (inventory.state > CKFE_POLICY_INVENTORY_NEEDS_REVIEW) return CKFE_POLICY_INVALID_EVIDENCE;
    for (const auto& evidence : inventory.classes) {
        if (evidence.flags & ~std::uint32_t{CKFE_POLICY_EVIDENCE_COMPLETE} || evidence.reserved)
            return CKFE_POLICY_UNKNOWN_FIELD;
        if (evidence.source > CKFE_POLICY_SOURCE_NEEDS_REVIEW ||
            evidence.destination > CKFE_POLICY_SUPPORT_NEEDS_REVIEW) return CKFE_POLICY_INVALID_EVIDENCE;
    }
    return CKFE_POLICY_VALID;
}

ckfe_preservation_assessment_v1 assess_preservation_inventory(
    const ckfe_preservation_policy_v1& policy, const ckfe_preservation_inventory_v1& inventory) noexcept {
    ckfe_preservation_assessment_v1 out{};
    out.version = CKFE_PRESERVATION_POLICY_VERSION;
    out.struct_size = sizeof(out);
    out.validation = validate_preservation_policy(policy);
    if (out.validation != CKFE_POLICY_VALID) return out;
    out.validation = validate_preservation_inventory(inventory);
    if (out.validation != CKFE_POLICY_VALID) return out;

    if (inventory.state != CKFE_POLICY_INVENTORY_COMPLETE ||
        !(inventory.flags & CKFE_POLICY_INVENTORY_SECURITY_CLASSIFIED))
        out.incomplete_classes = CKFE_POLICY_ALL_CLASSES;
    switch (inventory.state) {
    case CKFE_POLICY_INVENTORY_UNSUPPORTED: out.unsupported_classes = CKFE_POLICY_ALL_CLASSES; break;
    case CKFE_POLICY_INVENTORY_DENIED: out.denied_classes = CKFE_POLICY_ALL_CLASSES; break;
    case CKFE_POLICY_INVENTORY_CHANGED: out.changed_classes = CKFE_POLICY_ALL_CLASSES; break;
    default: break;
    }
    for (std::uint32_t index = 0; index < CKFE_POLICY_CLASS_COUNT; ++index) {
        const auto bit = UINT64_C(1) << index;
        const auto& evidence = inventory.classes[index];
        assess_source(evidence, bit, out);
        // Aggregate gaps block the final result, but do not hide already-known
        // per-class destination failures elsewhere in the inventory.
        if (!(evidence.flags & CKFE_POLICY_EVIDENCE_COMPLETE) || !source_known(evidence.source)) continue;
        const auto disposition = policy.dispositions[index];
        if (disposition == CKFE_POLICY_CURRENT_CALLER) {
            assess_destination(evidence.destination, bit, out);
        } else if (evidence.source == CKFE_POLICY_SOURCE_ABSENT) {
            out.supported_classes |= bit;
        } else if (disposition == CKFE_POLICY_DISCARD_SOURCE) {
            out.discarded_classes |= bit;
        } else if (disposition == CKFE_POLICY_REVIEW) {
            out.needs_review_classes |= bit;
        } else {
            assess_destination(evidence.destination, bit, out);
        }
    }
    out.inventory_complete = out.incomplete_classes == 0 ? 1u : 0u;
    summarize(out);
    return out;
}

} // namespace ck::files
