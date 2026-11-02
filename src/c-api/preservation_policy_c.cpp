// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../files/preservation_policy.hpp"

extern "C" {

ckfe_policy_validation ckfe_preservation_policy_init_v1(ckfe_preservation_policy_v1* policy) noexcept {
    if (!policy) return CKFE_POLICY_INVALID_ARGUMENT;
    *policy = ck::files::default_preservation_policy();
    return CKFE_POLICY_VALID;
}

ckfe_policy_validation ckfe_preservation_inventory_init_v1(ckfe_preservation_inventory_v1* inventory) noexcept {
    if (!inventory) return CKFE_POLICY_INVALID_ARGUMENT;
    *inventory = ck::files::empty_preservation_inventory();
    return CKFE_POLICY_VALID;
}

ckfe_policy_validation ckfe_preservation_policy_validate_v1(const ckfe_preservation_policy_v1* policy) noexcept {
    return policy ? ck::files::validate_preservation_policy(*policy) : ckfe_policy_validation{CKFE_POLICY_INVALID_ARGUMENT};
}

ckfe_policy_validation ckfe_preservation_inventory_validate_v1(
    const ckfe_preservation_inventory_v1* inventory) noexcept {
    return inventory ? ck::files::validate_preservation_inventory(*inventory)
                     : ckfe_policy_validation{CKFE_POLICY_INVALID_ARGUMENT};
}

ckfe_policy_result ckfe_preservation_assess_v1(const ckfe_preservation_policy_v1* policy,
    const ckfe_preservation_inventory_v1* inventory, ckfe_preservation_assessment_v1* assessment,
    size_t assessment_size) noexcept {
    if (!assessment || assessment_size != sizeof(*assessment)) return CKFE_POLICY_RESULT_INVALID;
    *assessment = {};
    assessment->version = CKFE_PRESERVATION_POLICY_VERSION;
    assessment->struct_size = sizeof(*assessment);
    if (!policy || !inventory) {
        assessment->validation = CKFE_POLICY_INVALID_ARGUMENT;
        return CKFE_POLICY_RESULT_INVALID;
    }
    *assessment = ck::files::assess_preservation_inventory(*policy, *inventory);
    return assessment->result;
}

} // extern "C"
