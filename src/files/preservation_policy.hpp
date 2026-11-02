// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "../../include/ck_fs_policy.h"

#include <cstdint>

namespace ck::files {

// Worker evidence assessment only; no probing, apply, elevation or consent.
ckfe_preservation_policy_v1 default_preservation_policy() noexcept;
ckfe_preservation_inventory_v1 empty_preservation_inventory() noexcept;
ckfe_policy_validation validate_preservation_policy(const ckfe_preservation_policy_v1& policy) noexcept;
ckfe_policy_validation validate_preservation_inventory(const ckfe_preservation_inventory_v1& inventory) noexcept;
ckfe_preservation_assessment_v1 assess_preservation_inventory(
    const ckfe_preservation_policy_v1& policy, const ckfe_preservation_inventory_v1& inventory) noexcept;

struct PreservationPermissionBits final {
    std::uint32_t ordinary;
    std::uint32_t privilege;
};

// Never hand raw source mode to an ordinary-permissions replay path. The
// privilege field requires its OWN policy disposition and explicit opt-in.
constexpr PreservationPermissionBits split_preservation_permissions(std::uint32_t mode) noexcept {
    return {mode & CKFE_POLICY_ORDINARY_MODE_MASK, mode & CKFE_POLICY_PRIVILEGE_MODE_MASK};
}

} // namespace ck::files
