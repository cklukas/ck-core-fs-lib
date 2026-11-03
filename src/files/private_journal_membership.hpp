// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "held_child.hpp"
#include "prepared_journal_root.hpp"
#include <array>
#include <cstring>
#include <optional>
#include <stop_token>
#include <string_view>

namespace ck::files {
struct PrivateJournalMembershipLimits final {
    std::size_t max_records = 4096;
    std::size_t max_directories = 128;
    std::size_t max_depth = 64;
    std::size_t max_name_bytes = 1024 * 1024;
};

// Worker-only, fresh native membership observation for a selected regular
// object (normally needed for nlink > 1). Both Root and the selected parent
// must be genuine native providers; this implementation certifies them.
// Available(true) means the complete bounded Root walk found no matching
// kernel identity, with Root, selected object and namespace bookends intact.
// It is not a cached ID set, namespace lease, or authority to mutate a name.
// Callers retain their ancestry/mount guards and repeat this proof at their
// existing revalidation boundaries. No contents or navigation hints are read.
Observation<bool> qualify_private_journal_disjointness(
    PreparedJournalRoot&, const HeldChild&, PrivateJournalMembershipLimits = {},
    std::stop_token = {});

namespace detail {
// Internal failure-only test seam. Close is observed AFTER the actual close;
// it never skips I/O or manufactures a successful qualification.
enum class PrivateMembershipFaultPoint { DirectoryReadComplete, BeforeFinalCheck, Close };
using PrivateMembershipFault = std::optional<std::int64_t>(*)(PrivateMembershipFaultPoint);
inline thread_local PrivateMembershipFault private_membership_test_fault = nullptr;

struct PrivateMembershipFailure final {
    ObservationState state = ObservationState::Available;
    ErrorDomain domain = ErrorDomain::None;
    std::int64_t code = 0;
    std::array<char, 160> operation{};
    explicit operator bool() const noexcept { return state != ObservationState::Available; }
    void record(ObservationState s, ErrorDomain d, std::int64_t c, std::string_view op) noexcept {
        if (*this) return;
        state=s; domain=d; code=c;
        const auto n=op.size()<operation.size()-1?op.size():operation.size()-1;
        if(n)std::memcpy(operation.data(),op.data(),n);
    }
    void record(const UnavailableObservation& e) noexcept { record(e.state,e.error.domain,e.error.code,e.error.operation); }
    void unsafe(const char* op) noexcept {
        record(ObservationState::Unsupported,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe),op);
    }
    void changed(const char* op) noexcept {
        record(ObservationState::Changed,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::MetadataChanged),op);
    }
    Observation<bool> result() const;
};
bool private_membership_entry_qualified(const BasicMetadata&) noexcept;
bool private_membership_entry_same(const BasicMetadata&, const BasicMetadata&) noexcept;
Observation<bool> native_private_journal_disjointness(
    PreparedJournalRoot&, const HeldChild&, const PrivateJournalMembershipLimits&, std::stop_token);
} // namespace detail
} // namespace ck::files
