// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../prepared_journal_root.hpp"
#include <array>
#include <string_view>
#include <vector>
namespace ck::files::detail {
// Failure-only, allocation-free bridge. A successful record acknowledges the
// genuine native provider, not mutation authority. First error wins forever.
struct PreparedJournalConsumerFailure final {
    ObservationState state=ObservationState::Unknown;
    ErrorDomain domain=ErrorDomain::None;
    std::int64_t code=0;
    std::array<char,96> operation{};
    bool pending=false;
};
bool record_prepared_journal_consumer_failure(PreparedJournalRoot&,ObservationState,
    ErrorDomain,std::int64_t,std::string_view operation) noexcept;
// Memory-only readback; true for a pending OR published failure. A pending
// failure blocks new authority immediately and must not permanently replace
// the original native error, which becomes available when pending is false.
// Clears output even for absent/foreign providers. Never waits or allocates.
bool read_prepared_journal_consumer_failure(const PreparedJournalRoot&,
    PreparedJournalConsumerFailure&) noexcept;
// Internal Linux scope identity. Object IDs alone are insufficient across a
// whole-filesystem bind alias; the native mount ID is part of the retained
// Root scope domain and is never exposed as public ABI.
#ifdef __linux__
struct RootScopeIdentity final {
    ObjectIdentity object;
    std::uint64_t mount_id = 0;
};
Observation<std::vector<RootScopeIdentity>> inspect_prepared_journal_scope_ancestry(PreparedJournalRoot&);
#endif
// Worker-only Root->namespace-endpoint evidence from checked native handles.
// Genuine factory class only. IDs are minted in Root's scope after kernel
// queries and validation on both sides; DTOs alone grant no scope authority.
Observation<std::vector<ObjectIdentity>> inspect_prepared_journal_ancestry(PreparedJournalRoot&);
// Provider-only worker bridge: verifies the actual native factory's dynamic
// class, revalidates its retained root and transfers one owning duplicate.
// No raw/invented input descriptor, navigation address, procfd or path fallback.
// Adopters MUST retain the shared root owner for the duplicate's lifetime,
// revalidate it before/after their I/O, and explicitly close/report errors on
// the worker. Never finish the shared root from a consumer/store finalizer.
#ifdef _WIN32
Observation<void*> duplicate_prepared_journal_directory(PreparedJournalRoot& root);
#else
Observation<int> duplicate_prepared_journal_directory(PreparedJournalRoot& root);
#endif
} // namespace ck::files::detail
