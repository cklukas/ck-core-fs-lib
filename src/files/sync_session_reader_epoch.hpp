// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "sync_session.hpp"
#include <array>
#include <vector>
#include <type_traits>
namespace ck::files::detail {
class NativeSessionLease;
struct SessionReaderFailure final {
    bool failed=false;
    ObservationState state=ObservationState::Unknown;ErrorDomain domain=ErrorDomain::None;
    std::int64_t code=0;std::array<char,96> operation{};
    Observation<bool> result()const;
};
static_assert(std::is_trivially_copyable_v<SessionReaderFailure>);
static_assert(std::is_nothrow_default_constructible_v<SessionReaderFailure>);
class SessionReadConsumer {
public:
    virtual ~SessionReadConsumer()=default;
    // Private native registration only. Revoke ALL descendants/aliases and
    // finish/latch every actual close before returning; no reentry or allocation.
    virtual SessionReaderFailure revoke_readers()noexcept=0;
};
class SessionReaderEpoch final {
    friend class ck::files::SyncSession;
    friend class NativeSessionLease;
    explicit SessionReaderEpoch(SyncSession*,std::uint64_t);
    SessionReaderFailure revoke()noexcept;
    SyncSession* session_;
    std::uint64_t id_;
    bool active_=true;
    SessionReaderFailure first_;
    std::vector<std::weak_ptr<SessionReadConsumer>> readers_;
public:
    ~SessionReaderEpoch();
};
} // namespace ck::files::detail
