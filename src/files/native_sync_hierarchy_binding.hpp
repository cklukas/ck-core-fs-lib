// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "sync_session.hpp"
#include "file_metadata.hpp"
#include "native_name.hpp"
#include <chrono>
#include <array>
#include <type_traits>
#include <memory>
#include <span>
#include <stop_token>
namespace ck::files {
class NativeSyncCoordinator;class NativeSyncResolution;
namespace detail {struct HierarchyContextState;struct HierarchyBindingState;}
struct NativeHierarchyLimits final {
    std::size_t max_depth=64,max_entries=65536,max_wire_bytes=8*1024*1024;
    std::size_t max_retained_fds=32768,max_fd_opens=1U<<28,max_reads=1U<<20;
    std::chrono::milliseconds max_elapsed{30000};
};
struct NativeHierarchyUsage final {
    std::size_t entries=0,wire_bytes=0,retained_fds=0,fd_opens=0,reads=0;
};
// Fixed failure evidence for teardown/unwinding. No string/container proxy.
struct NativeHierarchyFailure final {
    bool present=false;
    ObservationState state=ObservationState::Unknown;
    ErrorDomain domain=ErrorDomain::None;
    std::int64_t code=0;
    std::array<char,96> operation{};
};
static_assert(std::is_trivially_copyable_v<NativeHierarchyFailure>);
static_assert(std::is_nothrow_default_constructible_v<NativeHierarchyFailure>);
enum class NativeHierarchyPresence { Present, Missing };
class NativeHierarchyBinding final {
public:
    using Pointer=std::shared_ptr<NativeHierarchyBinding>;
    ~NativeHierarchyBinding();
    NativeHierarchyBinding(const NativeHierarchyBinding&)=delete;
    NativeHierarchyBinding& operator=(const NativeHierarchyBinding&)=delete;
    NativeHierarchyPresence presence()const noexcept;
    std::size_t missing_component()const noexcept;
    std::uint64_t epoch()const noexcept;
    // Descriptive values only. No held cursor/entry, write handle, execution
    // receipt, thaw constructor or pathname reopening authority is exported.
    Observation<BasicMetadata> metadata()const;
    Observation<bool> revalidate(std::stop_token={});
    // Drains before constructing its allocating result. std::bad_alloc may escape;
    // first_failure() remains allocation-free even under persistent OOM.
    Observation<bool> finish_io();
    NativeHierarchyFailure first_failure()const noexcept;
    // Allocation-free terminal close; use this in an allocation exception handler.
    NativeHierarchyFailure drain()noexcept;
private:
    friend class NativeHierarchyContext;
    explicit NativeHierarchyBinding(std::shared_ptr<detail::HierarchyBindingState>)noexcept;
    std::shared_ptr<detail::HierarchyBindingState> state_;
};
class NativeHierarchyContext final {
public:
    using Pointer=std::shared_ptr<NativeHierarchyContext>;
    // This factory acquires the REAL native session backend/overlap locks.
    // It never accepts a caller backend/cursor/identity DTO. It does not load,
    // recover or commit baseline storage. Epoch identifies this lock lifetime,
    // not a durable baseline generation. Existing flat callers are unaffected.
    static Observation<Pointer> open(PreparedJournalRoot::Pointer,
        NativeAbsolutePath left,NativeAbsolutePath right,NativeHierarchyLimits={},std::stop_token={});
    static Observation<Pointer> borrow(SyncSession&,NativeHierarchyLimits={},std::stop_token={});
    static Observation<Pointer> borrow(NativeSyncCoordinator&,NativeHierarchyLimits={},std::stop_token={});
    static Observation<Pointer> borrow(NativeSyncResolution&,NativeHierarchyLimits={},std::stop_token={});
    ~NativeHierarchyContext();
    NativeHierarchyContext(const NativeHierarchyContext&)=delete;
    NativeHierarchyContext& operator=(const NativeHierarchyContext&)=delete;
    Observation<NativeHierarchyBinding::Pointer> bind(bool right,std::span<const NativeName>,std::stop_token={});
    NativeHierarchyUsage usage()const noexcept;
    // Invalidates the epoch, drains all bindings, then cursors/backend locks.
    // Never finishes the caller's original PreparedJournalRoot lifecycle.
    // Drains before constructing its allocating result. std::bad_alloc may escape;
    // first_failure() remains allocation-free even under persistent OOM.
    Observation<bool> finish_io();
    NativeHierarchyFailure first_failure()const noexcept;
    // Allocation-free terminal close; use this in an allocation exception handler.
    NativeHierarchyFailure drain()noexcept;
private:
    explicit NativeHierarchyContext(std::shared_ptr<detail::HierarchyContextState>)noexcept;
    std::shared_ptr<detail::HierarchyContextState> state_;
};
// All operations belong to one serialized native worker. Cooperative elapsed
// checks cannot interrupt a blocking OS call. FD/read accounting covers helper
// operations plus a conservative 16384-descriptor provider reservation per
// backend/scope walk (provider ancestry has its own fixed hard limits). Caps
// are cumulative across binds/revalidation; retained reservations release on
// drain. Unknown/denied/wrong-kind is never Missing. No mutation API is offered.
} // namespace ck::files
