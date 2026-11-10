// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <type_traits>
namespace ck::files::detail {
enum class LegacyNativeOperation : std::uint8_t {
    Read, Write, Close, Duplicate, NativeCreate, Create, OpenById, Query, Flush, SetInfo
};
enum class LegacyNativePhase : std::uint8_t { Before, After, OpenCompleted };
enum class LegacyNativeDomain : std::uint8_t { None, Win32, NtStatus, Errno };
// Read-only observation DTO. No output buffer, writable IOSB/result pointer,
// pathname, owner-fabrication factory or callback return value is exposed.
struct LegacyNativeEvent final {
    LegacyNativeOperation operation;
    LegacyNativePhase phase;
    LegacyNativeDomain domain;
    std::uintptr_t handle;
    std::uint32_t count, query_class, native_error; // count=request units, never completed bytes
    std::int64_t native_result;
    bool succeeded;
    bool pending;
    const char* tag; // provider-owned fixed literal; no borrowed string allocation
};
static_assert(std::is_trivial_v<decltype(LegacyNativeEvent::handle)>);
static_assert(std::is_trivial_v<LegacyNativeEvent> && std::is_trivially_copyable_v<LegacyNativeEvent> && std::is_standard_layout_v<LegacyNativeEvent>);
constexpr std::uint64_t legacy_operation_bit(LegacyNativeOperation op)noexcept {
    return std::uint64_t{1}<<static_cast<unsigned>(op);
}
inline constexpr std::uint64_t legacy_all_operations=(std::uint64_t{1}<<10)-1;
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
using LegacyNativeObserver=void(*)(const LegacyNativeEvent&)noexcept;
static_assert(std::atomic<LegacyNativeObserver>::is_always_lock_free);
inline std::atomic<LegacyNativeObserver> legacy_native_test_observer{nullptr};
inline thread_local bool legacy_native_observer_active=false;
inline void observe_legacy_native_event(const LegacyNativeEvent& event)noexcept {
    if(const auto observer=legacy_native_test_observer.load(std::memory_order_acquire)) {
        // Re-entering an SDK wrapper from a selector is an instrumentation
        // defect, not permission to drop an event or run an unbounded loop.
        // Selection uses direct real native queries, never these wrappers.
        if(legacy_native_observer_active)std::abort();
        legacy_native_observer_active=true;observer(event);legacy_native_observer_active=false;
    }
}
// Implemented by genuine provider TUs ONLY after their call-site closure has
// been reviewed. These are intentionally not inline zero/success defaults.
// Missing integration fails linking, never becomes an Unsupported/native pass.
std::uint64_t legacy_native_metadata_coverage()noexcept;
std::uint64_t legacy_native_journal_coverage()noexcept;
std::uint64_t legacy_native_scope_coverage()noexcept;
#else
inline void observe_legacy_native_event(const LegacyNativeEvent&)noexcept{}
#endif
} // namespace ck::files::detail
