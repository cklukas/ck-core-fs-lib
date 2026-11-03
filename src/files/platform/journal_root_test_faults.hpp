// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include <cstdint>
#include <optional>
#include <atomic>
namespace ck::files::detail {
enum class JournalRootFaultPoint { DirectoryFlush, DirectoryClose, JournalClose };
// Internal, thread-local fault observation for native contract tests. Faults
// are reported AFTER the real flush/close, never used to skip a native barrier
// or disposition. No production authority or success can be manufactured here.
using JournalRootFault = std::optional<std::int64_t>(*)(JournalRootFaultPoint);
inline thread_local JournalRootFault journal_root_test_fault = nullptr;
inline std::atomic<JournalRootFault> journal_root_test_worker_fault{nullptr};
// Failure-only worker seam; never bypasses a native operation or grants authority.
inline std::atomic<bool> journal_root_test_worker_exception{false};
using JournalRootPublicationPause=void(*)() noexcept;
inline std::atomic<JournalRootPublicationPause> journal_root_test_publication_pause{nullptr};
inline std::optional<std::int64_t> journal_root_fault(JournalRootFaultPoint point) {
    const auto fault=journal_root_test_fault?journal_root_test_fault:journal_root_test_worker_fault.load(std::memory_order_acquire);
    return fault?fault(point):std::nullopt;
}
} // namespace ck::files::detail
