// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "operation_journal_file.hpp"
#include "file_metadata.hpp"
#include <functional>
#include <optional>
#include <stop_token>

namespace ck::files {
class DirectoryCursor;

enum class JournalRootDisposition : std::uint8_t {
    AdoptHeld = 0, AdoptChild = 1, ProvisionChild = 2
};
enum class JournalRootPreparationPhase : std::uint8_t {
    Acquiring, Provisioning, Ancestry, Flushing, Ready
};
struct JournalRootPreparationProgress final {
    JournalRootPreparationPhase phase = JournalRootPreparationPhase::Acquiring;
    std::uint32_t acquired_directories = 0;
    std::uint32_t flushed_directories = 0;
    std::uint32_t directory_creates = 0;
};
struct PreparedJournalRootRequest final {
    std::shared_ptr<const DirectoryCursor> parent;
    std::optional<NativeName> child;
    JournalRootDisposition disposition = JournalRootDisposition::AdoptHeld;
    std::uint32_t max_ancestors = 256;
    // Optional exact native navigation/evidence hint, copied in memory only.
    // It never authorizes an open, stat, preflight, barrier or recovery action.
    std::optional<NativeAbsolutePath> navigation_hint;
};

// Native, provider-owned authority. Addresses and display strings are never
// retained as reopening authority. Every journal opens below the held root;
// privacy, identity and ancestry are checked again through native handles.
// Sharing this owner is memory-only. Native methods and destruction are worker
// operations. Keep consumer owners alive until their journal I/O has finished.
class PreparedJournalRoot {
public:
    using Pointer = std::shared_ptr<PreparedJournalRoot>;
    virtual ~PreparedJournalRoot() = default;
    virtual Observation<std::unique_ptr<OperationJournalFile>> open_journal(
        const NativeName& basename, bool create_new) = 0;
    virtual Observation<bool> revalidate() const = 0;
    virtual Observation<bool> sync() = 0;
    virtual Observation<bool> finish_io() = 0;
    virtual const ObjectIdentity& identity() const noexcept = 0;
    virtual NameEncoding encoding() const noexcept = 0;
    virtual const std::optional<NativeAbsolutePath>& navigation_address() const noexcept = 0;
};

// Worker-only acquisition/provisioning, never a path-based replacement for a
// previously held root. ProvisionChild creates if absent, then adopts the exact
// private directory acquired by native open; it does NOT claim an identity-
// bound mkdir receipt. No cleanup by name is attempted on cancellation/failure.
// The observer runs only on this worker, between bounded native steps. It must
// not perform native I/O or invoke frontend callbacks.
Observation<PreparedJournalRoot::Pointer> prepare_native_journal_root(
    PreparedJournalRootRequest request, JournalRootPreparationProgress& progress,
    std::stop_token stop = {},
    const std::function<void(const JournalRootPreparationProgress&)>& observer = {});
} // namespace ck::files
