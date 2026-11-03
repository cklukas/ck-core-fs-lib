// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../observation.hpp"
namespace ck::files {
class DirectoryCursor;
namespace detail {
// Provider-only bridge. Available transfers one native owning duplicate of
// the genuine cursor's current held directory. No path/procfd reopen, access
// upgrade, caller-supplied integer, or injected cursor fallback is permitted.
#ifdef _WIN32
Observation<void*> duplicate_windows_journal_directory(const DirectoryCursor&);
// Synchronous worker-only close observation. Caller restores the previous
// observer after every native owner in its scope has drained; nested scopes
// restore exactly. The callback records scalars and must never throw/allocate.
struct WindowsJournalCloseObserver {
    void* context=nullptr;
    void (*record)(void*,std::uint32_t,const char*) noexcept=nullptr;
};
WindowsJournalCloseObserver exchange_windows_journal_close_observer(WindowsJournalCloseObserver) noexcept;
#else
Observation<int> duplicate_posix_journal_directory(const DirectoryCursor&);
#endif
} // namespace detail
} // namespace ck::files
