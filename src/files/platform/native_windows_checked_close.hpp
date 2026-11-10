// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "native_close_test_faults.hpp"

namespace ck::files::detail {
// The caller consumes its ownership before calling. Always perform the real
// close exactly once. Compiled test observers may add a failure only after a
// successful close; they cannot suppress or replace a real native failure.
inline BOOL close_windows_handle_once(HANDLE handle, const char* operation) noexcept {
    const DWORD previous_error = GetLastError();
    observe_native_close(handle, operation);
    SetLastError(previous_error);
    const BOOL closed = ::CloseHandle(handle);
    const DWORD native_error = GetLastError();
    const auto injected = inject_native_close_failure(handle, operation, closed != FALSE, native_error);
    if (closed && injected) {
        SetLastError(injected);
        return FALSE;
    }
    SetLastError(native_error);
    return closed;
}
} // namespace ck::files::detail
