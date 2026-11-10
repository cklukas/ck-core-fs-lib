// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#ifdef _WIN32
#ifndef CK_FS_NATIVE_CLOSE_TEST_HOOKS
#error Native read/close capture fixtures require a whole matching hooks-enabled SDK closure
#endif
#include "platform/native_close_test_faults.hpp"

// Test executable ownership only. No installed header, public class or native
// result replacement. Restoration also runs on exceptions and early returns.
struct NativeCaptureFixtureScope final {
    using Read = ck::files::detail::NativeReadAfter;
    using Before = ck::files::detail::NativeCloseBefore;
    using After = ck::files::detail::NativeCloseAfter;
    Read old_read;
    Before old_before;
    After old_after;
    explicit NativeCaptureFixtureScope(Read read, Before before=nullptr, After after=nullptr) noexcept
      : old_read(ck::files::detail::native_read_test_after.exchange(read)),
        old_before(ck::files::detail::native_close_test_before.exchange(before)),
        old_after(ck::files::detail::native_close_test_after.exchange(after)) {}
    ~NativeCaptureFixtureScope() {
        ck::files::detail::native_read_test_after.store(old_read);
        ck::files::detail::native_close_test_before.store(old_before);
        ck::files::detail::native_close_test_after.store(old_after);
    }
    NativeCaptureFixtureScope(const NativeCaptureFixtureScope&)=delete;
    NativeCaptureFixtureScope& operator=(const NativeCaptureFixtureScope&)=delete;
};
#endif
