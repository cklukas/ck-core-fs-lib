// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <atomic>
#include <cerrno>
#include "native_close_test_faults.hpp"
#include "legacy_native_fixture_windows.hpp"

namespace ck::files::detail {
#ifdef CK_FS_NATIVE_CLOSE_TEST_HOOKS
// Private compiled seams; the recursive SDK header install currently copies
// this header too. No public C ABI or native authority. All callbacks are POD,
// noexcept and allocation-free. They cannot skip an OS call, replace bytes,
// suppress a real failure, or turn any failure into success.
using NativeMetadataFlushBefore = void(*)(HANDLE,const char*) noexcept;
using NativeMetadataFlushAfter = DWORD(*)(HANDLE,bool,DWORD,const char*) noexcept;
using NativeMetadataTimesAfter = void(*)(HANDLE,const FILETIME*,const FILETIME*,
                                       const FILETIME*,bool,DWORD,const char*) noexcept;
inline std::atomic<NativeMetadataFlushBefore> native_metadata_flush_before{nullptr};
inline std::atomic<NativeMetadataFlushAfter> native_metadata_flush_after{nullptr};
inline std::atomic<NativeMetadataTimesAfter> native_metadata_times_after{nullptr};
#endif

inline BOOL write_windows_metadata_file(HANDLE handle,const void* bytes,DWORD count,
        DWORD* written,const char* operation) noexcept {
#ifndef CK_FS_NATIVE_CLOSE_TEST_HOOKS
    (void)operation;
    return legacy_write_file(handle,bytes,count,written,nullptr,"legacy.metadata_helper.WriteFile.1");
#else
    const DWORD previous_error=GetLastError();const int previous_errno=errno;
    observe_native_file_before(handle,NativeTestIo::Write,count,operation);
    errno=previous_errno;SetLastError(previous_error);
    const BOOL native_ok=legacy_write_file(handle,bytes,count,written,nullptr,"legacy.metadata_helper.WriteFile.2");
    const DWORD native_error=GetLastError();const int native_errno=errno;
    observe_native_file_after(handle,NativeTestIo::Write,native_ok!=FALSE,
                              native_ok?ERROR_SUCCESS:native_error,operation);
    errno=native_errno;SetLastError(native_error);return native_ok;
#endif
}

inline BOOL flush_windows_metadata_file(HANDLE handle,const char* operation) noexcept {
#ifndef CK_FS_NATIVE_CLOSE_TEST_HOOKS
    (void)operation;
    return legacy_flush(handle,"legacy.metadata_helper.FlushFileBuffers.1");
#else
    const DWORD previous_error=GetLastError();const int previous_errno=errno;
    if(const auto f=native_metadata_flush_before.load(std::memory_order_acquire))f(handle,operation);
    errno=previous_errno;SetLastError(previous_error);
    const BOOL native_ok=legacy_flush(handle,"legacy.metadata_helper.FlushFileBuffers.2");
    const DWORD native_error=GetLastError();const int native_errno=errno;
    DWORD injected=ERROR_SUCCESS;
    if(const auto f=native_metadata_flush_after.load(std::memory_order_acquire))
        injected=f(handle,native_ok!=FALSE,native_ok?ERROR_SUCCESS:native_error,operation);
    errno=native_errno;
    if(native_ok&&injected){SetLastError(injected);return FALSE;}
    SetLastError(native_error);return native_ok;
#endif
}

inline BOOL set_windows_metadata_times(HANDLE handle,const FILETIME* creation,
        const FILETIME* access,const FILETIME* write,const char* operation) noexcept {
#ifndef CK_FS_NATIVE_CLOSE_TEST_HOOKS
    (void)operation;
    return ::SetFileTime(handle,creation,access,write);
#else
    const BOOL native_ok=::SetFileTime(handle,creation,access,write);
    const DWORD native_error=GetLastError();const int native_errno=errno;
    if(const auto f=native_metadata_times_after.load(std::memory_order_acquire))
        f(handle,creation,access,write,native_ok!=FALSE,native_ok?ERROR_SUCCESS:native_error,operation);
    errno=native_errno;SetLastError(native_error);return native_ok;
#endif
}
} // namespace ck::files::detail
