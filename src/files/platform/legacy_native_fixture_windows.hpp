// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#ifdef _WIN32
#include "legacy_native_fixture_observation.hpp"
#include "native_close_test_faults.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cerrno>
#include <winternl.h>
namespace ck::files::detail {
// Wrap existing noexcept before/after/inject callbacks without changing their
// return value or duplicating their invocation. Restore both error channels.
template<class Callback>
auto legacy_preserve_windows_error(Callback&& callback)noexcept -> decltype(callback()) {
    static_assert(noexcept(callback()));
    const DWORD native_error=GetLastError();const int native_errno=errno;
    if constexpr(std::is_void_v<decltype(callback())>) {
        callback();errno=native_errno;SetLastError(native_error);
    } else {
        static_assert(std::is_trivially_copyable_v<decltype(callback())>);
        auto result=callback();errno=native_errno;SetLastError(native_error);return result;
    }
}
// Each adapter executes EXACTLY its original native operation. There is no
// injected result and no fallback. Capture the native scalar/error FIRST;
// restore LastError after the void observer. Close failures use the existing
// separate failure-only native_close_test_faults seam, not this observer.
inline void legacy_windows_event(LegacyNativeOperation op,LegacyNativePhase phase,HANDLE h,
    bool okay,DWORD error,std::int64_t result,const char* tag,DWORD count=0,DWORD query=0,
    LegacyNativeDomain domain=LegacyNativeDomain::Win32,bool pending=false)noexcept {
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
    const DWORD saved=GetLastError();const int saved_errno=errno;
    observe_legacy_native_event({op,phase,domain,reinterpret_cast<std::uintptr_t>(h),count,query,error,result,okay,pending,tag});
    errno=saved_errno;SetLastError(saved);
#else
    (void)op;(void)phase;(void)h;(void)okay;(void)error;(void)result;(void)tag;(void)count;(void)query;(void)domain;(void)pending;
#endif
}
inline BOOL legacy_read_file(HANDLE h,LPVOID data,DWORD n,LPDWORD copied,LPOVERLAPPED io,const char* tag)noexcept {
    legacy_windows_event(LegacyNativeOperation::Read,LegacyNativePhase::Before,h,false,0,0,tag,n);
    const BOOL result=::ReadFile(h,data,n,copied,io);const DWORD error=GetLastError();const int native_errno=errno;
    legacy_windows_event(LegacyNativeOperation::Read,LegacyNativePhase::After,h,result!=FALSE,result?0:error,result,tag,n,0,LegacyNativeDomain::Win32,!result&&error==ERROR_IO_PENDING);
    errno=native_errno;SetLastError(error);return result;
}
inline BOOL legacy_write_file(HANDLE h,LPCVOID data,DWORD n,LPDWORD copied,LPOVERLAPPED io,const char* tag)noexcept {
    legacy_windows_event(LegacyNativeOperation::Write,LegacyNativePhase::Before,h,false,0,0,tag,n);
    const BOOL result=::WriteFile(h,data,n,copied,io);const DWORD error=GetLastError();const int native_errno=errno;
    legacy_windows_event(LegacyNativeOperation::Write,LegacyNativePhase::After,h,result!=FALSE,result?0:error,result,tag,n,0,LegacyNativeDomain::Win32,!result&&error==ERROR_IO_PENDING);
    errno=native_errno;SetLastError(error);return result;
}
inline BOOL legacy_query(HANDLE h,FILE_INFO_BY_HANDLE_CLASS kind,LPVOID out,DWORD size,const char* tag)noexcept {
    legacy_windows_event(LegacyNativeOperation::Query,LegacyNativePhase::Before,h,false,0,0,tag,0,DWORD(kind));
    const BOOL result=::GetFileInformationByHandleEx(h,kind,out,size);const DWORD error=GetLastError();const int native_errno=errno;
    legacy_windows_event(LegacyNativeOperation::Query,LegacyNativePhase::After,h,result!=FALSE,result?0:error,result,tag,0,DWORD(kind));
    errno=native_errno;SetLastError(error);return result;
}
inline BOOL legacy_duplicate(HANDLE p,HANDLE source,HANDLE q,LPHANDLE output,DWORD access,BOOL inherit,DWORD flags,const char* tag)noexcept {
    legacy_windows_event(LegacyNativeOperation::Duplicate,LegacyNativePhase::Before,source,false,0,0,tag);
    const BOOL result=::DuplicateHandle(p,source,q,output,access,inherit,flags);const DWORD error=GetLastError();const int native_errno=errno;
    legacy_windows_event(LegacyNativeOperation::Duplicate,LegacyNativePhase::After,result&&output?*output:nullptr,result!=FALSE,result?0:error,result,tag);
    errno=native_errno;SetLastError(error);return result;
}
inline HANDLE legacy_create(LPCWSTR path,DWORD access,DWORD sharing,LPSECURITY_ATTRIBUTES security,DWORD disposition,DWORD flags,HANDLE pattern,const char* tag)noexcept {
    legacy_windows_event(LegacyNativeOperation::Create,LegacyNativePhase::Before,nullptr,false,0,0,tag);
    const HANDLE result=::CreateFileW(path,access,sharing,security,disposition,flags,pattern);const DWORD error=GetLastError();const int native_errno=errno;
    legacy_windows_event(LegacyNativeOperation::Create,LegacyNativePhase::After,result,result!=INVALID_HANDLE_VALUE,result!=INVALID_HANDLE_VALUE?0:error,0,tag);
    errno=native_errno;SetLastError(error);return result;
}
inline HANDLE legacy_open_by_id(HANDLE volume,LPFILE_ID_DESCRIPTOR id,DWORD access,DWORD sharing,LPSECURITY_ATTRIBUTES security,DWORD flags,const char* tag)noexcept {
    legacy_windows_event(LegacyNativeOperation::OpenById,LegacyNativePhase::Before,nullptr,false,0,0,tag);
    const HANDLE result=::OpenFileById(volume,id,access,sharing,security,flags);const DWORD error=GetLastError();const int native_errno=errno;
    legacy_windows_event(LegacyNativeOperation::OpenById,LegacyNativePhase::After,result,result!=INVALID_HANDLE_VALUE,result!=INVALID_HANDLE_VALUE?0:error,0,tag);
    errno=native_errno;SetLastError(error);return result;
}
inline NTSTATUS legacy_nt_create(PHANDLE output,ACCESS_MASK access,POBJECT_ATTRIBUTES attributes,PIO_STATUS_BLOCK io,
    PLARGE_INTEGER allocation,ULONG attrs,ULONG sharing,ULONG disposition,ULONG options,PVOID ea,ULONG ea_size,const char* tag)noexcept {
    legacy_windows_event(LegacyNativeOperation::NativeCreate,LegacyNativePhase::Before,nullptr,false,0,0,tag);
    const NTSTATUS result=::NtCreateFile(output,access,attributes,io,allocation,attrs,sharing,disposition,options,ea,ea_size);
    const DWORD error=GetLastError();const int native_errno=errno;const bool pending=result==0x103;
    // Do not touch a pending request's output handle or IOSB. The owning
    // provider must emit OpenCompleted ONLY after its existing exact drain.
    const bool complete=result>=0&&!pending;
    legacy_windows_event(LegacyNativeOperation::NativeCreate,LegacyNativePhase::After,complete&&output?*output:nullptr,
        complete,0,static_cast<std::uint32_t>(result),tag,0,0,LegacyNativeDomain::NtStatus,pending);
    errno=native_errno;SetLastError(error);return result;
}
inline void legacy_nt_open_completed(HANDLE handle,NTSTATUS status,const char* tag)noexcept {
    const bool pending=status==0x103;
    legacy_windows_event(LegacyNativeOperation::NativeCreate,LegacyNativePhase::OpenCompleted,
        status>=0&&!pending?handle:nullptr,status>=0&&!pending,0,static_cast<std::uint32_t>(status),tag,0,0,LegacyNativeDomain::NtStatus,pending);
}
inline BOOL legacy_flush(HANDLE h,const char* tag)noexcept {
    legacy_windows_event(LegacyNativeOperation::Flush,LegacyNativePhase::Before,h,false,0,0,tag);
    const BOOL result=::FlushFileBuffers(h);const DWORD error=GetLastError();const int native_errno=errno;
    legacy_windows_event(LegacyNativeOperation::Flush,LegacyNativePhase::After,h,result!=FALSE,result?0:error,result,tag);
    errno=native_errno;SetLastError(error);return result;
}
inline BOOL legacy_set_info(HANDLE h,FILE_INFO_BY_HANDLE_CLASS kind,LPVOID data,DWORD size,const char* tag)noexcept {
    legacy_windows_event(LegacyNativeOperation::SetInfo,LegacyNativePhase::Before,h,false,0,0,tag);
    const BOOL result=::SetFileInformationByHandle(h,kind,data,size);const DWORD error=GetLastError();const int native_errno=errno;
    legacy_windows_event(LegacyNativeOperation::SetInfo,LegacyNativePhase::After,h,result!=FALSE,result?0:error,result,tag,0,DWORD(kind));
    errno=native_errno;SetLastError(error);return result;
}
// At an EXISTING safe close helper use legacy_close_before/after around the
// same real CloseHandle (no second close). Only after native result capture.
inline void legacy_close_before(HANDLE h,const char* tag)noexcept {
    legacy_windows_event(LegacyNativeOperation::Close,LegacyNativePhase::Before,h,false,0,0,tag);
}
inline void legacy_close_after(HANDLE h,BOOL native_result,DWORD error,const char* tag)noexcept {
    legacy_windows_event(LegacyNativeOperation::Close,LegacyNativePhase::After,h,native_result!=FALSE,error,native_result,tag);
}
// Observation-only native call for an EXISTING close/inject/latch body.
// It does not add a second before/inject/Root-record callback to that body.
inline BOOL legacy_close_native_call(HANDLE h,const char* tag)noexcept {
    legacy_close_before(h,tag);
    const BOOL result=::CloseHandle(h);const DWORD saved=GetLastError();const int native_errno=errno;
    legacy_close_after(h,result,result?ERROR_SUCCESS:saved,tag);
    errno=native_errno;SetLastError(saved);return result;
}
// Delegate an existing helper BODY here once, never nest two injectors.
inline BOOL legacy_close_handle(HANDLE h,const char* tag)noexcept {
    const DWORD before=GetLastError();const int before_errno=errno;
    observe_native_close(h,tag);errno=before_errno;SetLastError(before);
    const BOOL result=legacy_close_native_call(h,tag);
    const DWORD saved=GetLastError();const int native_errno=errno;
    const DWORD native_error=result?ERROR_SUCCESS:saved;
    const auto injected=inject_native_close_failure(h,tag,result!=FALSE,native_error);
    errno=native_errno;
    if (!result) {SetLastError(native_error);return FALSE;}
    if (injected) {SetLastError(injected);return FALSE;}
    SetLastError(saved);return result;
}
} // namespace ck::files::detail
#endif
