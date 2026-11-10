// SPDX-License-Identifier: LGPL-2.0-or-later
// Private Windows fixture startup evidence; never installed or SDK authority.
#pragma once
#ifndef _WIN32
#error Windows runtime self-report requires a genuine Windows process
#endif
#include <windows.h>
#include <cerrno>
#include <cstdio>

namespace ckfs_test {
inline bool runtime_report_failure(const char* phase,DWORD code,int crt_error=0) noexcept {
    std::fprintf(stderr,"CKFS_TEST_RUNTIME_ERROR_V1 phase=%s win32=%lu crt_errno=%d\n",
        phase,static_cast<unsigned long>(code),crt_error);
    std::fflush(stderr);
    return false;
}
inline bool runtime_utf16_hex(const wchar_t* path,DWORD length) noexcept {
    static_assert(sizeof(wchar_t)==2,"Exact Windows UTF-16 units required");
    for(DWORD i=0;i<length;++i)
        if(std::fprintf(stdout,"%04x",static_cast<unsigned>(static_cast<unsigned short>(path[i])))<0)
            return false;
    return true;
}
inline bool report_runtime_self(const char* fixture) noexcept {
    // No C++ allocation, SDK callbacks, polling, sleeps, imported-address patch,
    // or environment-driven module lookup. Call before tests/observers/OOM gates.
    const DWORD saved_error=GetLastError();const int saved_errno=errno;
    constexpr DWORD capacity=32768;
    wchar_t image[capacity]{};
    wchar_t runtime[capacity]{};
    const DWORD pid=GetCurrentProcessId();
    const DWORD image_length=GetModuleFileNameW(nullptr,image,capacity);
    if(!image_length)return runtime_report_failure("image_path",GetLastError());
    if(image_length>=capacity)return runtime_report_failure("image_truncated",GetLastError());
    SetLastError(ERROR_SUCCESS);
    const HMODULE asan=GetModuleHandleW(L"clang_rt.asan_dynamic-x86_64.dll");
    const DWORD lookup_error=asan?ERROR_SUCCESS:GetLastError();
    if(!asan&&lookup_error!=ERROR_MOD_NOT_FOUND)
        return runtime_report_failure("asan_module_query",lookup_error);
#if defined(__SANITIZE_ADDRESS__)
    constexpr unsigned asan_required=1;
    if(!asan)return runtime_report_failure("asan_required_but_absent",lookup_error);
#else
    constexpr unsigned asan_required=0;
#endif
    DWORD runtime_length=0;
    if(asan){
        runtime_length=GetModuleFileNameW(asan,runtime,capacity);
        if(!runtime_length)return runtime_report_failure("asan_path",GetLastError());
        if(runtime_length>=capacity)return runtime_report_failure("asan_truncated",GetLastError());
    }
    if(std::fprintf(stdout,"CKFS_TEST_RUNTIME_V1 pid=%lu fixture=%s asan_required=%u image_units=%lu image_utf16=",
        static_cast<unsigned long>(pid),fixture,asan_required,static_cast<unsigned long>(image_length))<0||
       !runtime_utf16_hex(image,image_length)||
       std::fprintf(stdout," asan_present=%u asan_units=%lu asan_utf16=",asan?1U:0U,
           static_cast<unsigned long>(runtime_length))<0||
       !runtime_utf16_hex(runtime,runtime_length)||std::fputc('\n',stdout)==EOF||std::fflush(stdout)!=0)
        return runtime_report_failure("stdout",ERROR_SUCCESS,errno);
    errno=saved_errno;SetLastError(saved_error);
    return true;
}
} // namespace ckfs_test
