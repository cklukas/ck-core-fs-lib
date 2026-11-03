// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../observation.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <array>
#include <bit>
#include <cstddef>
#include <cstring>
namespace ck::files::detail {
// Generic I/O-manager driver-path proof for a genuine held file OR directory.
// No filesystem IRP, pathname/reopen, specific access, allocation or ownership.
// Callers separately retain object-kind/identity/storage/remote-provider checks.
struct WindowsNativeFsdProof {
 bool qualified=false;
 ObservationState state=ObservationState::Unsupported;
 ErrorDomain domain=ErrorDomain::Adapter;
 std::int64_t code=static_cast<std::int64_t>(AdapterError::ProviderReviewRequired);
 const char* operation="metadata_provider.windows_driver_unqualified";
};
using WindowsVolumeQuery=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
inline WindowsNativeFsdProof query_windows_native_fsd(HANDLE handle,WindowsVolumeQuery query) noexcept {
 WindowsNativeFsdProof proof;auto& certified=proof.qualified;auto& state=proof.state;
 auto& domain=proof.domain;auto& code=proof.code;auto& operation=proof.operation;
                // FILE_FS_DRIVER_PATH_INFORMATION is handled by the I/O
                // manager without sending a filesystem IRP. Unlike fsName or
                // disk/remote flags, the FSD cannot supply this answer.
                // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_fs_driver_path_information
                struct Header { BOOLEAN present;ULONG bytes;WCHAR name[1]; };
                struct alignas(8) Buffer { BOOLEAN present;ULONG bytes;WCHAR name[16]; };
                static_assert(offsetof(Header,name)==8&&offsetof(Buffer,name)==8);
                static_assert(sizeof(Header)==12&&alignof(Buffer)>=8&&sizeof(Buffer)==40);
                constexpr wchar_t ntfs[]=L"\\FileSystem\\Ntfs";
                constexpr wchar_t refs[]=L"\\FileSystem\\ReFS";
                static_assert(sizeof(ntfs)==sizeof(refs)&&sizeof(ntfs)-sizeof(WCHAR)==sizeof(Buffer::name));

                for(const auto* driver:std::array{ntfs,refs}) {
                    Buffer buffer{};
                    buffer.bytes=sizeof(buffer.name);
                    std::memcpy(buffer.name,driver,buffer.bytes); // Exact UTF-16, no terminator.
                    constexpr ULONG length=offsetof(Buffer,name)+sizeof(Buffer::name);
                    static_assert(length>=sizeof(Header)&&length<=sizeof(Buffer));
                    IO_STATUS_BLOCK io{};
                    const auto status=query(handle,&io,&buffer,length,9);
                    // An absent kernel driver object cannot be in this path.
                    if(static_cast<ULONG>(status)==0xC0000034u)continue;
                    if(status!=0) {
                        state=ObservationState::Unknown;domain=ErrorDomain::NtStatus;
                        code=static_cast<std::uint32_t>(status);
                        operation="metadata_provider.driver_path_query";break;
                    }
                    if(io.Status!=0||io.Information<sizeof(Header)||io.Information>length||
                        buffer.bytes!=sizeof(buffer.name)||buffer.present>TRUE) {
                        state=ObservationState::Unknown;domain=ErrorDomain::Adapter;
                        code=static_cast<std::int64_t>(AdapterError::InvalidNativeResult);
                        operation="metadata_provider.driver_path_result";break;
                    }
                    if(buffer.present==TRUE) { certified=true;break; }
                }
 return proof;
}
inline WindowsNativeFsdProof prove_windows_native_fsd(HANDLE handle) noexcept {
 const auto module=GetModuleHandleW(L"ntdll.dll");
 const auto symbol=module?GetProcAddress(module,"NtQueryVolumeInformationFile"):nullptr;
 if(!symbol){WindowsNativeFsdProof p;p.state=ObservationState::Unknown;p.domain=ErrorDomain::Win32;p.code=GetLastError();p.operation="metadata_provider.driver_query_entry";return p;}
 return query_windows_native_fsd(handle,std::bit_cast<WindowsVolumeQuery>(symbol));
}
} // namespace ck::files::detail
