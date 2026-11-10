// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../observation.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include "legacy_native_fixture_windows.hpp"
#include <array>
#include <bit>
#include <cstddef>
#include <cstring>
namespace ck::files::detail {
// Allocation-free proof for a genuine held native directory. Does not own or
// close the handle; callers retain their existing close/failure-latch protocol.
struct WindowsJournalVolumeProof {
    bool qualified=false;
    ObservationState state=ObservationState::Unsupported;
    ErrorDomain domain=ErrorDomain::Adapter;
    std::int64_t code=static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe);
    const char* operation="journal_scope.windows_driver_unqualified";
};
inline WindowsJournalVolumeProof prove_windows_journal_volume(HANDLE handle) noexcept {
    WindowsJournalVolumeProof proof;
    auto& certified=proof.qualified;
    auto& state=proof.state;
    auto& domain=proof.domain;
    auto& code=proof.code;
    auto& operation=proof.operation;
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if(!::ck::files::detail::legacy_query(handle,FileAttributeTagInfo,&tag,sizeof(tag),"legacy.native_windows_journal_volume.GetFileInformationByHandleEx.32")) {
        state=ObservationState::Unknown;domain=ErrorDomain::Win32;code=GetLastError();
        operation="journal_scope.cursor_attributes";
    } else {
        // Admit ordinary directory attributes only. Reparse, offline, virtual,
        // recall/storage-managed and unknown kinds are not scope authority.
        constexpr DWORD ordinary=FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|
            FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_ARCHIVE|
            FILE_ATTRIBUTE_TEMPORARY|FILE_ATTRIBUTE_SPARSE_FILE|FILE_ATTRIBUTE_COMPRESSED|
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED|FILE_ATTRIBUTE_ENCRYPTED|
            FILE_ATTRIBUTE_INTEGRITY_STREAM|FILE_ATTRIBUTE_NO_SCRUB_DATA;
        if(!(tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)||tag.ReparseTag||
            (tag.FileAttributes&~ordinary)) {
            operation="journal_scope.cursor_attributes_unqualified";
        } else {
            using Query=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
            const auto module=GetModuleHandleW(L"ntdll.dll");
            const auto symbol=module?GetProcAddress(module,"NtQueryVolumeInformationFile"):nullptr;
            if(!symbol) {
                state=ObservationState::Unknown;domain=ErrorDomain::Win32;code=GetLastError();
                operation="journal_scope.driver_query_entry";
            } else {
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
                const auto query=std::bit_cast<Query>(symbol);
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
                        operation="journal_scope.driver_path_query";break;
                    }
                    if(io.Status!=0||io.Information<sizeof(Header)||io.Information>length||
                        buffer.bytes!=sizeof(buffer.name)||buffer.present>TRUE) {
                        state=ObservationState::Unknown;domain=ErrorDomain::Adapter;
                        code=static_cast<std::int64_t>(AdapterError::InvalidNativeResult);
                        operation="journal_scope.driver_path_result";break;
                    }
                    if(buffer.present==TRUE) { certified=true;break; }
                }
            }
        }
    }
    return proof;
}
} // namespace ck::files::detail
