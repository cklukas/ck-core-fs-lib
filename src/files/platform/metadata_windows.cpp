#include "native_sync_session_lease.hpp"
// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_filesystem.hpp"
#include "../native_trash.hpp"
#include "native_journal_directory_bridge.hpp"
#include "metadata_replay.hpp"
#include "metadata_capture_job.hpp"
#include "native_metadata_stream_target.hpp"
#include "native_target_read_seed.hpp"
#include "native_target_read_budget.hpp"
#include "native_windows_native_fsd.hpp"
#include "sha256.hpp"
#include "windows_name.hpp"
#include "windows_directory_record.hpp"
#include "windows_stream_records.hpp"
#include "windows_parent_record.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <sddl.h>
#include <aclapi.h>

#include <bit>
#include <set>
#include <algorithm>
#include <array>
#include <span>
#include <vector>
#include <cstddef>
#include <cstring>
#include <optional>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <atomic>

namespace ck::files {
namespace {
thread_local detail::WindowsJournalCloseObserver journal_close_observer;
}
detail::WindowsJournalCloseObserver detail::exchange_windows_journal_close_observer(WindowsJournalCloseObserver next) noexcept {
    const auto previous=journal_close_observer;
    journal_close_observer=next;
    return previous;
}
namespace {


// Explicit persistent SD classes. BACKUP_SECURITY_INFORMATION alone does
// not enumerate the modern resource/trust/access-filter request contract.
constexpr SECURITY_INFORMATION persistent_security_information=
    OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|
    SACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION|ATTRIBUTE_SECURITY_INFORMATION|
    SCOPE_SECURITY_INFORMATION|PROCESS_TRUST_LABEL_SECURITY_INFORMATION|ACCESS_FILTER_SECURITY_INFORMATION;
constexpr SECURITY_INFORMATION persistent_sacl_information=persistent_security_information&
    ~(OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION);

void report_capture_close(DWORD code,const char* operation)noexcept {
    const auto observer=journal_close_observer;
    if(observer.record)observer.record(observer.context,code,operation);
    detail::record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Win32,code,operation});
    SetLastError(code);
}
struct HandleCloser {
    void operator()(void* handle) const noexcept {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE && !CloseHandle(handle)) {
            const DWORD e=GetLastError();
            const auto observer=journal_close_observer;
            if(observer.record)observer.record(observer.context,e,"sync_session.native_cursor_close");
            detail::record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Win32,e,"metadata_capture.temporary_CloseHandle"});
            SetLastError(e);
        }
    }
};

using OwnedHandle = std::unique_ptr<void, HandleCloser>;

ObservationState error_state(DWORD code) noexcept {
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) return ObservationState::Gone;
    if (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS) return ObservationState::Changed;
    if (code == ERROR_ACCESS_DENIED || code == ERROR_PRIVILEGE_NOT_HELD ||
        code == ERROR_SHARING_VIOLATION || code == ERROR_LOCK_VIOLATION) return ObservationState::Denied;
    if (code == ERROR_FILE_INVALID || code == ERROR_DELETE_PENDING) return ObservationState::Changed;
    if (code == ERROR_INVALID_FUNCTION || code == ERROR_NOT_SUPPORTED ||
        code == ERROR_CALL_NOT_IMPLEMENTED || code == ERROR_INVALID_LEVEL || code == ERROR_INVALID_PARAMETER)
        return ObservationState::Unsupported;
    return ObservationState::Failed;
}

template <class T>
Observation<T> failure(DWORD code, const char* operation);

Observation<std::wstring> final_path(HANDLE handle, const char* operation) {
    using Result = Observation<std::wstring>;
    const DWORD required = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED);
    if (!required) return failure<std::wstring>(GetLastError(), operation);
    std::wstring path(required, L'\0');
    const DWORD written = GetFinalPathNameByHandleW(handle, path.data(), required + 1, FILE_NAME_NORMALIZED);
    if (!written || written > required)
        return failure<std::wstring>(GetLastError(), operation);
    path.resize(written);
    return Result::available(std::move(path));
}

Observation<std::wstring> current_user_sid() {
    using Result = Observation<std::wstring>;
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
        return failure<std::wstring>(GetLastError(), "trash.open_process_token");
    OwnedHandle token(raw);
    DWORD bytes = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &bytes);
    if (!bytes || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return failure<std::wstring>(GetLastError(), "trash.token_user_size");
    std::vector<std::byte> buffer(bytes);
    if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), bytes, &bytes))
        return failure<std::wstring>(GetLastError(), "trash.token_user");
    auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &text))
        return failure<std::wstring>(GetLastError(), "trash.sid");
    std::wstring result(text);
    LocalFree(text);
    return Result::available(std::move(result));
}

Observation<std::wstring> volume_path_for(std::wstring_view file_path) {
    using Result = Observation<std::wstring>;
    const std::wstring input(file_path);
    std::vector<wchar_t> buffer(256);
    for (;;) {
        if (GetVolumePathNameW(input.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()))) {
            return Result::available(std::wstring(buffer.data()));
        }
        const DWORD code = GetLastError();
        if ((code != ERROR_MORE_DATA && code != ERROR_INSUFFICIENT_BUFFER) || buffer.size() >= 32768)
            return failure<std::wstring>(code, "trash_child.volume_path");
        buffer.resize(buffer.size() * 2);
    }
}

std::wstring hex_suffix(std::uint64_t value) {
    constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring result(16, L'0');
    for (std::size_t index = 0; index != result.size(); ++index)
        result[result.size() - index - 1] = digits[(value >> (index * 4U)) & 0xfU];
    return result;
}

template <class T>
Observation<T> failure(DWORD code, const char* operation) {
    return Observation<T>::unavailable(error_state(code), {ErrorDomain::Win32, code, operation});
}

template <class T>
Observation<T> not_applicable(const char* operation) {
    return Observation<T>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), operation});
}

using NtSetInformationFileFunction = NTSTATUS (NTAPI *)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);

struct FileLinkInformationCompat {
    BOOLEAN ReplaceIfExists;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
};

bool set_file_rename_information(HANDLE source, PFILE_RENAME_INFO information, ULONG size) {
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto address = module ? GetProcAddress(module, "NtSetInformationFile") : nullptr;
    if (!address) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return false;
    }
    static_assert(sizeof(NtSetInformationFileFunction) == sizeof(address));
    const auto set_information = std::bit_cast<NtSetInformationFileFunction>(address);
    IO_STATUS_BLOCK io{};io.Status=0x00000103L;
    // FileRenameInformation is the documented native information class used
    // by NtSetInformationFile. Unlike the Win32 wrapper, the native call
    // preserves a verified relative RootDirectory handle on local volumes.
    auto status = set_information(source, &io, information, size, 10);
    if (status == 0x00000103L) {
        // A RenameSource handle is asynchronous. Its outstanding oplock can
        // also signal the file object; inspect this exact request's status,
        // never treat a signaled file handle or STATUS_PENDING as success.
        // Both the caller's rename buffer and this IOSB remain live until the
        // native request is complete. SYNCHRONIZE is required at guard open.
        do {
            const DWORD waited=WaitForSingleObject(source,50);
            if (waited==WAIT_FAILED) {
                // The operation owns this handle for its whole duration. A
                // failed wait cannot permit early destruction of native I/O
                // storage. Continue draining the exact IOSB after cancellation.
                using Cancel=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PIO_STATUS_BLOCK);
                const auto cancel_address=GetProcAddress(module,"NtCancelIoFileEx");
                if (cancel_address) {IO_STATUS_BLOCK cancelled{};std::bit_cast<Cancel>(cancel_address)(source,&io,&cancelled);}
                Sleep(1);
            }
            MemoryBarrier();
            status=*reinterpret_cast<volatile NTSTATUS*>(&io.Status);
            if (status==0x00000103L && waited==WAIT_OBJECT_0) Sleep(1);
        } while(status==0x00000103L);
    }
    if (status >= 0) return true;
    SetLastError(RtlNtStatusToDosError(status));
    return false;
}

bool set_file_link_information(HANDLE source, FileLinkInformationCompat *information, ULONG size) {
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto address = module ? GetProcAddress(module, "NtSetInformationFile") : nullptr;
    if (!address) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return false;
    }
    static_assert(sizeof(NtSetInformationFileFunction) == sizeof(address));
    const auto set_information = std::bit_cast<NtSetInformationFileFunction>(address);
    IO_STATUS_BLOCK io{};
    // FileLinkInformation is native information class 11. The destination
    // parent remains a verified RootDirectory handle; no absolute path is
    // reconstructed and no replacement is permitted.
    const auto status = set_information(source, &io, information, size, 11);
    if (status >= 0) return true;
    SetLastError(RtlNtStatusToDosError(status));
    return false;
}

Observation<ObjectIdentity> identity(HANDLE handle, const AdapterScope& scope) {
    FILE_ID_INFO native{};
    if (GetFileInformationByHandleEx(handle, FileIdInfo, &native, sizeof(native))) {
        NativeIdentifier object;
        static_assert(sizeof(native.FileId.Identifier) == sizeof(object.bytes));
        std::memcpy(object.bytes.data(), native.FileId.Identifier, sizeof(native.FileId.Identifier));
        if (object == NativeIdentifier{})
            return Observation<ObjectIdentity>::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity), "FileIdInfo.zero"});
        return Observation<ObjectIdentity>::available({scope, IdentityScheme::WindowsFileId128,
            NativeIdentifier::from_u64(native.VolumeSerialNumber), object, std::nullopt});
    }
    const DWORD code = GetLastError();
    if (error_state(code) != ObservationState::Unsupported) return failure<ObjectIdentity>(code, "FileIdInfo");

    // Filesystems without the 128-bit query may expose the documented classic
    // index. Keep its scheme explicit, never truncate a successful 128-bit ID,
    // and never use a query error/zero index as evidence of object identity.
    BY_HANDLE_FILE_INFORMATION legacy{};
    if (!GetFileInformationByHandle(handle, &legacy)) return failure<ObjectIdentity>(GetLastError(), "GetFileInformationByHandle");
    const auto index = (static_cast<std::uint64_t>(legacy.nFileIndexHigh) << 32U) | legacy.nFileIndexLow;
    if (index == 0)
        return Observation<ObjectIdentity>::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity), "legacy_file_index.zero"});
    return Observation<ObjectIdentity>::available({scope, IdentityScheme::WindowsFileIndex64,
        NativeIdentifier::from_u64(legacy.dwVolumeSerialNumber), NativeIdentifier::from_u64(index), std::nullopt});
}

Observation<FileTimestamp> timestamp(LARGE_INTEGER native) {
    return Observation<FileTimestamp>::available(FileTimestamp::from_windows_ticks(static_cast<std::uint64_t>(native.QuadPart)));
}

Observation<LONGLONG> windows_ticks(const FileTimestamp& value, const char* operation) {
    constexpr std::int64_t epoch_seconds = 11'644'473'600;
    constexpr std::uint64_t ticks_per_second = 10'000'000;
    if (value.nanoseconds() % 100U != 0 || value.seconds() < -epoch_seconds ||
        value.seconds() > std::numeric_limits<std::int64_t>::max() - epoch_seconds)
        return Observation<LONGLONG>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), operation});
    const auto seconds = static_cast<std::uint64_t>(value.seconds() + epoch_seconds);
    if (seconds > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max()) / ticks_per_second)
        return Observation<LONGLONG>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), operation});
    const auto ticks = seconds * ticks_per_second + value.nanoseconds() / 100U;
    if (ticks > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max()))
        return Observation<LONGLONG>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), operation});
    return Observation<LONGLONG>::available(static_cast<LONGLONG>(ticks));
}

Observation<std::uint64_t> nonnegative(LONGLONG value, const char* operation) {
    if (value < 0)
        return Observation<std::uint64_t>::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), operation});
    return Observation<std::uint64_t>::available(static_cast<std::uint64_t>(value));
}

Observation<BasicMetadata> handle_metadata(HANDLE handle, const AdapterScope& scope) {
    FILE_BASIC_INFO native{};
    if (!GetFileInformationByHandleEx(handle, FileBasicInfo, &native, sizeof(native)))
        return failure<BasicMetadata>(GetLastError(), "FileBasicInfo");
    BasicMetadata result;
    result.identity = identity(handle, scope);
    if (result.identity.value()) {
        std::uint64_t mount = 0;
        for (unsigned byte = 0; byte != sizeof(mount); ++byte)
            mount |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(
                result.identity.value()->volume.bytes[byte])) << (byte * 8U);
        result.mount_id = Observation<std::uint64_t>::available(mount);
    }
    result.windows_attributes = Observation<std::uint32_t>::available(native.FileAttributes);
    result.accessed = timestamp(native.LastAccessTime);
    result.modified = timestamp(native.LastWriteTime);
    result.changed = timestamp(native.ChangeTime);
    result.created = timestamp(native.CreationTime);
    result.kind = Observation<ObjectKind>::available((native.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? ObjectKind::Directory : ObjectKind::RegularFile);
    if ((native.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        result.kind = Observation<ObjectKind>::available(ObjectKind::ReparsePoint);
        FILE_ATTRIBUTE_TAG_INFO tag{};
        if (GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag))) {
            result.reparse_tag = Observation<std::uint32_t>::available(tag.ReparseTag);
            if (tag.ReparseTag == IO_REPARSE_TAG_SYMLINK) result.kind = Observation<ObjectKind>::available(ObjectKind::SymbolicLink);
            if (tag.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) result.kind = Observation<ObjectKind>::available(ObjectKind::Junction);
        } else {
            result.reparse_tag = failure<std::uint32_t>(GetLastError(), "FileAttributeTagInfo");
        }
    } else {
        result.reparse_tag = not_applicable<std::uint32_t>("reparse_tag");
    }
    if (GetFileType(handle) == FILE_TYPE_CHAR) result.kind = Observation<ObjectKind>::available(ObjectKind::CharacterDevice);
    result.posix_uid = not_applicable<std::uint64_t>("posix_uid");
    result.posix_gid = not_applicable<std::uint64_t>("posix_gid");
    result.posix_permissions = not_applicable<std::uint32_t>("posix_permissions");
    result.bsd_flags = not_applicable<std::uint32_t>("bsd_flags");
    result.linux_attributes = not_applicable<LinuxFileAttributes>("linux_attributes");

    FILE_STANDARD_INFO standard{};
    if (GetFileInformationByHandleEx(handle, FileStandardInfo, &standard, sizeof(standard))) {
        result.link_count = Observation<std::uint64_t>::available(standard.NumberOfLinks);
        if (*result.kind.value() == ObjectKind::RegularFile) {
            result.logical_size = nonnegative(standard.EndOfFile.QuadPart, "FileStandardInfo.size");
            result.allocated_size = nonnegative(standard.AllocationSize.QuadPart, "FileStandardInfo.allocation");
        } else {
            result.logical_size = not_applicable<std::uint64_t>("regular_file.size");
            result.allocated_size = not_applicable<std::uint64_t>("regular_file.allocation");
        }
    } else {
        const DWORD code = GetLastError();
        result.link_count = failure<std::uint64_t>(code, "FileStandardInfo");
        result.logical_size = failure<std::uint64_t>(code, "FileStandardInfo");
        result.allocated_size = failure<std::uint64_t>(code, "FileStandardInfo");
    }
    return Observation<BasicMetadata>::available(std::move(result));
}

// Public native-system-service ABI: ZwQueryEaFile contract, Nt user-mode
// entry point. No private information class or hard-coded syscall number.
using QueryEa = NTSTATUS (NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN);
using SetEa = NTSTATUS (NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG);
struct FullEaInformation final {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    char EaName[1];
};
static_assert(offsetof(FullEaInformation, EaName) == 8);
Observation<QueryEa> query_ea_api() {
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto address = module ? GetProcAddress(module, "NtQueryEaFile") : nullptr;
    if (!address) {
        const DWORD code = GetLastError();
        return Observation<QueryEa>::unavailable(ObservationState::Unsupported, {ErrorDomain::Win32, code, "NtQueryEaFile.resolve"});
    }
    static_assert(sizeof(QueryEa) == sizeof(address));
    return Observation<QueryEa>::available(std::bit_cast<QueryEa>(address));
}
Observation<SetEa> set_ea_api() {
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto address = module ? GetProcAddress(module, "NtSetEaFile") : nullptr;
    if (!address) {
        const DWORD code = GetLastError();
        return Observation<SetEa>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Win32, code, "NtSetEaFile.resolve"});
    }
    static_assert(sizeof(SetEa) == sizeof(address));
    return Observation<SetEa>::available(std::bit_cast<SetEa>(address));
}
constexpr std::uint32_t no_eas = 0xC0000052U;
constexpr std::uint32_t no_more_eas = 0x80000012U;
constexpr std::uint32_t nonexistent_ea = 0xC0000051U;
constexpr std::uint32_t buffer_overflow = 0x80000005U;
constexpr std::uint32_t buffer_too_small = 0xC0000023U;

template <class T>
Observation<T> ea_failure(std::uint32_t code, const char* operation) {
    auto state = error_state(RtlNtStatusToDosError(static_cast<NTSTATUS>(code)));
    if (code == no_eas || code == no_more_eas || code == nonexistent_ea) state = ObservationState::Gone;
    if (code == 0xC000004FU || code == 0xC0000010U) state = ObservationState::Unsupported;
    return Observation<T>::unavailable(state, {ErrorDomain::NtStatus, code, operation});
}

struct WindowsPublicationContext final {
    WindowsPublicationContext(OwnedHandle retained_parent, NativeName retained_name,
                              Observation<ObjectIdentity> retained_parent_identity)
        : parent(std::move(retained_parent)), name(std::move(retained_name)),
          parent_identity(std::move(retained_parent_identity)) {}
    OwnedHandle parent;
    NativeName name;
    Observation<ObjectIdentity> parent_identity;
};

// Borrows one worker-owned asynchronous read+DELETE handle. The kernel keeps
// writing this request's OVERLAPPED/output until a break or cancellation has
// completed, so this owner must be destroyed before the borrowed handle.
class WindowsContentLease final {
public:
    explicit WindowsContentLease(HANDLE file):file_(file),event_(CreateEventW(nullptr,TRUE,FALSE,nullptr)) {
        request_.StructureVersion=REQUEST_OPLOCK_CURRENT_VERSION;
        request_.StructureLength=sizeof(request_);
        request_.RequestedOplockLevel=OPLOCK_LEVEL_CACHE_READ|OPLOCK_LEVEL_CACHE_HANDLE;
        request_.Flags=REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
        overlapped_.hEvent=event_.get();
    }
    WindowsContentLease(const WindowsContentLease&)=delete;
    WindowsContentLease& operator=(const WindowsContentLease&)=delete;
    ~WindowsContentLease() {
        if (pending_) {
            // Cancel only our lease IRP, then wait for its completion before
            // releasing any kernel-referenced member. ERROR_NOT_FOUND means
            // it raced completion; GetOverlappedResult still drains that IRP.
            CancelIoEx(file_,&overlapped_);
            DWORD count=0;GetOverlappedResult(file_,&overlapped_,&count,TRUE);
        }
    }
    Observation<bool> acquire() {
        if (!event_ || event_.get()==INVALID_HANDLE_VALUE)
            return failure<bool>(GetLastError(),"stable_content.CreateEventW");
        const BOOL immediate=DeviceIoControl(file_,FSCTL_REQUEST_OPLOCK,&request_,sizeof(request_),
            &reply_,sizeof(reply_),nullptr,&overlapped_);
        const DWORD code=immediate?ERROR_SUCCESS:GetLastError();
        if (immediate) return Observation<bool>::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"stable_content.oplock_not_pending"});
        if (code!=ERROR_IO_PENDING) {
            if (code==ERROR_OPLOCK_NOT_GRANTED || code==ERROR_CANNOT_GRANT_REQUESTED_OPLOCK)
                return Observation<bool>::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Win32,code,"stable_content.FSCTL_REQUEST_OPLOCK"});
            return failure<bool>(code,"stable_content.FSCTL_REQUEST_OPLOCK");
        }
        pending_=true;
        return check();
    }
    Observation<bool> check() const {
        if (broken_) return changed();
        DWORD count=0;
        if (!GetOverlappedResult(file_,const_cast<OVERLAPPED*>(&overlapped_),&count,FALSE)) {
            const auto code=GetLastError();
            if (code==ERROR_IO_INCOMPLETE) return Observation<bool>::available(true);
        }
        // Any completion loses this exact admission token. Never silently
        // re-request after a break, switch, cancellation or unsolicited error.
        broken_=true;
        return changed();
    }
    HANDLE event() const noexcept {return event_.get();}
private:
    static Observation<bool> changed() {
        return Observation<bool>::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"stable_content.windows_rh_broken"});
    }
    HANDLE file_;
    OwnedHandle event_;
    REQUEST_OPLOCK_INPUT_BUFFER request_{};
    REQUEST_OPLOCK_OUTPUT_BUFFER reply_{};
    OVERLAPPED overlapped_{};
    bool pending_=false;
    mutable bool broken_=false;
};

// Query every persistent SACL class, but set only classes whose actual ACE
// bytes differ. Requesting a write to an absent process-trust class can require
// kernel-only authority even when both queried descriptors have none.
Observation<std::array<NativeBytes,6>> persistent_sacl_classes(const NativeSecurityValue& security) {
    using Result=Observation<std::array<NativeBytes,6>>;
    const auto checked=detail::validate_windows_descriptor(security.bytes,
        {InventoryLimits::hard_native_bytes,InventoryLimits::hard_records});
    if(!checked.value()){const auto& e=*checked.unavailable_detail();return Result::unavailable(e.state,e.error);}
    SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;
    if(!GetSecurityDescriptorControl(const_cast<std::byte*>(security.bytes.data()),&control,&revision))
        return failure<std::array<NativeBytes,6>>(GetLastError(),"metadata_replay.coverage_descriptor_control");
    constexpr auto replayable_control=SE_OWNER_DEFAULTED|SE_GROUP_DEFAULTED|SE_DACL_PRESENT|SE_DACL_DEFAULTED|
        SE_SACL_PRESENT|SE_SACL_DEFAULTED|SE_DACL_AUTO_INHERIT_REQ|SE_SACL_AUTO_INHERIT_REQ|
        SE_DACL_AUTO_INHERITED|SE_SACL_AUTO_INHERITED|SE_DACL_PROTECTED|SE_SACL_PROTECTED|SE_SELF_RELATIVE;
    if((control&~replayable_control)!=0)
        return failure<std::array<NativeBytes,6>>(ERROR_NOT_SUPPORTED,"metadata_replay.coverage_unhandled_descriptor_control");
    PACL dacl=nullptr;BOOL dacl_present=FALSE,dacl_defaulted=FALSE;
    if(!GetSecurityDescriptorDacl(const_cast<std::byte*>(security.bytes.data()),&dacl_present,&dacl,&dacl_defaulted))
        return failure<std::array<NativeBytes,6>>(GetLastError(),"metadata_replay.coverage_dacl");
    if(dacl)for(DWORD i=0;i<dacl->AceCount;++i) {
        void* raw=nullptr;if(!GetAce(dacl,i,&raw))return failure<std::array<NativeBytes,6>>(GetLastError(),"metadata_replay.coverage_dacl_ace");
        switch(static_cast<const ACE_HEADER*>(raw)->AceType) {
        case ACCESS_ALLOWED_ACE_TYPE:case ACCESS_DENIED_ACE_TYPE:case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE:case ACCESS_DENIED_OBJECT_ACE_TYPE:
        case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:case ACCESS_DENIED_CALLBACK_ACE_TYPE:
        case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:break;
        default:return failure<std::array<NativeBytes,6>>(ERROR_NOT_SUPPORTED,"metadata_replay.coverage_unknown_dacl_ace");
        }
    }
    PACL acl=nullptr;BOOL present=FALSE,defaulted=FALSE;
    if(!GetSecurityDescriptorSacl(const_cast<std::byte*>(security.bytes.data()),&present,&acl,&defaulted))
        return failure<std::array<NativeBytes,6>>(GetLastError(),"metadata_replay.coverage_sacl");
    std::array<NativeBytes,6> classes;
    if(!acl)return Result::available(std::move(classes));
    for(DWORD i=0;i<acl->AceCount;++i) {
        void* raw=nullptr;if(!GetAce(acl,i,&raw))return failure<std::array<NativeBytes,6>>(GetLastError(),"metadata_replay.coverage_ace");
        const auto* ace=static_cast<const ACE_HEADER*>(raw);std::size_t part=0;
        switch(ace->AceType) {
        case SYSTEM_AUDIT_ACE_TYPE:case SYSTEM_ALARM_ACE_TYPE:case SYSTEM_AUDIT_OBJECT_ACE_TYPE:case SYSTEM_ALARM_OBJECT_ACE_TYPE:
        case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
        case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:part=0;break;
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE:part=1;break;
        case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:part=2;break;
        case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:part=3;break;
        case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:part=4;break;
        case SYSTEM_ACCESS_FILTER_ACE_TYPE:part=5;break;
        default:return failure<std::array<NativeBytes,6>>(ERROR_NOT_SUPPORTED,"metadata_replay.coverage_unknown_sacl_ace");
        }
        const auto* bytes=static_cast<const std::byte*>(raw);classes[part].insert(classes[part].end(),bytes,bytes+ace->AceSize);
    }
    return Result::available(std::move(classes));
}
Observation<bool> require_enabled_security_privilege() {
    using Result=Observation<bool>;HANDLE raw=nullptr;
    if(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&raw)) {
        if(GetLastError()!=ERROR_NO_TOKEN||!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw))
            return failure<bool>(GetLastError(),"metadata_replay.coverage_effective_token");
    }
    OwnedHandle token(raw);DWORD size=0;GetTokenInformation(token.get(),TokenPrivileges,nullptr,0,&size);
    if(!size||GetLastError()!=ERROR_INSUFFICIENT_BUFFER)return failure<bool>(GetLastError(),"metadata_replay.coverage_privilege_size");
    NativeBytes bytes(size);
    if(!GetTokenInformation(token.get(),TokenPrivileges,bytes.data(),size,&size))return failure<bool>(GetLastError(),"metadata_replay.coverage_privileges");
    LUID security{};if(!LookupPrivilegeValueW(nullptr,L"SeSecurityPrivilege",&security))return failure<bool>(GetLastError(),"metadata_replay.coverage_security_luid");
    const auto* privileges=reinterpret_cast<const TOKEN_PRIVILEGES*>(bytes.data());
    for(DWORD i=0;i<privileges->PrivilegeCount;++i) {
        const auto& item=privileges->Privileges[i];
        if(item.Luid.LowPart==security.LowPart&&item.Luid.HighPart==security.HighPart&&(item.Attributes&SE_PRIVILEGE_ENABLED))
            return Result::available(true);
    }
    return failure<bool>(ERROR_PRIVILEGE_NOT_HELD,"metadata_replay.coverage_security_privilege_disabled");
}

class WindowsMetadataChannel final:public MetadataReplayChannelSource {
public:
    void retain_capture_lease(std::shared_ptr<const void> lease)const{capture_lease_=std::move(lease);}

    WindowsMetadataChannel(OwnedHandle handle,AdapterScope scope,NativeFeatureIdentifier identifier,ObjectIdentity owner,bool writable)
        :handle_(std::move(handle)),scope_(std::move(scope)),identifier_(std::move(identifier)),owner_(std::move(owner)),writable_(writable){}
    Observation<MetadataReplayChannelState> inspect() const override {
        using Result=Observation<MetadataReplayChannelState>;
        if(finished_)return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"metadata_channels.finished_inspection"});
        const auto current=identity(handle_.get(),scope_);
        if(!current.value()){const auto& e=*current.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(compare_identity(*current.value(),owner_)!=IdentityComparison::Same)return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_channels.owner_changed"});
        FILE_STANDARD_INFO standard{};
        if(!GetFileInformationByHandleEx(handle_.get(),FileStandardInfo,&standard,sizeof(standard)))
            return failure<MetadataReplayChannelState>(GetLastError(),"metadata_channels.FileStandardInfo");
        if(standard.DeletePending)return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_channels.delete_pending"});
        LARGE_INTEGER size{};FILE_BASIC_INFO attributes{};
        if(!GetFileSizeEx(handle_.get(),&size))return failure<MetadataReplayChannelState>(GetLastError(),"metadata_channels.GetFileSizeEx");
        if(!GetFileInformationByHandleEx(handle_.get(),FileBasicInfo,&attributes,sizeof(attributes)))
            return failure<MetadataReplayChannelState>(GetLastError(),"metadata_channels.FileBasicInfo");
        constexpr DWORD supported=FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|
            FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        if(size.QuadPart<0 || (attributes.FileAttributes&~supported))return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"metadata_channels.storage_provider"});
        return Result::available({identifier_,*current.value(),static_cast<std::uint64_t>(size.QuadPart)});
    }
    Observation<ContentRead> read_content(ContentReadLimits limits,std::uint64_t offset,std::stop_token stop={}) const override {
        using Result=Observation<ContentRead>;
        if(!limits.valid())return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidLimit),"metadata_channels.read_limit"});
        if(stop.stop_requested())return Result::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InterruptedRead),"metadata_channels.read_cancelled"});
        const auto before=inspect();if(!before.value()){const auto& e=*before.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(offset>before.value()->logical_size)return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_channels.read_offset"});
        LARGE_INTEGER at{};at.QuadPart=static_cast<LONGLONG>(offset);
        if(!SetFilePointerEx(handle_.get(),at,nullptr,FILE_BEGIN))return failure<ContentRead>(GetLastError(),"metadata_channels.read_seek");
        const auto count=static_cast<DWORD>(std::min<std::uint64_t>(limits.max_bytes,before.value()->logical_size-offset));
        std::vector<std::byte> bytes(count);DWORD copied=0;
        if(count&&!ReadFile(handle_.get(),bytes.data(),count,&copied,nullptr))return failure<ContentRead>(GetLastError(),"metadata_channels.ReadFile");
        bytes.resize(copied);const auto after=inspect();
        if(!after.value()){const auto& e=*after.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(after.value()->logical_size!=before.value()->logical_size)return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_channels.read_size_changed"});
        return Result::available({std::move(bytes),offset+copied>=before.value()->logical_size});
    }
    Observation<bool> truncate() {
        if(!writable_||finished_)return failure<bool>(ERROR_ACCESS_DENIED,"metadata_channels.truncate_access");
        FILE_END_OF_FILE_INFO size{};
        if(!SetFileInformationByHandle(handle_.get(),FileEndOfFileInfo,&size,sizeof(size)))
            return failure<bool>(GetLastError(),"metadata_channels.FileEndOfFileInfo");
        return Observation<bool>::available(true);
    }
    Observation<std::size_t> write(std::uint64_t offset,std::span<const std::byte> data) {
        if(!writable_||finished_)return failure<std::size_t>(ERROR_ACCESS_DENIED,"metadata_channels.write_access");
        if(offset>static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max())||data.size()>64*1024)
            return Observation<std::size_t>::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidLimit),"metadata_channels.write_limit"});
        LARGE_INTEGER at{};at.QuadPart=static_cast<LONGLONG>(offset);
        if(!SetFilePointerEx(handle_.get(),at,nullptr,FILE_BEGIN))return failure<std::size_t>(GetLastError(),"metadata_channels.write_seek");
        DWORD written=0;
        if(!WriteFile(handle_.get(),data.data(),static_cast<DWORD>(data.size()),&written,nullptr))
            return failure<std::size_t>(GetLastError(),"metadata_channels.WriteFile");
        return Observation<std::size_t>::available(written);
    }
    Observation<bool> flush() {
        if(!writable_||finished_)return failure<bool>(ERROR_ACCESS_DENIED,"metadata_channels.flush_access");
        if(!FlushFileBuffers(handle_.get()))return failure<bool>(GetLastError(),"metadata_channels.FlushFileBuffers");
        return Observation<bool>::available(true);
    }
    Observation<bool> finish() {
        using Result=Observation<bool>;
        if(!writer_finish_started_) {
            writer_finish_started_=true;
            if(!writable_||finished_)writer_finish_error_=MetadataCaptureCleanupError{ObservationState::Failed,
                ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"metadata_channels.finish_not_writer"};
            else {
                finished_=true;const HANDLE writer=handle_.release();
                const DWORD flush_error=FlushFileBuffers(writer)?ERROR_SUCCESS:GetLastError();
                const DWORD close_error=CloseHandle(writer)?ERROR_SUCCESS:GetLastError();
                if(flush_error)writer_finish_error_=MetadataCaptureCleanupError{error_state(flush_error),ErrorDomain::Win32,
                    flush_error,"metadata_channels.finish_FlushFileBuffers"};
                else if(close_error)writer_finish_error_=MetadataCaptureCleanupError{error_state(close_error),ErrorDomain::Win32,
                    close_error,"metadata_channels.finish_CloseHandle"};
            }
        }
        if(writer_finish_error_) {
            const auto& e=*writer_finish_error_;detail::record_metadata_capture_close(e);
            return Result::unavailable(e.state,{e.domain,e.code,e.operation});
        }
        return Result::available(true);
    }
    void finish_capture_reads()noexcept {
        if(capture_close_started_){if(capture_close_error_)detail::record_metadata_capture_close(*capture_close_error_);return;}
        capture_close_started_=true;
        if(writable_){capture_close_error_=MetadataCaptureCleanupError{ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"metadata_capture.writer_not_read_owner"};}
        else {finished_=true;const HANDLE h=handle_.release();if(h&&h!=INVALID_HANDLE_VALUE&&!CloseHandle(h)){const auto e=GetLastError();capture_close_error_=MetadataCaptureCleanupError{ObservationState::Failed,ErrorDomain::Win32,e,"metadata_capture.channel_CloseHandle"};report_capture_close(e,"metadata_capture.channel_CloseHandle");}}
        if(capture_close_error_)detail::record_metadata_capture_close(*capture_close_error_);
    }
    Observation<std::unique_ptr<WindowsMetadataChannel>> duplicate_capture_reader()const {
        using R=Observation<std::unique_ptr<WindowsMetadataChannel>>;
        if(writable_||finished_)return failure<std::unique_ptr<WindowsMetadataChannel>>(ERROR_INVALID_HANDLE,"target_read.channel_closed_or_writer");
        HANDLE raw=nullptr;
        if(!DuplicateHandle(GetCurrentProcess(),handle_.get(),GetCurrentProcess(),&raw,
            FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE,FALSE,0))
            return failure<std::unique_ptr<WindowsMetadataChannel>>(GetLastError(),"target_read.channel_duplicate");
        OwnedHandle owned(raw);
        return R::available(std::make_unique<WindowsMetadataChannel>(std::move(owned),scope_,identifier_,owner_,false));
    }
    const NativeFeatureIdentifier& identifier() const noexcept{return identifier_;}
    std::optional<MetadataCaptureCleanupError> capture_close_error()const noexcept{return capture_close_error_;}
    std::optional<MetadataCaptureCleanupError> writer_finish_error()const noexcept{return writer_finish_error_;}
private:
    bool writer_finish_started_=false;
    std::optional<MetadataCaptureCleanupError> writer_finish_error_;
    bool capture_close_started_=false;
    std::optional<MetadataCaptureCleanupError> capture_close_error_;
    mutable std::shared_ptr<const void> capture_lease_;

    OwnedHandle handle_;
    AdapterScope scope_;
    NativeFeatureIdentifier identifier_;
    ObjectIdentity owner_;
    bool writable_=false;
    bool finished_=false;
};

struct WindowsTargetReadManifest final {
    MetadataReplayPolicy policy;
    std::vector<std::shared_ptr<WindowsMetadataChannel>> readers;
    std::shared_ptr<detail::NativeTargetReadBudget> budget;
};
class WindowsTargetReadSeed;
class WindowsOpenedEntry final : public OpenedEntry {
public:
    WindowsOpenedEntry(OwnedHandle handle, AdapterScope scope, bool layout_access = false,
                       bool content_access = false, bool content_write_access = false,
                       std::unique_ptr<WindowsPublicationContext> publication = {}, bool rename_access = false, bool directory_metadata_target = false)
        : handle_(std::move(handle)), scope_(std::move(scope)), layout_access_(layout_access),
          content_access_(content_access), content_write_access_(content_write_access),
          rename_access_(rename_access), publication_(std::move(publication)), directory_metadata_target_(directory_metadata_target) {}
    Observation<ContentRead> read_content(ContentReadLimits limits = {}, std::uint64_t offset = 0,
                                          std::stop_token stop = {}) const override {
        using Result = Observation<ContentRead>;
        if (!limits.valid())
            return Result::unavailable(ObservationState::Failed,
                                       {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "content.limits"});
        if (stop.stop_requested())
            return Result::unavailable(ObservationState::Unknown,
                                       {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InterruptedRead), "content.cancelled"});
        if (!content_access_)
            return Result::unavailable(ObservationState::Denied,
                                       {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidAccess), "content.access_not_requested"});
        const auto before = inspect_basic();
        if (!before.value()) { const auto &e = *before.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (!before.value()->kind.value() || *before.value()->kind.value() != ObjectKind::RegularFile)
            return Result::unavailable(ObservationState::Unsupported,
                                       {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "content.object_kind"});
        if (!before.value()->logical_size.value()) { const auto &e = *before.value()->logical_size.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto size = *before.value()->logical_size.value();
        if (offset > size || offset > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max()))
            return Result::unavailable(ObservationState::Changed,
                                       {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "content.offset"});
        const auto count = static_cast<DWORD>(std::min<std::uint64_t>(limits.max_bytes, size - offset));
        std::vector<std::byte> bytes(count);
        DWORD copied = 0;
        if (rename_access_) {
            auto read=read_guarded(bytes,offset,stop);
            if (!read.value()) {const auto& e=*read.unavailable_detail();return Result::unavailable(e.state,e.error);}
            copied=*read.value();
        } else {
            LARGE_INTEGER position{}; position.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(handle_.get(), position, nullptr, FILE_BEGIN))
                return failure<ContentRead>(GetLastError(), "content.seek");
            if (count && !ReadFile(handle_.get(), bytes.data(), count, &copied, nullptr))
                return failure<ContentRead>(GetLastError(), "content.ReadFile");
        }
        bytes.resize(copied);
        if (stop.stop_requested())
            return Result::unavailable(ObservationState::Unknown,
                                       {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InterruptedRead), "content.cancelled"});
        const auto after = inspect_basic();
        if (!after.value()) { const auto &e = *after.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (!after.value()->identity.value() || !before.value()->identity.value() ||
            compare_identity(*before.value()->identity.value(), *after.value()->identity.value()) != IdentityComparison::Same ||
            !after.value()->logical_size.value() || *after.value()->logical_size.value() != size)
            return Result::unavailable(ObservationState::Changed,
                                       {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "content.identity"});
        return Result::available({std::move(bytes), offset + copied >= size});
    }
    Observation<std::size_t> write_content(std::uint64_t offset, std::span<const std::byte> bytes,
                                            ContentWriteLimits limits = {}, std::stop_token stop = {}) override {
        using Result = Observation<std::size_t>;
        if (!limits.valid() || bytes.size() > limits.max_bytes)
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "content.write_limits"});
        if (stop.stop_requested())
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InterruptedRead), "content.write_cancelled"});
        if (!content_write_access_)
            return Result::unavailable(ObservationState::Denied,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidAccess), "content.write_access_not_requested"});
        const auto before = inspect_basic();
        if (!before.value()) { const auto& e = *before.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (!before.value()->kind.value() || *before.value()->kind.value() != ObjectKind::RegularFile)
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "content.write_object_kind"});
        constexpr auto maximum = static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max());
        if (offset > maximum || bytes.size() > maximum - offset)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "content.write_offset"});
        LARGE_INTEGER position{}; position.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(handle_.get(), position, nullptr, FILE_BEGIN))
            return failure<std::size_t>(GetLastError(), "content.write_seek");
        DWORD written = 0;
        if (!WriteFile(handle_.get(), bytes.data(), static_cast<DWORD>(std::min(bytes.size(), static_cast<std::size_t>(MAXDWORD))), &written, nullptr))
            return failure<std::size_t>(GetLastError(), "content.WriteFile");
        if (stop.stop_requested())
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InterruptedRead), "content.write_cancelled"});
        const auto after = inspect_basic();
        if (!after.value()) { const auto& e = *after.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (!after.value()->identity.value() || !before.value()->identity.value() ||
            compare_identity(*before.value()->identity.value(), *after.value()->identity.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "content.write_identity"});
        return Result::available(static_cast<std::size_t>(written));
    }
    Observation<bool> flush_content() override {
        if (!content_write_access_)
            return Observation<bool>::unavailable(ObservationState::Denied,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidAccess), "content.flush_access"});
        if (!FlushFileBuffers(handle_.get())) return failure<bool>(GetLastError(), "content.FlushFileBuffers");
        return Observation<bool>::available(true);
    }
    Observation<bool> finish_content_writes() override {
        using Result=Observation<bool>;
        if (finish_result_) return *finish_result_;
        if (finish_started_) return failure<bool>(ERROR_INVALID_HANDLE,"content.finish_result_unrecorded");
        if (!content_write_access_) return Result::available(true);
        finish_started_=true;
        content_write_access_=false;
        content_access_=false;
        layout_access_=false;
        rename_access_=false;
        std::optional<Observation<bool>> channel_error;bool channel_exception=false;
        for(auto& channel:channel_writers_) {
            try {auto result=channel->finish();if((!result.value()||!*result.value())&&!channel_error)channel_error=std::move(result);}
            catch(...){channel_exception=true;}
        }
        channel_writers_.clear();
        // Close the independent metadata-mutating handle before flushing the
        // data writer. Consume both owners first so destructors cannot retry.
        const HANDLE security=security_handle_.release();
        const HANDLE writer=handle_.release();
        const DWORD security_error=!security || security==INVALID_HANDLE_VALUE || CloseHandle(security) ? ERROR_SUCCESS : GetLastError();
        const DWORD flush_error=FlushFileBuffers(writer) ? ERROR_SUCCESS : GetLastError();
        const DWORD close_error=CloseHandle(writer) ? ERROR_SUCCESS : GetLastError();
        if(channel_error)finish_result_=std::move(*channel_error);
        else if(channel_exception)finish_result_=Observation<bool>::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"content.finish_channel_exception"});
        else if (security_error) finish_result_=failure<bool>(security_error,"content.finish_security_close");
        else if (flush_error) finish_result_=failure<bool>(flush_error,"content.finish_FlushFileBuffers");
        else if (close_error) finish_result_=failure<bool>(close_error,"content.finish_CloseHandle");
        else finish_result_=Result::available(true);
        return *finish_result_;
    }
    void finish_capture_reads()noexcept {
        if(capture_close_started_){if(capture_close_error_)detail::record_metadata_capture_close(*capture_close_error_);return;}
        capture_close_started_=true;
        if(content_write_access_){capture_close_error_=MetadataCaptureCleanupError{ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"metadata_capture.writer_not_read_owner"};}
        else {
            finish_started_=true;content_access_=false;layout_access_=false;
            const HANDLE security=security_handle_.release(),data=handle_.release();
            for(const HANDLE h:{security,data})if(h&&h!=INVALID_HANDLE_VALUE&&!CloseHandle(h)){
                const MetadataCaptureCleanupError e{ObservationState::Failed,ErrorDomain::Win32,GetLastError(),"metadata_capture.source_CloseHandle"};
                if(!capture_close_error_)capture_close_error_=e;report_capture_close(static_cast<DWORD>(e.code),e.operation);
            }
        }
        target_read_manifest_.reset();
        if(capture_close_error_)detail::record_metadata_capture_close(*capture_close_error_);
    }
    // Content-only observation: no security/EA rights or metadata qualification.
    // OpenFileById is checked against this held object's identity before adoption.
    Observation<std::shared_ptr<const OpenedEntry>> open_main_content_source()const {
        using R=Observation<std::shared_ptr<const OpenedEntry>>;
        if(content_write_access_||!content_access_)return failure<std::shared_ptr<const OpenedEntry>>(
            ERROR_ACCESS_DENIED,"main_content.readonly_content_source_required");
        auto h=metadata_security_handle(FILE_READ_DATA|FILE_READ_ATTRIBUTES);
        if(!h.value()){const auto&e=*h.unavailable_detail();return R::unavailable(e.state,e.error);}
        return R::available(std::make_shared<WindowsOpenedEntry>(std::move(h).take_value(),scope_,false,true));
    }
    Observation<std::shared_ptr<const OpenedEntry>> open_progressive_metadata_source(const MetadataReplayPolicy& policy)const {
        using Result=Observation<std::shared_ptr<const OpenedEntry>>;
        if(target_read_manifest_) {
            const auto& bound=target_read_manifest_->policy;
            if(finish_started_||policy.version!=bound.version||policy.scope!=bound.scope||policy.ownership!=bound.ownership||
               policy.allow_privilege_metadata!=bound.allow_privilege_metadata||policy.limits.max_records!=bound.limits.max_records||
               policy.limits.max_native_bytes!=bound.limits.max_native_bytes)
                return failure<std::shared_ptr<const OpenedEntry>>(ERROR_INVALID_PARAMETER,"target_read.closed_or_policy_changed");
            HANDLE raw=nullptr;
            if(!DuplicateHandle(GetCurrentProcess(),handle_.get(),GetCurrentProcess(),&raw,0,FALSE,DUPLICATE_SAME_ACCESS))
                return failure<std::shared_ptr<const OpenedEntry>>(GetLastError(),"target_read.source_duplicate");
            OwnedHandle owned(raw);auto clone=std::make_shared<WindowsOpenedEntry>(std::move(owned),scope_,false,content_access_);
            clone->target_read_manifest_=target_read_manifest_;
            return Result::available(std::move(clone));
        }
        if(content_write_access_)return failure<std::shared_ptr<const OpenedEntry>>(ERROR_ACCESS_DENIED,"metadata_capture.readonly_source_required");
        const auto qualified=qualify_metadata_replay(policy);if(!qualified.value()){const auto&e=*qualified.unavailable_detail();return Result::unavailable(e.state,e.error);}if(!*qualified.value())return failure<std::shared_ptr<const OpenedEntry>>(ERROR_NOT_SUPPORTED,"metadata_capture.provider_false");
        const auto basic=inspect_basic();if(!basic.value()){const auto&e=*basic.unavailable_detail();return Result::unavailable(e.state,e.error);}
        const bool file=basic.value()->kind.value()&&*basic.value()->kind.value()==ObjectKind::RegularFile;
        const DWORD rights=FILE_READ_ATTRIBUTES|FILE_READ_EA|READ_CONTROL|(file?FILE_READ_DATA:0)|
            (policy.scope==RegularMetadataScope::CompleteMetadataV1?ACCESS_SYSTEM_SECURITY:0);
        auto h=metadata_security_handle(rights);if(!h.value()){const auto&e=*h.unavailable_detail();return Result::unavailable(e.state,e.error);}
        return Result::available(std::make_shared<WindowsOpenedEntry>(std::move(h).take_value(),scope_,false,file));
    }
    Observation<std::unique_ptr<OpenedEntry>> open_metadata_replay_view(const MetadataReplayPolicy& policy) const override {
        using Result=Observation<std::unique_ptr<OpenedEntry>>;
        if (!policy.valid()) return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidIdentifier),"metadata_replay.query_policy"});
        const DWORD rights=FILE_READ_EA|READ_CONTROL|
            (policy.scope==RegularMetadataScope::CompleteMetadataV1 ? ACCESS_SYSTEM_SECURITY : 0);
        auto opened=metadata_security_handle(rights);
        if (!opened.value()) {const auto& e=*opened.unavailable_detail();return Result::unavailable(e.state,e.error);}
        // The original handle remains alive. OpenFileById verifies this query
        // handle against its retained identity; no source basename is reopened.
        return Result::available(std::make_unique<WindowsOpenedEntry>(std::move(opened).take_value(),scope_));
    }
    Observation<std::unique_ptr<OpenedEntry>> open_directory_metadata_target(const MetadataReplayPolicy& policy) const override {
        using Result=Observation<std::unique_ptr<OpenedEntry>>;
        if(!policy.valid())return failure<std::unique_ptr<OpenedEntry>>(ERROR_INVALID_PARAMETER,"metadata_replay.directory_policy");
        const auto before=inspect_basic();
        if(!before.value()){const auto& e=*before.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(!before.value()->kind.value()||*before.value()->kind.value()!=ObjectKind::Directory)
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::NotApplicable),"metadata_replay.directory_kind"});
        const DWORD rights=FILE_GENERIC_READ|FILE_GENERIC_WRITE|READ_CONTROL|WRITE_DAC|WRITE_OWNER|
            (policy.scope==RegularMetadataScope::CompleteMetadataV1?ACCESS_SYSTEM_SECURITY:0);
        auto opened=metadata_security_handle(rights);
        if(!opened.value()){const auto& e=*opened.unavailable_detail();return Result::unavailable(e.state,e.error);}
        auto writer=std::make_unique<WindowsOpenedEntry>(std::move(opened).take_value(),scope_,false,false,true,nullptr,false,true);
        const auto qualified=writer->qualify_metadata_replay(policy);
        if(!qualified.value()){const auto& e=*qualified.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(!*qualified.value())return failure<std::unique_ptr<OpenedEntry>>(ERROR_NOT_SUPPORTED,"metadata_replay.directory_qualification_false");
        return Result::available(std::move(writer));
    }
    Observation<std::shared_ptr<const MetadataSecurityCoverageEvidence>> issue_metadata_security_coverage(
        const MetadataReplaySnapshot&) const override;
    Observation<bool> preflight_metadata_security_coverage(const MetadataReplaySnapshot&) override;
    Observation<bool> verify_metadata_security_coverage(const MetadataReplaySnapshot&) const override;
    Observation<bool> qualify_stable_content() const override {
        using Result=Observation<bool>;
        const auto unsupported=[](const char* op){return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),op});};
        // This proof is restricted to the main data stream of RenameSource.
        // MoveSource still has no metadata freeze or source-retirement proof.
        if (!rename_access_ || !content_access_) return unsupported("stable_content.rename_read_guard_required");
        if (content_lease_) return content_lease_->check();
        const auto basic=inspect_basic();
        if (!basic.value()) {const auto& e=*basic.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if (!basic.value()->kind.value() || *basic.value()->kind.value()!=ObjectKind::RegularFile ||
            !basic.value()->link_count.value() || *basic.value()->link_count.value()!=1 ||
            !basic.value()->identity.value() || basic.value()->identity.value()->scheme!=IdentityScheme::WindowsFileId128)
            return unsupported("stable_content.regular_single_identity");
        if (const auto provider=provider_guard(*basic.value())) return Result::unavailable(provider->state,provider->error);
        auto provider_view=metadata_security_handle(0);
        if(!provider_view.value()){const auto& e=*provider_view.unavailable_detail();return Result::unavailable(e.state,e.error);}
        WCHAR filesystem[32]{};
        if (!GetVolumeInformationByHandleW(provider_view.value()->get(),nullptr,0,nullptr,nullptr,nullptr,filesystem,32))
            return failure<bool>(GetLastError(),"stable_content.volume");
        if (std::wstring_view(filesystem)!=L"NTFS" && std::wstring_view(filesystem)!=L"ReFS")
            return unsupported("stable_content.filesystem");
        const auto native_driver=detail::prove_windows_native_fsd(provider_view.value()->get());
        if(!native_driver.qualified)return Result::unavailable(native_driver.state,
            {native_driver.domain,native_driver.code,native_driver.operation});
        using QueryVolume=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
        const auto address=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryVolumeInformationFile");
        if (!address) return unsupported("stable_content.device_query");
        struct Device {ULONG type,characteristics;} device{};IO_STATUS_BLOCK io{};
        const auto status=std::bit_cast<QueryVolume>(address)(provider_view.value()->get(),&io,&device,sizeof(device),4);
        if (status!=0) return Result::unavailable(error_state(RtlNtStatusToDosError(status)),
            {ErrorDomain::NtStatus,static_cast<std::uint32_t>(status),"stable_content.device"});
        if (io.Information!=sizeof(device) || (device.characteristics&0x10U)) return unsupported("stable_content.remote_provider");
        auto lease=std::make_unique<WindowsContentLease>(handle_.get());
        const auto granted=lease->acquire();
        if (!granted.value() || !*granted.value()) return granted;
        content_lease_=std::move(lease);
        return content_lease_->check();
    }
    Observation<bool> qualify_metadata_replay(const MetadataReplayPolicy& policy) const override {
        using Result=Observation<bool>;
        if (rename_access_) {
            auto view=synchronous_query_view(0);
            if(!view.value()){const auto& e=*view.unavailable_detail();return Result::unavailable(e.state,e.error);}
            return (*view.value())->qualify_metadata_replay(policy);
        }
        const auto refuse=[](const char* op){return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),op});};
        if (!policy.valid()) return refuse("metadata_replay.policy");
        const auto basic=inspect_basic();
        if (!basic.value()) {const auto& e=*basic.unavailable_detail();return Result::unavailable(e.state,e.error);}
        const bool directory=basic.value()->kind.value()&&*basic.value()->kind.value()==ObjectKind::Directory;
        if (!basic.value()->kind.value() || (!directory&&*basic.value()->kind.value()!=ObjectKind::RegularFile) ||
            !basic.value()->link_count.value() || ((directory||!content_write_access_)?*basic.value()->link_count.value()<1:*basic.value()->link_count.value()!=1) || !basic.value()->windows_attributes.value())
            return refuse("metadata_replay.windows_kind_links");
        if (const auto guard=provider_guard(*basic.value())) return Result::unavailable(guard->state,guard->error);
        // Full directory preservation has no case-flag replay field yet.
        // Only the explicitly queried zero state is covered; a volume search
        // flag never proves the namespace policy of this held directory.
        if(directory&&policy.scope==RegularMetadataScope::CompleteMetadataV1) {
            FILE_CASE_SENSITIVE_INFO case_info{};
            if(!GetFileInformationByHandleEx(handle_.get(),FileCaseSensitiveInfo,&case_info,sizeof(case_info)))
                return Result::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Win32,GetLastError(),"metadata_replay.directory_case_query_unqualified"});
            if(case_info.Flags!=0)return refuse("metadata_replay.directory_case_flags_unimplemented");
        }
        const DWORD supported=(directory?FILE_ATTRIBUTE_DIRECTORY:0)|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|
            FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
        if ((*basic.value()->windows_attributes.value() & ~supported)!=0)
            return refuse("metadata_replay.windows_storage_provider");
        DWORD flags=0;WCHAR filesystem[32]{};
        if (!GetVolumeInformationByHandleW(handle_.get(),nullptr,0,nullptr,nullptr,&flags,filesystem,32))
            return failure<bool>(GetLastError(),"metadata_replay.GetVolumeInformationByHandleW");
        if ((std::wstring_view(filesystem)!=L"NTFS" && std::wstring_view(filesystem)!=L"ReFS") || (flags&FILE_PERSISTENT_ACLS)==0)
            return refuse("metadata_replay.windows_unaudited_filesystem");
        const auto native_driver=detail::prove_windows_native_fsd(handle_.get());
        if(!native_driver.qualified)return Result::unavailable(native_driver.state,
            {native_driver.domain,native_driver.code,native_driver.operation});
        using QueryVolume=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
        const auto query_address=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryVolumeInformationFile");
        if (!query_address) return refuse("metadata_replay.windows_device_query");
        struct DeviceInformation {ULONG type,characteristics;} device{};IO_STATUS_BLOCK io{};
        const auto status=std::bit_cast<QueryVolume>(query_address)(handle_.get(),&io,&device,sizeof(device),4);
        if (status!=0) return Result::unavailable(error_state(RtlNtStatusToDosError(status)),
            {ErrorDomain::NtStatus,static_cast<std::uint32_t>(status),"metadata_replay.windows_device"});
        if (io.Information!=sizeof(device) || (device.characteristics&0x10U)!=0)
            return refuse("metadata_replay.windows_remote_provider_unqualified");
        const auto channels=inspect_data_channels(policy.limits);
        if (!channels.value()) {const auto& e=*channels.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if (channels.value()->coverage!=DataChannelCoverage::WindowsFileStreamInfo)
            return refuse("metadata_replay.windows_stream_coverage");
        if(!channels.value()->owner.value()||!basic.value()->identity.value()||
           compare_identity(*channels.value()->owner.value(),*basic.value()->identity.value())!=IdentityComparison::Same||
           std::count_if(channels.value()->channels.begin(),channels.value()->channels.end(),[](const auto& item){return item.kind==DataChannelKind::MainData;})!=(directory?0:1))
            return refuse("metadata_replay.windows_stream_owner_set");
        for (const auto& channel:channels.value()->channels)
            if (channel.kind!=DataChannelKind::MainData&&channel.kind!=DataChannelKind::NamedData) return refuse("metadata_replay.windows_opaque_stream_unimplemented");
        if (policy.scope==RegularMetadataScope::CompleteMetadataV1 && !policy.allow_privilege_metadata)
            return refuse("metadata_replay.full_windows_security_requires_optin");
        return Result::available(true);
    }
    Observation<bool> apply_replay_ownership(const BasicMetadata&, const MetadataReplayPolicy& policy) override {
        using Result=Observation<bool>;
        if (!policy.valid() || !content_write_access_ || (!publication_&&!directory_metadata_target_))
            return failure<bool>(ERROR_ACCESS_DENIED,"metadata_replay.staging_ownership");
        if (policy.ownership==MetadataOwnership::Original) return Result::available(true); // descriptor phase sets original SIDs
        HANDLE raw=nullptr;
        if (!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&raw)) {
            if (GetLastError()!=ERROR_NO_TOKEN || !OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw))
                return failure<bool>(GetLastError(),"metadata_replay.caller_token");
        }
        OwnedHandle token(raw);
        const auto query=[&](TOKEN_INFORMATION_CLASS info)->Observation<NativeBytes> {
            DWORD size=0;GetTokenInformation(token.get(),info,nullptr,0,&size);
            if (!size || GetLastError()!=ERROR_INSUFFICIENT_BUFFER) return failure<NativeBytes>(GetLastError(),"metadata_replay.token_size");
            NativeBytes data(size);
            if (!GetTokenInformation(token.get(),info,data.data(),size,&size)) return failure<NativeBytes>(GetLastError(),"metadata_replay.token_query");
            return Observation<NativeBytes>::available(std::move(data));
        };
        const auto owner=query(TokenOwner),group=query(TokenPrimaryGroup);
        if (!owner.value() || !group.value()) {const auto& e=*(owner.value()?group:owner).unavailable_detail();return Result::unavailable(e.state,e.error);}
        auto opened=ensure_metadata_security_handle(WRITE_OWNER|READ_CONTROL);
        if (!opened.value()) {const auto& e=*opened.unavailable_detail();return Result::unavailable(e.state,e.error);}
        const auto code=SetSecurityInfo(*opened.value(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION,
            reinterpret_cast<const TOKEN_OWNER*>(owner.value()->data())->Owner,
            reinterpret_cast<const TOKEN_PRIMARY_GROUP*>(group.value()->data())->PrimaryGroup,nullptr,nullptr);
        if (code!=ERROR_SUCCESS) return failure<bool>(code,"metadata_replay.caller_SetSecurityInfo");
        const auto captured=read_security(SecurityPart::WindowsAccess,policy.limits);
        if (!captured.value()) {const auto& e=*captured.unavailable_detail();return Result::unavailable(e.state,e.error);}
        caller_security_=*captured.value();
        return Result::available(true);
    }
    Observation<bool> apply_replay_attribute(const AttributeValue& value, const MetadataReplayPolicy& policy) override {
        if (!policy.valid() || (!publication_&&!directory_metadata_target_)) return failure<bool>(ERROR_ACCESS_DENIED,"metadata_replay.staging_attribute");
        // Windows zero-sized EAs encode deletion, not a present empty value.
        if (value.bytes.empty()) return Observation<bool>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::UnsupportedQuery),"metadata_replay.empty_windows_ea"});
        return apply_nonsecurity_attribute(value);
    }
    Observation<bool> remove_replay_attribute(const NativeFeatureIdentifier& id, const MetadataReplayPolicy& policy) override {
        if (!policy.valid() || (!publication_&&!directory_metadata_target_)) return failure<bool>(ERROR_ACCESS_DENIED,"metadata_replay.staging_remove_attribute");
        const auto basic=inspect_basic();
        if (!basic.value()) {const auto& e=*basic.unavailable_detail();return Observation<bool>::unavailable(e.state,e.error);}
        return apply_nonsecurity_attribute({id,{},basic.value()->identity,Observation<std::uint32_t>::available(0)});
    }
    Observation<bool> apply_replay_basic(const BasicMetadata& value, const MetadataReplayPolicy& policy) override {
        if (!policy.valid() || (!publication_&&!directory_metadata_target_)) return failure<bool>(ERROR_ACCESS_DENIED,"metadata_replay.staging_basic");
        return apply_portable_basic_metadata(value);
    }
    Observation<bool> apply_replay_security(const NativeSecurityValue& source, const MetadataReplayPolicy& policy) override {
        using Result=Observation<bool>;
        if (!policy.valid() || !content_write_access_ || (!publication_&&!directory_metadata_target_) || source.encoding!=SecurityEncoding::WindowsRelativeDescriptor ||
            source.presence!=SecurityPresence::Present || !source.owner.value())
            return failure<bool>(ERROR_ACCESS_DENIED,"metadata_replay.staging_security");
        const auto checked=detail::validate_windows_descriptor(source.bytes,policy.limits);
        if (!checked.value()) {const auto& e=*checked.unavailable_detail();return Result::unavailable(e.state,e.error);}
        SECURITY_INFORMATION mask=0;DWORD rights=READ_CONTROL;
        switch(source.part) {
        case SecurityPart::WindowsAccess:
            mask=DACL_SECURITY_INFORMATION;rights|=WRITE_DAC;
            if (policy.ownership==MetadataOwnership::Original) {mask|=OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION;rights|=WRITE_OWNER;}
            break;
        case SecurityPart::WindowsIntegrity:
            // Even an opted-in write can change an implicit/absent label into
            // a present null SACL. Preserve the exact already-matching native
            // state without issuing a mutation. A query failure is not a
            // reason to attempt a less-informed security write.
            {
                auto unchanged=verify_replay_security(source,policy);
                if (unchanged.value() || unchanged.state()!=ObservationState::Changed || !policy.allow_privilege_metadata)
                    return unchanged;
            }
            mask=LABEL_SECURITY_INFORMATION;rights|=WRITE_OWNER;break;
        case SecurityPart::WindowsFullDescriptor:
            if (!policy.allow_privilege_metadata) return failure<bool>(ERROR_ACCESS_DENIED,"metadata_replay.full_security_optin");
            mask=DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION|
                LABEL_SECURITY_INFORMATION|ATTRIBUTE_SECURITY_INFORMATION|SCOPE_SECURITY_INFORMATION|
                PROCESS_TRUST_LABEL_SECURITY_INFORMATION|ACCESS_FILTER_SECURITY_INFORMATION;
            rights|=WRITE_DAC|WRITE_OWNER|ACCESS_SYSTEM_SECURITY;
            if (policy.ownership==MetadataOwnership::Original) mask|=OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION;
            break;
        default:return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::NotApplicable),"metadata_replay.security_model"});
        }
        auto* descriptor=const_cast<std::byte*>(source.bytes.data());
        PSID owner=nullptr,group=nullptr;PACL dacl=nullptr,sacl=nullptr;BOOL present=FALSE,defaulted=FALSE;
        SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;
        if (!GetSecurityDescriptorControl(descriptor,&control,&revision) ||
            !GetSecurityDescriptorOwner(descriptor,&owner,&defaulted) || !GetSecurityDescriptorGroup(descriptor,&group,&defaulted) ||
            !GetSecurityDescriptorDacl(descriptor,&present,&dacl,&defaulted) || !GetSecurityDescriptorSacl(descriptor,&present,&sacl,&defaulted))
            return failure<bool>(GetLastError(),"metadata_replay.descriptor_fields");
        if(source.part==SecurityPart::WindowsFullDescriptor) {
            // Do not materialize a present-null SACL when the complete queried
            // SACL is already identical. All classes are still queried/verified.
            const auto current=read_security(SecurityPart::WindowsFullDescriptor,policy.limits);
            if(!current.value()){const auto& e=*current.unavailable_detail();return Result::unavailable(e.state,e.error);}
            PACL other=nullptr;BOOL other_present=FALSE,other_defaulted=FALSE;
            BOOL source_present=FALSE,source_defaulted=FALSE;PACL source_acl=nullptr;
            SECURITY_DESCRIPTOR_CONTROL other_control=0;DWORD other_revision=0;
            auto* other_descriptor=const_cast<std::byte*>(current.value()->bytes.data());
            if(!GetSecurityDescriptorSacl(descriptor,&source_present,&source_acl,&source_defaulted)||
               !GetSecurityDescriptorSacl(other_descriptor,&other_present,&other,&other_defaulted)||
               !GetSecurityDescriptorControl(other_descriptor,&other_control,&other_revision))
                return failure<bool>(GetLastError(),"metadata_replay.full_sacl_query");
            constexpr auto sacl_control=SE_SACL_PROTECTED|SE_SACL_AUTO_INHERITED|SE_SACL_AUTO_INHERIT_REQ;
            const auto desired_classes=persistent_sacl_classes(source),actual_classes=persistent_sacl_classes(*current.value());
            if(!desired_classes.value()||!actual_classes.value()){const auto& e=*(desired_classes.value()?actual_classes:desired_classes).unavailable_detail();return Result::unavailable(e.state,e.error);}
            constexpr SECURITY_INFORMATION class_masks[]{SACL_SECURITY_INFORMATION,LABEL_SECURITY_INFORMATION,
                ATTRIBUTE_SECURITY_INFORMATION,SCOPE_SECURITY_INFORMATION,PROCESS_TRUST_LABEL_SECURITY_INFORMATION,ACCESS_FILTER_SECURITY_INFORMATION};
            mask&=~persistent_sacl_information;
            for(std::size_t index=0;index<6;++index)
                if((*desired_classes.value())[index]!=(*actual_classes.value())[index])mask|=class_masks[index];
            if(source_present!=other_present||source_defaulted!=other_defaulted||(!source_acl!=!other)||
               (source_acl&&other&&(source_acl->AclRevision!=other->AclRevision||source_acl->AclSize!=other->AclSize))||
               (control&sacl_control)!=(other_control&sacl_control))mask|=SACL_SECURITY_INFORMATION;
        }
        if (mask&DACL_SECURITY_INFORMATION) mask|=(control&SE_DACL_PROTECTED)?PROTECTED_DACL_SECURITY_INFORMATION:UNPROTECTED_DACL_SECURITY_INFORMATION;
        if (mask&SACL_SECURITY_INFORMATION) mask|=(control&SE_SACL_PROTECTED)?PROTECTED_SACL_SECURITY_INFORMATION:UNPROTECTED_SACL_SECURITY_INFORMATION;
        // Native assignment consumes AUTO_INHERIT_REQ while preserving the
        // corresponding stored AUTO_INHERITED bit. Supplying only the stored
        // bit clears it (0x8404 -> 0x8004) even when every ACE byte matches.
        // This changes only our request copy; verification retains the exact
        // captured control word and avoids parent ACL recalculation.
        SECURITY_DESCRIPTOR_CONTROL inheritance_requests=0;
        if((mask&DACL_SECURITY_INFORMATION)&&(control&SE_DACL_AUTO_INHERITED))
            inheritance_requests|=SE_DACL_AUTO_INHERIT_REQ;
        if((mask&SACL_SECURITY_INFORMATION)&&(control&SE_SACL_AUTO_INHERITED))
            inheritance_requests|=SE_SACL_AUTO_INHERIT_REQ;
        NativeBytes requested;
        if(inheritance_requests) {
            requested=source.bytes;
            if(!SetSecurityDescriptorControl(requested.data(),inheritance_requests,inheritance_requests))
                return failure<bool>(GetLastError(),"metadata_replay.inheritance_request");
            descriptor=requested.data();
        }
        auto opened=ensure_metadata_security_handle(rights);
        if (!opened.value()) {const auto& e=*opened.unavailable_detail();return Result::unavailable(e.state,e.error);}
        // SetSecurityInfo reapplies parent inheritance, which can add ACEs
        // to this already inventoried ACL. Replay the validated descriptor on
        // the exact held staging object using the native security boundary.
        using SetSecurity=NTSTATUS(NTAPI*)(HANDLE,SECURITY_INFORMATION,PSECURITY_DESCRIPTOR);
        const auto address=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetSecurityObject");
        if (!address) return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::UnsupportedQuery),"metadata_replay.NtSetSecurityObject.resolve"});
        const auto status=std::bit_cast<SetSecurity>(address)(*opened.value(),mask,descriptor);
        if (status!=0) return Result::unavailable(error_state(RtlNtStatusToDosError(status)),
            {ErrorDomain::NtStatus,static_cast<std::uint32_t>(status),"metadata_replay.NtSetSecurityObject"});
        return verify_replay_security(source,policy);
    }
    Observation<bool> verify_replay_security(const NativeSecurityValue& source, const MetadataReplayPolicy& policy) const override {
        using Result=Observation<bool>;
        auto actual=read_security(source.part,policy.limits);
        if (!actual.value()) {const auto& e=*actual.unavailable_detail();return Result::unavailable(e.state,e.error);}
        const auto mismatch=[](const char* operation) {return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),operation});};
        auto* a=const_cast<std::byte*>(source.bytes.data());auto* b=const_cast<std::byte*>(actual.value()->bytes.data());
        if (!detail::validate_windows_descriptor(source.bytes,policy.limits).value() || source.part!=actual.value()->part ||
            source.native_query_mask!=actual.value()->native_query_mask) return mismatch("metadata_replay.windows_security_structure");
        const auto same_sid=[](PSECURITY_DESCRIPTOR x,PSECURITY_DESCRIPTOR y,bool owner) {
            PSID xs=nullptr,ys=nullptr;BOOL xd=FALSE,yd=FALSE;
            const auto ok=owner?(GetSecurityDescriptorOwner(x,&xs,&xd)&&GetSecurityDescriptorOwner(y,&ys,&yd)):
                (GetSecurityDescriptorGroup(x,&xs,&xd)&&GetSecurityDescriptorGroup(y,&ys,&yd));
            return ok && xd==yd && ((!xs&&!ys)||(xs&&ys&&EqualSid(xs,ys)));
        };
        const auto acl_mismatch=[](PSECURITY_DESCRIPTOR x,PSECURITY_DESCRIPTOR y,bool dacl)->const char* {
            PACL xs=nullptr,ys=nullptr;BOOL xp=FALSE,yp=FALSE,xd=FALSE,yd=FALSE;
            const auto ok=dacl?(GetSecurityDescriptorDacl(x,&xp,&xs,&xd)&&GetSecurityDescriptorDacl(y,&yp,&ys,&yd)):
                (GetSecurityDescriptorSacl(x,&xp,&xs,&xd)&&GetSecurityDescriptorSacl(y,&yp,&ys,&yd));
            if (!ok) return "metadata_replay.windows_acl_query";
            if (xp!=yp) return "metadata_replay.windows_acl_presence";
            if (xd!=yd) return "metadata_replay.windows_acl_defaulted";
            if (!xs!=!ys) return "metadata_replay.windows_acl_nullness";
            if (!xs) return nullptr;
            if (xs->AclRevision!=ys->AclRevision) return "metadata_replay.windows_acl_revision";
            if (xs->AceCount!=ys->AceCount) return "metadata_replay.windows_acl_count";
            if (xs->AclSize!=ys->AclSize) return "metadata_replay.windows_acl_allocation_size";
            return std::memcmp(xs,ys,xs->AclSize)==0?nullptr:"metadata_replay.windows_acl_bytes";
        };
        if (source.part!=SecurityPart::WindowsIntegrity) {
            auto* desired=policy.ownership==MetadataOwnership::Original?a:
                caller_security_?const_cast<std::byte*>(caller_security_->bytes.data()):nullptr;
            if (!desired) return mismatch("metadata_replay.windows_security_caller_missing");
            if (!same_sid(desired,b,true)) return mismatch("metadata_replay.windows_security_owner");
            if (!same_sid(desired,b,false)) return mismatch("metadata_replay.windows_security_group");
            if (const auto* error=acl_mismatch(a,b,true)) return mismatch(error);
        }
        if (source.part!=SecurityPart::WindowsAccess) if (const auto* error=acl_mismatch(a,b,false)) return mismatch(error);
        SECURITY_DESCRIPTOR_CONTROL ac=0,bc=0;DWORD ar=0,br=0;
        if (!GetSecurityDescriptorControl(a,&ac,&ar)||!GetSecurityDescriptorControl(b,&bc,&br)) return mismatch("metadata_replay.windows_security_control_query");
        const auto bits=source.part==SecurityPart::WindowsAccess ? SE_DACL_PROTECTED|SE_DACL_AUTO_INHERITED|SE_DACL_AUTO_INHERIT_REQ :
            source.part==SecurityPart::WindowsIntegrity ? 0 : SE_DACL_PROTECTED|SE_DACL_AUTO_INHERITED|SE_DACL_AUTO_INHERIT_REQ|
                SE_SACL_PROTECTED|SE_SACL_AUTO_INHERITED|SE_SACL_AUTO_INHERIT_REQ;
        if ((ac&bits)!=(bc&bits)) return mismatch("metadata_replay.windows_security_control_bits");
        return Result::available(true);
    }
    Observation<bool> rename_noreplace(const DirectoryCursor& source_parent, const DirectoryCursor& destination,
                                     const NativeName& name) const override;
    Observation<bool> qualify_progressive_target(const NativeMetadataProof& proof,const NativeFeatureIdentifier* identifier=nullptr)const {
        using R=Observation<bool>;
        const auto reject=[](const char* op){return R::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),op});};
        if(auto e=proof.cleanup_error())return R::unavailable(e->state,{e->domain,e->code,e->operation});
        if(proof.io_finished()||!content_write_access_||finish_started_||
           (!publication_&&!directory_metadata_target_))return reject("metadata_stream.private_open_target_required");
        const auto& snapshot=proof.snapshot();
        if(!snapshot.policy.valid()||snapshot.channel_coverage!=DataChannelCoverage::WindowsFileStreamInfo||
           !snapshot.basic.kind.value()||!snapshot.basic.identity.value()||
           (identifier&&std::none_of(snapshot.channels.begin(),snapshot.channels.end(),[&](const auto& c){return c.identifier==*identifier;})))
            return reject("metadata_stream.open_native_channel_proof_required");
        auto qualified=qualify_metadata_replay(snapshot.policy);if(!qualified.value()||!*qualified.value())return qualified;
        auto source=verify_native_metadata_replay_channels(snapshot);if(!source.value()||!*source.value())return source;
        auto target=inspect_basic();if(!target.value()){const auto&e=*target.unavailable_detail();return R::unavailable(e.state,e.error);}
        if(!target.value()->identity.value()||!target.value()->kind.value()||*target.value()->kind.value()!=*snapshot.basic.kind.value()||
           (*snapshot.basic.kind.value()==ObjectKind::RegularFile&&(!target.value()->logical_size.value()||
            !snapshot.basic.logical_size.value()||*target.value()->logical_size.value()!=*snapshot.basic.logical_size.value())))
            return reject("metadata_stream.target_shape");
        return R::available(true);
    }
    Observation<std::shared_ptr<WindowsMetadataChannel>> open_progressive_writer(
        const NativeMetadataProof& proof,const NativeFeatureIdentifier& identifier) {
        using R=Observation<std::shared_ptr<WindowsMetadataChannel>>;
        auto checked=qualify_progressive_target(proof,&identifier);
        if(!checked.value()||!*checked.value())return R::unavailable(checked.value()?ObservationState::Failed:checked.state(),
            checked.value()?NativeError{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_stream.target_false"}:checked.unavailable_detail()->error);
        const auto& snapshot=proof.snapshot();auto catalog=inspect_data_channels(snapshot.policy.limits);
        if(!catalog.value()){const auto&e=*catalog.unavailable_detail();return R::unavailable(e.state,e.error);}
        if(catalog.value()->coverage!=snapshot.channel_coverage)return R::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_stream.target_catalog"});
        for(const auto& c:catalog.value()->channels)if(c.kind!=DataChannelKind::MainData&&
            (c.kind!=DataChannelKind::NamedData||
             std::none_of(channel_writers_.begin(),channel_writers_.end(),[&](const auto& w){return w->identifier()==c.identifier;})||
             std::none_of(snapshot.channels.begin(),snapshot.channels.end(),[&](const auto& s){return s.identifier==c.identifier;})))
            return R::unavailable(ObservationState::Unsupported,{ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"metadata_stream.unowned_target_channel"});
        auto opened=open_metadata_channel(identifier,true);
        if(!opened.value()){const auto&e=*opened.unavailable_detail();return R::unavailable(e.state,e.error);}
        std::shared_ptr<WindowsMetadataChannel> owner(std::move(opened).take_value());
        channel_writers_.push_back(owner);return R::available(std::move(owner));
    }
    Observation<std::unique_ptr<WindowsMetadataChannel>> open_progressive_reader(
        const NativeMetadataProof& proof,const NativeFeatureIdentifier& identifier) {
        using R=Observation<std::unique_ptr<WindowsMetadataChannel>>;
        auto checked=qualify_progressive_target(proof,&identifier);
        if(!checked.value()||!*checked.value())return R::unavailable(checked.value()?ObservationState::Failed:checked.state(),
            checked.value()?NativeError{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_stream.target_false"}:checked.unavailable_detail()->error);
        // Bypass channel_writers_: this must be an independent file object,
        // opened after that stream's writer closes and before final security.
        return open_metadata_channel(identifier,false,true);
    }
    Observation<std::shared_ptr<const MetadataReplayChannelSource>> open_metadata_replay_channel_read(
        const NativeFeatureIdentifier& identifier) const override {
        using Result=Observation<std::shared_ptr<const MetadataReplayChannelSource>>;
        // Verification reuses this already-owned stream writer, whose own
        // automatic timestamps are suppressed. A separately reopened reader
        // could change the file's access time after final timestamp replay.
        for(const auto& owned:channel_writers_)if(owned->identifier()==identifier)return Result::available(owned);
        if(target_read_manifest_) {
            for(const auto& prepared:target_read_manifest_->readers)if(prepared->identifier()==identifier) {
                auto clone=prepared->duplicate_capture_reader();
                if(!clone.value()){const auto&e=*clone.unavailable_detail();return Result::unavailable(e.state,e.error);}
                return Result::available(std::shared_ptr<const MetadataReplayChannelSource>(std::move(clone).take_value()));
            }
            return Result::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::MetadataChanged),"target_read.unprepared_stream"});
        }
        auto opened=open_metadata_channel(identifier,false);
        if(!opened.value()){const auto& e=*opened.unavailable_detail();return Result::unavailable(e.state,e.error);}
        return Result::available(std::shared_ptr<const MetadataReplayChannelSource>(std::move(opened).take_value()));
    }
    Observation<bool> apply_replay_channels(const MetadataReplaySnapshot& snapshot,std::stop_token stop={}) override {
        using Result=Observation<bool>;
        if(!content_write_access_||(!publication_&&!directory_metadata_target_)||!snapshot.policy.valid()||snapshot.channel_coverage!=DataChannelCoverage::WindowsFileStreamInfo)
            return failure<bool>(ERROR_ACCESS_DENIED,"metadata_channels.staging_access");
        const auto proof=verify_native_metadata_replay_channels(snapshot);
        if(!proof.value()||!*proof.value())return proof;
        const auto catalog=inspect_data_channels(snapshot.policy.limits);
        if(!catalog.value()){const auto& e=*catalog.unavailable_detail();return Result::unavailable(e.state,e.error);}
        for(const auto& channel:catalog.value()->channels)if(channel.kind!=DataChannelKind::MainData) {
            if(channel.kind!=DataChannelKind::NamedData||std::none_of(channel_writers_.begin(),channel_writers_.end(),[&](const auto& own){return own->identifier()==channel.identifier;})||
                std::none_of(snapshot.channels.begin(),snapshot.channels.end(),[&](const auto& expected){return expected.identifier==channel.identifier;}))
                return Result::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"metadata_channels.unowned_staging_stream"});
        }
        for(std::size_t index=0;index<snapshot.channels.size();++index) {
            const auto& expected=snapshot.channels[index];
            if(!expected.source||!snapshot.basic.identity.value())return failure<bool>(ERROR_INVALID_DATA,"metadata_channels.source_missing");
            for(std::size_t prior=0;prior<index;++prior)if(snapshot.channels[prior].identifier==expected.identifier)
                return failure<bool>(ERROR_INVALID_DATA,"metadata_channels.duplicate_snapshot");
            const auto source=expected.source->inspect();
            if(!source.value()){const auto& e=*source.unavailable_detail();return Result::unavailable(e.state,e.error);}
            if(source.value()->identifier!=expected.identifier || source.value()->logical_size!=expected.logical_size ||
                compare_identity(source.value()->owner,*snapshot.basic.identity.value())!=IdentityComparison::Same)
                return Result::unavailable(ObservationState::Changed,
                    {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_channels.source_identity"});
            auto existing=std::find_if(channel_writers_.begin(),channel_writers_.end(),[&](const auto& own){return own->identifier()==expected.identifier;});
            WindowsMetadataChannel* writer=nullptr;
            if(existing==channel_writers_.end()) {
                auto opened=open_metadata_channel(expected.identifier,true);
                if(!opened.value()){const auto& e=*opened.unavailable_detail();return Result::unavailable(e.state,e.error);}
                channel_writers_.push_back(std::move(opened).take_value());writer=channel_writers_.back().get();
            } else writer=existing->get();
            auto truncated=writer->truncate();if(!truncated.value()||!*truncated.value())return truncated;
            Sha256 digest;std::uint64_t offset=0;
            while(offset<expected.logical_size) {
                if(stop.stop_requested())return Result::unavailable(ObservationState::Unknown,
                    {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InterruptedRead),"metadata_channels.copy_cancelled"});
                const auto data=expected.source->read_content({64*1024},offset,stop);
                if(!data.value()){const auto& e=*data.unavailable_detail();return Result::unavailable(e.state,e.error);}
                if(data.value()->bytes.empty()||data.value()->bytes.size()>expected.logical_size-offset ||
                    (data.value()->complete&&data.value()->bytes.size()!=expected.logical_size-offset))
                    return Result::unavailable(ObservationState::Changed,
                        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_channels.copy_shape"});
                digest.update(data.value()->bytes);
                std::size_t done=0;
                while(done<data.value()->bytes.size()) {
                    const auto wrote=writer->write(offset+done,std::span(data.value()->bytes).subspan(done));
                    if(!wrote.value()){const auto& e=*wrote.unavailable_detail();return Result::unavailable(e.state,e.error);}
                    if(!*wrote.value()||*wrote.value()>data.value()->bytes.size()-done)return failure<bool>(ERROR_WRITE_FAULT,"metadata_channels.write_progress");
                    done+=*wrote.value();
                }
                offset+=data.value()->bytes.size();
            }
            if(digest.digest()!=expected.digest)return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_channels.source_bytes_changed"});
            const auto stable=expected.source->inspect();
            if(!stable.value()){const auto& e=*stable.unavailable_detail();return Result::unavailable(e.state,e.error);}
            if(stable.value()->logical_size!=expected.logical_size || stable.value()->identifier!=expected.identifier ||
                compare_identity(stable.value()->owner,*snapshot.basic.identity.value())!=IdentityComparison::Same)
                return Result::unavailable(ObservationState::Changed,
                    {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_channels.source_changed"});
            const auto flushed=writer->flush();if(!flushed.value()||!*flushed.value())return flushed;
            const auto target=writer->inspect();
            if(!target.value()){const auto& e=*target.unavailable_detail();return Result::unavailable(e.state,e.error);}
            const auto checked=digest_metadata_replay_channel(*writer,expected.identifier,target.value()->owner,expected.logical_size,stop);
            if(!checked.value()){const auto& e=*checked.unavailable_detail();return Result::unavailable(e.state,e.error);}
            if(*checked.value()!=expected.digest)return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_channels.target_bytes_changed"});
        }
        return Result::available(true);
    }
    Observation<bool> apply_portable_basic_metadata(const BasicMetadata& source) override {
        using Result = Observation<bool>;
        if (!content_write_access_)
            return Result::unavailable(ObservationState::Denied,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidAccess), "metadata.portable_basic.write_access"});
        const auto target = inspect_basic();
        if (!target.value()) {
            const auto& error = *target.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!target.value()->kind.value() || (*target.value()->kind.value() != ObjectKind::RegularFile&&!(directory_metadata_target_&&*target.value()->kind.value()==ObjectKind::Directory)))
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "metadata.portable_basic.target_kind"});
        if (!source.kind.value() || (*source.kind.value() != ObjectKind::RegularFile&&!(directory_metadata_target_&&*source.kind.value()==ObjectKind::Directory)))
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "metadata.portable_basic.source_kind"});
        if (!source.windows_attributes.value()) {
            const auto& error = *source.windows_attributes.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!source.accessed.value() || !source.modified.value() || !source.changed.value() || !source.created.value()) {
            const auto& missing = !source.accessed.value() ? source.accessed :
                !source.modified.value() ? source.modified : !source.changed.value() ? source.changed : source.created;
            const auto& error = *missing.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        const auto accessed = windows_ticks(*source.accessed.value(), "metadata.portable_basic.accessed_range");
        const auto modified = windows_ticks(*source.modified.value(), "metadata.portable_basic.modified_range");
        const auto changed = windows_ticks(*source.changed.value(), "metadata.portable_basic.changed_range");
        const auto created = windows_ticks(*source.created.value(), "metadata.portable_basic.created_range");
        for (const auto* value : {&accessed, &modified, &changed, &created}) {
            if (!value->value()) {
                const auto& error = *value->unavailable_detail();
                return Result::unavailable(error.state, error.error);
            }
        }
        FILE_BASIC_INFO native{};
        native.CreationTime.QuadPart = *created.value();
        native.LastAccessTime.QuadPart = *accessed.value();
        native.LastWriteTime.QuadPart = *modified.value();
        native.ChangeTime.QuadPart = *changed.value();
        native.FileAttributes = *source.windows_attributes.value()&~FILE_ATTRIBUTE_DIRECTORY;
        if(!native.FileAttributes)native.FileAttributes=FILE_ATTRIBUTE_NORMAL;
        if (!SetFileInformationByHandle(handle_.get(), FileBasicInfo, &native, sizeof(native)))
            return failure<bool>(GetLastError(), "metadata.portable_basic.FileBasicInfo");
        return Result::available(true);
    }
    Observation<bool> apply_nonsecurity_attribute(const AttributeValue& source) override {
        using Result = Observation<bool>;
        if (!content_write_access_)
            return Result::unavailable(ObservationState::Denied,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidAccess), "attributes.nonsecurity.write_access"});
        const auto* name = source.identifier.windows_ea_bytes();
        if (!name || !NativeFeatureIdentifier::from_windows_ea(*name))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidIdentifier), "attributes.nonsecurity.identifier"});
        if (attribute_role(source.identifier, source.native_flags.value() ? *source.native_flags.value() : 0) == AttributeRole::Security)
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "attributes.nonsecurity.security_attribute"});
        if (name->size() > UCHAR_MAX || source.bytes.size() > USHRT_MAX)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InventoryLimit), "attributes.nonsecurity.value_limit"});
        if (!source.native_flags.value()) {
            const auto& error = *source.native_flags.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!source.owner.value() || !source.owner.value()->scope.is_valid()) {
            if (!source.owner.value()) {
                const auto& error = *source.owner.unavailable_detail();
                return Result::unavailable(error.state, error.error);
            }
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity), "attributes.nonsecurity.owner"});
        }
        const auto before = inspect_basic();
        if (!before.value()) {
            const auto& error = *before.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!before.value()->identity.value() || !before.value()->kind.value() ||
            (*before.value()->kind.value() != ObjectKind::RegularFile&&!(directory_metadata_target_&&*before.value()->kind.value()==ObjectKind::Directory)))
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "attributes.nonsecurity.target_kind"});
        if (const auto guarded = provider_guard(*before.value()))
            return Result::unavailable(guarded->state, guarded->error);
        const auto api = set_ea_api();
        if (!api.value()) {
            const auto& error = *api.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        const auto bytes = offsetof(FullEaInformation, EaName) + name->size() + 1 + source.bytes.size();
        if (bytes > std::numeric_limits<ULONG>::max())
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InventoryLimit), "attributes.nonsecurity.wire_limit"});
        std::vector<std::uint32_t> storage((bytes + sizeof(std::uint32_t) - 1) / sizeof(std::uint32_t), 0);
        auto wire = std::as_writable_bytes(std::span(storage)).first(bytes);
        auto* record = reinterpret_cast<FullEaInformation*>(wire.data());
        record->NextEntryOffset = 0;
        record->Flags = static_cast<UCHAR>(*source.native_flags.value());
        record->EaNameLength = static_cast<UCHAR>(name->size());
        record->EaValueLength = static_cast<USHORT>(source.bytes.size());
        std::memcpy(record->EaName, name->data(), name->size());
        record->EaName[name->size()] = '\0';
        if (!source.bytes.empty())
            std::memcpy(record->EaName + name->size() + 1, source.bytes.data(), source.bytes.size());
        IO_STATUS_BLOCK io{};
        const auto status = (*api.value())(handle_.get(), &io, wire.data(), static_cast<ULONG>(wire.size()));
        if (status < 0)
            return ea_failure<bool>(static_cast<std::uint32_t>(status), "NtSetEaFile");
        const auto after = inspect_basic();
        if (!after.value()) {
            const auto& error = *after.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!after.value()->identity.value() ||
            compare_identity(*before.value()->identity.value(), *after.value()->identity.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "attributes.nonsecurity.identity"});
        return Result::available(true);
    }
    Observation<bool> publish_noreplace(const DirectoryCursor& destination, const NativeName& name) override;
    Observation<BasicMetadata> inspect_basic() const override {
        if (finish_started_) return Observation<BasicMetadata>::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"content.finished_inspection"});
        return handle_metadata(handle_.get(), scope_);
    }
    Observation<FileIntegrityInfo> inspect_integrity(InventoryLimits limits = {}) const override {
        using Result = Observation<FileIntegrityInfo>;
        if (rename_access_) {
            auto view=synchronous_query_view(0);
            if(!view.value()){const auto& e=*view.unavailable_detail();return Result::unavailable(e.state,e.error);}
            return (*view.value())->inspect_integrity(limits);
        }
        if (!limits.valid()) return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "integrity.limits"});
        if (limits.max_native_bytes < WindowsIntegrityData::wire_bytes) return Result::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InventoryLimit), "integrity.buffer_limit"});
        static_assert(sizeof(FSCTL_GET_INTEGRITY_INFORMATION_BUFFER) == WindowsIntegrityData::wire_bytes);
        static_assert(offsetof(FSCTL_GET_INTEGRITY_INFORMATION_BUFFER, ChecksumAlgorithm) == 0 && offsetof(FSCTL_GET_INTEGRITY_INFORMATION_BUFFER, Reserved) == 2);
        static_assert(offsetof(FSCTL_GET_INTEGRITY_INFORMATION_BUFFER, Flags) == 4 && offsetof(FSCTL_GET_INTEGRITY_INFORMATION_BUFFER, ChecksumChunkSizeInBytes) == 8 && offsetof(FSCTL_GET_INTEGRITY_INFORMATION_BUFFER, ClusterSizeInBytes) == 12);
        static_assert(CHECKSUM_TYPE_NONE == 0 && CHECKSUM_TYPE_CRC64 == 2 && FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF == 1);
        static_assert(FILE_ATTRIBUTE_INTEGRITY_STREAM == 0x8000 && FILE_ATTRIBUTE_REPARSE_POINT == 0x400);
        static_assert(((FSCTL_GET_INTEGRITY_INFORMATION >> 14) & 3U) == FILE_ANY_ACCESS);
        const auto before = inspect_basic();
        const auto valid = detail::qualify_integrity_subject(before, before);
        if (!valid.value()) { const auto& e = *valid.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        FSCTL_GET_INTEGRITY_INFORMATION_BUFFER native{}; DWORD returned = 0;
        if (!DeviceIoControl(handle_.get(), FSCTL_GET_INTEGRITY_INFORMATION, nullptr, 0, &native, sizeof(native), &returned, nullptr)) {
            const DWORD code = GetLastError();
            return Result::unavailable(code == ERROR_INVALID_PARAMETER || code == ERROR_MORE_DATA ? ObservationState::Unknown : error_state(code),
                {ErrorDomain::Win32, code, "FSCTL_GET_INTEGRITY_INFORMATION"});
        }
        if (returned != sizeof(native)) return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "integrity.returned_count"});
        auto decoded = WindowsIntegrityData::decode(std::as_bytes(std::span(&native, 1)));
        if (!decoded.value()) { const auto& e = *decoded.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto after = inspect_basic(); const auto owner = detail::qualify_integrity_subject(before, after);
        if (!owner.value()) { const auto& e = *owner.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return Result::available({IntegrityQueryFamily::WindowsFsctl, Observation<ObjectIdentity>::available(*owner.value()), *before.value()->kind.value(),
            *before.value()->windows_attributes.value(), *after.value()->windows_attributes.value(), std::move(decoded).take_value()});
    }
    Observation<FileDataLayout> inspect_data_layout(InventoryLimits limits = {}, std::stop_token stop = {}) const override {
        using Result = Observation<FileDataLayout>;
        if (!limits.valid()) return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "layout.limits"});
        if (stop.stop_requested()) return Result::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InterruptedRead), "layout.cancelled"});
        if (!layout_access_) return Result::unavailable(ObservationState::Denied,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidAccess), "layout.access_not_requested"});
        if (rename_access_) {
            auto view=synchronous_query_view(FILE_READ_DATA,true);
            if(!view.value()){const auto& e=*view.unavailable_detail();return Result::unavailable(e.state,e.error);}
            return (*view.value())->inspect_data_layout(limits,stop);
        }
        const auto before = inspect_basic();
        if (!before.value()) { const auto& e = *before.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto guard = detail::data_layout_access_guard(*before.value(), StorageModel::WindowsHandleAttributes);
        if (!guard.value()) { const auto& e = *guard.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (!before.value()->logical_size.value()) { const auto& e = *before.value()->logical_size.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto size = *before.value()->logical_size.value();
        if (size > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max())) return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), "layout.offset_range"});
        const auto query = [&](std::uint64_t at, std::uint64_t end) -> Observation<std::optional<FileDataRange>> {
            using Reply = Observation<std::optional<FileDataRange>>;
            FILE_ALLOCATED_RANGE_BUFFER input{}, output{};
            input.FileOffset.QuadPart = static_cast<LONGLONG>(at); input.Length.QuadPart = static_cast<LONGLONG>(end - at);
            DWORD bytes = 0;
            const auto success = DeviceIoControl(handle_.get(), FSCTL_QUERY_ALLOCATED_RANGES, &input, sizeof(input), &output, sizeof(output), &bytes, nullptr);
            const DWORD code = success ? ERROR_SUCCESS : GetLastError();
            if (!success && code != ERROR_MORE_DATA) return failure<std::optional<FileDataRange>>(code, "FSCTL_QUERY_ALLOCATED_RANGES");
            if (bytes == 0 && success) return Reply::available(std::nullopt);
            if (bytes != sizeof(output) || output.FileOffset.QuadPart < 0 || output.Length.QuadPart <= 0)
                return Reply::unavailable(ObservationState::Failed,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "layout.windows_range"});
            return Reply::available(FileDataRange{static_cast<std::uint64_t>(output.FileOffset.QuadPart), static_cast<std::uint64_t>(output.Length.QuadPart)});
        };
        auto result = detail::collect_data_layout(query, DataLayoutFamily::WindowsAllocatedRanges, before.value()->identity, size, limits, stop);
        if (!result.value()) return result;
        if (stop.stop_requested()) return Result::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InterruptedRead), "layout.cancelled"});
        const auto after = inspect_basic();
        if (stop.stop_requested()) return Result::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InterruptedRead), "layout.cancelled"});
        if (!after.value()) { const auto& e = *after.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto unchanged = detail::data_layout_metadata_unchanged(*before.value(), *after.value());
        if (!unchanged.value()) { const auto& e = *unchanged.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return result;
    }
    Observation<std::unique_ptr<OpenedEntry>> open_parent_directory() const override;
    Observation<LinkMetadata> read_link_metadata(InventoryLimits limits = {}) const override {
        using Result = Observation<LinkMetadata>;
        if (rename_access_) {
            auto view=synchronous_query_view(0);
            if(!view.value()){const auto& e=*view.unavailable_detail();return Result::unavailable(e.state,e.error);}
            return (*view.value())->read_link_metadata(limits);
        }
        if (!limits.valid()) return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "link.limits"});
        const auto metadata = inspect_basic();
        if (!metadata.value()) { const auto& e = *metadata.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (!metadata.value()->windows_attributes.value()) { const auto& e = *metadata.value()->windows_attributes.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if ((*metadata.value()->windows_attributes.value() & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "link.object_kind"});
        static_assert(MAXIMUM_REPARSE_DATA_BUFFER_SIZE == detail::windows_reparse_max_bytes);
        const auto maximum = std::min(limits.max_native_bytes, detail::windows_reparse_max_bytes);
        if (maximum < 8) return Result::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InventoryLimit), "reparse.buffer_limit"});
        auto capacity = std::min<std::size_t>(1024, maximum);
        for (;;) {
            std::vector<std::uint64_t> buffer((capacity + 7) / 8, 0);
            DWORD returned = 0;
            if (DeviceIoControl(handle_.get(), FSCTL_GET_REPARSE_POINT, nullptr, 0, buffer.data(), static_cast<DWORD>(capacity), &returned, nullptr)) {
                if (returned > capacity) return Result::unavailable(ObservationState::Failed,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "reparse.returned_count"});
                auto decoded = detail::decode_windows_reparse(std::as_bytes(std::span(buffer)).first(returned), limits);
                if (!decoded.value()) { const auto& e = *decoded.unavailable_detail(); return Result::unavailable(e.state, e.error); }
                auto data = std::move(decoded).take_value();
                if (metadata.value()->reparse_tag.value() && *metadata.value()->reparse_tag.value() != data.tag)
                    return Result::unavailable(ObservationState::Changed,
                        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "reparse.tag_changed"});
                return Result::available({metadata.value()->identity, std::move(data)});
            }
            const DWORD code = GetLastError();
            if (code != ERROR_INSUFFICIENT_BUFFER && code != ERROR_MORE_DATA) return failure<LinkMetadata>(code, "FSCTL_GET_REPARSE_POINT");
            if (capacity == maximum) return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32, code, "FSCTL_GET_REPARSE_POINT.buffer_limit"});
            capacity = capacity > maximum / 2 ? maximum : capacity * 2;
        }
    }
    Observation<StorageInfo> inspect_storage() const override {
        using Result = Observation<StorageInfo>;
        const auto metadata = inspect_basic();
        if (!metadata.value()) { const auto& e = *metadata.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        auto decoded = storage_from_basic(*metadata.value(), StorageModel::WindowsHandleAttributes);
        if (!decoded.value()) return decoded;
        auto result = std::move(decoded).take_value();
        if (const auto guarded = provider_guard(*metadata.value()))
            result.windows_compression = Observation<WindowsCompressionDetails>::unavailable(guarded->state, guarded->error);
        else if (metadata.value()->kind.value() && *metadata.value()->kind.value() == ObjectKind::RegularFile) {
            FILE_COMPRESSION_INFO native{};
            if (GetFileInformationByHandleEx(handle_.get(), FileCompressionInfo, &native, sizeof(native))) {
                if (native.CompressedFileSize.QuadPart >= 0)
                    result.windows_compression = Observation<WindowsCompressionDetails>::available({
                        static_cast<std::uint64_t>(native.CompressedFileSize.QuadPart), native.CompressionFormat,
                        native.CompressionUnitShift, native.ChunkShift, native.ClusterShift});
                else result.windows_compression = Observation<WindowsCompressionDetails>::unavailable(ObservationState::Failed,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "FileCompressionInfo.size"});
            } else {
                const DWORD code = GetLastError();
                result.windows_compression = failure<WindowsCompressionDetails>(code, "FileCompressionInfo");
            }
        } else result.windows_compression = Observation<WindowsCompressionDetails>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "storage.regular_compression_details"});
        return Result::available(std::move(result));
    }
    Observation<DataChannelCatalog> inspect_data_channels(InventoryLimits limits = {}) const override {
        using Result = Observation<DataChannelCatalog>;
        static_assert(offsetof(FILE_STREAM_INFO, StreamName) == detail::windows_stream_name_offset);
        static_assert(offsetof(FILE_STREAM_INFO, StreamNameLength) == 4);
        static_assert(offsetof(FILE_STREAM_INFO, StreamSize) == 8);
        static_assert(offsetof(FILE_STREAM_INFO, StreamAllocationSize) == 16);
        if (!limits.valid())
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "channels.limits"});
        const auto metadata = inspect_basic();
        if (!metadata.value()) { const auto& e = *metadata.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (const auto guarded = provider_guard(*metadata.value())) return Result::unavailable(guarded->state, guarded->error);
        if (limits.max_native_bytes < sizeof(FILE_STREAM_INFO))
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InventoryLimit), "FileStreamInfo.buffer_limit"});
        auto capacity = std::min<std::size_t>(4096, limits.max_native_bytes);
        for (;;) {
            // uint64_t storage provides the SDK-required 8-byte alignment. The
            // supplied byte count is exact; rounding storage costs at most 7 bytes.
            std::vector<std::uint64_t> buffer((capacity + 7) / 8, 0);
            SetLastError(ERROR_SUCCESS);
            const bool success = GetFileInformationByHandleEx(handle_.get(), FileStreamInfo,
                buffer.data(), static_cast<DWORD>(capacity)) != 0;
            const DWORD code = GetLastError();
            // FileStreamInfo documents HANDLE_EOF when no streams are returned,
            // including its special success/no-streams outcome.
            if (code == ERROR_HANDLE_EOF) {
                DataChannelCatalog empty;
                empty.coverage = DataChannelCoverage::WindowsFileStreamInfo;
                empty.owner = identity(handle_.get(), scope_);
                return Result::available(std::move(empty));
            }
            if (success) {
                auto decoded = detail::decode_windows_stream_records(std::as_bytes(std::span(buffer)).first(capacity), limits);
                if (!decoded.value()) return decoded;
                auto result = std::move(decoded).take_value();
                result.owner = identity(handle_.get(), scope_);
                return Result::available(std::move(result));
            }
            if (code != ERROR_MORE_DATA && code != ERROR_INSUFFICIENT_BUFFER && code != ERROR_BAD_LENGTH)
                return failure<DataChannelCatalog>(code, "FileStreamInfo");
            if (capacity == limits.max_native_bytes)
                return Result::unavailable(ObservationState::Unknown, {ErrorDomain::Win32, code, "FileStreamInfo.buffer_limit"});
            capacity = capacity > limits.max_native_bytes / 2 ? limits.max_native_bytes : capacity * 2;
            // Retry this whole read-only query, never a continuation from an
            // unsuccessful/truncated prefix. Denial and I/O errors are not retried.
        }
    }
    Observation<AttributeCatalog> inspect_attributes(InventoryLimits limits = {}) const override {
        using Result = Observation<AttributeCatalog>;
        if (rename_access_) {
            auto view=synchronous_query_view(FILE_READ_EA);
            if(!view.value()){const auto& e=*view.unavailable_detail();return Result::unavailable(e.state,e.error);}
            return (*view.value())->inspect_attributes(limits);
        }
        if (!limits.valid()) return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "attributes.limits"});
        const auto metadata = inspect_basic();
        if (!metadata.value()) { const auto& e = *metadata.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (const auto guarded = provider_guard(*metadata.value())) return Result::unavailable(guarded->state, guarded->error);
        AttributeCatalog result;
        result.coverage = AttributeCoverage::WindowsExtendedAttributes;
        result.owner = identity(handle_.get(), scope_);
        std::set<std::string> seen;
        for (ULONG index = 1; ; ++index) {
            auto queried = query_ea(nullptr, 0, &index, limits);
            if (!queried.value()) {
                const auto& e = *queried.unavailable_detail();
                if (e.error.domain == ErrorDomain::NtStatus &&
                    (e.error.code == no_eas || e.error.code == no_more_eas || e.error.code == nonexistent_ea))
                    return Result::available(std::move(result));
                return Result::unavailable(e.state, e.error);
            }
            auto record = std::move(queried).take_value();
            if (record.value.empty() || !seen.insert(*record.identifier.windows_ea_bytes()).second)
                return Result::unavailable(ObservationState::Failed,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "attributes.ea_enumeration"});
            if (result.attributes.size() == limits.max_records)
                return Result::unavailable(ObservationState::Unknown,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InventoryLimit), "attributes.record_limit"});
            const auto role = attribute_role(record.identifier, record.flags);
            result.attributes.push_back({std::move(record.identifier), role,
                Observation<std::uint64_t>::available(record.value.size()), Observation<std::uint32_t>::available(record.flags)});
        }
    }
    Observation<AttributeValue> read_attribute(const NativeFeatureIdentifier& id, InventoryLimits limits = {}) const override {
        using Result = Observation<AttributeValue>;
        if (rename_access_) {
            auto view=synchronous_query_view(FILE_READ_EA);
            if(!view.value()){const auto& e=*view.unavailable_detail();return Result::unavailable(e.state,e.error);}
            return (*view.value())->read_attribute(id,limits);
        }
        if (!limits.valid()) return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "attributes.limits"});
        const auto* name = id.windows_ea_bytes();
        if (!name || !NativeFeatureIdentifier::from_windows_ea(*name))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidIdentifier), "attributes.identifier"});
        const auto metadata = inspect_basic();
        if (!metadata.value()) { const auto& e = *metadata.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        if (const auto guarded = provider_guard(*metadata.value())) return Result::unavailable(guarded->state, guarded->error);
        // FILE_GET_EA_INFORMATION: next offset, one-byte name length, name/NUL.
        std::vector<std::uint32_t> storage((6 + name->size() + 3) / 4, 0);
        auto request = std::as_writable_bytes(std::span(storage));
        request[4] = static_cast<std::byte>(name->size());
        std::memcpy(request.data() + 5, name->data(), name->size());
        auto queried = query_ea(request.data(), static_cast<ULONG>(6 + name->size()), nullptr, limits);
        if (!queried.value()) { const auto& e = *queried.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        auto record = std::move(queried).take_value();
        if (record.value.empty()) // Native filtered-query witness: zero deletes an EA.
            return Result::unavailable(ObservationState::Gone,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::AttributeAbsent), "attributes.ea_absent"});
        return Result::available({std::move(record.identifier), std::move(record.value), identity(handle_.get(), scope_),
            Observation<std::uint32_t>::available(record.flags)});
    }
    Observation<NativeSecurityValue> read_security(SecurityPart part, InventoryLimits limits = {}) const override {
        using Result = Observation<NativeSecurityValue>;
        if (!valid_security_part(part) || !limits.valid())
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(!valid_security_part(part) ? AdapterError::InvalidIdentifier : AdapterError::InvalidLimit), "security.query"});
        SECURITY_INFORMATION mask = 0;
        switch (part) {
        case SecurityPart::WindowsAccess: mask = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION; break;
        case SecurityPart::WindowsIntegrity: mask = LABEL_SECURITY_INFORMATION; break;
        case SecurityPart::WindowsFullDescriptor: mask = persistent_security_information; break;
        default: return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "security.model"});
        }
        // No named lookup and no privilege adjustment. Missing handle rights
        // remain native denial, not an empty descriptor or silently weaker query.
        auto bytes = detail::read_attribute_bytes([&](std::span<std::byte> buffer) -> detail::BufferReply {
            DWORD needed = 0;
            const bool success = GetKernelObjectSecurity(security_handle_ ? security_handle_.get() : handle_.get(), mask,
                buffer.empty() ? nullptr : buffer.data(), static_cast<DWORD>(buffer.size()), &needed) != 0;
            const DWORD code = GetLastError();
            if (success) return static_cast<std::size_t>(needed);
            const NativeError error{ErrorDomain::Win32, code, "GetKernelObjectSecurity"};
            if (code == ERROR_INSUFFICIENT_BUFFER)
                return buffer.empty() ? detail::BufferReply{static_cast<std::size_t>(needed)} : detail::BufferReply{detail::BufferTooSmall{error}};
            return UnavailableObservation{error_state(code), error};
        }, limits);
        if (!bytes.value()) { const auto& e = *bytes.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto checked = detail::validate_windows_descriptor(*bytes.value(), limits);
        if (!checked.value()) { const auto& e = *checked.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return Result::available({part, SecurityEncoding::WindowsRelativeDescriptor, SecurityPresence::Present,
            std::move(bytes).take_value(), identity(handle_.get(), scope_), mask});
    }
private:
    friend class WindowsDirectoryCursor;
    friend class WindowsTargetReadSeed;
    friend class ::ck::files::NativeCreatedDirectory;
    Observation<std::unique_ptr<WindowsMetadataChannel>> open_metadata_channel(const NativeFeatureIdentifier& identifier,bool create,
        bool suppress_read_times=false) const {
        using Result=Observation<std::unique_ptr<WindowsMetadataChannel>>;
        const auto* units=identifier.windows_units();
        if(!units||units->size()<=7||units->front()!=u':'||!units->ends_with(u":$DATA")||
            units->substr(1,units->size()-7).find_first_of(u":/\\\0",0,4)!=std::u16string::npos ||
            units->size()>std::numeric_limits<USHORT>::max()/sizeof(WCHAR))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidIdentifier),"metadata_channels.native_identifier"});
        if(create&&(!content_write_access_||(!publication_&&!directory_metadata_target_)))return failure<std::unique_ptr<WindowsMetadataChannel>>(ERROR_ACCESS_DENIED,"metadata_channels.create_access");
        const auto owner=identity(handle_.get(),scope_);
        if(!owner.value()){const auto& e=*owner.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(owner.value()->scheme!=IdentityScheme::WindowsFileId128)return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity),"metadata_channels.owner_scheme"});
        const auto basic=inspect_basic();
        if(!basic.value()){const auto& e=*basic.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(!basic.value()->kind.value()||(*basic.value()->kind.value()!=ObjectKind::RegularFile&&*basic.value()->kind.value()!=ObjectKind::Directory))
            return failure<std::unique_ptr<WindowsMetadataChannel>>(ERROR_NOT_SUPPORTED,"metadata_channels.base_kind");
        const bool directory=*basic.value()->kind.value()==ObjectKind::Directory;
        std::wstring spelling(units->begin(),units->end());UNICODE_STRING name{};
        name.Length=static_cast<USHORT>(spelling.size()*sizeof(WCHAR));name.MaximumLength=name.Length;name.Buffer=spelling.data();
        OBJECT_ATTRIBUTES attributes{};attributes.Length=sizeof(attributes);attributes.RootDirectory=handle_.get();attributes.ObjectName=&name;
        IO_STATUS_BLOCK io{};HANDLE raw=nullptr;
        const auto status=NtCreateFile(&raw,create?FILE_GENERIC_READ|FILE_GENERIC_WRITE:
            FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE|(suppress_read_times?FILE_WRITE_ATTRIBUTES:0),
            &attributes,&io,nullptr,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ|FILE_SHARE_DELETE,
            create?FILE_CREATE:FILE_OPEN,(directory?0:FILE_NON_DIRECTORY_FILE)|FILE_OPEN_REPARSE_POINT|FILE_OPEN_NO_RECALL|FILE_SYNCHRONOUS_IO_NONALERT,nullptr,0);
        OwnedHandle opened(raw);
        if(status!=0)return Result::unavailable(error_state(RtlNtStatusToDosError(status)),
            {ErrorDomain::NtStatus,static_cast<std::uint32_t>(status),"metadata_channels.NtCreateFile.relative"});
        if(!opened||opened.get()==INVALID_HANDLE_VALUE||io.Information!=(create?FILE_CREATED:FILE_OPENED))
            return failure<std::unique_ptr<WindowsMetadataChannel>>(ERROR_INVALID_DATA,"metadata_channels.open_result");
        if(create||suppress_read_times) {
            // Stream writes and close otherwise defer updates to the base
            // file's times. Suppress updates from this specific file object;
            // final base-object timestamp replay still sets the actual values.
            const FILETIME suppressed{MAXDWORD,MAXDWORD};
            if(!SetFileTime(opened.get(),nullptr,&suppressed,&suppressed))
                return failure<std::unique_ptr<WindowsMetadataChannel>>(GetLastError(),"metadata_channels.suppress_automatic_times");
        }
        auto channel=std::make_unique<WindowsMetadataChannel>(std::move(opened),scope_,identifier,*owner.value(),create);
        const auto checked=channel->inspect();
        if(!checked.value()){const auto& e=*checked.unavailable_detail();return Result::unavailable(e.state,e.error);}
        return Result::available(std::move(channel));
    }
    Observation<std::unique_ptr<WindowsOpenedEntry>> synchronous_query_view(DWORD rights,bool layout=false) const {
        using Result=Observation<std::unique_ptr<WindowsOpenedEntry>>;
        auto handle=metadata_security_handle(rights);
        if(!handle.value()){const auto& e=*handle.unavailable_detail();return Result::unavailable(e.state,e.error);}
        return Result::available(std::make_unique<WindowsOpenedEntry>(std::move(handle).take_value(),scope_,layout));
    }
    Observation<DWORD> read_guarded(std::span<std::byte> bytes,std::uint64_t offset,std::stop_token stop) const {
        using Result=Observation<DWORD>;
        if (content_lease_) {const auto stable=content_lease_->check();if(!stable.value()){const auto& e=*stable.unavailable_detail();return Result::unavailable(e.state,e.error);}}
        if (bytes.empty()) return Result::available(0);
        OwnedHandle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));
        if (!event || event.get()==INVALID_HANDLE_VALUE) return failure<DWORD>(GetLastError(),"content.guard_read_event");
        OVERLAPPED io{};io.hEvent=event.get();io.Offset=static_cast<DWORD>(offset);io.OffsetHigh=static_cast<DWORD>(offset>>32U);
        DWORD copied=0;
        if (!ReadFile(handle_.get(),bytes.data(),static_cast<DWORD>(bytes.size()),&copied,&io)) {
            const DWORD code=GetLastError();
            if (code!=ERROR_IO_PENDING) return failure<DWORD>(code,"content.guard_ReadFile");
            bool cancelled=false,broken=false;DWORD wait_error=0;
            for (;;) {
                HANDLE events[]{event.get(),content_lease_?content_lease_->event():nullptr};
                const DWORD result=WaitForMultipleObjects(content_lease_?2:1,events,FALSE,50);
                if (result==WAIT_OBJECT_0) break;
                cancelled=stop.stop_requested();broken=result==WAIT_OBJECT_0+1;
                if (result==WAIT_FAILED) wait_error=GetLastError();
                if (cancelled || broken || wait_error) {
                    CancelIoEx(handle_.get(),&io);
                    // Cancellation is a request, not completion. Drain this
                    // read before its buffer, event or OVERLAPPED can unwind.
                    GetOverlappedResult(handle_.get(),&io,&copied,TRUE);
                    if (cancelled) return Result::unavailable(ObservationState::Unknown,
                        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InterruptedRead),"content.guard_read_cancelled"});
                    if (broken) {const auto e=content_lease_->check();return Result::unavailable(e.state(),e.unavailable_detail()->error);}
                    return failure<DWORD>(wait_error,"content.guard_read_wait");
                }
            }
            if (!GetOverlappedResult(handle_.get(),&io,&copied,FALSE)) return failure<DWORD>(GetLastError(),"content.guard_read_completion");
        }
        if (content_lease_) {const auto stable=content_lease_->check();if(!stable.value()){const auto& e=*stable.unavailable_detail();return Result::unavailable(e.state,e.error);}}
        return Result::available(copied);
    }
    static std::optional<UnavailableObservation> provider_guard(const BasicMetadata& metadata) {
        const auto review = provider_review_required(metadata, StorageModel::WindowsHandleAttributes);
        if (!review.value()) return *review.unavailable_detail();
        if (*review.value()) return UnavailableObservation{ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::ProviderReviewRequired), "storage.provider_review"}};
        return std::nullopt;
    }
    Observation<detail::WindowsEaRecord> query_ea(void* names, ULONG names_size, PULONG index, InventoryLimits limits) const {
        using Result = Observation<detail::WindowsEaRecord>;
        const auto api = query_ea_api();
        if (!api.value()) { const auto& e = *api.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        auto capacity = std::min<std::size_t>(4096, limits.max_native_bytes);
        for (;;) {
            std::vector<std::uint32_t> buffer((capacity + 3) / 4, 0);
            IO_STATUS_BLOCK io{};
            // Explicit one-based index makes retries independent of the handle's
            // EA enumeration cursor. A name list, when present, selects the key.
            const NTSTATUS status = (*api.value())(handle_.get(), &io, buffer.data(), static_cast<ULONG>(capacity),
                TRUE, names, names_size, index, FALSE);
            const auto code = static_cast<std::uint32_t>(status);
            if (code == 0 || (code == buffer_overflow && io.Information != 0)) {
                if (io.Information > capacity)
                    return Result::unavailable(ObservationState::Failed,
                        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "attributes.ea_count"});
                return detail::decode_windows_ea_record(std::as_bytes(std::span(buffer)).first(static_cast<std::size_t>(io.Information)));
            }
            if (code != buffer_too_small && code != buffer_overflow) return ea_failure<detail::WindowsEaRecord>(code, "NtQueryEaFile");
            if (capacity == limits.max_native_bytes)
                return Result::unavailable(ObservationState::Unknown, {ErrorDomain::NtStatus, code, "NtQueryEaFile.buffer_limit"});
            capacity = capacity > limits.max_native_bytes / 2 ? limits.max_native_bytes : capacity * 2;
        }
    }
    Observation<OwnedHandle> metadata_security_handle(DWORD rights) const {
        using Result=Observation<OwnedHandle>;
        const auto held=identity(handle_.get(),scope_);
        if (!held.value()) {const auto& e=*held.unavailable_detail();return Result::unavailable(e.state,e.error);}
        FILE_ID_DESCRIPTOR id{};id.dwSize=sizeof(id);
        if (held.value()->scheme==IdentityScheme::WindowsFileId128) {
            id.Type=ExtendedFileIdType;std::memcpy(id.ExtendedFileId.Identifier,held.value()->object.bytes.data(),16);
        } else if (held.value()->scheme==IdentityScheme::WindowsFileIndex64) {
            id.Type=FileIdType;std::memcpy(&id.FileId.QuadPart,held.value()->object.bytes.data(),8);
        } else return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity),"metadata_replay.windows_id_scheme"});
        OwnedHandle opened(OpenFileById(handle_.get(),&id,rights|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL|FILE_FLAG_BACKUP_SEMANTICS));
        if (!opened || opened.get()==INVALID_HANDLE_VALUE) return failure<OwnedHandle>(GetLastError(),"metadata_replay.OpenFileById.security");
        const auto checked=identity(opened.get(),scope_);
        if (!checked.value() || compare_identity(*held.value(),*checked.value())!=IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_replay.security_handle_identity"});
        return Result::available(std::move(opened));
    }
    Observation<HANDLE> ensure_metadata_security_handle(DWORD rights) {
        using Result=Observation<HANDLE>;
        if(security_handle_&&(security_access_&rights)==rights) return Result::available(security_handle_.get());
        auto opened=metadata_security_handle(rights|security_access_);
        if(!opened.value()){const auto& e=*opened.unavailable_detail();return Result::unavailable(e.state,e.error);}
        security_handle_=std::move(opened).take_value();security_access_|=rights;
        return Result::available(security_handle_.get());
    }
    bool capture_close_started_=false;
    std::optional<MetadataCaptureCleanupError> capture_close_error_;
    DWORD security_access_=0;
    OwnedHandle security_handle_;
    bool finish_started_ = false;
    std::optional<Observation<bool>> finish_result_;
    std::optional<NativeSecurityValue> caller_security_;
    OwnedHandle handle_;
    AdapterScope scope_;
    bool layout_access_;
    bool content_access_ = false;
    bool content_write_access_ = false;
    bool rename_access_ = false;
    std::unique_ptr<WindowsPublicationContext> publication_;
    bool directory_metadata_target_=false;
    std::shared_ptr<const WindowsTargetReadManifest> target_read_manifest_;
    mutable std::unique_ptr<WindowsContentLease> content_lease_;
    std::vector<std::shared_ptr<WindowsMetadataChannel>> channel_writers_;
};

// This type is deliberately private to the native adapter. A caller-created
// snapshot or evidence implementation cannot authorize complete native replay.
class WindowsChannelManifestProof final:public MetadataReplayChannelEvidence {
public:
    WindowsChannelManifestProof(std::unique_ptr<OpenedEntry> source,MetadataReplaySnapshot observed,std::shared_ptr<const void> lease={})
        :source_(std::move(source)),observed_(std::move(observed)),capture_lease_(std::move(lease)) {
        observed_.channel_evidence.reset();observed_.security_coverage.reset();
    }
    Observation<bool> recheck(const MetadataReplaySnapshot& requested)const {
        using Result=Observation<bool>;
        const auto changed=[](const char* op){return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),op});};
        const auto& expected=observed_;
        if(!requested.policy.valid()||requested.policy.version!=expected.policy.version||requested.policy.scope!=expected.policy.scope||
           requested.policy.ownership!=expected.policy.ownership||requested.policy.allow_privilege_metadata!=expected.policy.allow_privilege_metadata||
           requested.policy.limits.max_native_bytes!=expected.policy.limits.max_native_bytes||
           requested.policy.limits.max_records!=expected.policy.limits.max_records||
           requested.channel_coverage!=DataChannelCoverage::WindowsFileStreamInfo||
           requested.channel_coverage!=expected.channel_coverage||requested.channels.size()!=expected.channels.size()||
           requested.channels.size()>requested.policy.limits.max_records||
           !requested.basic.identity.value()||!expected.basic.identity.value()||
           compare_identity(*requested.basic.identity.value(),*expected.basic.identity.value())!=IdentityComparison::Same||
           !requested.basic.kind.value()||!expected.basic.kind.value()||*requested.basic.kind.value()!=*expected.basic.kind.value())
            return changed("metadata_channels.proof_manifest");
        const auto qualified=source_->qualify_metadata_replay(expected.policy);
        if(!qualified.value()||!*qualified.value())return qualified;
        const auto basic=source_->inspect_basic();
        if(!basic.value()){const auto& e=*basic.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(!basic.value()->identity.value()||!basic.value()->kind.value()||
           compare_identity(*basic.value()->identity.value(),*expected.basic.identity.value())!=IdentityComparison::Same||
           *basic.value()->kind.value()!=*expected.basic.kind.value())return changed("metadata_channels.proof_owner");
        const auto catalog=source_->inspect_data_channels(expected.policy.limits);
        if(!catalog.value()){const auto& e=*catalog.unavailable_detail();return Result::unavailable(e.state,e.error);}
        const auto main_count=*expected.basic.kind.value()==ObjectKind::Directory?0U:1U;
        if(catalog.value()->coverage!=expected.channel_coverage||!catalog.value()->owner.value()||
           compare_identity(*catalog.value()->owner.value(),*expected.basic.identity.value())!=IdentityComparison::Same||
           catalog.value()->channels.size()!=expected.channels.size()+main_count)
            return changed("metadata_channels.proof_catalog");
        for(std::size_t i=0;i<expected.channels.size();++i) {
            const auto& channel=expected.channels[i];
            for(std::size_t j=0;j<i;++j)if(expected.channels[j].identifier==channel.identifier)
                return changed("metadata_channels.proof_duplicate");
            const auto found=std::find_if(requested.channels.begin(),requested.channels.end(),[&](const auto& x){return x.identifier==channel.identifier;});
            if(found==requested.channels.end()||found->logical_size!=channel.logical_size||found->digest!=channel.digest||
               found->source.get()!=channel.source.get()||!dynamic_cast<const WindowsMetadataChannel*>(channel.source.get()))
                return changed("metadata_channels.proof_channel_binding");
            const auto current=std::find_if(catalog.value()->channels.begin(),catalog.value()->channels.end(),
                [&](const auto& x){return x.kind==DataChannelKind::NamedData&&x.identifier==channel.identifier;});
            if(current==catalog.value()->channels.end()||!current->logical_size.value()||*current->logical_size.value()!=channel.logical_size)
                return changed("metadata_channels.proof_channel_catalog");
            const auto state=channel.source->inspect();
            if(!state.value()){const auto& e=*state.unavailable_detail();return Result::unavailable(e.state,e.error);}
            if(state.value()->identifier!=channel.identifier||state.value()->logical_size!=channel.logical_size||
               compare_identity(state.value()->owner,*expected.basic.identity.value())!=IdentityComparison::Same)
                return changed("metadata_channels.proof_channel_owner");
        }
        return Result::available(true);
    }
    void finish_capture_reads()const noexcept {
        auto* native=dynamic_cast<WindowsOpenedEntry*>(source_.get());
        if(native)native->finish_capture_reads();
        else detail::record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_capture.native_proof_source_missing"});
    }
private:
    std::unique_ptr<OpenedEntry> source_;
    MetadataReplaySnapshot observed_;
    std::shared_ptr<const void> capture_lease_;
};

class WindowsPersistentSecurityProof final : public MetadataSecurityCoverageEvidence {
public:
    WindowsPersistentSecurityProof(std::unique_ptr<WindowsOpenedEntry> source,MetadataReplaySnapshot observed,std::shared_ptr<const void> lease={})
        :source_(std::move(source)),observed_(std::move(observed)),capture_lease_(std::move(lease)) {observed_.security_coverage.reset();}
    MetadataSecurityCoverage family() const noexcept override {return MetadataSecurityCoverage::WindowsPersistentSecurityV1;}
    Observation<bool> recheck(const MetadataReplaySnapshot& requested) const override {
        using Result=Observation<bool>;
        const auto channels=verify_native_metadata_replay_channels(requested);
        if(!channels.value()||!*channels.value())return channels;
        const auto changed=[](const char* op){return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),op});};
        const auto unsupported=[](const char* op){return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),op});};
        const auto same_owner=[](const Observation<ObjectIdentity>& a,const Observation<ObjectIdentity>& b) {
            return a.value()&&b.value()&&compare_identity(*a.value(),*b.value())==IdentityComparison::Same;
        };
        const auto& expected=observed_;
        if(requested.policy.version!=expected.policy.version||requested.policy.scope!=expected.policy.scope||
           requested.policy.ownership!=expected.policy.ownership||requested.policy.allow_privilege_metadata!=expected.policy.allow_privilege_metadata||
           requested.policy.limits.max_native_bytes!=expected.policy.limits.max_native_bytes||requested.policy.limits.max_records!=expected.policy.limits.max_records||
           !same_owner(requested.basic.identity,expected.basic.identity)||requested.attribute_coverage!=expected.attribute_coverage||
           requested.attributes.size()!=expected.attributes.size()||requested.security.size()!=1||expected.security.size()!=1)
            return changed("metadata_replay.coverage_manifest");
        const auto& security=requested.security.front();const auto& original=expected.security.front();
        if(security.part!=SecurityPart::WindowsFullDescriptor||security.encoding!=SecurityEncoding::WindowsRelativeDescriptor||security.encoding!=original.encoding||
           security.presence!=SecurityPresence::Present||security.presence!=original.presence||security.native_query_mask!=persistent_security_information||
           security.bytes!=original.bytes||!same_owner(security.owner,expected.basic.identity))
            return changed("metadata_replay.coverage_security_manifest");
        for(const auto& attribute:expected.attributes) {
            const auto found=std::find_if(requested.attributes.begin(),requested.attributes.end(),
                [&](const auto& item){return item.identifier==attribute.identifier;});
            if(found==requested.attributes.end()||found->bytes!=attribute.bytes||!found->native_flags.value()||
               !attribute.native_flags.value()||*found->native_flags.value()!=*attribute.native_flags.value()||
               !same_owner(found->owner,expected.basic.identity)) return changed("metadata_replay.coverage_ea_manifest");
            if(!attribute.native_flags.value()||*attribute.native_flags.value()!=0)
                return unsupported("metadata_replay.coverage_ea_interpretation_flags");
            const auto* name=attribute.identifier.windows_ea_bytes();
            if(!name)return unsupported("metadata_replay.coverage_ea_namespace");
            std::string upper=*name;
            for(auto& byte:upper)if(byte>='a'&&byte<='z')byte=static_cast<char>(byte-'a'+'A');
            // NtQueryEaFile includes kernel EAs. These can require kernel-mode
            // writes, so refuse before effects rather than silently dropping
            // persistent state or treating a derived trust cache as replayable.
            if(upper.starts_with("$KERNEL."))return unsupported("metadata_replay.coverage_kernel_ea_not_replayable");
        }
        if(requested.channel_coverage!=DataChannelCoverage::WindowsFileStreamInfo||
           expected.channel_coverage!=requested.channel_coverage||requested.channels.size()!=expected.channels.size())
            return changed("metadata_replay.coverage_channel_manifest");
        const auto catalog_channels=source_->inspect_data_channels(expected.policy.limits);
        if(!catalog_channels.value()){const auto& e=*catalog_channels.unavailable_detail();return Result::unavailable(e.state,e.error);}
        const auto main_count=expected.basic.kind.value()&&*expected.basic.kind.value()==ObjectKind::Directory?0U:1U;
        if(catalog_channels.value()->coverage!=DataChannelCoverage::WindowsFileStreamInfo||
           !same_owner(catalog_channels.value()->owner,expected.basic.identity)||
           catalog_channels.value()->channels.size()!=expected.channels.size()+main_count)
            return changed("metadata_replay.coverage_source_channel_set");
        for(const auto& channel:expected.channels) {
            const auto requested_channel=std::find_if(requested.channels.begin(),requested.channels.end(),
                [&](const auto& item){return item.identifier==channel.identifier;});
            if(requested_channel==requested.channels.end()||requested_channel->logical_size!=channel.logical_size||
               requested_channel->digest!=channel.digest||requested_channel->source.get()!=channel.source.get()||
               !dynamic_cast<const WindowsMetadataChannel*>(channel.source.get()))
                return changed("metadata_replay.coverage_channel_binding");
            const auto current=std::find_if(catalog_channels.value()->channels.begin(),catalog_channels.value()->channels.end(),
                [&](const auto& item){return item.kind==DataChannelKind::NamedData&&item.identifier==channel.identifier;});
            if(current==catalog_channels.value()->channels.end()||!current->logical_size.value()||*current->logical_size.value()!=channel.logical_size)
                return changed("metadata_replay.coverage_source_channel_size");
            const auto state=channel.source->inspect();
            if(!state.value()){const auto& e=*state.unavailable_detail();return Result::unavailable(e.state,e.error);}
            if(state.value()->identifier!=channel.identifier||state.value()->logical_size!=channel.logical_size||
               compare_identity(state.value()->owner,*expected.basic.identity.value())!=IdentityComparison::Same)
                return changed("metadata_replay.coverage_channel_owner_size");
        }
        const auto classes=persistent_sacl_classes(original);
        if(!classes.value()){const auto& e=*classes.unavailable_detail();return Result::unavailable(e.state,e.error);}
        const auto qualified=source_->qualify_metadata_replay(expected.policy);
        if(!qualified.value()||!*qualified.value())return qualified;
        const auto basic=source_->inspect_basic();
        if(!basic.value()){const auto& e=*basic.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(!same_owner(basic.value()->identity,expected.basic.identity)||!basic.value()->kind.value()||
           !expected.basic.kind.value()||*basic.value()->kind.value()!=*expected.basic.kind.value())
            return changed("metadata_replay.coverage_source_identity");
        const auto actual=source_->read_security(SecurityPart::WindowsFullDescriptor,expected.policy.limits);
        if(!actual.value()){const auto& e=*actual.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(actual.value()->native_query_mask!=persistent_security_information||actual.value()->bytes!=original.bytes||
           !same_owner(actual.value()->owner,expected.basic.identity))return changed("metadata_replay.coverage_source_security_changed");
        const auto catalog=source_->inspect_attributes(expected.policy.limits);
        if(!catalog.value()){const auto& e=*catalog.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(catalog.value()->coverage!=AttributeCoverage::WindowsExtendedAttributes||
           !same_owner(catalog.value()->owner,expected.basic.identity)||catalog.value()->attributes.size()!=expected.attributes.size())
            return changed("metadata_replay.coverage_source_ea_set");
        for(const auto& descriptor:catalog.value()->attributes) {
            const auto found=std::find_if(expected.attributes.begin(),expected.attributes.end(),
                [&](const auto& item){return item.identifier==descriptor.identifier;});
            if(found==expected.attributes.end())return changed("metadata_replay.coverage_source_ea_name");
            const auto value=source_->read_attribute(descriptor.identifier,expected.policy.limits);
            if(!value.value()){const auto& e=*value.unavailable_detail();return Result::unavailable(e.state,e.error);}
            if(value.value()->bytes!=found->bytes||!value.value()->native_flags.value()||!found->native_flags.value()||
               *value.value()->native_flags.value()!=*found->native_flags.value()||!same_owner(value.value()->owner,expected.basic.identity))
                return changed("metadata_replay.coverage_source_ea_changed");
        }
        return Result::available(true);
    }
    void finish_capture_reads()const noexcept {
        auto* native=dynamic_cast<WindowsOpenedEntry*>(source_.get());
        if(native)native->finish_capture_reads();
        else detail::record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_capture.native_proof_source_missing"});
    }
private:
    std::unique_ptr<WindowsOpenedEntry> source_;
    MetadataReplaySnapshot observed_;
    std::shared_ptr<const void> capture_lease_;
};
Observation<std::shared_ptr<const MetadataSecurityCoverageEvidence>> WindowsOpenedEntry::issue_metadata_security_coverage(
    const MetadataReplaySnapshot& snapshot) const {
    using Result=Observation<std::shared_ptr<const MetadataSecurityCoverageEvidence>>;
    if(snapshot.policy.scope!=RegularMetadataScope::CompleteMetadataV1||snapshot.attribute_coverage!=AttributeCoverage::WindowsExtendedAttributes)
        return failure<std::shared_ptr<const MetadataSecurityCoverageEvidence>>(ERROR_INVALID_PARAMETER,"metadata_replay.coverage_policy");
    const auto channel_proof=verify_native_metadata_replay_channels(snapshot);
    if(!channel_proof.value()){const auto& e=*channel_proof.unavailable_detail();return Result::unavailable(e.state,e.error);}
    auto opened=synchronous_query_view(FILE_READ_EA|READ_CONTROL|ACCESS_SYSTEM_SECURITY);
    if(!opened.value()){const auto& e=*opened.unavailable_detail();return Result::unavailable(e.state,e.error);}
    auto evidence=std::make_shared<WindowsPersistentSecurityProof>(std::move(opened).take_value(),snapshot);
    const auto checked=evidence->recheck(snapshot);
    if(!checked.value()){const auto& e=*checked.unavailable_detail();return Result::unavailable(e.state,e.error);}
    if(!*checked.value())return failure<std::shared_ptr<const MetadataSecurityCoverageEvidence>>(ERROR_INVALID_DATA,"metadata_replay.coverage_false");
    return Result::available(std::move(evidence));
}
Observation<bool> WindowsOpenedEntry::verify_metadata_security_coverage(const MetadataReplaySnapshot& snapshot) const {
    const auto* proof=dynamic_cast<const WindowsPersistentSecurityProof*>(snapshot.security_coverage.get());
    if(!proof)return Observation<bool>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"metadata_replay.native_security_evidence_required"});
    const auto qualified=qualify_metadata_replay(snapshot.policy);
    if(!qualified.value()||!*qualified.value())return qualified;
    return proof->recheck(snapshot);
}
Observation<bool> WindowsOpenedEntry::preflight_metadata_security_coverage(const MetadataReplaySnapshot& snapshot) {
    using Result=Observation<bool>;
    if(!content_write_access_||(!publication_&&!directory_metadata_target_))return failure<bool>(ERROR_ACCESS_DENIED,"metadata_replay.coverage_target_access");
    const auto checked=verify_metadata_security_coverage(snapshot);
    if(!checked.value()||!*checked.value())return checked;
    const auto privilege=require_enabled_security_privilege();
    if(!privilege.value())return privilege;
    auto opened=ensure_metadata_security_handle(READ_CONTROL|WRITE_OWNER|WRITE_DAC|ACCESS_SYSTEM_SECURITY);
    if(!opened.value()){const auto& e=*opened.unavailable_detail();return Result::unavailable(e.state,e.error);}
    // Actual all-class target query also rejects unknown masks/providers before
    // ownership, ACL, attribute or timestamp mutation.
    const auto security=read_security(SecurityPart::WindowsFullDescriptor,snapshot.policy.limits);
    if(!security.value()){const auto& e=*security.unavailable_detail();return Result::unavailable(e.state,e.error);}
    const auto classes=persistent_sacl_classes(*security.value());
    if(!classes.value()){const auto& e=*classes.unavailable_detail();return Result::unavailable(e.state,e.error);}
    const auto attributes=inspect_attributes(snapshot.policy.limits);
    if(!attributes.value()){const auto& e=*attributes.unavailable_detail();return Result::unavailable(e.state,e.error);}
    for(const auto& item:attributes.value()->attributes) {
        const auto* name=item.identifier.windows_ea_bytes();
        if(!name)return failure<bool>(ERROR_NOT_SUPPORTED,"metadata_replay.target_ea_namespace");
        std::string upper=*name;for(auto& byte:upper)if(byte>='a'&&byte<='z')byte=static_cast<char>(byte-'a'+'A');
        if(upper.starts_with("$KERNEL."))return failure<bool>(ERROR_NOT_SUPPORTED,"metadata_replay.target_kernel_ea_not_replayable");
    }
    return Result::available(true);
}

Observation<detail::WindowsParentIds> windows_parent_ids(HANDLE handle, IdentityScheme scheme) {
    using Result = Observation<detail::WindowsParentIds>;
    static_assert(offsetof(USN_RECORD_V2, FileName) == 60 && offsetof(USN_RECORD_V3, FileName) == 76);
    const WORD major = scheme == IdentityScheme::WindowsFileId128 ? 3 : scheme == IdentityScheme::WindowsFileIndex64 ? 2 : 0;
    if (major == 0) return Result::unavailable(ObservationState::Unknown,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity), "parent.usn_scheme"});
    READ_FILE_USN_DATA input{major, major};
    // USHORT name length plus the largest supported header, rounded to 8 bytes.
    alignas(8) std::array<std::byte, 65536 + 80> buffer{};
    DWORD bytes = 0;
    if (!DeviceIoControl(handle, FSCTL_READ_FILE_USN_DATA, &input, sizeof(input), buffer.data(), static_cast<DWORD>(buffer.size()), &bytes, nullptr)) {
        const auto code = GetLastError();
        if (code == ERROR_JOURNAL_NOT_ACTIVE || code == ERROR_JOURNAL_DELETE_IN_PROGRESS)
            return Result::unavailable(ObservationState::Unsupported, {ErrorDomain::Win32, code, "FSCTL_READ_FILE_USN_DATA.parent"});
        return failure<detail::WindowsParentIds>(code, "FSCTL_READ_FILE_USN_DATA.parent");
    }
    if (bytes > buffer.size()) return Result::unavailable(ObservationState::Failed,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "parent.usn_bytes"});
    return detail::decode_windows_parent_record(std::span<const std::byte>(buffer).first(bytes), major);
}
Observation<std::unique_ptr<OpenedEntry>> open_windows_parent(HANDLE child, const AdapterScope& scope) {
    using Result = Observation<std::unique_ptr<OpenedEntry>>;
    const auto check = [](const Observation<BasicMetadata>& metadata) -> std::optional<UnavailableObservation> {
        if (!metadata.value()) return *metadata.unavailable_detail();
        if (!metadata.value()->kind.value()) return *metadata.value()->kind.unavailable_detail();
        if (*metadata.value()->kind.value() != ObjectKind::Directory) return UnavailableObservation{ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "parent.object_kind"}};
        const auto review = provider_review_required(*metadata.value(), StorageModel::WindowsHandleAttributes);
        if (!review.value()) return *review.unavailable_detail();
        if (*review.value()) return UnavailableObservation{ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::ProviderReviewRequired), "parent.provider_review"}};
        return {};
    };
    const auto before = handle_metadata(child, scope);
    if (const auto denied = check(before)) return Result::unavailable(denied->state, denied->error);
    if (!before.value()->identity.value()) { const auto& e = *before.value()->identity.unavailable_detail(); return Result::unavailable(e.state, e.error); }
    const auto& own = *before.value()->identity.value();
    auto ids = windows_parent_ids(child, own.scheme);
    if (!ids.value()) { const auto& e = *ids.unavailable_detail(); return Result::unavailable(e.state, e.error); }
    const auto qualify = [&](const NativeIdentifier& id, const ObjectIdentity& observed) -> std::optional<UnavailableObservation> {
        const auto compared = compare_identity({scope, ids.value()->scheme, own.volume, id, {}}, observed);
        if (compared == IdentityComparison::Same) return {};
        return UnavailableObservation{compared == IdentityComparison::Different ? ObservationState::Changed : ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(compared == IdentityComparison::Different ? AdapterError::MetadataChanged : AdapterError::UnqualifiedIdentity), "parent.usn_identity"}};
    };
    if (const auto mismatch = qualify(ids.value()->child, own)) return Result::unavailable(mismatch->state, mismatch->error);
    if ((ids.value()->attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) return Result::unavailable(ObservationState::Changed,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "parent.usn_kind"});
    FILE_ID_DESCRIPTOR descriptor{}; descriptor.dwSize = sizeof(descriptor);
    if (own.scheme == IdentityScheme::WindowsFileId128) { descriptor.Type = ExtendedFileIdType; std::memcpy(descriptor.ExtendedFileId.Identifier, ids.value()->parent.bytes.data(), 16); }
    else { descriptor.Type = FileIdType; std::memcpy(&descriptor.FileId.QuadPart, ids.value()->parent.bytes.data(), 8); }
    // Original live directory supplies the volume hint. No basename/path open,
    // enumeration, FILE_READ_DATA, backup intent, elevation or journal mutation.
    OwnedHandle parent(OpenFileById(child, &descriptor, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL));
    if (parent.get() == INVALID_HANDLE_VALUE || parent.get() == nullptr) return failure<std::unique_ptr<OpenedEntry>>(GetLastError(), "OpenFileById.parent");
    auto opened = std::make_unique<WindowsOpenedEntry>(std::move(parent), scope);
    const auto metadata = opened->inspect_basic();
    if (const auto denied = check(metadata)) return Result::unavailable(denied->state, denied->error);
    if (!metadata.value()->identity.value()) { const auto& e = *metadata.value()->identity.unavailable_detail(); return Result::unavailable(e.state, e.error); }
    if (const auto mismatch = qualify(ids.value()->parent, *metadata.value()->identity.value())) return Result::unavailable(mismatch->state, mismatch->error);
    const auto again = windows_parent_ids(child, own.scheme);
    if (!again.value()) { const auto& e = *again.unavailable_detail(); return Result::unavailable(e.state, e.error); }
    if (again.value()->scheme != ids.value()->scheme || again.value()->child != ids.value()->child || again.value()->parent != ids.value()->parent ||
        (again.value()->attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        return Result::unavailable(ObservationState::Changed, {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "parent.usn_changed"});
    const auto after = handle_metadata(child, scope);
    if (const auto denied = check(after)) return Result::unavailable(denied->state, denied->error);
    if (!after.value()->identity.value()) { const auto& e = *after.value()->identity.unavailable_detail(); return Result::unavailable(e.state, e.error); }
    if (const auto mismatch = qualify(ids.value()->child, *after.value()->identity.value())) return Result::unavailable(mismatch->state, mismatch->error);
    return Result::available(std::move(opened));
}
Observation<std::unique_ptr<OpenedEntry>> WindowsOpenedEntry::open_parent_directory() const {
    if (rename_access_) {
        auto view=synchronous_query_view(0);
        if(!view.value()){const auto& e=*view.unavailable_detail();return Observation<std::unique_ptr<OpenedEntry>>::unavailable(e.state,e.error);}
        return (*view.value())->open_parent_directory();
    }
    return open_windows_parent(handle_.get(), scope_);
}

// Public FILE_FS_FULL_SIZE_INFORMATION wire layout. The desktop SDK does not
// declare this WDK structure; no private members or syscall numbers are used.
struct alignas(8) VolumeSpaceCounters {
    std::int64_t total;
    std::int64_t caller_available;
    std::int64_t actual_available;
    std::uint32_t sectors_per_unit;
    std::uint32_t bytes_per_sector;
};
static_assert(sizeof(VolumeSpaceCounters) == 32 && offsetof(VolumeSpaceCounters, sectors_per_unit) == 24);
Observation<VolumeSpaceCounters> volume_space(HANDLE handle) {
    using Result = Observation<VolumeSpaceCounters>;
    using QueryVolume = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
    const auto address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVolumeInformationFile");
    if (!address) return Result::unavailable(ObservationState::Unsupported, {ErrorDomain::Win32, GetLastError(), "NtQueryVolumeInformationFile.resolve"});
    const auto query = std::bit_cast<QueryVolume>(address);
    VolumeSpaceCounters counters{};
    IO_STATUS_BLOCK io{};
    // FileFsFullSizeInformation = 7 in the documented FS information classes.
    // This directory's Win32 handle is synchronous (no OVERLAPPED flag).
    const auto status = query(handle, &io, &counters, sizeof(counters), 7);
    if (status != 0) return Result::unavailable(error_state(RtlNtStatusToDosError(status)),
        {ErrorDomain::NtStatus, static_cast<std::uint32_t>(status), "NtQueryVolumeInformationFile.full_size"});
    if (io.Information != sizeof(counters)) return Result::unavailable(ObservationState::Failed,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "NtQueryVolumeInformationFile.full_size_length"});
    return Result::available(counters);
}

class WindowsDirectoryCursor final : public DirectoryCursor {
    friend class WindowsOpenedEntry;
    friend class WindowsTargetReadSeed;
public:
    Observation<std::shared_ptr<const OpenedEntry>> open_progressive_directory_source(const MetadataReplayPolicy& policy)const {
        using R=Observation<std::shared_ptr<const OpenedEntry>>;HANDLE h=nullptr;
        if(!DuplicateHandle(GetCurrentProcess(),handle_.get(),GetCurrentProcess(),&h,0,FALSE,DUPLICATE_SAME_ACCESS))
            return failure<std::shared_ptr<const OpenedEntry>>(GetLastError(),"metadata_capture.directory_query_dup");
        WindowsOpenedEntry held(OwnedHandle(h),scope_);
        return held.open_progressive_metadata_source(policy);
    }


    WindowsDirectoryCursor(OwnedHandle handle, Observation<ObjectIdentity> native_identity, AdapterScope scope)
        : DirectoryCursor(std::move(native_identity)), handle_(std::move(handle)), scope_(std::move(scope)) {}
    Observation<AdapterScope> source_scope() const override { return Observation<AdapterScope>::available(scope_); }
    Observation<WindowsTrashHandle> duplicate_trash_parent() const {
        HANDLE raw=nullptr;
        if(!DuplicateHandle(GetCurrentProcess(),handle_.get(),GetCurrentProcess(),&raw,0,FALSE,DUPLICATE_SAME_ACCESS))
            return Observation<WindowsTrashHandle>::unavailable(error_state(GetLastError()),
                {ErrorDomain::Win32,GetLastError(),"trash.duplicate_parent"});
        return Observation<WindowsTrashHandle>::available(WindowsTrashHandle(raw));
    }
    Observation<BasicMetadata> inspect_basic() const override { return handle_metadata(handle_.get(), scope_); }
    Observation<std::unique_ptr<OpenedEntry>> open_parent_directory() const override { return open_windows_parent(handle_.get(), scope_); }
    Observation<CreatedStagingFile> create_staging_file(const NativeName& recovery_hint) const override {
        using Result=Observation<CreatedStagingFile>;
        const auto qualified=qualify_identity_bound_rename();
        if (!qualified.value()) {const auto& e=*qualified.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if (!*qualified.value()) return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"staging.windows_publication_unqualified"});
        auto created=create_child_file(recovery_hint);
        if (!created.value()) {const auto& e=*created.unavailable_detail();return Result::unavailable(e.state,e.error);}
        // The original DELETE-bearing writer denies WRITE/DELETE sharing
        // from NtCreateFile through same-handle no-replace publication.
        return Result::available({std::move(created).take_value(),StagingNamespace::Named,recovery_hint});
    }
    Observation<std::unique_ptr<OpenedEntry>> create_child_file(const NativeName& name) const override {
        using Result = Observation<std::unique_ptr<OpenedEntry>>;
        const auto* units = name.windows_units();
        if (!units || !name.is_valid() || units->find(u':') != std::u16string::npos ||
            units->size() > std::numeric_limits<USHORT>::max() / sizeof(WCHAR))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidPath), "create_child_file.name"});
        std::wstring spelling;
        spelling.reserve(units->size());
        for (const auto unit : *units) spelling.push_back(static_cast<wchar_t>(unit));
        HANDLE retained_raw = nullptr;
        if (!DuplicateHandle(GetCurrentProcess(), handle_.get(), GetCurrentProcess(), &retained_raw,
                             0, FALSE, DUPLICATE_SAME_ACCESS))
            return failure<std::unique_ptr<OpenedEntry>>(GetLastError(), "create_child_file.parent_handle");
        OwnedHandle retained_parent(retained_raw);
        auto parent_identity = ::ck::files::identity(handle_.get(), scope_);
        if (!parent_identity.value()) {
            const auto& error = *parent_identity.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        UNICODE_STRING native_name{};
        native_name.Length = static_cast<USHORT>(spelling.size() * sizeof(WCHAR));
        native_name.MaximumLength = native_name.Length;
        native_name.Buffer = spelling.data();
        OBJECT_ATTRIBUTES attributes{};
        attributes.Length = sizeof(attributes);
        attributes.RootDirectory = handle_.get();
        attributes.ObjectName = &native_name;
        IO_STATUS_BLOCK io{};
        HANDLE raw = nullptr;
        const NTSTATUS status = NtCreateFile(&raw, FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | DELETE,
            &attributes, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
            // Exclusion starts atomically with creation. No external writer
            // or DELETE-bearing opener can race staged data/metadata or the
            // held-handle publication; the original handle already has DELETE.
            FILE_SHARE_READ, FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH,
            nullptr, 0);
        OwnedHandle opened(raw);
        if (status < 0)
            return Result::unavailable(error_state(RtlNtStatusToDosError(status)),
                {ErrorDomain::NtStatus, static_cast<std::int64_t>(status), "NtCreateFile.create_child_file"});
        if (io.Information != FILE_CREATED || raw == nullptr || raw == INVALID_HANDLE_VALUE)
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "create_child_file.result"});
        FILE_BASIC_INFO basic{};
        if (!GetFileInformationByHandleEx(opened.get(), FileBasicInfo, &basic, sizeof(basic)))
            return failure<std::unique_ptr<OpenedEntry>>(GetLastError(), "create_child_file.info");
        if ((basic.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "create_child_file.kind"});
        return Result::available(std::make_unique<WindowsOpenedEntry>(std::move(opened), scope_, false, true, true,
            std::make_unique<WindowsPublicationContext>(std::move(retained_parent), name, std::move(parent_identity))));
    }
    Observation<bool> create_hard_link(const NativeName& source_name, const ObjectIdentity& expected_source,
                                       const DirectoryCursor& destination,
                                       const NativeName& destination_name) const override {
        using Result = Observation<bool>;
        const auto *target = dynamic_cast<const WindowsDirectoryCursor *>(&destination);
        const auto *source_units = source_name.windows_units();
        const auto *destination_units = destination_name.windows_units();
        if (!target || !source_units || !destination_units || !source_name.is_valid() || !destination_name.is_valid() ||
            source_units->find(u':') != std::u16string::npos || destination_units->find(u':') != std::u16string::npos ||
            source_units->size() > std::numeric_limits<USHORT>::max() / sizeof(WCHAR) ||
            destination_units->size() > std::numeric_limits<USHORT>::max() / sizeof(WCHAR))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidPath), "create_hard_link.name"});
        const auto destination_identity = target->identity();
        if (!destination_identity.value() || expected_source.scope != scope_ ||
            destination_identity.value()->scope != scope_ || expected_source.scheme != destination_identity.value()->scheme ||
            expected_source.volume != destination_identity.value()->volume)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity),
                 "create_hard_link.parent_identity"});
        auto source_opened = open_native_component(source_name, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                                                   ChildLookupMode::NativeDefault, true);
        if (!source_opened.value()) {
            const auto &error = *source_opened.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        auto source = std::move(source_opened).take_value();
        const auto source_metadata = handle_metadata(source.get(), scope_);
        if (!source_metadata.value() || !source_metadata.value()->identity.value() ||
            compare_identity(*source_metadata.value()->identity.value(), expected_source) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged),
                 "create_hard_link.source_identity"});
        if (!source_metadata.value()->kind.value() || *source_metadata.value()->kind.value() != ObjectKind::RegularFile)
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "create_hard_link.source_kind"});
        auto destination_access = target->open_namespace_write_handle();
        if (!destination_access.value()) {
            const auto &error = *destination_access.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        std::wstring spelling;
        spelling.reserve(destination_units->size());
        for (const auto unit : *destination_units) spelling.push_back(static_cast<wchar_t>(unit));
        const auto length = spelling.size() * sizeof(WCHAR);
        if (length > std::numeric_limits<ULONG>::max() - offsetof(FileLinkInformationCompat, FileName))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InventoryLimit),
                 "create_hard_link.name_limit"});
        std::vector<std::byte> buffer(std::max(sizeof(FileLinkInformationCompat),offsetof(FileLinkInformationCompat, FileName) + length));
        auto *info = reinterpret_cast<FileLinkInformationCompat *>(buffer.data());
        info->ReplaceIfExists = FALSE;
        info->RootDirectory = destination_access.value()->get();
        info->FileNameLength = static_cast<ULONG>(length);
        std::memcpy(info->FileName, spelling.data(), length);
        if (!set_file_link_information(source.get(), info, static_cast<ULONG>(buffer.size()))) {
            const DWORD code = GetLastError();
            if (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS)
                return Result::unavailable(ObservationState::Changed,
                    {ErrorDomain::Win32, code, "create_hard_link.destination_occupied"});
            if (code == ERROR_INVALID_FUNCTION || code == ERROR_NOT_SUPPORTED || code == ERROR_CALL_NOT_IMPLEMENTED ||
                code == ERROR_INVALID_PARAMETER)
                return Result::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Win32, code, "create_hard_link.native_query"});
            return Result::unavailable(error_state(code), {ErrorDomain::Win32, code, "create_hard_link.native_query"});
        }
        auto published = target->open_native_component(destination_name, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                                        ChildLookupMode::NativeDefault, true);
        if (!published.value())
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult),
                 "create_hard_link.published_identity"});
        const auto published_identity = ::ck::files::identity(published.value()->get(), scope_);
        if (!published_identity.value() ||
            compare_identity(*published_identity.value(), *source_metadata.value()->identity.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged),
                 "create_hard_link.published_identity"});
        if (!FlushFileBuffers(destination_access.value()->get()))
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32, GetLastError(), "create_hard_link.directory_flush"});
        return Result::available(true);
    }
    Observation<std::unique_ptr<DirectoryCursor>> create_child_directory(const NativeName& name) const override {
        using Result = Observation<std::unique_ptr<DirectoryCursor>>;
        const auto* units = name.windows_units();
        if (!units || !name.is_valid() || units->find(u':') != std::u16string::npos ||
            units->size() > std::numeric_limits<USHORT>::max() / sizeof(WCHAR))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidPath), "create_child_directory.name"});
        std::wstring spelling;
        spelling.reserve(units->size());
        for (const auto unit : *units) spelling.push_back(static_cast<wchar_t>(unit));
        UNICODE_STRING native_name{};
        native_name.Length = static_cast<USHORT>(spelling.size() * sizeof(WCHAR));
        native_name.MaximumLength = native_name.Length;
        native_name.Buffer = spelling.data();
        OBJECT_ATTRIBUTES attributes{};
        attributes.Length = sizeof(attributes);
        attributes.RootDirectory = handle_.get();
        attributes.ObjectName = &native_name;
        IO_STATUS_BLOCK io{};
        HANDLE raw = nullptr;
        const NTSTATUS status = NtCreateFile(&raw, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes, &io, nullptr, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH,
            nullptr, 0);
        OwnedHandle opened(raw);
        if (status < 0) {
            const DWORD code = RtlNtStatusToDosError(status);
            if (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS)
                return Result::unavailable(ObservationState::Changed,
                    {ErrorDomain::Win32, code, "NtCreateFile.create_child_directory.existing"});
            return Result::unavailable(error_state(code),
                {ErrorDomain::NtStatus, static_cast<std::int64_t>(status), "NtCreateFile.create_child_directory"});
        }
        if (io.Information != FILE_CREATED || raw == nullptr || raw == INVALID_HANDLE_VALUE)
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "create_child_directory.result"});
        FILE_BASIC_INFO basic{};
        if (!GetFileInformationByHandleEx(opened.get(), FileBasicInfo, &basic, sizeof(basic)))
            return failure<std::unique_ptr<DirectoryCursor>>(GetLastError(), "create_child_directory.info");
        if ((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
            (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "create_child_directory.kind"});
        auto observed = ::ck::files::identity(opened.get(), scope_);
        if (!observed.value()) {
            const auto& error = *observed.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        auto parent_access = open_namespace_write_handle();
        if (!parent_access.value()) {
            const auto& error = *parent_access.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!FlushFileBuffers(parent_access.value()->get()))
            return failure<std::unique_ptr<DirectoryCursor>>(GetLastError(),
                "FlushFileBuffers.create_child_directory_parent");
        return Result::available(std::make_unique<WindowsDirectoryCursor>(std::move(opened), std::move(observed), scope_));
    }
    Observation<bool> retire_child(const NativeName& name, const ObjectIdentity& expected_identity) const override {
        using Result = Observation<bool>;
        if (!name.is_valid() || compare_identity(expected_identity, expected_identity) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity), "retire_child.input"});
        // Open relative to the retained parent with DELETE access and
        // no-reparse semantics. The resulting handle, not the basename, is
        // the disposition target, so a rename after open cannot redirect the
        // delete to a replacement object.
        auto opened = open_native_component(name, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                             ChildLookupMode::NativeDefault);
        if (!opened.value()) {
            const auto& error = *opened.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        auto source = std::move(opened).take_value();
        const auto metadata = handle_metadata(source.get(), scope_);
        if (!metadata.value()) {
            const auto& error = *metadata.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!metadata.value()->identity.value() ||
            compare_identity(*metadata.value()->identity.value(), expected_identity) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "retire_child.identity"});
        if (!metadata.value()->kind.value())
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity), "retire_child.kind"});
        if (*metadata.value()->kind.value() == ObjectKind::Directory) {
            // Directory retirement is deliberately limited to an empty
            // directory. The probe is relative to this held parent and its
            // identity is checked before the handle-bound disposition below;
            // no recursive pathname deletion is attempted.
            auto child_directory = open_directory_child(name);
            if (!child_directory.value()) {
                const auto &error = *child_directory.unavailable_detail();
                return Result::unavailable(error.state, error.error);
            }
            const auto child_identity = (*child_directory.value())->identity();
            if (!child_identity.value() ||
                compare_identity(*child_identity.value(), expected_identity) != IdentityComparison::Same)
                return Result::unavailable(ObservationState::Changed,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged),
                     "retire_child.directory_identity"});
            const auto entries = (*child_directory.value())->read(DirectoryCursor::max_batch_size);
            if (entries.error)
                return Result::unavailable(entries.error->state, entries.error->error);
            if (!entries.names.empty() || entries.state == DirectoryReadState::More)
                return Result::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable),
                     "retire_child.nonempty_directory"});
        } else if (*metadata.value()->kind.value() != ObjectKind::RegularFile)
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "retire_child.kind"});

        FILE_STANDARD_INFO standard{};
        if (!GetFileInformationByHandleEx(source.get(), FileStandardInfo, &standard, sizeof(standard)))
            return failure<bool>(GetLastError(), "retire_child.standard_info");
        // A selected hard-link alias is not a removable single-source object;
        // preserve the link group until the planner supplies its full policy.
        if (standard.NumberOfLinks != 1)
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), "retire_child.hard_link"});

        FILE_DISPOSITION_INFO disposition{};
        disposition.DeleteFile = TRUE;
        if (!SetFileInformationByHandle(source.get(), FileDispositionInfo, &disposition, sizeof(disposition))) {
            const DWORD code = GetLastError();
            return Result::unavailable(code == ERROR_IO_PENDING ? ObservationState::Unknown : error_state(code),
                {ErrorDomain::Win32, code, "retire_child.disposition"});
        }
        auto parent_access = open_namespace_write_handle();
        if (!parent_access.value()) {
            const auto& error = *parent_access.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        if (!FlushFileBuffers(parent_access.value()->get()))
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32, GetLastError(), "retire_child.directory_flush"});
        return Result::available(true);
    }
    Observation<bool> discard_child(const NativeName& name, const ObjectIdentity& expected_identity) const override {
        // Staging cleanup uses the same handle-bound disposition protocol as
        // source retirement, but is exposed separately so callers cannot
        // mistake cleanup for an authorized Move operation.
        return retire_child(name, expected_identity);
    }
    Observation<bool> trash_child(const NativeName& name, const ObjectIdentity& expected_identity) const override {
        using Result = Observation<bool>;
        const auto* units = name.windows_units();
        if (!name.is_valid() || !units || units->find(u':') != std::u16string::npos ||
            units->find(u'\\') != std::u16string::npos || units->find(u'/') != std::u16string::npos ||
            units->size() > std::numeric_limits<USHORT>::max() / sizeof(WCHAR) ||
            compare_identity(expected_identity, expected_identity) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity), "trash_child.input"});

        // The source handle denies concurrent writers and namespace deletion.
        // The handle, rather than the original basename, is the object moved
        // into the Recycle Bin. This is the race boundary that a shell/path
        // based recycle call cannot provide.
        auto opened = open_native_component(name, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                             ChildLookupMode::NativeDefault, true);
        if (!opened.value()) {
            const auto& error = *opened.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        auto source = std::move(opened).take_value();
        const auto metadata = handle_metadata(source.get(), scope_);
        if (!metadata.value() || !metadata.value()->identity.value() ||
            compare_identity(*metadata.value()->identity.value(), expected_identity) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "trash_child.identity"});
        if (!metadata.value()->kind.value() ||
            (*metadata.value()->kind.value() != ObjectKind::RegularFile &&
             *metadata.value()->kind.value() != ObjectKind::Directory))
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "trash_child.kind"});
        FILE_STANDARD_INFO standard{};
        if (!GetFileInformationByHandleEx(source.get(), FileStandardInfo, &standard, sizeof(standard)))
            return failure<bool>(GetLastError(), "trash_child.standard_info");
        if (*metadata.value()->kind.value() == ObjectKind::RegularFile && standard.NumberOfLinks != 1)
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), "trash_child.hard_link"});

        auto parent_path = final_path(handle_.get(), "trash_child.parent_path");
        if (!parent_path.value()) return Result::unavailable(parent_path.unavailable_detail()->state,
                                                             parent_path.unavailable_detail()->error);
        std::wstring original_path = *parent_path.value();
        if (original_path.empty() || original_path.size() > std::numeric_limits<std::size_t>::max() - units->size())
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), "trash_child.original_path"});
        if (original_path.back() != L'\\') original_path.push_back(L'\\');
        original_path.append(units->begin(), units->end());
        // Recycle Bin v2 stores a fixed 260-WCHAR original path field.
        if (original_path.size() >= 260)
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), "trash_child.original_path_limit"});

        const auto volume = volume_path_for(*parent_path.value());
        if (!volume.value())
            return Result::unavailable(volume.unavailable_detail()->state, volume.unavailable_detail()->error);
        std::wstring recycle_root = *volume.value();
        if (recycle_root.empty() || recycle_root.back() != L'\\') recycle_root.push_back(L'\\');
        recycle_root += L"$Recycle.Bin";
        if (!CreateDirectoryW(recycle_root.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
            return failure<bool>(GetLastError(), "trash_child.recycle_root");
        auto sid = current_user_sid();
        if (!sid.value()) return Result::unavailable(sid.unavailable_detail()->state,
                                                     sid.unavailable_detail()->error);
        const std::wstring recycle_directory_path = recycle_root + L"\\" + *sid.value();
        if (!CreateDirectoryW(recycle_directory_path.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
            return failure<bool>(GetLastError(), "trash_child.recycle_user_directory");

        auto open_recycle_directory = [&]() -> Observation<OwnedHandle> {
            HANDLE raw = CreateFileW(recycle_directory_path.c_str(),
                FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (raw == INVALID_HANDLE_VALUE) return failure<OwnedHandle>(GetLastError(), "trash_child.recycle_directory");
            OwnedHandle directory(raw);
            FILE_BASIC_INFO basic{};
            if (!GetFileInformationByHandleEx(directory.get(), FileBasicInfo, &basic, sizeof(basic)))
                return failure<OwnedHandle>(GetLastError(), "trash_child.recycle_directory_info");
            if ((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                return Observation<OwnedHandle>::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable),
                     "trash_child.recycle_directory_kind"});
            return Observation<OwnedHandle>::available(std::move(directory));
        };
        auto recycle_directory = open_recycle_directory();
        if (!recycle_directory.value()) return Result::unavailable(recycle_directory.unavailable_detail()->state,
                                                                    recycle_directory.unavailable_detail()->error);

        static std::atomic<std::uint64_t> sequence{1};
        const auto seed = static_cast<std::uint64_t>(GetTickCount64()) ^
            (static_cast<std::uint64_t>(GetCurrentProcessId()) << 32U);
        OwnedHandle metadata_file;
        std::wstring r_name;
        std::wstring i_name;
        std::wstring r_path;
        std::wstring i_path;
        for (unsigned attempt = 0; attempt != 32 && !metadata_file; ++attempt) {
            const auto suffix = hex_suffix(seed ^ sequence.fetch_add(1, std::memory_order_relaxed) ^ attempt);
            r_name = L"$R" + suffix;
            i_name = L"$I" + suffix;
            r_path = recycle_directory_path + L"\\" + r_name;
            i_path = recycle_directory_path + L"\\" + i_name;
            HANDLE existing = CreateFileW(r_path.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (existing != INVALID_HANDLE_VALUE) {
                CloseHandle(existing);
                continue;
            }
            const DWORD existing_error = GetLastError();
            if (existing_error != ERROR_FILE_NOT_FOUND && existing_error != ERROR_PATH_NOT_FOUND)
                return failure<bool>(existing_error, "trash_child.recycle_name_probe");
            HANDLE raw = CreateFileW(i_path.c_str(), GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, nullptr);
            if (raw != INVALID_HANDLE_VALUE) metadata_file.reset(raw);
            else if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS)
                return failure<bool>(GetLastError(), "trash_child.metadata_create");
        }
        if (!metadata_file)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InventoryLimit),
                 "trash_child.recycle_name_exhausted"});

        std::array<std::byte, 544> metadata_bytes{};
        auto put_u64 = [&metadata_bytes](std::size_t offset, std::uint64_t value) {
            for (unsigned byte = 0; byte != 8; ++byte)
                metadata_bytes[offset + byte] = static_cast<std::byte>((value >> (byte * 8U)) & 0xffU);
        };
        put_u64(0, 2); // Recycle Bin v2 metadata.
        const auto file_size = *metadata.value()->kind.value() == ObjectKind::RegularFile && standard.EndOfFile.QuadPart >= 0
            ? static_cast<std::uint64_t>(standard.EndOfFile.QuadPart) : 0;
        put_u64(8, file_size);
        FILETIME deletion_time{};
        GetSystemTimeAsFileTime(&deletion_time);
        put_u64(16, (static_cast<std::uint64_t>(deletion_time.dwHighDateTime) << 32U) |
            deletion_time.dwLowDateTime);
        std::memcpy(metadata_bytes.data() + 24, original_path.data(), original_path.size() * sizeof(wchar_t));
        DWORD written = 0;
        if (!WriteFile(metadata_file.get(), metadata_bytes.data(), static_cast<DWORD>(metadata_bytes.size()), &written, nullptr) ||
            written != metadata_bytes.size() || !FlushFileBuffers(metadata_file.get())) {
            const DWORD code = GetLastError();
            FILE_DISPOSITION_INFO cleanup{TRUE};
            SetFileInformationByHandle(metadata_file.get(), FileDispositionInfo, &cleanup, sizeof(cleanup));
            return failure<bool>(code, "trash_child.metadata_write");
        }

        const auto length = r_name.size() * sizeof(WCHAR);
        if (length > std::numeric_limits<ULONG>::max() - offsetof(FILE_RENAME_INFO, FileName))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "trash_child.recycle_name_limit"});
        std::vector<std::byte> rename_buffer(std::max(sizeof(FILE_RENAME_INFO),offsetof(FILE_RENAME_INFO, FileName) + length));
        auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(rename_buffer.data());
        rename->ReplaceIfExists = FALSE;
        rename->RootDirectory = recycle_directory.value()->get();
        rename->FileNameLength = static_cast<DWORD>(length);
        std::memcpy(rename->FileName, r_name.data(), length);
        if (!set_file_rename_information(source.get(), rename, static_cast<ULONG>(rename_buffer.size()))) {
            const DWORD code = GetLastError();
            FILE_DISPOSITION_INFO cleanup{TRUE};
            if (!SetFileInformationByHandle(metadata_file.get(), FileDispositionInfo, &cleanup, sizeof(cleanup)))
                return Result::unavailable(ObservationState::Unknown,
                    {ErrorDomain::Win32, GetLastError(), "trash_child.metadata_cleanup"});
            return Result::unavailable(error_state(code), {ErrorDomain::Win32, code, "trash_child.native_rename"});
        }

        HANDLE raw_published = CreateFileW(r_path.c_str(), FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (raw_published == INVALID_HANDLE_VALUE)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32, GetLastError(), "trash_child.recycle_identity"});
        OwnedHandle published(raw_published);
        const auto published_identity = ::ck::files::identity(published.get(), scope_);
        if (!published_identity.value() ||
            compare_identity(*published_identity.value(), expected_identity) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged),
                 "trash_child.recycle_identity"});
        auto parent_access = open_namespace_write_handle();
        if (!parent_access.value())
            return Result::unavailable(ObservationState::Unknown,
                parent_access.unavailable_detail()->error);
        if (!FlushFileBuffers(parent_access.value()->get()) ||
            !FlushFileBuffers(recycle_directory.value()->get()))
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32, GetLastError(), "trash_child.directory_flush"});
        return Result::available(true);
    }
    Observation<bool> qualify_identity_bound_rename() const override {
        using Result=Observation<bool>;
        const auto refuse=[](const char* op) {return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),op});};
        const auto basic=inspect_basic();
        if (!basic.value()) {const auto& e=*basic.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if (!basic.value()->kind.value() || *basic.value()->kind.value()!=ObjectKind::Directory ||
            !basic.value()->identity.value() || basic.value()->identity.value()->scheme!=IdentityScheme::WindowsFileId128 ||
            compare_identity(*basic.value()->identity.value(),*basic.value()->identity.value())!=IdentityComparison::Same)
            return refuse("rename.identity_bound.directory_identity");
        const auto provider=provider_review_required(*basic.value(),StorageModel::WindowsHandleAttributes);
        if (!provider.value()) {const auto& e=*provider.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if (*provider.value()) return refuse("rename.identity_bound.provider");
        DWORD flags=0;WCHAR filesystem[32]{};
        if (!GetVolumeInformationByHandleW(handle_.get(),nullptr,0,nullptr,nullptr,&flags,filesystem,32))
            return failure<bool>(GetLastError(),"rename.identity_bound.volume");
        if (std::wstring_view(filesystem)!=L"NTFS" && std::wstring_view(filesystem)!=L"ReFS") return refuse("rename.identity_bound.filesystem");
        const auto native_driver=detail::prove_windows_native_fsd(handle_.get());
        if(!native_driver.qualified)return Result::unavailable(native_driver.state,
            {native_driver.domain,native_driver.code,native_driver.operation});
        using QueryVolume=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
        const auto address=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryVolumeInformationFile");
        if (!address) return refuse("rename.identity_bound.device_query");
        struct DeviceInformation {ULONG type,characteristics;} device{};
        IO_STATUS_BLOCK io{};
        // Documented FileFsDeviceInformation=4; FILE_REMOTE_DEVICE=0x10.
        const auto status=std::bit_cast<QueryVolume>(address)(handle_.get(),&io,&device,sizeof(device),4);
        if (status!=0) return Result::unavailable(error_state(RtlNtStatusToDosError(status)),
            {ErrorDomain::NtStatus,static_cast<std::uint32_t>(status),"rename.identity_bound.device"});
        if (io.Information!=sizeof(device) || (device.characteristics&0x10U)!=0)
            return refuse("rename.identity_bound.remote_provider");
        auto writable=open_namespace_write_handle();
        if (!writable.value()) {const auto& e=*writable.unavailable_detail();return Result::unavailable(e.state,e.error);}
        return Result::available(true);
    }
    Observation<bool> rename_child_noreplace(const NativeName& name, const ObjectIdentity& expected_identity,
                                              const DirectoryCursor& destination,
                                              const NativeName& destination_name) const override {
        using Result = Observation<bool>;
        const auto* target = dynamic_cast<const WindowsDirectoryCursor*>(&destination);
        const auto* source_units = name.windows_units();
        const auto* destination_units = destination_name.windows_units();
        if (!target || !source_units || !destination_units || !name.is_valid() || !destination_name.is_valid() ||
            source_units->find(u':') != std::u16string::npos || destination_units->find(u':') != std::u16string::npos ||
            source_units->size() > std::numeric_limits<USHORT>::max() / sizeof(WCHAR) ||
            destination_units->size() > std::numeric_limits<USHORT>::max() / sizeof(WCHAR))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidPath), "rename_child_noreplace.name"});
        const auto destination_identity = target->identity();
        if (!destination_identity.value() || compare_identity(*destination_identity.value(), *destination_identity.value()) != IdentityComparison::Same ||
            expected_identity.scope != scope_ || destination_identity.value()->scope != scope_ ||
            expected_identity.scheme != destination_identity.value()->scheme ||
            expected_identity.volume != destination_identity.value()->volume)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity), "rename_child_noreplace.parent_identity"});

        auto source_opened = open_native_component(name, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                                   ChildLookupMode::NativeDefault);
        if (!source_opened.value()) {
            const auto& error = *source_opened.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        auto source = std::move(source_opened).take_value();
        const auto source_metadata = handle_metadata(source.get(), scope_);
        if (!source_metadata.value() || !source_metadata.value()->identity.value() ||
            compare_identity(*source_metadata.value()->identity.value(), expected_identity) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "rename_child_noreplace.source_identity"});

        auto occupied = target->open_native_component(destination_name, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                                      ChildLookupMode::NativeDefault);
        if (occupied.value())
            return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::PlanDecisionStale), "rename_child_noreplace.destination_occupied"});
        if (!occupied.unavailable_detail() || occupied.unavailable_detail()->state != ObservationState::Gone)
            return Result::unavailable(occupied.unavailable_detail() ? occupied.unavailable_detail()->state : ObservationState::Unknown,
                occupied.unavailable_detail() ? occupied.unavailable_detail()->error :
                    NativeError{ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "rename_child_noreplace.destination_probe"});

        // The enumeration cursor is intentionally not opened with namespace
        // write access. Acquire the durable source-parent handle before the
        // rename so a post-rename flush failure cannot be mistaken for a
        // pre-mutation refusal.
        auto source_access = open_namespace_write_handle();
        if (!source_access.value()) {
            const auto &error = *source_access.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        std::wstring spelling;
        spelling.reserve(destination_units->size());
        for (const auto unit : *destination_units) spelling.push_back(static_cast<wchar_t>(unit));
        auto destination_access = target->open_namespace_write_handle();
        if (!destination_access.value()) {
            const auto& error = *destination_access.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        const auto length = spelling.size() * sizeof(WCHAR);
        if (length > std::numeric_limits<ULONG>::max() - offsetof(FILE_RENAME_INFO, FileName))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "rename_child_noreplace.name_limit"});
        std::vector<std::byte> buffer(std::max(sizeof(FILE_RENAME_INFO),offsetof(FILE_RENAME_INFO, FileName) + length));
        auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
        info->ReplaceIfExists = FALSE;
        info->RootDirectory = destination_access.value()->get();
        info->FileNameLength = static_cast<DWORD>(length);
        std::memcpy(info->FileName, spelling.data(), length);
        if (!set_file_rename_information(source.get(), info, static_cast<ULONG>(buffer.size()))) {
            const DWORD code = GetLastError();
            if (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS)
                return Result::unavailable(ObservationState::Changed,
                    {ErrorDomain::Win32, code, "rename_child_noreplace.destination_occupied"});
            if (code == ERROR_INVALID_FUNCTION || code == ERROR_NOT_SUPPORTED || code == ERROR_CALL_NOT_IMPLEMENTED ||
                code == ERROR_INVALID_PARAMETER)
                return Result::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Win32, code, "rename_child_noreplace.atomic_primitive"});
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32, code, "rename_child_noreplace.atomic_primitive"});
        }

        auto published = target->open_native_component(destination_name, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                                       ChildLookupMode::NativeDefault);
        if (!published.value())
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "rename_child_noreplace.destination_identity"});
        const auto published_metadata = handle_metadata(published.value()->get(), scope_);
        if (!published_metadata.value() || !published_metadata.value()->identity.value() ||
            compare_identity(*published_metadata.value()->identity.value(), *source_metadata.value()->identity.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "rename_child_noreplace.destination_identity"});
        if (!FlushFileBuffers(source_access.value()->get()) || !FlushFileBuffers(destination_access.value()->get()))
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32, GetLastError(), "rename_child_noreplace.directory_flush"});
        return Result::available(true);
    }
    Observation<bool> rename_child_case_only(const NativeName& name, const ObjectIdentity& expected_identity,
                                              const NativeName& destination_name) const override {
        using Result = Observation<bool>;
        const auto* source_units = name.windows_units();
        const auto* destination_units = destination_name.windows_units();
        if (!source_units || !destination_units || !name.is_valid() || !destination_name.is_valid() ||
            name == destination_name || source_units->find(u':') != std::u16string::npos ||
            destination_units->find(u':') != std::u16string::npos ||
            source_units->size() > std::numeric_limits<USHORT>::max() / sizeof(WCHAR) ||
            destination_units->size() > std::numeric_limits<USHORT>::max() / sizeof(WCHAR))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidPath), "rename_child_case_only.name"});
        auto source_opened = open_native_component(name, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                                   ChildLookupMode::NativeDefault);
        if (!source_opened.value()) {
            const auto& error = *source_opened.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        auto source = std::move(source_opened).take_value();
        const auto source_metadata = handle_metadata(source.get(), scope_);
        if (!source_metadata.value() || !source_metadata.value()->identity.value() ||
            compare_identity(*source_metadata.value()->identity.value(), expected_identity) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "rename_child_case_only.source_identity"});
        if (source_metadata.value()->kind.value() && *source_metadata.value()->kind.value() == ObjectKind::RegularFile) {
            FILE_STANDARD_INFO standard{};
            if (!GetFileInformationByHandleEx(source.get(), FileStandardInfo, &standard, sizeof(standard)))
                return failure<bool>(GetLastError(), "rename_child_case_only.standard_info");
            if (standard.NumberOfLinks != 1)
                return Result::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), "rename_child_case_only.hard_link"});
        }

        auto destination = open_native_component(destination_name, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                                 ChildLookupMode::NativeDefault);
        if (!destination.value()) {
            if (destination.unavailable_detail() && destination.unavailable_detail()->state == ObservationState::Gone)
                return Result::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), "rename_child_case_only.native_case_proof"});
            const auto& error = *destination.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        const auto destination_metadata = handle_metadata(destination.value()->get(), scope_);
        if (!destination_metadata.value() || !destination_metadata.value()->identity.value())
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "rename_child_case_only.destination_identity"});
        if (compare_identity(*destination_metadata.value()->identity.value(), *source_metadata.value()->identity.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Changed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::PlanDecisionStale), "rename_child_case_only.destination_occupied"});

        std::wstring spelling;
        spelling.reserve(destination_units->size());
        for (const auto unit : *destination_units) spelling.push_back(static_cast<wchar_t>(unit));
        auto destination_access = open_namespace_write_handle();
        if (!destination_access.value()) {
            const auto& error = *destination_access.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        const auto length = spelling.size() * sizeof(WCHAR);
        if (length > std::numeric_limits<ULONG>::max() - offsetof(FILE_RENAME_INFO, FileName))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "rename_child_case_only.name_limit"});
        std::vector<std::byte> buffer(std::max(sizeof(FILE_RENAME_INFO),offsetof(FILE_RENAME_INFO, FileName) + length));
        auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
        info->ReplaceIfExists = FALSE;
        info->RootDirectory = destination_access.value()->get();
        info->FileNameLength = static_cast<DWORD>(length);
        std::memcpy(info->FileName, spelling.data(), length);
        if (!set_file_rename_information(source.get(), info, static_cast<ULONG>(buffer.size()))) {
            const DWORD code = GetLastError();
            if (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS)
                return Result::unavailable(ObservationState::Changed,
                    {ErrorDomain::Win32, code, "rename_child_case_only.destination_occupied"});
            if (code == ERROR_INVALID_FUNCTION || code == ERROR_NOT_SUPPORTED || code == ERROR_CALL_NOT_IMPLEMENTED ||
                code == ERROR_INVALID_PARAMETER)
                return Result::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Win32, code, "rename_child_case_only.atomic_primitive"});
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32, code, "rename_child_case_only.atomic_primitive"});
        }
        auto renamed = open_native_component(destination_name, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                             ChildLookupMode::NativeDefault);
        if (!renamed.value())
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "rename_child_case_only.destination_identity"});
        const auto renamed_metadata = handle_metadata(renamed.value()->get(), scope_);
        if (!renamed_metadata.value() || !renamed_metadata.value()->identity.value() ||
            compare_identity(*renamed_metadata.value()->identity.value(), *source_metadata.value()->identity.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "rename_child_case_only.destination_identity"});
        if (!FlushFileBuffers(destination_access.value()->get()))
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32, GetLastError(), "rename_child_case_only.directory_flush"});
        return Result::available(true);
    }
    Observation<bool> publish_noreplace(HANDLE source, const NativeName& name) const {
        using Result = Observation<bool>;
        const auto* units = name.windows_units();
        if (!name.is_valid() || !units || units->find(u':') != std::u16string::npos ||
            units->size() > (std::numeric_limits<ULONG>::max() / sizeof(WCHAR)))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidPath), "publish_noreplace.name"});
        const auto length = units->size() * sizeof(WCHAR);
        if (length > std::numeric_limits<ULONG>::max() - offsetof(FILE_RENAME_INFO, FileName))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidLimit), "publish_noreplace.name_limit"});
        auto destination_access = open_namespace_write_handle();
        if (!destination_access.value()) {
            const auto& error = *destination_access.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        std::vector<std::byte> buffer(std::max(sizeof(FILE_RENAME_INFO),offsetof(FILE_RENAME_INFO, FileName) + length));
        auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
        info->ReplaceIfExists = FALSE;
        info->RootDirectory = destination_access.value()->get();
        info->FileNameLength = static_cast<DWORD>(length);
        std::memcpy(info->FileName, units->data(), length);
        if (!set_file_rename_information(source, info, static_cast<ULONG>(buffer.size()))) {
            const DWORD code = GetLastError();
            if (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS)
                return Result::unavailable(ObservationState::Changed,
                    {ErrorDomain::Win32, code, "publish_noreplace.destination_occupied"});
            if (code == ERROR_INVALID_FUNCTION || code == ERROR_NOT_SUPPORTED || code == ERROR_CALL_NOT_IMPLEMENTED ||
                code == ERROR_INVALID_PARAMETER)
                return Result::unavailable(ObservationState::Unsupported,
                    {ErrorDomain::Win32, code, "publish_noreplace.atomic_primitive"});
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32, code, "publish_noreplace.atomic_primitive"});
        }

        auto opened = open_native_component(name, FILE_READ_ATTRIBUTES | SYNCHRONIZE, ChildLookupMode::NativeDefault);
        if (!opened.value())
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "publish_noreplace.destination_identity"});
        auto destination = std::move(opened).take_value();
        const auto source_identity = ::ck::files::identity(source, scope_);
        const auto destination_metadata = handle_metadata(destination.get(), scope_);
        if (!source_identity.value() || !destination_metadata.value() || !destination_metadata.value()->identity.value() ||
            compare_identity(*source_identity.value(), *destination_metadata.value()->identity.value()) != IdentityComparison::Same ||
            !destination_metadata.value()->kind.value() || *destination_metadata.value()->kind.value() != ObjectKind::RegularFile)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged), "publish_noreplace.destination_identity"});
        if (!FlushFileBuffers(destination_access.value()->get()))
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Win32, GetLastError(), "publish_noreplace.directory_flush"});
        return Result::available(true);
    }
    Observation<DirectoryAccessCheck> check_access(DirectoryAccess access) const override {
        using Result = Observation<DirectoryAccessCheck>;
        if (!valid_directory_access(access)) return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidAccess), "directory.check_access"});
        const auto before = inspect_basic();
        const auto qualified = detail::qualify_access_directory(before, before, StorageModel::WindowsHandleAttributes);
        if (!qualified.value()) { const auto& e = *qualified.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto& id = *qualified.value();
        FILE_ID_DESCRIPTOR descriptor{}; descriptor.dwSize = sizeof(descriptor);
        if (id.scheme == IdentityScheme::WindowsFileId128) { descriptor.Type = ExtendedFileIdType; std::memcpy(descriptor.ExtendedFileId.Identifier, id.object.bytes.data(), 16); }
        else if (id.scheme == IdentityScheme::WindowsFileIndex64) { descriptor.Type = FileIdType; std::memcpy(&descriptor.FileId.QuadPart, id.object.bytes.data(), 8); }
        else return Result::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity), "directory.access_scheme"});
        const DWORD right = access == DirectoryAccess::List ? FILE_LIST_DIRECTORY : access == DirectoryAccess::Search ? FILE_TRAVERSE :
            access == DirectoryAccess::AddFile ? FILE_ADD_FILE : FILE_ADD_SUBDIRECTORY;
        const DWORD mask = right | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        // A temporary access-bearing handle, no content/namespace write. No
        // backup intent or privilege enablement; unsupported drivers may refuse.
        OwnedHandle checked(OpenFileById(handle_.get(), &descriptor, mask,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL));
        if (checked.get() == INVALID_HANDLE_VALUE || checked.get() == nullptr) return failure<DirectoryAccessCheck>(GetLastError(), "OpenFileById.directory_access");
        const auto opened = detail::qualify_access_directory(before, handle_metadata(checked.get(), scope_), StorageModel::WindowsHandleAttributes);
        if (!opened.value()) { const auto& e = *opened.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        auto after = detail::qualify_access_directory(before, inspect_basic(), StorageModel::WindowsHandleAttributes);
        if (!after.value()) { const auto& e = *after.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return Result::available({access, DirectoryAccessFamily::WindowsOpenById, std::move(after).take_value(), mask});
    }
    Observation<LocationInfo> inspect_location() const override {
        LocationInfo result;
        result.family = LocationQueryFamily::WindowsHandle;
        result.linux_directory_inode_flags = Observation<std::uint32_t>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "volume.linux_directory_inode_flags"});
        result.directory = ck::files::identity(handle_.get(), scope_);
        const auto not_applicable = [](const char* operation) {
            return Observation<std::uint64_t>::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), operation});
        };
        result.filesystem_type_code = not_applicable("volume.filesystem_type_code");
        result.filesystem_query_id = Observation<NativeIdentifier>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "volume.filesystem_query_id"});
        result.posix_name_max = result.posix_name_chars_max = result.posix_path_max = not_applicable("volume.posix_limits");
        result.posix_file_size_bits = result.posix_symlink_max = not_applicable("volume.posix_file_limits");
        result.native_mount_flags = not_applicable("volume.posix_mount_flags");
        DWORD serial = 0, maximum = 0, flags = 0;
        std::array<wchar_t, MAX_PATH + 1> name{};
        if (GetVolumeInformationByHandleW(handle_.get(), nullptr, 0, &serial, &maximum, &flags, name.data(), static_cast<DWORD>(name.size()))) {
            result.volume_query_serial = Observation<std::uint64_t>::available(serial);
            result.windows_component_utf16_max = maximum != 0 ? Observation<std::uint64_t>::available(maximum) :
                Observation<std::uint64_t>::unavailable(ObservationState::Unknown,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "volume.component_limit"});
            NativeVolumeFeatures features;
            features.domain = VolumeFeatureDomain::WindowsVolumeFlags;
            features.value[0] = flags;
            features.valid[0] = std::numeric_limits<std::uint32_t>::max();
            result.features = Observation<NativeVolumeFeatures>::available(features);
            result.read_only_mount = Observation<bool>::available((flags & FILE_READ_ONLY_VOLUME) != 0);
            result.case_preserving_names = Observation<bool>::available((flags & FILE_CASE_PRESERVED_NAMES) != 0);
            const auto end = std::find(name.begin(), name.end(), L'\0');
            std::u16string text;
            for (auto at = name.begin(); at != end; ++at) text.push_back(static_cast<char16_t>(*at));
            auto id = end != name.end() ? NativeFeatureIdentifier::from_windows(std::move(text)) : std::nullopt;
            result.filesystem_name = id ? Observation<NativeFeatureIdentifier>::available(std::move(*id)) :
                Observation<NativeFeatureIdentifier>::unavailable(ObservationState::Failed,
                    {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "volume.filesystem_name"});
        } else {
            const DWORD code = GetLastError();
            const NativeError error{ErrorDomain::Win32, code, "GetVolumeInformationByHandleW"};
            result.volume_query_serial = result.windows_component_utf16_max = Observation<std::uint64_t>::unavailable(error_state(code), error);
            result.features = Observation<NativeVolumeFeatures>::unavailable(error_state(code), error);
            result.filesystem_name = Observation<NativeFeatureIdentifier>::unavailable(error_state(code), error);
            result.read_only_mount = result.case_preserving_names = Observation<bool>::unavailable(error_state(code), error);
        }
        FILE_CASE_SENSITIVE_INFO case_info{};
        if (GetFileInformationByHandleEx(handle_.get(), FileCaseSensitiveInfo, &case_info, sizeof(case_info))) {
            result.windows_directory_case_flags = Observation<std::uint32_t>::available(case_info.Flags);
            result.case_sensitive_directory = Observation<bool>::available((case_info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR) != 0);
        } else {
            const DWORD code = GetLastError();
            const NativeError error{ErrorDomain::Win32, code, "FileCaseSensitiveInfo"};
            result.windows_directory_case_flags = Observation<std::uint32_t>::unavailable(error_state(code), error);
            result.case_sensitive_directory = Observation<bool>::unavailable(error_state(code), error);
        }
        const auto space = volume_space(handle_.get());
        if (space.value()) {
            const auto native_unit = static_cast<std::uint64_t>(space.value()->sectors_per_unit) * space.value()->bytes_per_sector;
            const auto unit = detail::space_bytes(1, native_unit);
            result.space_accounting_unit = unit;
            if (unit.value()) {
                result.total_bytes = detail::signed_space_bytes(space.value()->total, *unit.value());
                result.free_bytes = detail::signed_space_bytes(space.value()->actual_available, *unit.value());
                result.available_bytes = detail::signed_space_bytes(space.value()->caller_available, *unit.value());
            } else result.total_bytes = result.free_bytes = result.available_bytes = unit;
        } else {
            const auto& e = *space.unavailable_detail();
            result.space_accounting_unit = result.total_bytes = result.free_bytes = result.available_bytes =
                Observation<std::uint64_t>::unavailable(e.state, e.error);
        }
        return Observation<LocationInfo>::available(std::move(result));
    }
    Observation<std::unique_ptr<DirectoryCursor>> open_directory_child(const NativeName& name) const override {
        using Result = Observation<std::unique_ptr<DirectoryCursor>>;
        // As for the absolute Win32 directory open, retain reparse/no-recall
        // options and validate kind on the returned handle before enumeration.
        // FILE_DIRECTORY_FILE has a restricted compatible-option set; do not
        // combine it here or retry an error with weaker no-follow protection.
        auto result = open_native_component(name, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            ChildLookupMode::NativeDefault);
        if (!result.value()) {
            const auto& error = *result.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        auto child = std::move(result).take_value();
        FILE_BASIC_INFO basic{};
        if (!GetFileInformationByHandleEx(child.get(), FileBasicInfo, &basic, sizeof(basic)))
            return failure<std::unique_ptr<DirectoryCursor>>(GetLastError(), "FileBasicInfo.directory_child");
        if ((basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::FinalLinkRejected), "open_directory_child.reparse"});
        if ((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotDirectory), "open_directory_child.kind"});
        auto observed = ck::files::identity(child.get(), scope_);
        return Result::available(std::make_unique<WindowsDirectoryCursor>(std::move(child), std::move(observed), scope_));
    }
    Observation<ChildLookup> lookup_child(const NativeName& name, ChildLookupMode mode) const override {
        using Result=Observation<ChildLookup>;
        if(!valid_child_lookup_mode(mode))return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidIdentifier),"lookup_child.mode"});
        auto opened=open_component(name,EntryAccess::MetadataOnly,mode);
        if(opened.value()) {
            auto owned=std::move(opened).take_value();
            if(!owned)return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"lookup_child.null_entry"});
            return Result::available(ChildLookup::found({name,mode,identity()},std::move(owned)));
        }
        const auto& e=*opened.unavailable_detail();
        // STATUS_OBJECT_NAME_NOT_FOUND / STATUS_NO_SUCH_FILE. Never turn a
        // path failure, delete-pending state or generic Gone into absence.
        if(detail::definite_child_absence(e,detail::ChildLookupFamily::WindowsNt))
            return Result::available(ChildLookup::missing({name,mode,identity()},e.error));
        return Result::unavailable(e.state,e.error);
    }
    Observation<std::unique_ptr<OpenedEntry>> open_child(const NativeName& name, EntryAccess access = EntryAccess::MetadataOnly) const override {
        return open_component(name,access,ChildLookupMode::NativeDefault);
    }
private:
    friend auto ::ck::files::qualify_native_directory_creation(const DirectoryCursor&,const MetadataReplayPolicy&) -> Observation<bool>;
    friend auto ::ck::files::create_native_directory(std::shared_ptr<const DirectoryCursor>,NativeName,const MetadataReplayPolicy&) -> Observation<std::unique_ptr<NativeCreatedDirectory>>;
    Observation<std::unique_ptr<OpenedEntry>> open_component(const NativeName& name, EntryAccess access, ChildLookupMode mode) const {
        if (!valid_entry_access(access)) return Observation<std::unique_ptr<OpenedEntry>>::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidAccess), "open_child.access"});
        const auto rights = FILE_READ_ATTRIBUTES | SYNCHRONIZE | ((requests_content_read(access) || (requests_rename_source(access) && requests_layout(access))) ? FILE_READ_DATA : 0) |
            (requests_attributes(access) ? FILE_READ_EA : 0) |
            (requests_security(access) ? READ_CONTROL : 0) | (requests_audit_security(access) ? ACCESS_SYSTEM_SECURITY : 0) |
            (requests_rename_source(access) ? DELETE : 0);
        auto result = open_native_component(name, rights, mode, requests_move_source(access), requests_rename_source(access));
        if (!result.value()) {
            const auto& error = *result.unavailable_detail();
            return Observation<std::unique_ptr<OpenedEntry>>::unavailable(error.state, error.error);
        }
        using Result = Observation<std::unique_ptr<OpenedEntry>>;
        auto original = std::make_unique<WindowsOpenedEntry>(std::move(result).take_value(), scope_, requests_rename_source(access) && requests_layout(access),
                                                             requests_content_read(access), false, nullptr, requests_rename_source(access));
        if (!requests_layout(access)) return Result::available(std::move(original));
        const auto before = original->inspect_basic();
        if (!before.value()) { const auto& e = *before.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto guard = detail::data_layout_access_guard(*before.value(), StorageModel::WindowsHandleAttributes);
        if (!guard.value()) { const auto& e = *guard.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto* id = before.value()->identity.value();
        if (!id || compare_identity(*id, *id) != IdentityComparison::Same) return Result::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity), "layout.open_identity"});
        if (requests_rename_source(access)) {
            // A second DELETE-bearing open would conflict with this guard's
            // deny-DELETE sharing. Layout query rights were requested on the
            // original handle; keep that exact handle for queries and rename.
            const auto after=original->inspect_basic();
            if (!after.value()) {const auto& e=*after.unavailable_detail();return Result::unavailable(e.state,e.error);}
            const auto checked=detail::data_layout_metadata_unchanged(*before.value(),*after.value());
            if (!checked.value()) {const auto& e=*checked.unavailable_detail();return Result::unavailable(e.state,e.error);}
            return Result::available(std::move(original));
        }
        FILE_ID_DESCRIPTOR descriptor{}; descriptor.dwSize = sizeof(descriptor);
        if (id->scheme == IdentityScheme::WindowsFileId128) {
            descriptor.Type = ExtendedFileIdType; std::memcpy(descriptor.ExtendedFileId.Identifier, id->object.bytes.data(), 16);
        } else if (id->scheme == IdentityScheme::WindowsFileIndex64) {
            descriptor.Type = FileIdType; std::memcpy(&descriptor.FileId.QuadPart, id->object.bytes.data(), 8);
        } else return Result::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity), "layout.open_scheme"});
        // A live original handle supplies the volume/share hint and prevents ID
        // reuse. Native identity open avoids a basename-replacement race. No
        // backup privilege, elevation, name fallback or content read is used.
        OwnedHandle readable(OpenFileById(original->handle_.get(), &descriptor, rights | FILE_READ_DATA,
            requests_rename_source(access) ? FILE_SHARE_READ :
            requests_move_source(access) ? FILE_SHARE_READ : FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL));
        if (readable.get() == nullptr || readable.get() == INVALID_HANDLE_VALUE) return failure<std::unique_ptr<OpenedEntry>>(GetLastError(), "OpenFileById.layout");
        auto opened = std::make_unique<WindowsOpenedEntry>(std::move(readable), scope_, true,
                                                           requests_content_read(access), false, nullptr, requests_rename_source(access));
        const auto after = opened->inspect_basic();
        if (!after.value()) { const auto& e = *after.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto checked = detail::data_layout_metadata_unchanged(*before.value(), *after.value());
        if (!checked.value()) { const auto& e = *checked.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        const auto final_guard = detail::data_layout_access_guard(*after.value(), StorageModel::WindowsHandleAttributes);
        if (!final_guard.value()) { const auto& e = *final_guard.unavailable_detail(); return Result::unavailable(e.state, e.error); }
        return Result::available(std::move(opened));
    }
    Observation<OwnedHandle> open_namespace_write_handle() const {
        using Result = Observation<OwnedHandle>;
        const auto current = identity();
        if (!current.value()) {
            const auto& error = *current.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        FILE_ID_DESCRIPTOR descriptor{};
        descriptor.dwSize = sizeof(descriptor);
        if (current.value()->scheme == IdentityScheme::WindowsFileId128) {
            descriptor.Type = ExtendedFileIdType;
            std::memcpy(descriptor.ExtendedFileId.Identifier, current.value()->object.bytes.data(),
                        sizeof(descriptor.ExtendedFileId.Identifier));
        } else if (current.value()->scheme == IdentityScheme::WindowsFileIndex64) {
            descriptor.Type = FileIdType;
            std::memcpy(&descriptor.FileId.QuadPart, current.value()->object.bytes.data(),
                        sizeof(descriptor.FileId.QuadPart));
        } else {
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity),
                 "publish_noreplace.directory_scheme"});
        }
        OwnedHandle opened(OpenFileById(handle_.get(), &descriptor,
            FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD |
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL));
        if (opened.get() == nullptr || opened.get() == INVALID_HANDLE_VALUE)
            return failure<OwnedHandle>(GetLastError(), "publish_noreplace.directory_access");
        const auto observed = ::ck::files::identity(opened.get(), scope_);
        if (!observed.value() || compare_identity(*observed.value(), *current.value()) != IdentityComparison::Same)
            return Result::unavailable(ObservationState::Unknown,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity),
                 "publish_noreplace.directory_identity"});
        return Result::available(std::move(opened));
    }
    Observation<OwnedHandle> open_native_component(const NativeName& name, ACCESS_MASK rights, ChildLookupMode mode,
                                                   bool exclusive = false, bool rename_guard = false) const {
        using Result = Observation<OwnedHandle>;
        const auto* units = name.windows_units();
        if (!units || !name.is_valid() || units->find(u':') != std::u16string::npos ||
            units->size() > std::numeric_limits<USHORT>::max() / sizeof(WCHAR))
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidPath), "open_child.name"});
        // A counted, single relative component has no Win32 DOS-device aliasing
        // or trailing-dot/space rewriting. Stream syntax is refused above.
        std::wstring spelling;
        spelling.reserve(units->size());
        for (const auto unit : *units) spelling.push_back(static_cast<wchar_t>(unit));
        UNICODE_STRING native_name{};
        native_name.Length = static_cast<USHORT>(spelling.size() * sizeof(WCHAR));
        native_name.MaximumLength = native_name.Length;
        native_name.Buffer = spelling.data();
        OBJECT_ATTRIBUTES attributes{};
        attributes.Length = sizeof(attributes);
        attributes.RootDirectory = handle_.get();
        attributes.ObjectName = &native_name;
        // Zero delegates comparison to native defaults. This is not a
        // guarantee of byte-exact filesystem spelling or normalization.
        static_assert(OBJ_CASE_INSENSITIVE==0x40);
        attributes.Attributes=mode==ChildLookupMode::WindowsIgnoreCase?OBJ_CASE_INSENSITIVE:0;
        IO_STATUS_BLOCK io{};
        HANDLE raw = nullptr;
        const auto sharing = rename_guard ? FILE_SHARE_READ :
            exclusive ? FILE_SHARE_READ : FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        const NTSTATUS status = NtCreateFile(&raw, rights, &attributes, &io, nullptr, 0,
            sharing, FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_OPEN_NO_RECALL | (rename_guard?0:FILE_SYNCHRONOUS_IO_NONALERT), nullptr, 0);
        OwnedHandle opened(raw);
        if (status < 0 || status == 0x00000103L)
            return Result::unavailable(status < 0 ? error_state(RtlNtStatusToDosError(status)) : ObservationState::Failed,
                {ErrorDomain::NtStatus, static_cast<std::uint32_t>(status), "NtCreateFile.child"});
        if (raw == nullptr || raw == INVALID_HANDLE_VALUE)
            return Result::unavailable(ObservationState::Failed,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult), "NtCreateFile.child_handle"});
        return Result::available(std::move(opened));
    }
private:
    Observation<DirectoryStep> next_step() override {
        using Result = Observation<DirectoryStep>;
        static_assert(offsetof(FILE_ID_BOTH_DIR_INFO, FileName) == detail::windows_directory_name_offset);
        static_assert(offsetof(FILE_ID_BOTH_DIR_INFO, FileNameLength) == detail::windows_directory_name_length_offset);
        if(target_read_enumeration_finished_)return Result::available(DirectoryEnd{});
        if (!offset_) {
            buffer_.fill(std::byte{});
            const auto info_class = started_ ? FileIdBothDirectoryInfo : FileIdBothDirectoryRestartInfo;
            if (!GetFileInformationByHandleEx(handle_.get(), info_class, buffer_.data(), static_cast<DWORD>(buffer_.size()))) {
                const DWORD code = GetLastError();
                if (code == ERROR_NO_MORE_FILES) {
                    if(target_read_enumeration_lease_){target_read_enumeration_finished_=true;target_read_enumeration_lease_.reset();}
                    return Result::available(DirectoryEnd{});
                }
                return failure<DirectoryStep>(code, "FileIdBothDirectoryInfo");
            }
            started_ = true;
            offset_ = 0;
        }
        auto decoded = detail::decode_windows_directory_record(buffer_, *offset_);
        if (!decoded.value()) {
            const auto& error = *decoded.unavailable_detail();
            return Result::unavailable(error.state, error.error);
        }
        auto record = std::move(decoded).take_value();
        offset_ = record.next_offset;
        if (!record.name) return Result::available(DirectorySkip{});
        return Result::available(std::move(*record.name));
    }
    std::shared_ptr<const void> target_read_budget_;
    std::shared_ptr<const void> target_read_enumeration_lease_;
    bool target_read_enumeration_finished_=false;
    OwnedHandle handle_;
    AdapterScope scope_;
    // Fixed bound, sufficient for a full native UTF-16 component plus header.
    // A provider rejecting the query reports an error; never reopen by path.
    alignas(8) std::array<std::byte, 128 * 1024> buffer_{};
    std::optional<std::size_t> offset_;
    bool started_ = false;
};

// Prepared target observation owners are independent of the metadata writer.
// Their actual file descriptions suppress automatic times before security is
// replayed. Only the native adapter constructs this implementation.
class WindowsTargetReadSeed final:public detail::NativeTargetReadSeed,public MetadataCaptureFailureLatch {
public:
    WindowsTargetReadSeed(WindowsOpenedEntry* target,std::shared_ptr<const NativeMetadataProof> proof,
        MetadataCaptureLimits limits,std::shared_ptr<MetadataCaptureBudget> budget,
        std::shared_ptr<const MetadataCaptureFailureLatch> latch,
        std::shared_ptr<const WindowsDirectoryCursor> container={})
        :target_(target),proof_(std::move(proof)),limits_(limits),budget_(std::move(budget)),latch_(std::move(latch)),container_(std::move(container)){}
    ~WindowsTargetReadSeed()override{try{(void)finish_io();}catch(...){}}
    void record_first(MetadataCaptureCleanupError e)const noexcept override {
        if(!close_error_)close_error_=e;
        if(latch_)latch_->record_first(e);
    }
    Observation<bool> advance(std::stop_token stop)override {
        if(failed_)return close_error_?Observation<bool>::unavailable(close_error_->state,
            {close_error_->domain,close_error_->code,close_error_->operation}):failure_result();
        if(finished_)return closed<bool>();
        if(ready_)return Observation<bool>::available(true);
        detail::MetadataCaptureCleanupScope scope(this);
        try{
            if(stop.stop_requested())return fail({ObservationState::Unknown,{ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InterruptedRead),"target_read.cancelled"}});
            if(!proof_||proof_->io_finished())return fail({ObservationState::Changed,{ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidAccess),"target_read.closed_source_proof"}});
            if(auto error=proof_->cleanup_error())return fail({error->state,{error->domain,error->code,error->operation}});
            if(!source_){
                auto checked=open_base();if(!checked.value()||!*checked.value())return fail(checked.value()?UnavailableObservation{
                    ObservationState::Failed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"target_read.base_false"}}:*checked.unavailable_detail());
                if(close_error_)return fail(close_observation());
                return Observation<bool>::available(false);
            }
            const auto& channels=proof_->snapshot().channels;
            if(index_<channels.size()){
                const auto& expected=channels[index_];auto bootstrap=source_->open_metadata_channel(expected.identifier,false,true);
                if(!bootstrap.value())return fail(*bootstrap.unavailable_detail());
                auto native=std::move(bootstrap).take_value();auto reduced=native->duplicate_capture_reader();
                if(!reduced.value())return fail(*reduced.unavailable_detail());
                native->finish_capture_reads();
                if(close_error_)return fail(close_observation());
                auto reader=std::shared_ptr<WindowsMetadataChannel>(std::move(reduced).take_value());
                auto inspected=reader->inspect();if(!inspected.value())return fail(*inspected.unavailable_detail());
                if(inspected.value()->identifier!=expected.identifier||inspected.value()->logical_size!=expected.logical_size)
                    return fail({ObservationState::Changed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"target_read.stream_changed"}});
                manifest_->readers.push_back(std::move(reader));++index_;
                return Observation<bool>::available(false);
            }
            auto catalog=source_->inspect_data_channels(manifest_->policy.limits);
            if(!catalog.value())return fail(*catalog.unavailable_detail());
            std::size_t named=0,main=0;
            for(const auto& entry:catalog.value()->channels){
                if(entry.kind==DataChannelKind::MainData){++main;continue;}
                if(entry.kind!=DataChannelKind::NamedData||!entry.logical_size.value())return fail({ObservationState::Unsupported,
                    {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"target_read.unknown_channel"}});
                const auto expected=std::find_if(channels.begin(),channels.end(),[&](const auto& c){return c.identifier==entry.identifier;});
                if(expected==channels.end()||expected->logical_size!=*entry.logical_size.value())return fail({ObservationState::Changed,
                    {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"target_read.catalog_changed"}});
                ++named;
            }
            if(catalog.value()->coverage!=DataChannelCoverage::WindowsFileStreamInfo||named!=channels.size()||main!=(directory_?0U:1U))
                return fail({ObservationState::Changed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"target_read.catalog_shape"}});
            source_->target_read_manifest_=manifest_;ready_=true;target_=nullptr;proof_.reset();container_.reset();
            return close_error_?fail(close_observation()):Observation<bool>::available(true);
        }catch(...){
            return fail({ObservationState::Unknown,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"target_read.prepare_exception"}});
        }
    }
    Observation<std::shared_ptr<const OpenedEntry>> source()const override {
        using R=Observation<std::shared_ptr<const OpenedEntry>>;
        if(!ready_||finished_||failed_)return closed<std::shared_ptr<const OpenedEntry>>();
        return R::available(source_);
    }
    Observation<std::shared_ptr<const DirectoryCursor>> directory_cursor()override {
        using R=Observation<std::shared_ptr<const DirectoryCursor>>;
        if(!ready_||finished_||failed_||!directory_)return closed<std::shared_ptr<const DirectoryCursor>>();
        if(!active_enumerator_.expired())return Observation<std::shared_ptr<const DirectoryCursor>>::unavailable(
            ObservationState::Unsupported,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"target_read.enumerator_still_owned"});
        detail::MetadataCaptureCleanupScope scope(this);
        auto lease=detail::NativeTargetReadBudget::acquire(budget_,1,sizeof(WindowsDirectoryCursor));
        if(!lease.value()){const auto&e=*lease.unavailable_detail();return R::unavailable(e.state,e.error);}
        HANDLE raw=nullptr;
        if(!DuplicateHandle(GetCurrentProcess(),enumeration_.get(),GetCurrentProcess(),&raw,0,FALSE,DUPLICATE_SAME_ACCESS))
            return failure<std::shared_ptr<const DirectoryCursor>>(GetLastError(),"target_read.cursor_duplicate");
        OwnedHandle owned(raw);auto current=identity(owned.get(),source_->scope_);
        if(!current.value()){const auto&e=*current.unavailable_detail();return R::unavailable(e.state,e.error);}
        auto cursor=std::make_shared<WindowsDirectoryCursor>(std::move(owned),std::move(current),source_->scope_);
        cursor->target_read_budget_=std::move(lease).take_value();
        cursor->target_read_enumeration_lease_=std::make_shared<const std::byte>();
        active_enumerator_=cursor->target_read_enumeration_lease_;
        return R::available(std::move(cursor));
    }
    Observation<bool> finish_io()override {
        if(!finished_){detail::MetadataCaptureCleanupScope scope(this);
            if(manifest_)for(const auto& reader:manifest_->readers)reader->finish_capture_reads();
            if(source_)source_->finish_capture_reads();
            enumeration_.reset();source_.reset();manifest_.reset();proof_.reset();container_.reset();target_=nullptr;
            budget_.reset();finished_=true;
        }
        if(close_error_)return Observation<bool>::unavailable(close_error_->state,
            {close_error_->domain,close_error_->code,close_error_->operation});
        return Observation<bool>::available(true);
    }
private:
    template<class T>static Observation<T> closed(){return Observation<T>::unavailable(ObservationState::Changed,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"target_read.not_ready_or_closed"});}
    UnavailableObservation close_observation()const{return {close_error_->state,{close_error_->domain,close_error_->code,close_error_->operation}};}
    Observation<bool> failure_result()const{return Observation<bool>::unavailable(failure_state_,{failure_domain_,failure_code_,failure_operation_.data()});}
    Observation<bool> fail(const UnavailableObservation& e){
        if(!failed_){failed_=true;failure_state_=e.state;failure_domain_=e.error.domain;failure_code_=e.error.code;
            std::copy_n(e.error.operation.data(),std::min(e.error.operation.size(),failure_operation_.size()-1),failure_operation_.data());}
        (void)finish_io();return close_error_?Observation<bool>::unavailable(close_error_->state,
            {close_error_->domain,close_error_->code,close_error_->operation}):failure_result();
    }
    Observation<bool> open_base(){
        const auto& snapshot=proof_->snapshot();
        if(!limits_.valid()||!budget_||!latch_||!snapshot.policy.valid()||!snapshot.basic.kind.value()||
           snapshot.channels.size()>snapshot.policy.limits.max_records||snapshot.channels.size()>limits_.max_retained_handles)
            return Observation<bool>::unavailable(ObservationState::Failed,{ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidLimit),"target_read.request"});
        directory_=*snapshot.basic.kind.value()==ObjectKind::Directory;
        if(!directory_&&*snapshot.basic.kind.value()!=ObjectKind::RegularFile)return Observation<bool>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::NotApplicable),"target_read.kind"});
        std::unique_ptr<WindowsOpenedEntry> container_view;
        if(container_){
            HANDLE raw=nullptr;
            if(!directory_||!DuplicateHandle(GetCurrentProcess(),container_->handle_.get(),GetCurrentProcess(),&raw,0,FALSE,DUPLICATE_SAME_ACCESS))
                return failure<bool>(GetLastError(),"target_read.container_duplicate");
            OwnedHandle owned(raw);container_view=std::make_unique<WindowsOpenedEntry>(std::move(owned),container_->scope_);
            auto current=container_view->inspect_basic();if(!current.value()){const auto&e=*current.unavailable_detail();return Observation<bool>::unavailable(e.state,e.error);}
            if(!current.value()->identity.value()||!snapshot.basic.identity.value()||
               compare_identity(*current.value()->identity.value(),*snapshot.basic.identity.value())!=IdentityComparison::Same)
                return Observation<bool>::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::MetadataChanged),"target_read.container_proof"});
            target_=container_view.get();auto valid=target_->qualify_metadata_replay(snapshot.policy);if(!valid.value()||!*valid.value())return valid;
            valid=verify_native_metadata_replay_channels(snapshot);if(!valid.value()||!*valid.value())return valid;
        }else{
            auto valid=target_->qualify_progressive_target(*proof_);if(!valid.value()||!*valid.value())return valid;
        }
        std::size_t metadata=sizeof(WindowsTargetReadSeed)+sizeof(WindowsTargetReadManifest)+sizeof(WindowsOpenedEntry);
        for(const auto& entry:snapshot.channels){const auto* units=entry.identifier.windows_units();
            if(!units||units->size()>snapshot.policy.limits.max_native_bytes/sizeof(char16_t))return Observation<bool>::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidIdentifier),"target_read.stream_identifier"});
            const auto next=sizeof(WindowsMetadataChannel)+units->size()*sizeof(char16_t);
            if(next>limits_.max_metadata_bytes||metadata>limits_.max_metadata_bytes-next)return Observation<bool>::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InventoryLimit),"target_read.manifest_budget"});
            metadata+=next;
        }
        auto lease=detail::NativeTargetReadBudget::acquire(budget_,snapshot.channels.size()+4,metadata);
        if(!lease.value()){const auto&e=*lease.unavailable_detail();return Observation<bool>::unavailable(e.state,e.error);}
        auto manifest=std::make_shared<WindowsTargetReadManifest>();manifest->policy=snapshot.policy;
        manifest->budget=std::move(lease).take_value();manifest->readers.reserve(snapshot.channels.size());
        const DWORD read=FILE_READ_DATA|FILE_READ_ATTRIBUTES|FILE_READ_EA|READ_CONTROL|SYNCHRONIZE|
            (snapshot.policy.scope==RegularMetadataScope::CompleteMetadataV1?ACCESS_SYSTEM_SECURITY:0);
        auto opened=target_->metadata_security_handle(read|FILE_WRITE_ATTRIBUTES);
        if(!opened.value()){const auto&e=*opened.unavailable_detail();return Observation<bool>::unavailable(e.state,e.error);}
        auto bootstrap=std::move(opened).take_value();const FILETIME suppressed{MAXDWORD,MAXDWORD};
        if(!SetFileTime(bootstrap.get(),nullptr,&suppressed,&suppressed))return failure<bool>(GetLastError(),"target_read.base_suppress_times");
        HANDLE raw=nullptr;
        if(!DuplicateHandle(GetCurrentProcess(),bootstrap.get(),GetCurrentProcess(),&raw,read,FALSE,0))
            return failure<bool>(GetLastError(),"target_read.base_reduce_rights");
        OwnedHandle readonly(raw);auto prepared=std::make_shared<WindowsOpenedEntry>(std::move(readonly),target_->scope_,false,!directory_);
        bootstrap.reset();if(close_error_)return Observation<bool>::unavailable(close_error_->state,
            {close_error_->domain,close_error_->code,close_error_->operation});
        // A separate, freshly opened enumeration description is prepared
        // AFTER population. Never duplicate a pre-population cursor/OFD or
        // reopen after restrictive security. A single active returned cursor
        // owns its position; a later cursor restarts this prepared description.
        if(directory_){
            auto fresh=target_->metadata_security_handle(FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|SYNCHRONIZE|FILE_WRITE_ATTRIBUTES);
            if(!fresh.value()){const auto&e=*fresh.unavailable_detail();return Observation<bool>::unavailable(e.state,e.error);}
            auto enum_bootstrap=std::move(fresh).take_value();
            if(!SetFileTime(enum_bootstrap.get(),nullptr,&suppressed,&suppressed))return failure<bool>(GetLastError(),"target_read.enumeration_suppress_times");
            HANDLE raw_enum=nullptr;
            if(!DuplicateHandle(GetCurrentProcess(),enum_bootstrap.get(),GetCurrentProcess(),&raw_enum,
                FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|SYNCHRONIZE,FALSE,0))return failure<bool>(GetLastError(),"target_read.enumeration_reduce_rights");
            OwnedHandle reduced_enum(raw_enum);enum_bootstrap.reset();
            if(close_error_)return Observation<bool>::unavailable(close_error_->state,{close_error_->domain,close_error_->code,close_error_->operation});
            enumeration_=std::move(reduced_enum);
        }
        manifest_=std::move(manifest);source_=std::move(prepared);target_=nullptr;
        return Observation<bool>::available(true);
    }
    WindowsOpenedEntry* target_;
    std::shared_ptr<const NativeMetadataProof> proof_;
    MetadataCaptureLimits limits_;
    std::shared_ptr<MetadataCaptureBudget> budget_;
    std::shared_ptr<const MetadataCaptureFailureLatch> latch_;
    std::shared_ptr<const WindowsDirectoryCursor> container_;
    std::shared_ptr<WindowsTargetReadManifest> manifest_;
    std::shared_ptr<WindowsOpenedEntry> source_;
    OwnedHandle enumeration_;
    std::weak_ptr<const void> active_enumerator_;
    std::size_t index_=0;
    bool directory_=false,ready_=false,finished_=false,failed_=false;
    mutable std::optional<MetadataCaptureCleanupError> close_error_;
    ObservationState failure_state_=ObservationState::Unknown;
    ErrorDomain failure_domain_=ErrorDomain::None;
    std::int64_t failure_code_=0;
    std::array<char,128> failure_operation_{};
};

Observation<bool> WindowsOpenedEntry::rename_noreplace(const DirectoryCursor& source_parent,
    const DirectoryCursor& destination, const NativeName& name) const {
    using Result=Observation<bool>;
    if (!rename_access_) return failure<bool>(ERROR_ACCESS_DENIED,"rename_noreplace.held_guard_required");
    const auto* from=dynamic_cast<const WindowsDirectoryCursor*>(&source_parent);
    const auto* to=dynamic_cast<const WindowsDirectoryCursor*>(&destination);
    if (!from || !to) return OpenedEntry::rename_noreplace(source_parent,destination,name);
    for (const auto* cursor:{from,to}) {
        auto qualified=cursor->qualify_identity_bound_rename();
        if (!qualified.value() || !*qualified.value()) return qualified;
    }
    const auto held=inspect_basic();
    if (!held.value()) {const auto& e=*held.unavailable_detail();return Result::unavailable(e.state,e.error);}
    if (!held.value()->identity.value() || !held.value()->kind.value() || *held.value()->kind.value()!=ObjectKind::RegularFile ||
        !held.value()->link_count.value() || *held.value()->link_count.value()!=1 ||
        held.value()->identity.value()->scheme!=IdentityScheme::WindowsFileId128)
        return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"rename_noreplace.held_kind_identity_links"});
    const auto source_id=from->identity(),destination_id=to->identity();
    if (!source_id.value() || !destination_id.value() ||
        source_id.value()->scope!=scope_ || destination_id.value()->scope!=scope_ ||
        source_id.value()->volume!=held.value()->identity.value()->volume ||
        destination_id.value()->volume!=held.value()->identity.value()->volume)
        return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity),"rename_noreplace.held_volume"});
    const auto provider=provider_review_required(*held.value(),StorageModel::WindowsHandleAttributes);
    if (!provider.value()) {const auto& e=*provider.unavailable_detail();return Result::unavailable(e.state,e.error);}
    if (*provider.value()) return Result::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"rename_noreplace.held_provider"});
    if (content_lease_) {const auto stable=content_lease_->check();if(!stable.value()||!*stable.value()) return stable;}
    auto source_flush=from->open_namespace_write_handle();
    if (!source_flush.value()) {const auto& e=*source_flush.unavailable_detail();return Result::unavailable(e.state,e.error);}
    auto renamed=to->publish_noreplace(handle_.get(),name);
    if (!renamed.value() || !*renamed.value()) return renamed;
    if (!FlushFileBuffers(source_flush.value()->get())) return Result::unavailable(ObservationState::Unknown,
        {ErrorDomain::Win32,GetLastError(),"rename_noreplace.held_source_directory_flush"});
    if (content_lease_) {const auto stable=content_lease_->check();if(!stable.value()) return Result::unavailable(ObservationState::Unknown,stable.unavailable_detail()->error);}
    return Result::available(true);
}

Observation<bool> WindowsOpenedEntry::publish_noreplace(const DirectoryCursor& destination, const NativeName& name) {
    using Result = Observation<bool>;
    if (!publication_)
        return OpenedEntry::publish_noreplace(destination, name);
    const auto* source_units = publication_->name.windows_units();
    if (!source_units || !publication_->name.is_valid())
        return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidIdentifier),
             "publish_noreplace.source_name"});
    const auto current_parent = identity(publication_->parent.get(), scope_);
    if (!current_parent.value() || !publication_->parent_identity.value() ||
        compare_identity(*current_parent.value(), *publication_->parent_identity.value()) != IdentityComparison::Same)
        return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged),
             "publish_noreplace.source_parent"});
    std::wstring spelling;
    spelling.reserve(source_units->size());
    for (const auto unit : *source_units) spelling.push_back(static_cast<wchar_t>(unit));
    UNICODE_STRING native_name{};
    native_name.Length = static_cast<USHORT>(spelling.size() * sizeof(WCHAR));
    native_name.MaximumLength = native_name.Length;
    native_name.Buffer = spelling.data();
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = publication_->parent.get();
    attributes.ObjectName = &native_name;
    IO_STATUS_BLOCK io{};
    HANDLE raw = nullptr;
    const NTSTATUS status = NtCreateFile(&raw, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &io, nullptr, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_OPEN_NO_RECALL | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
    OwnedHandle named(raw);
    if (status < 0)
        return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::NtStatus, static_cast<std::int64_t>(status), "publish_noreplace.source_name"});
    const auto held_identity = identity(handle_.get(), scope_);
    const auto named_identity = identity(named.get(), scope_);
    if (!held_identity.value() || !named_identity.value() ||
        compare_identity(*held_identity.value(), *named_identity.value()) != IdentityComparison::Same)
        return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::MetadataChanged),
             "publish_noreplace.source_identity"});
    const auto* cursor = dynamic_cast<const WindowsDirectoryCursor*>(&destination);
    if (!cursor)
        return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery), "publish_noreplace.destination_adapter"});
    return cursor->publish_noreplace(handle_.get(), name);
}

} // namespace

namespace detail {
Observation<std::shared_ptr<const OpenedEntry>> open_native_main_content_source(
    std::shared_ptr<const OpenedEntry> source){
    using R=Observation<std::shared_ptr<const OpenedEntry>>;
    const auto* native=dynamic_cast<const WindowsOpenedEntry*>(source.get());
    if(!native)return R::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"main_content.native_source_required"});
    return native->open_main_content_source();
}
Observation<std::shared_ptr<const OpenedEntry>> open_native_metadata_capture_source(
    std::shared_ptr<const OpenedEntry> source,const MetadataReplayPolicy& policy){
    using R=Observation<std::shared_ptr<const OpenedEntry>>;
    const auto* native=dynamic_cast<const WindowsOpenedEntry*>(source.get());
    if(!native||!policy.valid())return R::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"metadata_capture.native_source_required"});
    return native->open_progressive_metadata_source(policy);
}
Observation<std::shared_ptr<const OpenedEntry>> open_native_directory_capture_source(
    std::shared_ptr<const DirectoryCursor> source,const MetadataReplayPolicy& policy){
    using R=Observation<std::shared_ptr<const OpenedEntry>>;
    const auto* native=dynamic_cast<const WindowsDirectoryCursor*>(source.get());
    if(!native||!policy.valid())return R::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"metadata_capture.native_directory_required"});
    return native->open_progressive_directory_source(policy);
}
namespace {
Observation<bool> stream_close_result(const std::optional<MetadataCaptureCleanupError>& error) {
    if(!error)return Observation<bool>::available(true);
    return Observation<bool>::unavailable(error->state,{error->domain,error->code,error->operation});
}
class ProgressiveStreamWriter final:public NativeMetadataStreamWriter {
public:
    ProgressiveStreamWriter(std::shared_ptr<WindowsMetadataChannel> channel,
        std::shared_ptr<const NativeMetadataProof> proof,std::shared_ptr<const MetadataCaptureFailureLatch> latch)
        :channel_(std::move(channel)),proof_(std::move(proof)),latch_(std::move(latch)){}
    ~ProgressiveStreamWriter()override{if(!finished_)try{(void)finish_io();}catch(...){}}
    Observation<MetadataReplayChannelState> inspect()const override{return channel_->inspect();}
    Observation<std::size_t> write(std::uint64_t offset,std::span<const std::byte> bytes)override {
        if(finished_||!proof_||proof_->io_finished())return Observation<std::size_t>::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidAccess),"metadata_stream.finished_write"});
        return channel_->write(offset,bytes);
    }
    Observation<bool> finish_io()override {
        if(!finished_) {
            finished_=true;
            { MetadataCaptureCleanupScope scope(latch_.get());
              try{(void)channel_->finish();}catch(...){
                  error_=channel_->writer_finish_error();
                  if(!error_)error_=MetadataCaptureCleanupError{ObservationState::Failed,ErrorDomain::Adapter,
                      static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_stream.writer_finish_exception"};
              }
              if(!error_)error_=channel_->writer_finish_error();
              if(error_)record_metadata_capture_close(*error_);
              proof_.reset();
            }
            latch_.reset();
        }
        return stream_close_result(error_);
    }
private:
    std::shared_ptr<WindowsMetadataChannel> channel_;
    std::shared_ptr<const NativeMetadataProof> proof_;
    std::shared_ptr<const MetadataCaptureFailureLatch> latch_;
    std::optional<MetadataCaptureCleanupError> error_;
    bool finished_=false;
};
class ProgressiveStreamReader final:public NativeMetadataStreamReader {
public:
    ProgressiveStreamReader(std::unique_ptr<WindowsMetadataChannel> channel,
        std::shared_ptr<const NativeMetadataProof> proof,std::shared_ptr<const MetadataCaptureFailureLatch> latch)
        :channel_(std::move(channel)),proof_(std::move(proof)),latch_(std::move(latch)){}
    ~ProgressiveStreamReader()override{if(!finished_)try{(void)finish_io();}catch(...){}}
    Observation<MetadataReplayChannelState> inspect()const override{return channel_->inspect();}
    Observation<ContentRead> read_content(ContentReadLimits limits,std::uint64_t offset,std::stop_token stop)const override {
        return channel_->read_content(limits,offset,stop);
    }
    Observation<bool> finish_io()override {
        if(!finished_) {
            finished_=true;
            { MetadataCaptureCleanupScope scope(latch_.get());channel_->finish_capture_reads();
              error_=channel_->capture_close_error();proof_.reset(); }
            latch_.reset();
        }
        return stream_close_result(error_);
    }
private:
    std::unique_ptr<WindowsMetadataChannel> channel_;
    std::shared_ptr<const NativeMetadataProof> proof_;
    std::shared_ptr<const MetadataCaptureFailureLatch> latch_;
    std::optional<MetadataCaptureCleanupError> error_;
    bool finished_=false;
};
template<class T>Observation<std::unique_ptr<T>> stream_factory_error(const char* operation) {
    return Observation<std::unique_ptr<T>>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),operation});
}
}
Observation<NativeTargetReadSeed::Pointer> begin_native_target_read_seed(OpenedEntry& target,
    std::shared_ptr<const NativeMetadataProof> proof,MetadataCaptureLimits limits,std::shared_ptr<MetadataCaptureBudget> budget,
    std::shared_ptr<const MetadataCaptureFailureLatch> latch) {
    using R=Observation<NativeTargetReadSeed::Pointer>;auto* native=dynamic_cast<WindowsOpenedEntry*>(&target);
    if(!native||!proof||!limits.valid()||!budget||!latch)return R::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"target_read.native_target_inputs"});
    return R::available(std::make_unique<WindowsTargetReadSeed>(native,std::move(proof),limits,std::move(budget),std::move(latch)));
}
Observation<NativeTargetReadSeed::Pointer> begin_native_directory_read_seed(std::shared_ptr<const DirectoryCursor> directory,
    std::shared_ptr<const NativeMetadataProof> proof,MetadataCaptureLimits limits,std::shared_ptr<MetadataCaptureBudget> budget,
    std::shared_ptr<const MetadataCaptureFailureLatch> latch) {
    using R=Observation<NativeTargetReadSeed::Pointer>;auto native=std::dynamic_pointer_cast<const WindowsDirectoryCursor>(directory);
    if(!native||!proof||!limits.valid()||!budget||!latch)return R::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"target_read.native_directory_inputs"});
    return R::available(std::make_unique<WindowsTargetReadSeed>(nullptr,std::move(proof),limits,std::move(budget),std::move(latch),std::move(native)));
}
Observation<bool> qualify_native_metadata_target(OpenedEntry& target,const NativeMetadataProof& proof) {
    auto* native=dynamic_cast<WindowsOpenedEntry*>(&target);
    if(!native)return Observation<bool>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"metadata_stream.native_target_required"});
    return native->qualify_progressive_target(proof);
}
Observation<std::unique_ptr<NativeMetadataStreamWriter>> open_native_metadata_stream_writer(OpenedEntry& target,
    std::shared_ptr<const NativeMetadataProof> proof,const NativeFeatureIdentifier& identifier,
    std::shared_ptr<const MetadataCaptureFailureLatch> latch) {
    using R=Observation<std::unique_ptr<NativeMetadataStreamWriter>>;
    auto* native=dynamic_cast<WindowsOpenedEntry*>(&target);
    if(!native||!proof||!latch)return stream_factory_error<NativeMetadataStreamWriter>("metadata_stream.native_writer_inputs");
    MetadataCaptureCleanupScope scope(latch.get());
    auto opened=native->open_progressive_writer(*proof,identifier);
    if(!opened.value()){const auto&e=*opened.unavailable_detail();return R::unavailable(e.state,e.error);}
    auto channel=std::move(opened).take_value();
    try{return R::available(std::make_unique<ProgressiveStreamWriter>(channel,proof,latch));}
    catch(...){try{(void)channel->finish();}catch(...){if(auto e=channel->writer_finish_error())record_metadata_capture_close(*e);}throw;}
}
Observation<std::unique_ptr<NativeMetadataStreamReader>> open_native_metadata_stream_reader(OpenedEntry& target,
    std::shared_ptr<const NativeMetadataProof> proof,const NativeFeatureIdentifier& identifier,
    std::shared_ptr<const MetadataCaptureFailureLatch> latch) {
    using R=Observation<std::unique_ptr<NativeMetadataStreamReader>>;
    auto* native=dynamic_cast<WindowsOpenedEntry*>(&target);
    if(!native||!proof||!latch)return stream_factory_error<NativeMetadataStreamReader>("metadata_stream.native_reader_inputs");
    MetadataCaptureCleanupScope scope(latch.get());
    auto opened=native->open_progressive_reader(*proof,identifier);
    if(!opened.value()){const auto&e=*opened.unavailable_detail();return R::unavailable(e.state,e.error);}
    auto channel=std::move(opened).take_value();
    try{return R::available(std::make_unique<ProgressiveStreamReader>(std::move(channel),proof,latch));}
    catch(...){if(channel)channel->finish_capture_reads();throw;}
}
void finish_native_metadata_capture(const OpenedEntry* source,const MetadataReplaySnapshot& snapshot)noexcept {
    for(const auto& c:snapshot.channels){
        auto* native=const_cast<WindowsMetadataChannel*>(dynamic_cast<const WindowsMetadataChannel*>(c.source.get()));
        if(native)native->finish_capture_reads();
        else record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_capture.native_channel_close_required"});
    }
    if(snapshot.security_coverage){
        const auto* proof=dynamic_cast<const WindowsPersistentSecurityProof*>(snapshot.security_coverage.get());
        if(proof)proof->finish_capture_reads();else record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_capture.native_security_close_required"});
    }
    if(snapshot.channel_evidence){
        const auto* proof=dynamic_cast<const WindowsChannelManifestProof*>(snapshot.channel_evidence.get());
        if(proof)proof->finish_capture_reads();else record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_capture.native_manifest_close_required"});
    }
    if(source){auto* native=const_cast<WindowsOpenedEntry*>(dynamic_cast<const WindowsOpenedEntry*>(source));
        if(native)native->finish_capture_reads();else record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"metadata_capture.native_source_close_required"});}
}
Observation<bool> seal_native_metadata_capture(MetadataCaptureJob& job){
    using R=Observation<bool>;
    const auto refuse=[](const char* op){return R::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),op});};
    if(!job.ready_to_seal())return refuse("metadata_capture.unfinished_producer");
    auto& snapshot=job.sealing_snapshot();const auto* native=dynamic_cast<const WindowsOpenedEntry*>(job.sealing_source().get());
    if(!native||snapshot.channel_coverage!=DataChannelCoverage::WindowsFileStreamInfo)return refuse("metadata_capture.native_seal_source");
    const auto qualified=native->qualify_metadata_replay(snapshot.policy);if(!qualified.value()||!*qualified.value())return qualified;
    for(const auto& channel:snapshot.channels){
        const auto* reader=dynamic_cast<const WindowsMetadataChannel*>(channel.source.get());
        if(!reader)return refuse("metadata_capture.native_reader_required");
        reader->retain_capture_lease(job.sealing_lease());
    }
    auto query=native->open_metadata_replay_view(snapshot.policy);
    if(!query.value()){const auto&e=*query.unavailable_detail();return R::unavailable(e.state,e.error);}
    if(!*query.value()||!dynamic_cast<const WindowsOpenedEntry*>(query.value()->get()))return refuse("metadata_capture.native_manifest_view");
    snapshot.channel_evidence=std::make_shared<WindowsChannelManifestProof>(std::move(query).take_value(),snapshot,job.sealing_lease());
    if(snapshot.policy.scope==RegularMetadataScope::CompleteMetadataV1){
        if(snapshot.security.size()!=1)return refuse("metadata_capture.native_full_descriptor");
        const auto classes=persistent_sacl_classes(snapshot.security.front());
        if(!classes.value()){const auto&e=*classes.unavailable_detail();return R::unavailable(e.state,e.error);}
        auto view=native->open_metadata_replay_view(snapshot.policy);
        if(!view.value()){const auto&e=*view.unavailable_detail();return R::unavailable(e.state,e.error);}
        if(!*view.value()||!dynamic_cast<WindowsOpenedEntry*>(view.value()->get()))return refuse("metadata_capture.native_full_view");
        auto owned=std::move(view).take_value();
        std::unique_ptr<WindowsOpenedEntry> exact(static_cast<WindowsOpenedEntry*>(owned.release()));
        snapshot.security_coverage=std::make_shared<WindowsPersistentSecurityProof>(std::move(exact),snapshot,job.sealing_lease());
    }
    // The only hashes being signed are the final job's private, twice-read
    // accumulators. No bulk issuer or public-snapshot hash is accepted here.
    return R::available(true);
}
} // namespace detail

Observation<std::shared_ptr<const MetadataReplayChannelEvidence>> issue_native_metadata_replay_channels(
    const OpenedEntry& source,const MetadataReplaySnapshot& snapshot,std::stop_token stop) {
    using Result=Observation<std::shared_ptr<const MetadataReplayChannelEvidence>>;
    if(!dynamic_cast<const WindowsOpenedEntry*>(&source)||!snapshot.policy.valid()||
       snapshot.channel_coverage!=DataChannelCoverage::WindowsFileStreamInfo||
       snapshot.channels.size()>snapshot.policy.limits.max_records)
        return Result::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"metadata_channels.native_issuer_bounds"});
    auto view=source.open_metadata_replay_view(snapshot.policy);
    if(!view.value()){const auto& e=*view.unavailable_detail();return Result::unavailable(e.state,e.error);}
    if(!*view.value()||!dynamic_cast<const WindowsOpenedEntry*>(view.value()->get()))
        return failure<std::shared_ptr<const MetadataReplayChannelEvidence>>(ERROR_INVALID_DATA,"metadata_channels.native_issuer_view");
    auto proof=std::make_shared<WindowsChannelManifestProof>(std::move(view).take_value(),snapshot);
    const auto checked=proof->recheck(snapshot);
    if(!checked.value()){const auto& e=*checked.unavailable_detail();return Result::unavailable(e.state,e.error);}
    if(!*checked.value())return failure<std::shared_ptr<const MetadataReplayChannelEvidence>>(ERROR_INVALID_DATA,"metadata_channels.native_issuer_false");
    // The public issuer never signs caller-supplied hashes. Hash only genuine
    // adapter readers, with cancellation, after catalog/identity/limit checks.
    for(const auto& channel:snapshot.channels) {
        const auto digest=digest_metadata_replay_channel(*channel.source,channel.identifier,
            *snapshot.basic.identity.value(),channel.logical_size,stop);
        if(!digest.value()){const auto& e=*digest.unavailable_detail();return Result::unavailable(e.state,e.error);}
        if(*digest.value()!=channel.digest)return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"metadata_channels.native_issuer_digest"});
    }
    if(stop.stop_requested())return Result::unavailable(ObservationState::Unknown,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InterruptedRead),"metadata_channels.native_issuer_cancelled"});
    const auto final=proof->recheck(snapshot);
    if(!final.value()){const auto& e=*final.unavailable_detail();return Result::unavailable(e.state,e.error);}
    return Result::available(std::move(proof));
}
Observation<bool> verify_native_metadata_replay_channels(const MetadataReplaySnapshot& snapshot) {
    const auto* proof=dynamic_cast<const WindowsChannelManifestProof*>(snapshot.channel_evidence.get());
    if(!proof)return Observation<bool>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"metadata_channels.native_evidence_required"});
    return proof->recheck(snapshot);
}

namespace {
Observation<NativeBytes> private_creation_descriptor() {
    using Result=Observation<NativeBytes>;HANDLE raw=nullptr;
    if(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&raw)) {
        if(GetLastError()!=ERROR_NO_TOKEN||!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw))
            return failure<NativeBytes>(GetLastError(),"directory_creation.effective_token");
    }
    OwnedHandle token(raw);DWORD size=0;GetTokenInformation(token.get(),TokenUser,nullptr,0,&size);
    if(!size||GetLastError()!=ERROR_INSUFFICIENT_BUFFER)return failure<NativeBytes>(GetLastError(),"directory_creation.token_size");
    NativeBytes user(size);
    if(!GetTokenInformation(token.get(),TokenUser,user.data(),size,&size))return failure<NativeBytes>(GetLastError(),"directory_creation.token_user");
    LPWSTR text=nullptr;
    if(!ConvertSidToStringSidW(reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid,&text))
        return failure<NativeBytes>(GetLastError(),"directory_creation.sid");
    const std::wstring sid(text);LocalFree(text);
    const auto sddl=L"O:"+sid+L"D:P(A;;FA;;;"+sid+L")(A;;FA;;;SY)";
    PSECURITY_DESCRIPTOR descriptor=nullptr;ULONG bytes=0;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&descriptor,&bytes))
        return failure<NativeBytes>(GetLastError(),"directory_creation.private_descriptor");
    const auto* first=static_cast<const std::byte*>(descriptor);NativeBytes result(first,first+bytes);LocalFree(descriptor);
    return Result::available(std::move(result));
}
Observation<OwnedHandle> readonly_created_directory(HANDLE created,const ObjectIdentity& expected,
    const AdapterScope& scope,DWORD rights) {
    using Result=Observation<OwnedHandle>;
    if(expected.scheme!=IdentityScheme::WindowsFileId128)return failure<OwnedHandle>(ERROR_NOT_SUPPORTED,"directory_creation.identity_scheme");
    FILE_ID_DESCRIPTOR id{};id.dwSize=sizeof(id);id.Type=ExtendedFileIdType;
    std::memcpy(id.ExtendedFileId.Identifier,expected.object.bytes.data(),16);
    OwnedHandle opened(OpenFileById(created,&id,rights|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL));
    if(!opened||opened.get()==INVALID_HANDLE_VALUE)return failure<OwnedHandle>(GetLastError(),"directory_creation.OpenFileById.readonly");
    const auto current=handle_metadata(opened.get(),scope);
    if(!current.value()){const auto& e=*current.unavailable_detail();return Result::unavailable(e.state,e.error);}
    if(!current.value()->identity.value()||compare_identity(*current.value()->identity.value(),expected)!=IdentityComparison::Same||
       !current.value()->kind.value()||*current.value()->kind.value()!=ObjectKind::Directory)
        return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"directory_creation.readonly_identity"});
    return Result::available(std::move(opened));
}
Observation<bool> verify_private_creation_descriptor(WindowsOpenedEntry& writer,const NativeBytes& expected) {
    using Result=Observation<bool>;
    const auto actual=writer.read_security(SecurityPart::WindowsAccess);
    if(!actual.value()){const auto& e=*actual.unavailable_detail();return Result::unavailable(e.state,e.error);}
    auto* a=const_cast<std::byte*>(expected.data());auto* b=const_cast<std::byte*>(actual.value()->bytes.data());
    PSID ao=nullptr,bo=nullptr;BOOL ad=FALSE,bd=FALSE;PACL aa=nullptr,ba=nullptr;BOOL ap=FALSE,bp=FALSE;
    SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;
    if(!GetSecurityDescriptorOwner(a,&ao,&ad)||!GetSecurityDescriptorOwner(b,&bo,&bd)||!ao||!bo||!EqualSid(ao,bo)||
       !GetSecurityDescriptorDacl(a,&ap,&aa,&ad)||!GetSecurityDescriptorDacl(b,&bp,&ba,&bd)||!ap||!bp||!aa||!ba||
       aa->AclSize!=ba->AclSize||std::memcmp(aa,ba,aa->AclSize)!=0||
       !GetSecurityDescriptorControl(b,&control,&revision)||(control&SE_DACL_PROTECTED)==0)
        return Result::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"directory_creation.private_descriptor_changed"});
    return Result::available(true);
}
}
Observation<bool> qualify_native_directory_creation(const DirectoryCursor& parent,const MetadataReplayPolicy& policy) {
    using Result=Observation<bool>;
    const auto unsupported=[](const char* op){return Result::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),op});};
    if(!policy.valid())return failure<bool>(ERROR_INVALID_PARAMETER,"directory_creation.policy");
    const auto* cursor=dynamic_cast<const WindowsDirectoryCursor*>(&parent);
    if(!cursor)return unsupported("directory_creation.native_cursor_required");
    const auto current=handle_metadata(cursor->handle_.get(),cursor->scope_);
    if(!current.value()){const auto& e=*current.unavailable_detail();return Result::unavailable(e.state,e.error);}
    constexpr DWORD supported=FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|
        FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    if(!current.value()->kind.value()||*current.value()->kind.value()!=ObjectKind::Directory||
       !current.value()->identity.value()||current.value()->identity.value()->scheme!=IdentityScheme::WindowsFileId128||
       !parent.identity().value()||compare_identity(*current.value()->identity.value(),*parent.identity().value())!=IdentityComparison::Same||
       !current.value()->windows_attributes.value()||(*current.value()->windows_attributes.value()&~supported))
        return unsupported("directory_creation.parent_provider_identity");
    DWORD flags=0;WCHAR filesystem[32]{};
    if(!GetVolumeInformationByHandleW(cursor->handle_.get(),nullptr,0,nullptr,nullptr,&flags,filesystem,32))
        return failure<bool>(GetLastError(),"directory_creation.volume");
    if((std::wstring_view(filesystem)!=L"NTFS"&&std::wstring_view(filesystem)!=L"ReFS")||!(flags&FILE_PERSISTENT_ACLS))
        return unsupported("directory_creation.filesystem");
    using QueryVolume=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
    const auto address=GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryVolumeInformationFile");
    if(!address)return unsupported("directory_creation.device_query");
    struct Device{ULONG type,characteristics;} device{};IO_STATUS_BLOCK io{};
    const auto status=std::bit_cast<QueryVolume>(address)(cursor->handle_.get(),&io,&device,sizeof(device),4);
    if(status!=0)return Result::unavailable(error_state(RtlNtStatusToDosError(status)),
        {ErrorDomain::NtStatus,static_cast<std::uint32_t>(status),"directory_creation.device"});
    if(io.Information!=sizeof(device)||(device.characteristics&0x10U))return unsupported("directory_creation.remote_provider");
    if(policy.scope==RegularMetadataScope::CompleteMetadataV1) {
        // New directories can inherit the parent's case-sensitive state.
        // Refuse unknown/nonzero state before FILE_CREATE, not afterwards.
        FILE_CASE_SENSITIVE_INFO case_info{};
        if(!GetFileInformationByHandleEx(cursor->handle_.get(),FileCaseSensitiveInfo,&case_info,sizeof(case_info)))
            return Result::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Win32,GetLastError(),"directory_creation.parent_case_query_unqualified"});
        if(case_info.Flags!=0)return unsupported("directory_creation.parent_case_flags_unimplemented");
        if(!policy.allow_privilege_metadata)return unsupported("directory_creation.full_security_optin_required");
        const auto privilege=require_enabled_security_privilege();if(!privilege.value())return privilege;
    }
    // Acquire actual namespace rights, but never infer creation identity from
    // this momentary check. The factory repeats qualification before FILE_CREATE.
    auto access=cursor->open_namespace_write_handle();
    if(!access.value()){const auto& e=*access.unavailable_detail();return Result::unavailable(e.state,e.error);}
    const HANDLE handle=std::move(access).take_value().release();
    if(!CloseHandle(handle))return failure<bool>(GetLastError(),"directory_creation.qualify_parent_close");
    return Result::available(true);
}
Observation<std::unique_ptr<NativeCreatedDirectory>> create_native_directory(
    std::shared_ptr<const DirectoryCursor> parent,NativeName name,const MetadataReplayPolicy& policy) {
    using Result=Observation<std::unique_ptr<NativeCreatedDirectory>>;
    if(!parent)return failure<std::unique_ptr<NativeCreatedDirectory>>(ERROR_INVALID_PARAMETER,"directory_creation.parent");
    const auto* units=name.windows_units();
    if(!units||!name.is_valid()||units->find(u':')!=std::u16string::npos||units->size()>std::numeric_limits<USHORT>::max()/sizeof(WCHAR))
        return failure<std::unique_ptr<NativeCreatedDirectory>>(ERROR_INVALID_PARAMETER,"directory_creation.name");
    const auto qualified=qualify_native_directory_creation(*parent,policy);
    if(!qualified.value()){const auto& e=*qualified.unavailable_detail();return Result::unavailable(e.state,e.error);}
    if(!*qualified.value())return failure<std::unique_ptr<NativeCreatedDirectory>>(ERROR_NOT_SUPPORTED,"directory_creation.qualification_false");
    const auto* cursor=dynamic_cast<const WindowsDirectoryCursor*>(parent.get());
    auto parent_access=cursor->open_namespace_write_handle();
    if(!parent_access.value()){const auto& e=*parent_access.unavailable_detail();return Result::unavailable(e.state,e.error);}
    auto descriptor=private_creation_descriptor();
    if(!descriptor.value()){const auto& e=*descriptor.unavailable_detail();return Result::unavailable(e.state,e.error);}
    std::wstring spelling(units->begin(),units->end());UNICODE_STRING native_name{};
    native_name.Length=static_cast<USHORT>(spelling.size()*sizeof(WCHAR));native_name.MaximumLength=native_name.Length;native_name.Buffer=spelling.data();
    OBJECT_ATTRIBUTES attributes{};attributes.Length=sizeof(attributes);attributes.RootDirectory=cursor->handle_.get();
    attributes.ObjectName=&native_name;attributes.SecurityDescriptor=const_cast<std::byte*>(descriptor.value()->data());
    IO_STATUS_BLOCK io{};HANDLE raw=nullptr;
    const DWORD rights=FILE_GENERIC_READ|FILE_GENERIC_WRITE|READ_CONTROL|WRITE_DAC|WRITE_OWNER|DELETE|
        (policy.scope==RegularMetadataScope::CompleteMetadataV1?ACCESS_SYSTEM_SECURITY:0);
    const auto status=NtCreateFile(&raw,rights,&attributes,&io,nullptr,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ|FILE_SHARE_WRITE,
        FILE_CREATE,FILE_DIRECTORY_FILE|FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT|FILE_WRITE_THROUGH,nullptr,0);
    OwnedHandle created(raw);
    if(status!=0)return Result::unavailable(error_state(RtlNtStatusToDosError(status)),
        {ErrorDomain::NtStatus,static_cast<std::uint32_t>(status),"directory_creation.NtCreateFile"});
    if(!created||created.get()==INVALID_HANDLE_VALUE||io.Information!=FILE_CREATED)
        return failure<std::unique_ptr<NativeCreatedDirectory>>(ERROR_INVALID_DATA,"directory_creation.not_created");
    const auto observed=handle_metadata(created.get(),cursor->scope_);
    if(!observed.value()){const auto& e=*observed.unavailable_detail();return Result::unavailable(e.state,e.error);}
    if(!observed.value()->kind.value()||*observed.value()->kind.value()!=ObjectKind::Directory||!observed.value()->identity.value())
        return failure<std::unique_ptr<NativeCreatedDirectory>>(ERROR_INVALID_DATA,"directory_creation.created_kind_identity");
    auto cursor_view=readonly_created_directory(created.get(),*observed.value()->identity.value(),cursor->scope_,FILE_LIST_DIRECTORY);
    if(!cursor_view.value()){const auto& e=*cursor_view.unavailable_detail();return Result::unavailable(e.state,e.error);}
    auto verify_view=readonly_created_directory(created.get(),*observed.value()->identity.value(),cursor->scope_,FILE_READ_EA|READ_CONTROL|
        (policy.scope==RegularMetadataScope::CompleteMetadataV1?ACCESS_SYSTEM_SECURITY:0));
    if(!verify_view.value()){const auto& e=*verify_view.unavailable_detail();return Result::unavailable(e.state,e.error);}
    auto writer=std::make_unique<WindowsOpenedEntry>(std::move(created),cursor->scope_,false,false,true,nullptr,false,true);
    const auto private_checked=verify_private_creation_descriptor(*writer,*descriptor.value());
    if(!private_checked.value()){const auto& e=*private_checked.unavailable_detail();return Result::unavailable(e.state,e.error);}
    const auto metadata_qualified=writer->qualify_metadata_replay(policy);
    if(!metadata_qualified.value()){const auto& e=*metadata_qualified.unavailable_detail();return Result::unavailable(e.state,e.error);}
    if(!*metadata_qualified.value())return failure<std::unique_ptr<NativeCreatedDirectory>>(ERROR_NOT_SUPPORTED,"directory_creation.metadata_qualification_false");
    const auto directory_identity=identity(cursor_view.value()->get(),cursor->scope_);
    if(!directory_identity.value()){const auto& e=*directory_identity.unavailable_detail();return Result::unavailable(e.state,e.error);}
    auto result_cursor=std::make_shared<WindowsDirectoryCursor>(std::move(cursor_view).take_value(),directory_identity,cursor->scope_);
    auto verifier=std::make_unique<WindowsOpenedEntry>(std::move(verify_view).take_value(),cursor->scope_);
    // Consume the temporary namespace writer and report its close error too.
    const HANDLE parent_writer=std::move(parent_access).take_value().release();
    const DWORD flush_error=FlushFileBuffers(parent_writer)?ERROR_SUCCESS:GetLastError();
    const DWORD close_error=CloseHandle(parent_writer)?ERROR_SUCCESS:GetLastError();
    if(flush_error)return failure<std::unique_ptr<NativeCreatedDirectory>>(flush_error,"directory_creation.parent_flush_after_create");
    if(close_error)return failure<std::unique_ptr<NativeCreatedDirectory>>(close_error,"directory_creation.parent_close_after_create");
    return Result::available(std::unique_ptr<NativeCreatedDirectory>(new NativeCreatedDirectory(std::move(parent),std::move(name),
        std::move(result_cursor),std::move(writer),std::move(verifier),*observed.value(),policy)));
}
Observation<bool> NativeCreatedDirectory::finish_io() {
    if(finish_result_)return *finish_result_;
    const auto* writer=dynamic_cast<const WindowsOpenedEntry*>(writer_.get());
    auto* verifier=dynamic_cast<WindowsOpenedEntry*>(verifier_.get());
    if(!writer||!verifier)return failure<bool>(ERROR_INVALID_HANDLE,"directory_creation.native_writer_required");
    // Preserve actual caller SID evidence before fully closing the writer.
    verifier->caller_security_=writer->caller_security_;
    finish_result_=writer_->finish_content_writes();return *finish_result_;
}


Observation<BasicMetadata> NativeFileSystem::inspect_basic(const std::filesystem::path& path) const {
    const auto address = NativeAbsolutePath::from_host(path);
    if (!address.value()) { const auto& e = *address.unavailable_detail(); return Observation<BasicMetadata>::unavailable(e.state, e.error); }
    const auto native_path = windows_extended_path(path.native());
    if (!native_path) return failure<BasicMetadata>(ERROR_INVALID_NAME, "CreateFileW.metadata.path");
    const std::unique_ptr<void, HandleCloser> handle(CreateFileW(native_path->c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL, nullptr));
    if (handle.get() == INVALID_HANDLE_VALUE) return failure<BasicMetadata>(GetLastError(), "CreateFileW.metadata");

    return handle_metadata(handle.get(), scope_);
}

Observation<std::unique_ptr<DirectoryCursor>> NativeFileSystem::open_directory(
    const std::filesystem::path& path, DirectoryLinkPolicy policy) const {
    using Result = Observation<std::unique_ptr<DirectoryCursor>>;
    const auto address = NativeAbsolutePath::from_host(path);
    if (!address.value()) { const auto& e = *address.unavailable_detail(); return Result::unavailable(e.state, e.error); }
    if (policy != DirectoryLinkPolicy::RejectFinalLink && policy != DirectoryLinkPolicy::FollowFinalLink)
        return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidPath), "open_directory"});
    const DWORD link_flag = policy == DirectoryLinkPolicy::RejectFinalLink ? FILE_FLAG_OPEN_REPARSE_POINT : 0;
    const auto native_path = windows_extended_path(path.native());
    if (!native_path) return failure<std::unique_ptr<DirectoryCursor>>(ERROR_INVALID_NAME, "CreateFileW.directory.path");
    OwnedHandle handle(CreateFileW(native_path->c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL | link_flag, nullptr));
    if (handle.get() == INVALID_HANDLE_VALUE) return failure<std::unique_ptr<DirectoryCursor>>(GetLastError(), "CreateFileW.directory");
    FILE_BASIC_INFO basic{};
    if (!GetFileInformationByHandleEx(handle.get(), FileBasicInfo, &basic, sizeof(basic)))
        return failure<std::unique_ptr<DirectoryCursor>>(GetLastError(), "FileBasicInfo.directory");
    if (policy == DirectoryLinkPolicy::RejectFinalLink && (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::FinalLinkRejected), "open_directory.reparse"});
    if ((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        return Result::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotDirectory), "open_directory.kind"});
    auto native_identity = identity(handle.get(), scope_);
    return Result::available(std::make_unique<WindowsDirectoryCursor>(std::move(handle), std::move(native_identity), scope_));
}
Observation<void*> detail::duplicate_windows_journal_directory(const DirectoryCursor& cursor) {
    const auto* native=dynamic_cast<const WindowsDirectoryCursor*>(&cursor);
    if(!native)return Observation<void*>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::UnsupportedQuery),"journal_root.native_cursor_required"});
    const auto current=native->inspect_basic();
    if(!current.value())return Observation<void*>::unavailable(current.state(),current.unavailable_detail()->error);
    if(!cursor.identity().value()||!current.value()->identity.value()||
        compare_identity(*cursor.identity().value(),*current.value()->identity.value())!=IdentityComparison::Same)
        return Observation<void*>::unavailable(ObservationState::Changed,
            {ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::MetadataChanged),"journal_root.cursor_changed"});
    auto duplicate=native->duplicate_trash_parent();
    if(!duplicate.value())return Observation<void*>::unavailable(duplicate.state(),duplicate.unavailable_detail()->error);
    auto owner=std::move(duplicate).take_value();
    return Observation<void*>::available(owner.release());
}
Observation<WindowsTrashHandle> duplicate_windows_trash_parent(const DirectoryCursor& cursor) {
    const auto* native=dynamic_cast<const WindowsDirectoryCursor*>(&cursor);
    if (!native) return Observation<WindowsTrashHandle>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<int64_t>(AdapterError::UnsupportedQuery),"trash.native_parent"});
    return native->duplicate_trash_parent();
}


Observation<std::unique_ptr<DirectoryCursor>> detail::open_native_session_root(const NativeSessionLease& lease,bool right) {
    using R=Observation<std::unique_ptr<DirectoryCursor>>;
    auto source=lease.handle(right);if(!source.value()){const auto& e=*source.unavailable_detail();return R::unavailable(e.state,e.error);}
    // Independent enumeration state for a genuine sealed Session handle. The
    // ID is queried here from the still-held original, never accepted as a
    // caller fact. Holding that object prevents ID reuse during this open.
    // ReOpenFile requires CreateFile origin; this Session handle is native-created.
    const auto original=reinterpret_cast<HANDLE>(*source.value());
    FILE_ID_INFO before{};
    if(!GetFileInformationByHandleEx(original,FileIdInfo,&before,sizeof(before)))
        return failure<std::unique_ptr<DirectoryCursor>>(GetLastError(),"session_lease.held_root_id");
    FILE_ID_DESCRIPTOR descriptor{};descriptor.dwSize=sizeof(descriptor);descriptor.Type=ExtendedFileIdType;
    std::memcpy(descriptor.ExtendedFileId.Identifier,before.FileId.Identifier,16);
    OwnedHandle opened(OpenFileById(original,&descriptor,FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL));
    if(!opened||opened.get()==INVALID_HANDLE_VALUE)return failure<std::unique_ptr<DirectoryCursor>>(GetLastError(),"session_lease.OpenFileById_root");
    FILE_ID_INFO after{};
    if(!GetFileInformationByHandleEx(opened.get(),FileIdInfo,&after,sizeof(after)))
        return failure<std::unique_ptr<DirectoryCursor>>(GetLastError(),"session_lease.opened_root_id");
    if(before.VolumeSerialNumber!=after.VolumeSerialNumber||std::memcmp(before.FileId.Identifier,after.FileId.Identifier,16)!=0)
        return R::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,19,"session_lease.held_root_identity_changed"});
    FILE_ATTRIBUTE_TAG_INFO tag{};if(!GetFileInformationByHandleEx(opened.get(),FileAttributeTagInfo,&tag,sizeof(tag)))return failure<std::unique_ptr<DirectoryCursor>>(GetLastError(),"session_lease.root_tag");
    constexpr DWORD unsafe=FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_OFFLINE;
    if(!(tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)||(tag.FileAttributes&unsafe))return R::unavailable(ObservationState::Unsupported,{ErrorDomain::Adapter,18,"session_lease.root_kind"});
    auto id=identity(opened.get(),lease.scope_);
    return R::available(std::make_unique<WindowsDirectoryCursor>(std::move(opened),std::move(id),lease.scope_));
}
} // namespace ck::files
