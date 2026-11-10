// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../operation_journal_file.hpp"
#include "../metadata_capture_job.hpp"
#include "../prepared_journal_root.hpp"
#include "../prepared_journal_directory.hpp"
#include "../windows_directory_record.hpp"
#include "prepared_journal_root_bridge.hpp"
#include "prepared_journal_failure_latch.hpp"
#include "../directory_cursor.hpp"
#include "../windows_parent_record.hpp"
#include "native_journal_directory_bridge.hpp"
#include "journal_root_test_faults.hpp"
#include "native_close_test_faults.hpp"
#include "native_windows_journal_volume.hpp"
#include "../windows_name.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include "legacy_native_fixture_windows.hpp"
#include <aclapi.h>
#include <winioctl.h>
#include <array>
#include <cstring>
#include <mutex>
#include <utility>

#include <algorithm>
#include <limits>
#include <vector>

namespace ck::files {
namespace {
// Regression observers bracket the same native call and cannot turn failure
// into success. Always preserve the OS result/error before invoking callbacks.
bool close_native_consumer_handle(HANDLE handle,const char* operation)noexcept {
#ifndef CK_FS_NATIVE_CLOSE_TEST_HOOKS
    (void)operation;return ::ck::files::detail::legacy_close_native_call(handle,"legacy.operation_journal_file_windows.CloseHandle.40")!=FALSE;
#else
    const DWORD before=GetLastError();
    ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_close(handle,operation);});
    SetLastError(before);const BOOL native_ok=::ck::files::detail::legacy_close_native_call(handle,"legacy.operation_journal_file_windows.CloseHandle.44");
    const DWORD saved=GetLastError();
    const DWORD native_error=native_ok?ERROR_SUCCESS:saved;
    const auto injected=::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::inject_native_close_failure(handle,operation,native_ok!=FALSE,native_error);});
    if(!native_ok){SetLastError(native_error);return false;}
    if(injected){SetLastError(injected);return false;}
    SetLastError(saved);return true;
#endif
}
bool write_native_consumer_file(HANDLE handle,const void* bytes,DWORD count,DWORD* written,const char* operation)noexcept {
#ifndef CK_FS_NATIVE_CLOSE_TEST_HOOKS
    (void)operation;return ::ck::files::detail::legacy_write_file(handle,bytes,count,written,nullptr,"legacy.operation_journal_file_windows.WriteFile.55")!=FALSE;
#else
    const DWORD before=GetLastError();
    ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_file_before(handle,detail::NativeTestIo::Write,count,operation);});
    SetLastError(before);const BOOL okay=::ck::files::detail::legacy_write_file(handle,bytes,count,written,nullptr,"legacy.operation_journal_file_windows.WriteFile.59");
    const DWORD error=GetLastError();
    ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_file_after(handle,detail::NativeTestIo::Write,okay!=FALSE,okay?ERROR_SUCCESS:error,operation);});
    SetLastError(error);return okay!=FALSE;
#endif
}
struct Close {
    void operator()(void* value) const noexcept {
        if(value&&value!=INVALID_HANDLE_VALUE){
            constexpr const char* operation="journal_file.temporary_CloseHandle";
            ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_close(value,operation);});
            const BOOL native_ok=::ck::files::detail::legacy_close_native_call(value,"legacy.operation_journal_file_windows.CloseHandle.70");
            const DWORD saved=GetLastError();
            const DWORD native_error=native_ok?ERROR_SUCCESS:saved;
            const auto injected=::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::inject_native_close_failure(value,operation,native_ok!=FALSE,native_error);});
            const DWORD error=native_ok?injected:native_error;
            if(error)detail::record_metadata_capture_close({ObservationState::Failed,ErrorDomain::Win32,error,operation});
            SetLastError(error?error:saved);
        }
    }
};
using Handle = std::unique_ptr<void, Close>;
struct LocalFreeOwner {
    void operator()(void* value) const noexcept { if (value) LocalFree(value); }
};
using Local = std::unique_ptr<void, LocalFreeOwner>;

ObservationState state(DWORD code) {
    if (code == ERROR_ACCESS_DENIED || code == ERROR_SHARING_VIOLATION || code == ERROR_PRIVILEGE_NOT_HELD)
        return ObservationState::Denied;
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
        return ObservationState::Gone;
    if (code == ERROR_NOT_SUPPORTED || code == ERROR_INVALID_FUNCTION || code == ERROR_CALL_NOT_IMPLEMENTED)
        return ObservationState::Unsupported;
    return ObservationState::Failed;
}
template <class T>
Observation<T> failure(DWORD code, const char* operation) {
    return Observation<T>::unavailable(state(code), {ErrorDomain::Win32, code, operation});
}
template <class T>
Observation<T> nt_failure(NTSTATUS code, const char* operation) {
    return Observation<T>::unavailable(state(RtlNtStatusToDosError(code)),
        {ErrorDomain::NtStatus, static_cast<std::int64_t>(code), operation});
}
template <class T>
Observation<T> rejected(AdapterError code, const char* operation,
                        ObservationState state = ObservationState::Failed) {
    return Observation<T>::unavailable(state,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(code), operation});
}

Observation<std::vector<std::byte>> effective_user() {
    HANDLE raw{};
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        const auto code = GetLastError();
        if (code != ERROR_NO_TOKEN) return failure<std::vector<std::byte>>(code, "journal_file.thread_token");
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
            return failure<std::vector<std::byte>>(GetLastError(), "journal_file.process_token");
    }
    Handle token(raw);
    DWORD required = 0;
    if (GetTokenInformation(token.get(), TokenUser, nullptr, 0, &required) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || required < sizeof(TOKEN_USER) || required > 64 * 1024)
        return rejected<std::vector<std::byte>>(AdapterError::InvalidNativeResult, "journal_file.token_size");
    std::vector<std::byte> data(required);
    if (!GetTokenInformation(token.get(), TokenUser, data.data(), required, &required))
        return failure<std::vector<std::byte>>(GetLastError(), "journal_file.token_user");
    const auto* user = reinterpret_cast<const TOKEN_USER*>(data.data())->User.Sid;
    if (!IsValidSid(const_cast<PSID>(user)))
        return rejected<std::vector<std::byte>>(AdapterError::InvalidNativeResult, "journal_file.user_sid");
    const auto length = GetLengthSid(const_cast<PSID>(user));
    if (length == 0 || length > SECURITY_MAX_SID_SIZE)
        return rejected<std::vector<std::byte>>(AdapterError::InvalidNativeResult, "journal_file.sid_length");
    std::vector<std::byte> result(length);
    if (!CopySid(length, result.data(), const_cast<PSID>(user)))
        return failure<std::vector<std::byte>>(GetLastError(), "journal_file.CopySid");
    return Observation<std::vector<std::byte>>::available(std::move(result));
}

Observation<bool> verify_security(HANDLE file, PSID expected) {
    PSID owner{}; PACL acl{}; PSECURITY_DESCRIPTOR raw{};
    const auto code = GetSecurityInfo(file, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &acl, nullptr, &raw);
    Local descriptor(raw);
    if (code != ERROR_SUCCESS) return failure<bool>(code, "journal_file.GetSecurityInfo");
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision{};
    if (!GetSecurityDescriptorControl(raw, &control, &revision))
        return failure<bool>(GetLastError(), "journal_file.GetSecurityDescriptorControl");
    if (!owner || !IsValidSid(owner) || !EqualSid(owner, expected)) {
        return rejected<bool>(AdapterError::InvalidNativeResult, "journal_file.private_descriptor.owner");
    }
    if (!acl || !IsValidAcl(acl))
        return rejected<bool>(AdapterError::InvalidNativeResult, "journal_file.private_descriptor.dacl");
    if (!(control & SE_DACL_PROTECTED))
        return rejected<bool>(AdapterError::InvalidNativeResult, "journal_file.private_descriptor.protection");
    ACL_SIZE_INFORMATION info{};
    if (!GetAclInformation(acl, &info, sizeof(info), AclSizeInformation))
        return failure<bool>(GetLastError(), "journal_file.GetAclInformation");
    if (info.AceCount != 2) return rejected<bool>(AdapterError::InvalidNativeResult, "journal_file.private_descriptor.ace_count");
    bool user = false, system = false;
    for (DWORD index = 0; index != info.AceCount; ++index) {
        void* raw_ace{};
        if (!GetAce(acl, index, &raw_ace)) return failure<bool>(GetLastError(), "journal_file.GetAce");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags != 0 ||
            ace->Header.AceSize < sizeof(ACCESS_ALLOWED_ACE) || ace->Mask != FILE_ALL_ACCESS)
            return rejected<bool>(AdapterError::InvalidNativeResult, "journal_file.private_descriptor.ace");
        auto* sid = reinterpret_cast<PSID>(const_cast<SID*>(reinterpret_cast<const SID*>(&ace->SidStart)));
        if (!IsValidSid(sid) || GetLengthSid(sid) > ace->Header.AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart))
            return rejected<bool>(AdapterError::InvalidNativeResult, "journal_file.private_descriptor.ace_sid");
        if (index == 0 && EqualSid(sid, expected)) user = true;
        else if (index == 1 && IsWellKnownSid(sid, WinLocalSystemSid)) system = true;
        else return rejected<bool>(AdapterError::InvalidNativeResult, "journal_file.private_descriptor.ace_principal");
    }
    return Observation<bool>::available(user && system);
}

Observation<bool> verify_root(HANDLE directory, PSID expected) {
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!::ck::files::detail::legacy_query(directory, FileAttributeTagInfo, &tag, sizeof(tag),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.179"))
        return failure<bool>(GetLastError(), "journal_file.root_tag");
    if (!(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return rejected<bool>(AdapterError::FinalLinkRejected, "journal_file.root_kind");
    DWORD flags{};
    if (!GetVolumeInformationByHandleW(directory, nullptr, 0, nullptr, nullptr, &flags, nullptr, 0))
        return failure<bool>(GetLastError(), "journal_file.volume");
    if (!(flags & FILE_PERSISTENT_ACLS))
        return rejected<bool>(AdapterError::UnsupportedQuery, "journal_file.persistent_acls", ObservationState::Unsupported);
    return verify_security(directory, expected);
}

Observation<SECURITY_ATTRIBUTES> make_security(std::vector<std::byte>& user,
                                               std::vector<std::byte>& system,
                                               std::vector<std::byte>& acl_data,
                                               SECURITY_DESCRIPTOR& descriptor) {
    DWORD system_size = SECURITY_MAX_SID_SIZE;
    system.resize(system_size);
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system.data(), &system_size))
        return failure<SECURITY_ATTRIBUTES>(GetLastError(), "journal_file.system_sid");
    system.resize(system_size);
    const auto acl_size = static_cast<DWORD>(sizeof(ACL) +
        2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) +
        GetLengthSid(user.data()) + GetLengthSid(system.data()));
    acl_data.resize(acl_size);
    auto* acl = reinterpret_cast<PACL>(acl_data.data());
    if (!InitializeAcl(acl, acl_size, ACL_REVISION) ||
        !AddAccessAllowedAceEx(acl, ACL_REVISION, 0, FILE_ALL_ACCESS, user.data()) ||
        !AddAccessAllowedAceEx(acl, ACL_REVISION, 0, FILE_ALL_ACCESS, system.data()) ||
        !InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorOwner(&descriptor, user.data(), FALSE) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE) ||
        !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED))
        return failure<SECURITY_ATTRIBUTES>(GetLastError(), "journal_file.security_descriptor");
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = &descriptor;
    return Observation<SECURITY_ATTRIBUTES>::available(attributes);
}

bool valid_io(std::uint64_t offset, std::size_t count) {
    constexpr auto max = static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max());
    return offset <= max && count <= max - offset;
}

class WindowsOperationJournalFile final : public OperationJournalFile {
public:
    WindowsOperationJournalFile(HANDLE file,HANDLE directory,std::vector<std::byte> user, PreparedJournalRoot::Pointer root = {}, bool read_only = false) noexcept
        : file_(file),directory_(directory),user_(std::move(user)),root_(std::move(root)),read_only_(read_only) {}
    ~WindowsOperationJournalFile() override {
        if(!finished_) {
            try {(void)finish_io();}catch(...) {
                record_failure(ObservationState::Unknown,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_file.finalizer_exception");
                close_handles();finished_=true;
            }
        }
    }
    Observation<std::uint64_t> size() override {
        const auto checked=revalidate();
        if(!checked.value()) return unavailable_read<std::uint64_t>(checked);
        LARGE_INTEGER value{};
        if (!GetFileSizeEx(file_.get(), &value)) return io_failure<std::uint64_t>(GetLastError(), "journal_file.GetFileSizeEx");
        if (value.QuadPart < 0) return rejected<std::uint64_t>(AdapterError::InvalidNativeResult, "journal_file.size");
        if(read_only_) {auto after=revalidate();if(!after.value())return unavailable_read<std::uint64_t>(after);}
        return Observation<std::uint64_t>::available(static_cast<std::uint64_t>(value.QuadPart));
    }
    Observation<std::size_t> read_at(std::uint64_t offset, std::span<std::byte> bytes) override {
        if (!valid_io(offset, bytes.size())) return rejected<std::size_t>(AdapterError::InvalidLimit, "journal_file.read_range");
        const auto checked=revalidate();
        if(!checked.value()) return unavailable_read<std::size_t>(checked);
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(file_.get(), at, nullptr, FILE_BEGIN)) return io_failure<std::size_t>(GetLastError(), "journal_file.read_seek");
        DWORD count{};
        ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_test_io(detail::NativeTestIo::Read);});
        if (!::ck::files::detail::legacy_read_file(file_.get(), bytes.data(), static_cast<DWORD>(std::min(bytes.size(), static_cast<std::size_t>(MAXDWORD))), &count, nullptr,"legacy.operation_journal_file_windows.ReadFile.254"))
            return io_failure<std::size_t>(GetLastError(), "journal_file.ReadFile");
        auto after=revalidate();
        if(!after.value())return unavailable_read<std::size_t>(after);
        return Observation<std::size_t>::available(count);
    }
    Observation<std::size_t> write_at(std::uint64_t offset, std::span<const std::byte> bytes) override {
        if(read_only_)return rejected<std::size_t>(AdapterError::InvalidAccess,"journal_reader.read_only_write",ObservationState::Denied);
        if (!valid_io(offset, bytes.size())) return rejected<std::size_t>(AdapterError::InvalidLimit, "journal_file.write_range");
        const auto checked=revalidate();
        if(!checked.value()) return unavailable_read<std::size_t>(checked);
        LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(file_.get(), at, nullptr, FILE_BEGIN)) return io_failure<std::size_t>(GetLastError(), "journal_file.write_seek");
        DWORD count{};
        ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_test_io(detail::NativeTestIo::Write);});
        if (!write_native_consumer_file(file_.get(), bytes.data(), static_cast<DWORD>(std::min(bytes.size(), static_cast<std::size_t>(MAXDWORD))), &count, "journal_file.WriteFile"))
            return io_failure<std::size_t>(GetLastError(), "journal_file.WriteFile");
        auto after=revalidate();
        if(!after.value())return unavailable_read<std::size_t>(after);
        return Observation<std::size_t>::available(count);
    }
    Observation<bool> flush() override {
        if(read_only_)return rejected<bool>(AdapterError::InvalidAccess,"journal_reader.read_only_flush",ObservationState::Denied);
        const auto checked=revalidate();if(!checked.value()) return checked;
        ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_test_io(detail::NativeTestIo::Flush);});
        if (!::ck::files::detail::legacy_flush(file_.get(),"legacy.operation_journal_file_windows.FlushFileBuffers.279")) return io_failure<bool>(GetLastError(), "journal_file.FlushFileBuffers");
        ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_test_io(detail::NativeTestIo::Flush);});
        if (!::ck::files::detail::legacy_flush(directory_.get(),"legacy.operation_journal_file_windows.FlushFileBuffers.281")) return io_failure<bool>(GetLastError(),"journal_file.parent_FlushFileBuffers");
        return revalidate();
    }
    Observation<bool> finish_io() override {
        if(finished_)return finish_result();
        if(read_only_) {
            bool exceptional=false;
            try {(void)finish_check();}catch(...) {exceptional=true;}
            close_read_only_handles();finished_=true;
            if(exceptional && !close_operation_) {
                detail::PreparedJournalConsumerFailure prior{};
                if(!finish_failure_.read(prior))remember_finish(ObservationState::Unknown,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_reader.finalizer_exception");
            }
            return finish_result();
        }
        if(finish_started_) {
            record_failure(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_file.finalizer_incomplete");
            if(!close_operation_) {close_exception_=true;close_error_=static_cast<std::int64_t>(AdapterError::InvalidNativeResult);
                close_operation_="journal_file.finalizer_incomplete";}
            close_handles();finished_=true;return finish_result();
        }
        finish_started_=true;
        // Diagnostic construction may allocate, including on MSVC Debug. Native
        // ownership must be consumed even when revalidation cannot report an
        // already-latched failure under persistent allocation exhaustion.
        try { finish_flush(); }
        catch(...) {
            detail::PreparedJournalConsumerFailure prior{};
            if(root_ && detail::read_prepared_journal_consumer_failure(*root_,prior) && !prior.pending)
                remember_finish(prior.state,prior.domain,prior.code,prior.operation.data());
            else
                remember_finish(ObservationState::Unknown,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_file.finish_flush_exception");
        }
        close_handles();finished_=true;return finish_result();
    }
    Observation<bool> bind_read_only(const NativeName& name) {
        reader_name_.emplace(name);
        if(!::ck::files::detail::legacy_query(file_.get(),FileIdInfo,&reader_file_,sizeof(reader_file_),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.321") ||
           !::ck::files::detail::legacy_query(directory_.get(),FileIdInfo,&reader_directory_,sizeof(reader_directory_),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.322") ||
           !::ck::files::detail::legacy_query(file_.get(),FileBasicInfo,&reader_basic_,sizeof(reader_basic_),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.323") ||
           !::ck::files::detail::legacy_query(file_.get(),FileStandardInfo,&reader_standard_,sizeof(reader_standard_),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.324")) {
            const auto code=GetLastError();remember_finish(state(code),ErrorDomain::Win32,code,"journal_reader.bind_identity");
            return io_failure<bool>(code,"journal_reader.bind_identity");
        }
        reader_bound_=true;
        return revalidate();
    }
    bool record_consumer_failure(ObservationState observed,ErrorDomain domain,
        std::int64_t code,std::string_view operation) noexcept {
        return root_ && detail::record_prepared_journal_consumer_failure(*root_,observed,domain,code,operation);
    }
private:

    template<class T> Observation<T> io_failure(DWORD code,const char* operation) {
        if(read_only_)remember_finish(state(code),ErrorDomain::Win32,code,operation);
        return failure<T>(code,operation);
    }
    template<class T> Observation<T> unavailable_read(const Observation<bool>& checked) {
        const auto& e=*checked.unavailable_detail();
        if(read_only_)remember_finish(e.state,e.error.domain,e.error.code,e.error.operation);
        return Observation<T>::unavailable(e.state,e.error);
    }
    void remember_finish(ObservationState observed,ErrorDomain domain,std::int64_t code,
        std::string_view operation) noexcept {
        finish_failure_.record(observed,domain,code,operation);
        record_failure(observed,domain,code,operation);
    }
    bool finish_check() {
        const auto checked=revalidate();
        if(checked.value() && *checked.value())return true;
        if(const auto* error=checked.unavailable_detail())
            remember_finish(error->state,error->error.domain,error->error.code,error->error.operation);
        else
            remember_finish(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_file.finish_flush_false");
        return false;
    }
    void finish_flush() {
        if(!finish_check())return;
        ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_test_io(detail::NativeTestIo::Flush);});
        if(!::ck::files::detail::legacy_flush(file_.get(),"legacy.operation_journal_file_windows.FlushFileBuffers.364")) {
            const auto code=GetLastError();
            remember_finish(state(code),ErrorDomain::Win32,code,"journal_file.FlushFileBuffers");return;
        }
        ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_test_io(detail::NativeTestIo::Flush);});
        if(!::ck::files::detail::legacy_flush(directory_.get(),"legacy.operation_journal_file_windows.FlushFileBuffers.369")) {
            const auto code=GetLastError();
            remember_finish(state(code),ErrorDomain::Win32,code,"journal_file.parent_FlushFileBuffers");return;
        }
        (void)finish_check();
    }
    void record_failure(ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view operation) noexcept {
        if(root_)detail::record_prepared_journal_consumer_failure(*root_,state,domain,code,operation);
    }
    void remember_close(std::int64_t code,const char* operation) noexcept {
        record_failure(state(static_cast<DWORD>(code)),ErrorDomain::Win32,code,operation);
        if(!close_operation_) {close_error_=code;close_operation_=operation;}
    }
    void observe_close_fault() noexcept {
        try {
            if(const auto fault=detail::journal_root_fault(detail::JournalRootFaultPoint::JournalClose))
                remember_close(*fault,"journal_file.close_fault");
        } catch(...) {
            record_failure(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_file.close_fault_exception");
            if(!close_operation_) {close_error_=static_cast<std::int64_t>(AdapterError::InvalidNativeResult);
                close_operation_="journal_file.close_fault_exception";close_exception_=true;}
        }
    }
    void close_read_only_handles() noexcept {
        auto consume=[this](Handle& owner,const char* operation) noexcept {
            const auto raw=owner.release();
            if(!raw||raw==INVALID_HANDLE_VALUE)return false;
            ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_close(raw,operation);});
            const BOOL okay=::ck::files::detail::legacy_close_native_call(raw,"legacy.operation_journal_file_windows.CloseHandle.398");const DWORD native_error=okay?ERROR_SUCCESS:GetLastError();
            const auto injected=::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::inject_native_close_failure(raw,operation,okay!=FALSE,native_error);});
            const auto error=okay?injected:native_error;
            if(error)remember_close(error,operation);
            return true;
        };
        if(consume(file_,"journal_reader.CloseHandle"))observe_close_fault();
        (void)consume(directory_,"journal_reader.parent_CloseHandle");
    }
    void close_handles() noexcept {
        const auto file=file_.release();
        if(file&&file!=INVALID_HANDLE_VALUE) {if(!close_native_consumer_handle(file,"journal_file.CloseHandle"))remember_close(GetLastError(),"journal_file.CloseHandle");observe_close_fault();}
        const auto directory=directory_.release();
        if(directory&&directory!=INVALID_HANDLE_VALUE&&!close_native_consumer_handle(directory,"journal_file.parent_CloseHandle"))remember_close(GetLastError(),"journal_file.parent_CloseHandle");
    }
    Observation<bool> finish_result() const {
        detail::PreparedJournalConsumerFailure cached{};
        if(finish_failure_.read(cached))return finish_failure_.result();
        if(close_operation_)return close_exception_?Observation<bool>::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter,close_error_,close_operation_}):failure<bool>(static_cast<DWORD>(close_error_),close_operation_);
        return Observation<bool>::available(true);
    }
    Observation<bool> validate_read_only_binding() {
        const auto proof=detail::prove_windows_journal_volume(directory_.get());
        if(!proof.qualified) {
            remember_finish(proof.state,proof.domain,proof.code,proof.operation);
            return Observation<bool>::unavailable(proof.state,{proof.domain,proof.code,proof.operation});
        }
        if(!reader_bound_ || !reader_name_ || !reader_name_->windows_units())
            return rejected<bool>(AdapterError::InvalidNativeResult,"journal_reader.unbound");
        FILE_ID_INFO file{},directory{};FILE_BASIC_INFO basic{};FILE_STANDARD_INFO standard{},root_standard{};
        if(!::ck::files::detail::legacy_query(file_.get(),FileIdInfo,&file,sizeof(file),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.429") ||
           !::ck::files::detail::legacy_query(directory_.get(),FileIdInfo,&directory,sizeof(directory),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.430") ||
           !::ck::files::detail::legacy_query(file_.get(),FileBasicInfo,&basic,sizeof(basic),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.431") ||
           !::ck::files::detail::legacy_query(file_.get(),FileStandardInfo,&standard,sizeof(standard),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.432") ||
           !::ck::files::detail::legacy_query(directory_.get(),FileStandardInfo,&root_standard,sizeof(root_standard),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.433")) {
            const auto code=GetLastError();remember_finish(state(code),ErrorDomain::Win32,code,"journal_reader.identity");
            return io_failure<bool>(code,"journal_reader.identity");
        }
        const bool same=root_standard.Directory && !root_standard.DeletePending && root_standard.NumberOfLinks &&
            file.VolumeSerialNumber==reader_file_.VolumeSerialNumber &&
            directory.VolumeSerialNumber==reader_directory_.VolumeSerialNumber &&
            file.VolumeSerialNumber==directory.VolumeSerialNumber &&
            !std::memcmp(file.FileId.Identifier,reader_file_.FileId.Identifier,16) &&
            !std::memcmp(directory.FileId.Identifier,reader_directory_.FileId.Identifier,16) &&
            !standard.DeletePending && standard.NumberOfLinks==1 &&
            standard.EndOfFile.QuadPart==reader_standard_.EndOfFile.QuadPart &&
            basic.LastWriteTime.QuadPart==reader_basic_.LastWriteTime.QuadPart &&
            basic.ChangeTime.QuadPart==reader_basic_.ChangeTime.QuadPart &&
            basic.FileAttributes==reader_basic_.FileAttributes;
        if(!same) {
            remember_finish(ObservationState::Changed,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"journal_reader.identity_or_version_changed");
            return rejected<bool>(AdapterError::MetadataChanged,"journal_reader.identity_or_version_changed",ObservationState::Changed);
        }
        alignas(8) std::array<std::byte,65536> buffer{};
        if(!::ck::files::detail::legacy_query(file_.get(),FileNameInfo,buffer.data(),static_cast<DWORD>(buffer.size()),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.453")) {
            const auto code=GetLastError();remember_finish(state(code),ErrorDomain::Win32,code,"journal_reader.exact_name");
            return io_failure<bool>(code,"journal_reader.exact_name");
        }
        const auto* native=reinterpret_cast<const FILE_NAME_INFO*>(buffer.data());
        if(native->FileNameLength%sizeof(wchar_t) || native->FileNameLength>buffer.size()-offsetof(FILE_NAME_INFO,FileName))
            return rejected<bool>(AdapterError::InvalidNativeResult,"journal_reader.name_extent");
        const std::wstring_view full(native->FileName,native->FileNameLength/sizeof(wchar_t));
        const auto slash=full.find_last_of(L'\\');
        const auto tail=slash==std::wstring_view::npos?full:full.substr(slash+1);
        const auto& expected=*reader_name_->windows_units();
        if(tail.size()!=expected.size() || !std::equal(tail.begin(),tail.end(),expected.begin(),
            [](wchar_t a,char16_t b){return static_cast<char16_t>(a)==b;}))
            return rejected<bool>(AdapterError::MetadataChanged,"journal_reader.exact_name_changed",ObservationState::Changed);
        return Observation<bool>::available(true);
    }
    Observation<bool> revalidate() {
        if(read_only_ && finished_)return rejected<bool>(AdapterError::InvalidAccess,"journal_reader.finished",ObservationState::Denied);
        if(root_) {auto verified=root_->revalidate();if(!verified.value())return verified;}
        const auto root=verify_root(directory_.get(),user_.data());if(!root.value())return root;
        if(!*root.value())return rejected<bool>(AdapterError::InvalidNativeResult,"journal_file.root_security");
        const auto security=verify_security(file_.get(),user_.data());if(!security.value())return security;
        if(!*security.value())return rejected<bool>(AdapterError::InvalidNativeResult,"journal_file.file_security");
        FILE_ATTRIBUTE_TAG_INFO tag{};FILE_STANDARD_INFO info{};
        if(!::ck::files::detail::legacy_query(file_.get(),FileAttributeTagInfo,&tag,sizeof(tag),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.477") ||
            !::ck::files::detail::legacy_query(file_.get(),FileStandardInfo,&info,sizeof(info),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.478"))
            return io_failure<bool>(GetLastError(),"journal_file.revalidate_info");
        if((tag.FileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)) || info.NumberOfLinks!=1)
            return rejected<bool>(AdapterError::InvalidAccess,"journal_file.revalidate_kind",ObservationState::Denied);
        if(read_only_) {
            constexpr DWORD ordinary_file=FILE_ATTRIBUTE_NORMAL|FILE_ATTRIBUTE_READONLY|FILE_ATTRIBUTE_HIDDEN|
                FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_TEMPORARY|FILE_ATTRIBUTE_SPARSE_FILE|
                FILE_ATTRIBUTE_COMPRESSED|FILE_ATTRIBUTE_NOT_CONTENT_INDEXED|FILE_ATTRIBUTE_ENCRYPTED|
                FILE_ATTRIBUTE_INTEGRITY_STREAM|FILE_ATTRIBUTE_NO_SCRUB_DATA;
            if(tag.ReparseTag || (tag.FileAttributes&~ordinary_file))return rejected<bool>(AdapterError::UnsupportedQuery,"journal_reader.file_provider_attributes",ObservationState::Unsupported);
            return validate_read_only_binding();
        }
        return Observation<bool>::available(true);
    }
    Handle file_,directory_;
    std::vector<std::byte> user_;
    PreparedJournalRoot::Pointer root_;
    std::optional<NativeName> reader_name_;
    FILE_ID_INFO reader_file_{},reader_directory_{};
    FILE_BASIC_INFO reader_basic_{};FILE_STANDARD_INFO reader_standard_{};
    bool reader_bound_=false;
    bool read_only_=false;
    bool finished_=false,finish_started_=false;
    std::int64_t close_error_=0;const char* close_operation_=nullptr;bool close_exception_=false;
    detail::PreparedJournalFailureLatch finish_failure_;
};
}

namespace {
Observation<std::unique_ptr<OperationJournalFile>> open_windows_journal_at(Handle directory,
    std::vector<std::byte> user_data,const NativeName& basename,bool create_new,PreparedJournalRoot::Pointer root_keep={},bool read_only=false) {
    using Pointer=std::unique_ptr<OperationJournalFile>;
    if(read_only && create_new)return rejected<Pointer>(AdapterError::InvalidAccess,"journal_reader.create_refused",ObservationState::Denied);
    if(!basename.is_valid()||!basename.windows_units()||basename.windows_units()->size()>32760||
        basename.windows_units()->find(u':')!=std::u16string::npos)
        return rejected<Pointer>(AdapterError::InvalidIdentifier,"journal_file.basename");
    std::wstring name;
    name.reserve(basename.windows_units()->size());
    for (const auto unit : *basename.windows_units()) name.push_back(static_cast<wchar_t>(unit));
    std::vector<std::byte> system, acl_data;
    std::vector<std::byte> relative_descriptor;
    SECURITY_DESCRIPTOR descriptor{};
    if (create_new) {
        auto security = make_security(user_data, system, acl_data, descriptor);
        if (!security.value()) {
            const auto& detail = *security.unavailable_detail();
            return Observation<Pointer>::unavailable(detail.state, detail.error);
        }
        DWORD relative_size = 0;
        if (MakeSelfRelativeSD(&descriptor, nullptr, &relative_size))
            return rejected<Pointer>(AdapterError::InvalidNativeResult, "journal_file.relative_descriptor_size");
        const DWORD size_error = GetLastError();
        if (size_error != ERROR_INSUFFICIENT_BUFFER || relative_size == 0)
            return failure<Pointer>(size_error, "journal_file.relative_descriptor_size");
        relative_descriptor.resize(relative_size);
        if (!MakeSelfRelativeSD(&descriptor,
                reinterpret_cast<PSECURITY_DESCRIPTOR>(relative_descriptor.data()), &relative_size))
            return failure<Pointer>(GetLastError(), "journal_file.relative_descriptor");
    }
    UNICODE_STRING relative{};
    relative.Buffer = name.data();
    relative.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
    relative.MaximumLength = relative.Length;
    OBJECT_ATTRIBUTES object{};
    object.Length = sizeof(object);
    object.RootDirectory = directory.get();
    object.ObjectName = &relative;
    object.SecurityDescriptor = create_new ? relative_descriptor.data() : nullptr;
    IO_STATUS_BLOCK io{};
    HANDLE raw_file{};
    const auto status = ::ck::files::detail::legacy_nt_create(&raw_file, read_only ? (FILE_GENERIC_READ | READ_CONTROL) : (FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_OWNER),
        &object, &io, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        create_new ? FILE_CREATE : FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT | (read_only ? FILE_OPEN_NO_RECALL : FILE_WRITE_THROUGH),
        nullptr, 0,"legacy.operation_journal_file_windows.NtCreateFile.548");
    Handle file(raw_file);
    // This is a synchronous, nonalertable file object with SYNCHRONIZE access.
    // The I/O manager completes the open before returning; no asynchronous
    // option/event, completion shortcut, or pending IOSB is accepted as success.
    // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile
    if(read_only && status!=0)return nt_failure<Pointer>(status,"journal_reader.NtCreateFile");
    if (status < 0) return nt_failure<Pointer>(status, "journal_file.NtCreateFile");
    if(read_only && io.Status!=0)return nt_failure<Pointer>(io.Status,"journal_reader.open_status");
    const auto expected = create_new ? FILE_CREATED : FILE_OPENED;
    if (io.Information != expected || file.get() == INVALID_HANDLE_VALUE)
        return rejected<Pointer>(AdapterError::InvalidNativeResult, "journal_file.open_result");
    FILE_ATTRIBUTE_TAG_INFO tag{};
    FILE_STANDARD_INFO info{};
    if (!::ck::files::detail::legacy_query(file.get(), FileAttributeTagInfo, &tag, sizeof(tag),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.566") ||
        !::ck::files::detail::legacy_query(file.get(), FileStandardInfo, &info, sizeof(info),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.567"))
        return failure<Pointer>(GetLastError(), "journal_file.file_info");
    if ((tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) || info.NumberOfLinks != 1 ||
        (create_new && info.EndOfFile.QuadPart != 0))
        return rejected<Pointer>(AdapterError::InvalidAccess, "journal_file.file_kind", ObservationState::Denied);
    if (create_new) {
        const auto owner_code = SetSecurityInfo(file.get(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
            user_data.data(), nullptr, nullptr, nullptr);
        if (owner_code != ERROR_SUCCESS) return failure<Pointer>(owner_code, "journal_file.set_owner");
    }
    auto security = verify_security(file.get(), user_data.data());
    if (!security.value()) {
        const auto& detail = *security.unavailable_detail();
        return Observation<Pointer>::unavailable(detail.state, detail.error);
    }
    if (!*security.value()) return rejected<Pointer>(AdapterError::InvalidNativeResult, "journal_file.file_security");
    auto result=std::make_unique<WindowsOperationJournalFile>(file.get(),directory.get(),std::move(user_data),std::move(root_keep),read_only);
    file.release();directory.release();
    if(read_only) {
        auto checked=result->bind_read_only(basename);
        if(!checked.value() || !*checked.value()) {
            (void)result->finish_io();
            if(!checked.value())return Observation<Pointer>::unavailable(checked.state(),checked.unavailable_detail()->error);
            return rejected<Pointer>(AdapterError::InvalidNativeResult,"journal_reader.bind_false");
        }
    }
    return Observation<Pointer>::available(std::move(result));
}
}

Observation<bool> prepare_native_operation_journal_root(const NativeAbsolutePath& private_root) {
    using Result = Observation<bool>;
    auto host = private_root.host_path();
    if (!host.value())
        return Result::unavailable(host.unavailable_detail()->state, host.unavailable_detail()->error);
    auto user = effective_user();
    if (!user.value())
        return Result::unavailable(user.unavailable_detail()->state, user.unavailable_detail()->error);
    auto user_data = std::move(user).take_value();
    const auto native_path = windows_extended_path(host.value()->native());
    if (!native_path) return rejected<bool>(AdapterError::InvalidPath, "journal_file.prepare_root.path");
    Handle directory(::ck::files::detail::legacy_create(native_path->c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL |
            WRITE_DAC | WRITE_OWNER, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr,"legacy.operation_journal_file_windows.CreateFileW.608"));
    if (directory.get() == INVALID_HANDLE_VALUE)
        return failure<bool>(GetLastError(), "journal_file.prepare_root.open");
    std::vector<std::byte> system, acl_data;
    SECURITY_DESCRIPTOR descriptor{};
    auto security = make_security(user_data, system, acl_data, descriptor);
    if (!security.value())
        return Result::unavailable(security.unavailable_detail()->state, security.unavailable_detail()->error);
    BOOL present = FALSE, defaulted = FALSE;
    PACL acl = nullptr;
    if (!GetSecurityDescriptorDacl(&descriptor, &present, &acl, &defaulted) || !present || !acl)
        return rejected<bool>(AdapterError::InvalidNativeResult, "journal_file.prepare_root.dacl");
    const auto code = SetSecurityInfo(directory.get(), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        user_data.data(), nullptr, acl, nullptr);
    if (code != ERROR_SUCCESS)
        return failure<bool>(code, "journal_file.prepare_root.security");
    return verify_root(directory.get(), user_data.data());
}

Observation<bool> detail::qualify_operation_journal_directory(const DirectoryCursor& cursor) {
    auto duplicate=duplicate_windows_journal_directory(cursor);
    if(!duplicate.value())return Observation<bool>::unavailable(duplicate.state(),duplicate.unavailable_detail()->error);
    Handle directory(static_cast<HANDLE>(*duplicate.value())); // own raw result without take_value/reset allocation
    auto checked=[&]() -> Observation<bool> {
        const auto proof=prove_windows_journal_volume(directory.get());
        if(!proof.qualified)return Observation<bool>::unavailable(proof.state,{proof.domain,proof.code,proof.operation});
        auto user=effective_user();if(!user.value())return Observation<bool>::unavailable(user.state(),user.unavailable_detail()->error);
        FILE_ID_INFO native{};FILE_STANDARD_INFO standard{};
        if(!::ck::files::detail::legacy_query(directory.get(),FileIdInfo,&native,sizeof(native),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.639") ||
           !::ck::files::detail::legacy_query(directory.get(),FileStandardInfo,&standard,sizeof(standard),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.640"))return failure<bool>(GetLastError(),"journal_reader.root_identity");
        if(!standard.Directory || standard.DeletePending || !standard.NumberOfLinks)return rejected<bool>(AdapterError::MetadataChanged,"journal_reader.root_unlinked",ObservationState::Changed);
        NativeIdentifier object;std::memcpy(object.bytes.data(),native.FileId.Identifier,16);
        const auto* old=cursor.identity().value();
        if(!old || old->scheme!=IdentityScheme::WindowsFileId128 || old->volume!=NativeIdentifier::from_u64(native.VolumeSerialNumber) || old->object!=object)
            return rejected<bool>(AdapterError::MetadataChanged,"journal_reader.root_identity_changed",ObservationState::Changed);
        return verify_root(directory.get(),const_cast<std::byte*>(user.value()->data()));
    }();
    const auto raw=directory.release();
    ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_close(raw,"journal_reader.validation_duplicate_close");});
    const BOOL native_ok=::ck::files::detail::legacy_close_native_call(raw,"legacy.operation_journal_file_windows.CloseHandle.650");const DWORD native_error=native_ok?ERROR_SUCCESS:GetLastError();
    const auto injected=::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::inject_native_close_failure(raw,"journal_reader.validation_duplicate_close",native_ok!=FALSE,native_error);});
    const auto error=native_ok?injected:native_error;
    if(error) {
        detail::record_metadata_capture_close({state(error),ErrorDomain::Win32,error,"journal_reader.validation_duplicate_close"});
        return failure<bool>(error,"journal_reader.validation_duplicate_close");
    }
    return checked;
}
Observation<std::unique_ptr<OperationJournalFile>> open_held_operation_journal_file(
    const DirectoryCursor& cursor,const NativeName& basename) {
    using Pointer=std::unique_ptr<OperationJournalFile>;
    if(!basename.is_valid()||!basename.windows_units())return rejected<Pointer>(AdapterError::InvalidIdentifier,"journal_reader.basename");
    auto checked=detail::qualify_operation_journal_directory(cursor);
    if(!checked.value())return Observation<Pointer>::unavailable(checked.state(),checked.unavailable_detail()->error);
    if(!*checked.value())return rejected<Pointer>(AdapterError::InvalidNativeResult,"journal_reader.root_false");
    auto user=effective_user();if(!user.value())return Observation<Pointer>::unavailable(user.state(),user.unavailable_detail()->error);
    auto user_data=std::move(user).take_value();
    auto duplicate=detail::duplicate_windows_journal_directory(cursor);
    if(!duplicate.value())return Observation<Pointer>::unavailable(duplicate.state(),duplicate.unavailable_detail()->error);
    Handle directory(static_cast<HANDLE>(*duplicate.value()));
    return open_windows_journal_at(std::move(directory),std::move(user_data),basename,false,{},true);
}

Observation<std::unique_ptr<OperationJournalFile>> open_native_operation_journal_file(
    const NativeAbsolutePath& private_root, const NativeName& basename, bool create_new) {
    using Pointer = std::unique_ptr<OperationJournalFile>;
    if (!basename.is_valid() || !basename.windows_units())
        return rejected<Pointer>(AdapterError::InvalidIdentifier, "journal_file.basename");
    auto host = private_root.host_path();
    if (!host.value()) {
        const auto& detail = *host.unavailable_detail();
        return Observation<Pointer>::unavailable(detail.state, detail.error);
    }
    const auto& root = *host.value();
    if (root.native().empty() || root.filename() == L"." || root.filename() == L"..")
        return rejected<Pointer>(AdapterError::InvalidPath, "journal_file.root_address");
    auto user = effective_user();
    if (!user.value()) {
        const auto& detail = *user.unavailable_detail();
        return Observation<Pointer>::unavailable(detail.state, detail.error);
    }
    auto user_data = std::move(user).take_value();
    const auto native_path = windows_extended_path(root.native());
    if (!native_path) return rejected<Pointer>(AdapterError::InvalidPath, "journal_file.root_address");
    Handle directory(::ck::files::detail::legacy_create(native_path->c_str(), FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr,"legacy.operation_journal_file_windows.CreateFileW.695"));
    if (directory.get() == INVALID_HANDLE_VALUE) return failure<Pointer>(GetLastError(), "journal_file.open_root");
    auto root_valid = verify_root(directory.get(), user_data.data());
    if (!root_valid.value()) {
        const auto& detail = *root_valid.unavailable_detail();
        return Observation<Pointer>::unavailable(detail.state, detail.error);
    }
    return open_windows_journal_at(std::move(directory),std::move(user_data),basename,create_new);
}


namespace {
struct WindowsJournalDirectory final {
    Handle handle;
    FILE_ID_INFO id{};
    NativeIdentifier parent{};
    std::u16string name;
};
Observation<bool> journal_local_volume(HANDLE handle) {
    const auto proof=detail::prove_windows_journal_volume(handle);
    if(!proof.qualified)
        return Observation<bool>::unavailable(proof.state,{proof.domain,proof.code,proof.operation});
    return Observation<bool>::available(true);
}
NativeIdentifier journal_object(const FILE_ID_INFO& id) {
    NativeIdentifier object;std::memcpy(object.bytes.data(),id.FileId.Identifier,16);return object;
}
Observation<WindowsJournalDirectory> query_journal_directory(HANDLE handle) {
    auto local=journal_local_volume(handle);
    if(!local.value())return Observation<WindowsJournalDirectory>::unavailable(local.state(),local.unavailable_detail()->error);
    FILE_ID_INFO id{};FILE_ATTRIBUTE_TAG_INFO tag{};FILE_STANDARD_INFO standard{};
    if(!::ck::files::detail::legacy_query(handle,FileIdInfo,&id,sizeof(id),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.728")||
        !::ck::files::detail::legacy_query(handle,FileAttributeTagInfo,&tag,sizeof(tag),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.729")||
        !::ck::files::detail::legacy_query(handle,FileStandardInfo,&standard,sizeof(standard),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.730"))
        return failure<WindowsJournalDirectory>(GetLastError(),"journal_root.directory_identity");
    if(!(tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)||(tag.FileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_OFFLINE))||standard.DeletePending)
        return rejected<WindowsJournalDirectory>(AdapterError::FinalLinkRejected,"journal_root.directory_kind",ObservationState::Unsupported);
    wchar_t filesystem[32]{};DWORD flags{};
    if(!GetVolumeInformationByHandleW(handle,nullptr,0,nullptr,nullptr,&flags,filesystem,32))
        return failure<WindowsJournalDirectory>(GetLastError(),"journal_root.volume");
    if(!(flags&FILE_PERSISTENT_ACLS)||(std::wstring_view(filesystem)!=L"NTFS"&&std::wstring_view(filesystem)!=L"ReFS"))
        return rejected<WindowsJournalDirectory>(AdapterError::UnsupportedQuery,"journal_root.durable_private_filesystem",ObservationState::Unsupported);
    READ_FILE_USN_DATA query{3,3};
    alignas(8) std::array<std::byte,65536+80> record{};DWORD count{};
    if(!DeviceIoControl(handle,FSCTL_READ_FILE_USN_DATA,&query,sizeof(query),record.data(),static_cast<DWORD>(record.size()),&count,nullptr)) {
        const auto error=GetLastError();
        if(error==ERROR_JOURNAL_NOT_ACTIVE||error==ERROR_JOURNAL_DELETE_IN_PROGRESS)
            return rejected<WindowsJournalDirectory>(AdapterError::UnsupportedQuery,"journal_root.parent_record_unavailable",ObservationState::Unsupported);
        return failure<WindowsJournalDirectory>(error,"journal_root.parent_record");
    }
    if(count>record.size())return rejected<WindowsJournalDirectory>(AdapterError::InvalidNativeResult,"journal_root.parent_record_size");
    auto decoded=detail::decode_windows_parent_record(std::span<const std::byte>(record).first(count),3);
    if(!decoded.value())return Observation<WindowsJournalDirectory>::unavailable(decoded.state(),decoded.unavailable_detail()->error);
    if(decoded.value()->child!=journal_object(id)||(decoded.value()->attributes&FILE_ATTRIBUTE_DIRECTORY)==0)
        return rejected<WindowsJournalDirectory>(AdapterError::MetadataChanged,"journal_root.parent_record_identity",ObservationState::Changed);
    // The existing bounded decoder has validated the v3 name extent/alignment.
    std::uint16_t length{},offset{};std::memcpy(&length,record.data()+72,2);std::memcpy(&offset,record.data()+74,2);
    std::u16string name(length/2,u'\0');if(length)std::memcpy(name.data(),record.data()+offset,length);
    return Observation<WindowsJournalDirectory>::available({Handle{},id,decoded.value()->parent,std::move(name)});
}
Observation<WindowsJournalDirectory> journal_directory(Handle handle) {
    auto result=query_journal_directory(handle.get());
    if(!result.value())return result;
    auto node=std::move(result).take_value();node.handle=std::move(handle);
    return Observation<WindowsJournalDirectory>::available(std::move(node));
}
Observation<Handle> guarded_journal_directory_by_id(HANDLE hint,const FILE_ID_INFO& id) {
    FILE_ID_DESCRIPTOR descriptor{};descriptor.dwSize=sizeof(descriptor);descriptor.Type=ExtendedFileIdType;descriptor.ExtendedFileId=id.FileId;
    // No FILE_SHARE_DELETE: this same owning open excludes prior/new DELETE
    // holders, so acquired directory memberships cannot subsequently be moved.
    Handle handle(::ck::files::detail::legacy_open_by_id(hint,&descriptor,FILE_GENERIC_READ|FILE_GENERIC_WRITE|READ_CONTROL|SYNCHRONIZE,
        FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL,"legacy.operation_journal_file_windows.OpenFileById.767"));
    if(!handle || handle.get()==INVALID_HANDLE_VALUE)return failure<Handle>(GetLastError(),"journal_root.OpenFileById");
    FILE_ID_INFO current{};
    if(!::ck::files::detail::legacy_query(handle.get(),FileIdInfo,&current,sizeof(current),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.771"))return failure<Handle>(GetLastError(),"journal_root.by_id_identity");
    if(current.VolumeSerialNumber!=id.VolumeSerialNumber||journal_object(current)!=journal_object(id))
        return rejected<Handle>(AdapterError::MetadataChanged,"journal_root.by_id_changed",ObservationState::Changed);
    return Observation<Handle>::available(std::move(handle));
}
Observation<Handle> open_journal_root_child(HANDLE parent,const NativeName& child,bool provision,std::vector<std::byte>& user,bool& created) {
    if(!child.is_valid()||!child.windows_units()||child.windows_units()->size()>32760||child.windows_units()->find(u':')!=std::u16string::npos)
        return rejected<Handle>(AdapterError::InvalidIdentifier,"journal_root.child_name");
    std::wstring name(child.windows_units()->begin(),child.windows_units()->end());
    std::vector<std::byte> system,acl,self_relative;SECURITY_DESCRIPTOR descriptor{};
    auto made=make_security(user,system,acl,descriptor);if(!made.value())return Observation<Handle>::unavailable(made.state(),made.unavailable_detail()->error);
    DWORD bytes{};MakeSelfRelativeSD(&descriptor,nullptr,&bytes);
    if(!bytes||GetLastError()!=ERROR_INSUFFICIENT_BUFFER)return failure<Handle>(GetLastError(),"journal_root.security_size");
    self_relative.resize(bytes);
    if(!MakeSelfRelativeSD(&descriptor,reinterpret_cast<PSECURITY_DESCRIPTOR>(self_relative.data()),&bytes))return failure<Handle>(GetLastError(),"journal_root.security");
    UNICODE_STRING n{};n.Buffer=name.data();n.Length=static_cast<USHORT>(name.size()*sizeof(wchar_t));n.MaximumLength=n.Length;
    OBJECT_ATTRIBUTES object{};object.Length=sizeof(object);object.RootDirectory=parent;object.ObjectName=&n;
    object.SecurityDescriptor=provision?self_relative.data():nullptr;
    IO_STATUS_BLOCK io{};HANDLE raw{};
    const auto status=::ck::files::detail::legacy_nt_create(&raw,FILE_GENERIC_READ|FILE_GENERIC_WRITE|READ_CONTROL|SYNCHRONIZE,&object,&io,nullptr,
        FILE_ATTRIBUTE_DIRECTORY,FILE_SHARE_READ|FILE_SHARE_WRITE,provision?FILE_OPEN_IF:FILE_OPEN,
        FILE_DIRECTORY_FILE|FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT,nullptr,0,"legacy.operation_journal_file_windows.NtCreateFile.790");
    Handle result(raw);if(status<0)return nt_failure<Handle>(status,"journal_root.NtCreateFile");
    if(io.Information!=FILE_CREATED&&io.Information!=FILE_OPENED)return rejected<Handle>(AdapterError::InvalidNativeResult,"journal_root.open_result");
    created=io.Information==FILE_CREATED;return Observation<Handle>::available(std::move(result));
}
bool flush_journal_directory(HANDLE handle,detail::PreparedJournalFailureLatch& failure) noexcept {
    ::ck::files::detail::legacy_preserve_windows_error([&]()noexcept{return detail::observe_native_test_io(detail::NativeTestIo::Flush);});
    if(!::ck::files::detail::legacy_flush(handle,"legacy.operation_journal_file_windows.FlushFileBuffers.799")) {const auto code=GetLastError();failure.record(state(code),ErrorDomain::Win32,code,"journal_root.directory_FlushFileBuffers");return false;}
    try {
        if(const auto fault=detail::journal_root_fault(detail::JournalRootFaultPoint::DirectoryFlush)) {
            failure.record(state(static_cast<DWORD>(*fault)),ErrorDomain::Win32,*fault,"journal_root.directory_FlushFileBuffers");return false;
        }
    } catch(...) {
        failure.record(ObservationState::Unknown,ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.flush_fault_exception");return false;
    }
    return true;
}
class WindowsPreparedJournalRoot final : public PreparedJournalRoot,public std::enable_shared_from_this<WindowsPreparedJournalRoot> {
public:
    WindowsPreparedJournalRoot(std::vector<WindowsJournalDirectory> chain,std::vector<std::byte> user,
        ObjectIdentity identity,std::optional<NativeAbsolutePath> navigation)
        :chain_(std::move(chain)),user_(std::move(user)),identity_(std::move(identity)),navigation_(std::move(navigation)){}
    ~WindowsPreparedJournalRoot() override {if(!finished_)try {(void)finish_io();}catch(...) {}}
    const ObjectIdentity& identity() const noexcept override{return identity_;}
    NameEncoding encoding() const noexcept override{return NameEncoding::WindowsUtf16;}
    const std::optional<NativeAbsolutePath>& navigation_address() const noexcept override{return navigation_;}
    void record_consumer_failure(ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view operation) noexcept {
        consumer_failure_.record(state,domain,code,operation);
    }
    bool read_consumer_failure(detail::PreparedJournalConsumerFailure& out) const noexcept {return consumer_failure_.read(out);}
    Observation<std::vector<ObjectIdentity>> inspect_ancestry() const {
        using R=Observation<std::vector<ObjectIdentity>>;std::lock_guard lock(mutex_);
        auto checked=check();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        std::vector<ObjectIdentity> ids;ids.reserve(chain_.size());
        for(const auto& node:chain_) {
            FILE_ID_INFO value{};
            if(!::ck::files::detail::legacy_query(node.handle.get(),FileIdInfo,&value,sizeof(value),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.829"))
                return failure<std::vector<ObjectIdentity>>(GetLastError(),"journal_root.ancestry_identity");
            ids.push_back({identity_.scope,IdentityScheme::WindowsFileId128,
                NativeIdentifier::from_u64(value.VolumeSerialNumber),journal_object(value),{}});
        }
        checked=check();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        return R::available(std::move(ids));
    }
    Observation<bool> revalidate() const override{std::lock_guard lock(mutex_);return check();}
    Observation<void*> duplicate_native_directory() const {
        std::lock_guard lock(mutex_);auto checked=check();
        if(!checked.value())return Observation<void*>::unavailable(checked.state(),checked.unavailable_detail()->error);
        HANDLE raw{};
        if(!::ck::files::detail::legacy_duplicate(GetCurrentProcess(),chain_.front().handle.get(),GetCurrentProcess(),&raw,0,FALSE,DUPLICATE_SAME_ACCESS,"legacy.operation_journal_file_windows.DuplicateHandle.842"))
            return failure<void*>(GetLastError(),"journal_root.duplicate_directory");
        return Observation<void*>::available(raw);
    }

    Observation<std::unique_ptr<OperationJournalFile>> open_journal(const NativeName& name,bool create) override {
        using R=Observation<std::unique_ptr<OperationJournalFile>>;
        if(!name.is_valid()||!name.windows_units())return rejected<std::unique_ptr<OperationJournalFile>>(AdapterError::InvalidIdentifier,"journal_root.basename");
        std::lock_guard lock(mutex_);auto checked=check();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        HANDLE raw{};
        if(!::ck::files::detail::legacy_duplicate(GetCurrentProcess(),chain_.front().handle.get(),GetCurrentProcess(),&raw,0,FALSE,DUPLICATE_SAME_ACCESS,"legacy.operation_journal_file_windows.DuplicateHandle.852"))
            return failure<std::unique_ptr<OperationJournalFile>>(GetLastError(),"journal_root.duplicate_root");
        Handle directory(raw); // own before the following user-vector copy can allocate
        return open_windows_journal_at(std::move(directory),user_,name,create,shared_from_this());
    }
    Observation<bool> sync() override {JournalRootPreparationProgress p;return flush_prepared(p,{},{});}
    Observation<bool> flush_prepared(JournalRootPreparationProgress& progress,std::stop_token stop,
        const std::function<void(const JournalRootPreparationProgress&)>& observer) {
        std::lock_guard lock(mutex_);auto checked=check();if(!checked.value())return checked;
        for(const auto& node:chain_) {
            if(stop.stop_requested())return rejected<bool>(AdapterError::InterruptedRead,"journal_root.cancelled",ObservationState::Changed);
            if(!flush_journal_directory(node.handle.get(),consumer_failure_))return consumer_failure_.result();
            ++progress.flushed_directories;if(observer)observer(progress);
        }
        return check();
    }
    Observation<bool> finish_io() override {
        std::lock_guard lock(mutex_);if(finished_)return consumer_failure_.result();
        if(weak_from_this().use_count()>1)return rejected<bool>(AdapterError::InvalidAccess,"journal_root.consumers_active",ObservationState::Changed);
        bool qualified=false;
        try {
            auto checked=check(false);qualified=checked.value()&&*checked.value();
            if(!checked.value()) {const auto& e=*checked.unavailable_detail();consumer_failure_.record(e.state,e.error.domain,e.error.code,e.error.operation);}
            else if(!qualified)consumer_failure_.record(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.check_false");
        } catch(...) {
            consumer_failure_.record(ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.finalizer_exception");
        }
        if(qualified)for(const auto& node:chain_)(void)flush_journal_directory(node.handle.get(),consumer_failure_);
        for(auto& node:chain_) {
            const auto handle=node.handle.release();if(!handle||handle==INVALID_HANDLE_VALUE)continue;
            if(!::ck::files::detail::legacy_close_native_call(handle,"legacy.operation_journal_file_windows.CloseHandle.884")) {const auto code=GetLastError();consumer_failure_.record(state(code),ErrorDomain::Win32,code,"journal_root.directory_CloseHandle");}
            try {
                if(const auto fault=detail::journal_root_fault(detail::JournalRootFaultPoint::DirectoryClose))
                    consumer_failure_.record(state(static_cast<DWORD>(*fault)),ErrorDomain::Win32,*fault,"journal_root.directory_CloseHandle");
            } catch(...) {
                consumer_failure_.record(ObservationState::Unknown,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.close_fault_exception");
            }
        }
        finished_=true;return consumer_failure_.result();
    }
private:
    Observation<bool> check(bool include_consumer=true) const {
        if(finished_||chain_.empty())return rejected<bool>(AdapterError::InvalidAccess,"journal_root.finished",ObservationState::Changed);
        if(include_consumer) {auto failure=consumer_failure_.result();if(!failure.value())return failure;}
        auto privacy=verify_root(chain_.front().handle.get(),const_cast<std::byte*>(user_.data()));if(!privacy.value())return privacy;
        if(!*privacy.value())return rejected<bool>(AdapterError::InvalidNativeResult,"journal_root.root_security_false");
        for(std::size_t i=0;i<chain_.size();++i) {
            auto current=query_journal_directory(chain_[i].handle.get());
            if(!current.value())return Observation<bool>::unavailable(current.state(),current.unavailable_detail()->error);
            if(current.value()->id.VolumeSerialNumber!=chain_[i].id.VolumeSerialNumber||journal_object(current.value()->id)!=journal_object(chain_[i].id)||
                current.value()->parent!=chain_[i].parent||current.value()->name!=chain_[i].name)
                return rejected<bool>(AdapterError::MetadataChanged,"journal_root.membership_changed",ObservationState::Changed);
            if(i+1<chain_.size()&&current.value()->parent!=journal_object(chain_[i+1].id))
                return rejected<bool>(AdapterError::MetadataChanged,"journal_root.ancestor_changed",ObservationState::Changed);
        }
        return Observation<bool>::available(true);
    }
    mutable std::mutex mutex_;std::vector<WindowsJournalDirectory> chain_;std::vector<std::byte> user_;
    ObjectIdentity identity_;std::optional<NativeAbsolutePath> navigation_;bool finished_=false;
    detail::PreparedJournalFailureLatch consumer_failure_;
};
class WindowsPreparedJournalDirectory final : public PreparedJournalDirectory {
public:
    WindowsPreparedJournalDirectory(Handle directory,PreparedJournalRoot::Pointer root)
        :PreparedJournalDirectory(root->identity()),directory_(std::move(directory)),root_(std::move(root)){}
    ~WindowsPreparedJournalDirectory() override {try {(void)finish_io();}catch(...) {}}
    Observation<AdapterScope> source_scope() const override {
        return root_?Observation<AdapterScope>::available(root_->identity().scope):
            rejected<AdapterScope>(AdapterError::InvalidAccess,"journal_root.enumeration_finished",ObservationState::Changed);
    }
    Observation<bool> finish_io() override {
        if(directory_) {
            const auto raw=directory_.release();if(!::ck::files::detail::legacy_close_native_call(raw,"legacy.operation_journal_file_windows.CloseHandle.927"))close_error_=GetLastError();
            if(close_error_)detail::record_prepared_journal_consumer_failure(*root_,
                state(close_error_),ErrorDomain::Win32,close_error_,"journal_root.enumeration_close");
            try {
                const auto fault=detail::journal_root_fault(detail::JournalRootFaultPoint::DirectoryClose);
                if(!close_error_&&fault)close_error_=static_cast<DWORD>(*fault);
            } catch(...) {
                detail::record_prepared_journal_consumer_failure(*root_,ObservationState::Unknown,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.enumeration_close_exception");
                if(!close_error_)close_exception_=true;
            }
            if(close_error_)detail::record_prepared_journal_consumer_failure(*root_,
                state(close_error_),ErrorDomain::Win32,close_error_,"journal_root.enumeration_close");
            root_.reset();
        }
        if(close_exception_)return Observation<bool>::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"journal_root.enumeration_close_exception"});
        return close_error_?failure<bool>(close_error_,"journal_root.enumeration_close"):Observation<bool>::available(true);
    }
private:
    Observation<DirectoryStep> next_step() override {
        using R=Observation<DirectoryStep>;
        if(!directory_||!root_)return rejected<DirectoryStep>(AdapterError::InvalidAccess,"journal_root.enumeration_finished",ObservationState::Changed);
        auto checked=root_->revalidate();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        if(!offset_) {
            buffer_.fill(0);
            const auto info=started_?FileIdBothDirectoryInfo:FileIdBothDirectoryRestartInfo;
            const bool success=::ck::files::detail::legacy_query(directory_.get(),info,buffer_.data(),static_cast<DWORD>(sizeof(buffer_)),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.954")!=0;
            const DWORD code=GetLastError();checked=root_->revalidate();
            if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
            if(!success)return code==ERROR_NO_MORE_FILES?R::available(DirectoryEnd{}):failure<DirectoryStep>(code,"journal_root.enumerate");
            started_=true;offset_=0;
        }
        auto decoded=detail::decode_windows_directory_record(std::as_bytes(std::span(buffer_)),*offset_);
        if(!decoded.value())return R::unavailable(decoded.state(),decoded.unavailable_detail()->error);
        auto record=std::move(decoded).take_value();offset_=record.next_offset;
        checked=root_->revalidate();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
        if(!record.name)return R::available(DirectorySkip{});
        return R::available(std::move(*record.name));
    }
    Handle directory_;PreparedJournalRoot::Pointer root_;DWORD close_error_=0;bool close_exception_=false;
    // Native 8-byte alignment without an explicit class-alignment attribute.
    std::array<std::uint64_t,16*1024> buffer_{};
    std::optional<std::size_t> offset_;bool started_=false;
};
}
namespace detail {
Observation<std::vector<ObjectIdentity>> inspect_prepared_journal_ancestry(PreparedJournalRoot& root) {
    const auto* native=dynamic_cast<const WindowsPreparedJournalRoot*>(&root);
    if(!native)return rejected<std::vector<ObjectIdentity>>(AdapterError::UnqualifiedIdentity,"journal_root.foreign_provider",ObservationState::Unsupported);
    return native->inspect_ancestry();
}
bool record_prepared_journal_file_consumer_failure(OperationJournalFile& file,ObservationState observed,
    ErrorDomain domain,std::int64_t code,std::string_view operation) noexcept {
    auto* native=dynamic_cast<WindowsOperationJournalFile*>(&file);
    return native && native->record_consumer_failure(observed,domain,code,operation);
}
bool record_prepared_journal_consumer_failure(PreparedJournalRoot& root,ObservationState state,
    ErrorDomain domain,std::int64_t code,std::string_view operation) noexcept {
    auto* native=dynamic_cast<WindowsPreparedJournalRoot*>(&root);if(!native)return false;
    native->record_consumer_failure(state,domain,code,operation);return true;
}
bool read_prepared_journal_consumer_failure(const PreparedJournalRoot& root,PreparedJournalConsumerFailure& out) noexcept {
    out={};const auto* native=dynamic_cast<const WindowsPreparedJournalRoot*>(&root);
    return native&&native->read_consumer_failure(out);
}
Observation<void*> duplicate_prepared_journal_directory(PreparedJournalRoot& root) {
    const auto* native=dynamic_cast<const WindowsPreparedJournalRoot*>(&root);
    if(!native)return rejected<void*>(AdapterError::UnqualifiedIdentity,"journal_root.foreign_provider",ObservationState::Unsupported);
    return native->duplicate_native_directory();
}
}
Observation<std::unique_ptr<PreparedJournalDirectory>> open_prepared_journal_directory(PreparedJournalRoot::Pointer root) {
    using R=Observation<std::unique_ptr<PreparedJournalDirectory>>;
    if(!root)return rejected<std::unique_ptr<PreparedJournalDirectory>>(AdapterError::InvalidAccess,"journal_root.null");
    auto duplicate=detail::duplicate_prepared_journal_directory(*root);
    if(!duplicate.value())return R::unavailable(duplicate.state(),duplicate.unavailable_detail()->error);
    Handle original(std::move(duplicate).take_value());FILE_ID_INFO id{};
    if(!::ck::files::detail::legacy_query(original.get(),FileIdInfo,&id,sizeof(id),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.1005"))return failure<std::unique_ptr<PreparedJournalDirectory>>(GetLastError(),"journal_root.enumeration_identity");
    // A fresh object-bound open gives an independent enumeration position.
    // DuplicateHandle alone shares the directory FILE_OBJECT state.
    auto directory=guarded_journal_directory_by_id(original.get(),id);
    if(!directory.value())return R::unavailable(directory.state(),directory.unavailable_detail()->error);
    const auto raw=original.release();if(!::ck::files::detail::legacy_close_native_call(raw,"legacy.operation_journal_file_windows.CloseHandle.1010"))return failure<std::unique_ptr<PreparedJournalDirectory>>(GetLastError(),"journal_root.enumeration_duplicate_close");
    auto checked=root->revalidate();if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
    return R::available(std::make_unique<WindowsPreparedJournalDirectory>(std::move(directory).take_value(),std::move(root)));
}
Observation<PreparedJournalRoot::Pointer> prepare_native_journal_root(PreparedJournalRootRequest request,
    JournalRootPreparationProgress& progress,std::stop_token stop,const std::function<void(const JournalRootPreparationProgress&)>& observer) {
    using R=Observation<PreparedJournalRoot::Pointer>;progress={};
    auto notify=[&](JournalRootPreparationPhase p){progress.phase=p;if(observer)observer(progress);};
    auto cancel=[] {return rejected<PreparedJournalRoot::Pointer>(AdapterError::InterruptedRead,"journal_root.cancelled",ObservationState::Changed);};
    if(!request.parent||request.max_ancestors<1||request.max_ancestors>4096||
        static_cast<unsigned>(request.disposition)>static_cast<unsigned>(JournalRootDisposition::ProvisionChild)||
        ((request.disposition==JournalRootDisposition::AdoptHeld)!=!request.child)||
        (request.child&&(!request.child->is_valid()||!request.child->windows_units())))
        return rejected<PreparedJournalRoot::Pointer>(AdapterError::InvalidIdentifier,"journal_root.request");
    if(stop.stop_requested())return cancel();notify(JournalRootPreparationPhase::Acquiring);
    auto user=effective_user();if(!user.value())return R::unavailable(user.state(),user.unavailable_detail()->error);
    auto user_data=std::move(user).take_value();
    auto duplicate=detail::duplicate_windows_journal_directory(*request.parent);
    if(!duplicate.value())return R::unavailable(duplicate.state(),duplicate.unavailable_detail()->error);
    Handle parent(std::move(duplicate).take_value());FILE_ID_INFO parent_id{};
    if(!::ck::files::detail::legacy_query(parent.get(),FileIdInfo,&parent_id,sizeof(parent_id),"legacy.operation_journal_file_windows.GetFileInformationByHandleEx.1030"))return failure<PreparedJournalRoot::Pointer>(GetLastError(),"journal_root.parent_identity");
    const auto* original=request.parent->identity().value();
    if(!original||original->scheme!=IdentityScheme::WindowsFileId128||original->volume!=NativeIdentifier::from_u64(parent_id.VolumeSerialNumber)||original->object!=journal_object(parent_id))
        return rejected<PreparedJournalRoot::Pointer>(AdapterError::MetadataChanged,"journal_root.parent_changed",ObservationState::Changed);
    auto local=journal_local_volume(parent.get());if(!local.value())return R::unavailable(local.state(),local.unavailable_detail()->error);
    Observation<Handle> opened;
    if(request.child) {
        notify(JournalRootPreparationPhase::Provisioning);bool created=false;
        opened=open_journal_root_child(parent.get(),*request.child,request.disposition==JournalRootDisposition::ProvisionChild,user_data,created);
        if(created)++progress.directory_creates;
    } else opened=guarded_journal_directory_by_id(parent.get(),parent_id);
    if(!opened.value())return R::unavailable(opened.state(),opened.unavailable_detail()->error);
    auto node=journal_directory(std::move(opened).take_value());if(!node.value())return R::unavailable(node.state(),node.unavailable_detail()->error);
    auto checked=verify_root(node.value()->handle.get(),user_data.data());
    if(!checked.value())return R::unavailable(checked.state(),checked.unavailable_detail()->error);
    if(!*checked.value())return rejected<PreparedJournalRoot::Pointer>(AdapterError::InvalidNativeResult,"journal_root.root_security_false");
    if(request.child&&(node.value()->id.VolumeSerialNumber!=parent_id.VolumeSerialNumber||node.value()->parent!=journal_object(parent_id)||node.value()->name!=*request.child->windows_units()))
        return rejected<PreparedJournalRoot::Pointer>(AdapterError::MetadataChanged,"journal_root.child_membership_changed",ObservationState::Changed);
    std::vector<WindowsJournalDirectory> chain;chain.reserve(16);chain.push_back(std::move(node).take_value());
    progress.acquired_directories=1;notify(JournalRootPreparationPhase::Ancestry);
    for(;;) {
        if(stop.stop_requested())return cancel();
        const auto& last=chain.back();if(last.parent==journal_object(last.id))break;
        if(chain.size()>=request.max_ancestors)return rejected<PreparedJournalRoot::Pointer>(AdapterError::InventoryLimit,"journal_root.ancestor_limit",ObservationState::Unsupported);
        FILE_ID_INFO id{};id.VolumeSerialNumber=last.id.VolumeSerialNumber;std::memcpy(id.FileId.Identifier,last.parent.bytes.data(),16);
        auto up=guarded_journal_directory_by_id(last.handle.get(),id);if(!up.value())return R::unavailable(up.state(),up.unavailable_detail()->error);
        auto ancestor=journal_directory(std::move(up).take_value());if(!ancestor.value())return R::unavailable(ancestor.state(),ancestor.unavailable_detail()->error);
        for(const auto& seen:chain)if(journal_object(ancestor.value()->id)==journal_object(seen.id))
            return rejected<PreparedJournalRoot::Pointer>(AdapterError::PlanTopologyUnsafe,"journal_root.ancestor_cycle",ObservationState::Unsupported);
        chain.push_back(std::move(ancestor).take_value());++progress.acquired_directories;notify(JournalRootPreparationPhase::Ancestry);
    }
    const auto parent_handle=parent.release();
    if(!::ck::files::detail::legacy_close_native_call(parent_handle,"legacy.operation_journal_file_windows.CloseHandle.1062"))return failure<PreparedJournalRoot::Pointer>(GetLastError(),"journal_root.input_duplicate_close");
    ObjectIdentity id{original->scope,IdentityScheme::WindowsFileId128,NativeIdentifier::from_u64(chain.front().id.VolumeSerialNumber),journal_object(chain.front().id),{}};
    auto navigation=std::move(request.navigation_hint);
    std::vector<wchar_t> path(32768);const auto length=GetFinalPathNameByHandleW(chain.front().handle.get(),path.data(),static_cast<DWORD>(path.size()),FILE_NAME_OPENED|VOLUME_NAME_DOS);
    if(length&&length<path.size()) {
        std::u16string text(path.begin(),path.begin()+length);auto hint=NativeAbsolutePath::from_windows(text);if(hint.value())navigation=std::move(hint).take_value();
    }
    auto result=std::make_shared<WindowsPreparedJournalRoot>(std::move(chain),std::move(user_data),std::move(id),std::move(navigation));
    notify(JournalRootPreparationPhase::Flushing);checked=result->flush_prepared(progress,stop,observer);
    if(!checked.value()){result->finish_io();return R::unavailable(checked.state(),checked.unavailable_detail()->error);}
    notify(JournalRootPreparationPhase::Ready);return R::available(std::move(result));
}

} // namespace ck::files

#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
namespace ck::files::detail {
// Test instrumentation closure only, not native authority/async completion.
std::uint64_t legacy_native_journal_coverage()noexcept {
    return legacy_operation_bit(LegacyNativeOperation::Read)|
        legacy_operation_bit(LegacyNativeOperation::Write)|
        legacy_operation_bit(LegacyNativeOperation::Close)|
        legacy_operation_bit(LegacyNativeOperation::Duplicate)|
        legacy_operation_bit(LegacyNativeOperation::NativeCreate)|
        legacy_operation_bit(LegacyNativeOperation::Create)|
        legacy_operation_bit(LegacyNativeOperation::OpenById)|
        legacy_operation_bit(LegacyNativeOperation::Query)|
        legacy_operation_bit(LegacyNativeOperation::Flush);
}
}
#endif
