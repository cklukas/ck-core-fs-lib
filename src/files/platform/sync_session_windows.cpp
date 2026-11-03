// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../sync_session.hpp"
#include "../sha256.hpp"
#include "../windows_name.hpp"
#include "native_windows_journal_volume.hpp"
#include "native_journal_directory_bridge.hpp"
#include "../native_filesystem.hpp"
#include "../windows_parent_record.hpp"
#include "prepared_journal_root_bridge.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>
#include <cstring>
#include <new>
#include <winternl.h>
#include <aclapi.h>
#include <bit>
#include <algorithm>
#include <future>
#include <atomic>
#include <thread>

namespace ck::files {
namespace {
// Scalar capture precedes all diagnostics. The stack context covers genuine
// native cursor/parent owners as well as Sync's own transient handles.
struct CloseFailure {
    DWORD code=ERROR_SUCCESS;
    const char* operation=nullptr;
    void record(DWORD error,const char* tag,const PreparedJournalRoot::Pointer& owner) noexcept {
        if(!operation) {code=error;operation=tag;}
        if(owner)detail::record_prepared_journal_consumer_failure(*owner,
            ObservationState::Failed,ErrorDomain::Win32,error,tag);
    }
    template<class T> Observation<T> result() const noexcept {
        try {return Observation<T>::unavailable(ObservationState::Failed,{ErrorDomain::Win32,code,operation});}
        catch(const std::bad_alloc&) {
            return Observation<T>::unavailable(ObservationState::Failed,{ErrorDomain::Win32,code,{}});
        }
    }
};
struct CloseContext;
thread_local CloseContext* active_close_context=nullptr;
struct CloseContext {
    PreparedJournalRoot::Pointer owner;
    CloseFailure failure;
    CloseContext* previous;
    detail::WindowsJournalCloseObserver previous_native;
    static void native_failure(void* opaque,std::uint32_t code,const char* operation) noexcept {
        auto& self=*static_cast<CloseContext*>(opaque);
        self.record(code,operation);
    }
    explicit CloseContext(PreparedJournalRoot::Pointer root):owner(std::move(root)),previous(active_close_context),
        previous_native(detail::exchange_windows_journal_close_observer({this,&native_failure})) {
        if(previous&&previous->owner.get()==owner.get())failure=previous->failure;
        active_close_context=this;
    }
    void record(DWORD code,const char* operation) noexcept {
        // Publish first failure into all enclosing scopes for this same Root
        // (including the ownerless factory), before outer cleanup can fail.
        for(auto* context=this;context&&context->owner.get()==owner.get();context=context->previous)
            context->failure.record(code,operation,context->owner);
    }
    ~CloseContext() {
        detail::exchange_windows_journal_close_observer(previous_native);
        active_close_context=previous;
    }
    template<class T,class F> Observation<T> run(F&& body) {
        try {
            auto result=body(); // body locals, including native smart owners, drain here
            if(failure.operation)return failure.result<T>();
            return result;
        } catch(...) {
            if(failure.operation)return failure.result<T>();
            throw;
        }
    }
};
PreparedJournalRoot::Pointer close_owner() noexcept {
    return active_close_context?active_close_context->owner:PreparedJournalRoot::Pointer{};
}
struct Close {
    PreparedJournalRoot::Pointer owner=close_owner();
    void operator()(void* h) const noexcept {
        if(h&&h!=INVALID_HANDLE_VALUE&&!CloseHandle(h)) {
            const auto code=GetLastError();
            if(active_close_context&&(!owner||owner.get()==active_close_context->owner.get()))active_close_context->record(code,"sync_session.directory_CloseHandle");
            else if(owner)detail::record_prepared_journal_consumer_failure(*owner,
                ObservationState::Failed,ErrorDomain::Win32,code,"sync_session.directory_CloseHandle");
        }
    }
};
using Handle=std::unique_ptr<void,Close>;
bool consume_transient(Handle& handle,const char* operation,CloseContext& context) noexcept {
    const auto raw=handle.release();
    if(CloseHandle(raw))return true;
    const auto code=GetLastError();
    context.record(code,operation);
    return false;
}
struct FreeLocal { void operator()(void* p) const noexcept { if(p) LocalFree(p); } };
using Local=std::unique_ptr<void,FreeLocal>;
template<class T> Observation<T> fail(DWORD e,const char* op) {
    auto s=ObservationState::Failed;
    if(e==ERROR_ACCESS_DENIED || e==ERROR_PRIVILEGE_NOT_HELD) s=ObservationState::Denied;
    if(e==ERROR_FILE_NOT_FOUND || e==ERROR_PATH_NOT_FOUND) s=ObservationState::Gone;
    if(e==ERROR_SHARING_VIOLATION || e==ERROR_LOCK_VIOLATION) s=ObservationState::Changed;
    if(e==ERROR_NOT_SUPPORTED || e==ERROR_INVALID_FUNCTION) s=ObservationState::Unsupported;
    return Observation<T>::unavailable(s,{ErrorDomain::Win32,e,op});
}
template<class T> Observation<T> reject(const char* op,ObservationState s=ObservationState::Changed) {
    return Observation<T>::unavailable(s,{ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::UnqualifiedIdentity),op});
}
template<class T,class U> Observation<T> propagate(const Observation<U>& r) {
    const auto& error=r.unavailable_detail()->error;
    try {return Observation<T>::unavailable(r.state(),error);}
    catch(const std::bad_alloc&) {return Observation<T>::unavailable(r.state(),{error.domain,error.code,{}});}
}
void put(Sha256& h,std::uint64_t n) {
    std::array<std::byte,8> b; for(unsigned i=0;i<8;++i) b[i]=std::byte((n>>(8*i))&255); h.update(b);
}
std::wstring hex(const SyncDigest& d) {
    std::wstring s; for(auto v:d) { auto n=std::to_integer<unsigned>(v);
        s+=L"0123456789abcdef"[n>>4]; s+=L"0123456789abcdef"[n&15]; } return s;
}
Observation<Handle> relative(HANDLE parent,std::wstring_view name,ACCESS_MASK access,
    ULONG disposition,bool directory,PSECURITY_DESCRIPTOR security=nullptr) {
    if(name.empty() || name.size()>32760 || name.find_first_of(L"\\/:")!=name.npos ||
        name==L"." || name==L".." || name.find(L'\0')!=name.npos)
        return reject<Handle>("sync_session.relative_name",ObservationState::Failed);
    UNICODE_STRING n{}; n.Buffer=const_cast<wchar_t*>(name.data());
    n.Length=static_cast<USHORT>(name.size()*sizeof(wchar_t)); n.MaximumLength=n.Length;
    OBJECT_ATTRIBUTES a{}; a.Length=sizeof(a); a.RootDirectory=parent; a.ObjectName=&n; a.SecurityDescriptor=security;
    // Exact UTF-16, no OBJ_CASE_INSENSITIVE and no DOS component reparsing.
    IO_STATUS_BLOCK io{}; HANDLE raw=nullptr;
    const auto status=NtCreateFile(&raw,access|SYNCHRONIZE,&a,&io,nullptr,FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,disposition,
        FILE_OPEN_REPARSE_POINT|FILE_SYNCHRONOUS_IO_NONALERT|
            (directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE),nullptr,0);
    Handle h(raw);
    if(status<0) return Observation<Handle>::unavailable(fail<bool>(RtlNtStatusToDosError(status),"unused").state(),
        {ErrorDomain::NtStatus,status,"sync_session.NtCreateFile"});
    return Observation<Handle>::available(std::move(h));
}
struct Object {
    SyncDigest id{},volume{};
    std::wstring volume_path;
    bool volume_root=false;
};
Observation<Object> identity(HANDLE h,bool directory) {
    FILE_ATTRIBUTE_TAG_INFO tag{}; FILE_STANDARD_INFO standard{}; FILE_ID_INFO id{}; FILE_BASIC_INFO basic{};
    if(!GetFileInformationByHandleEx(h,FileAttributeTagInfo,&tag,sizeof(tag)) ||
        !GetFileInformationByHandleEx(h,FileStandardInfo,&standard,sizeof(standard)) ||
        !GetFileInformationByHandleEx(h,FileIdInfo,&id,sizeof(id)) ||
        !GetFileInformationByHandleEx(h,FileBasicInfo,&basic,sizeof(basic)))
        return fail<Object>(GetLastError(),"sync_session.handle_identity");
    if(bool(tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=directory ||
        (tag.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) || standard.DeletePending ||
        (!directory && standard.NumberOfLinks!=1)) return reject<Object>("sync_session.object_kind");
    std::vector<wchar_t> path(32768);
    const auto count=GetFinalPathNameByHandleW(h,path.data(),static_cast<DWORD>(path.size()),FILE_NAME_OPENED|VOLUME_NAME_GUID);
    if(!count || count>=path.size()) return fail<Object>(count?ERROR_NOT_SUPPORTED:GetLastError(),"sync_session.volume_guid_path");
    std::wstring_view p(path.data(),count);
    const auto end=p.find(L'}');
    if(!p.starts_with(L"\\\\?\\Volume{") || end==p.npos || end+1>=p.size() || p[end+1]!=L'\\')
        return reject<Object>("sync_session.local_namespace",ObservationState::Unsupported);
    Object out; out.volume_path=std::wstring(p.substr(0,end+1)); out.volume_root=p.substr(end+1)==L"\\";
    DWORD flags{}; wchar_t fs[32]{};
    if(!GetVolumeInformationByHandleW(h,nullptr,0,nullptr,nullptr,&flags,fs,32))
        return fail<Object>(GetLastError(),"sync_session.volume_info");
    if(!(flags&FILE_PERSISTENT_ACLS) || (std::wstring_view(fs)!=L"NTFS" && std::wstring_view(fs)!=L"ReFS"))
        return reject<Object>("sync_session.durable_local_filesystem",ObservationState::Unsupported);
    Sha256 v; v.update(std::as_bytes(std::span(out.volume_path))); out.volume=v.digest();
    Sha256 hash; put(hash,0x31574e49574b43ULL); hash.update(out.volume); put(hash,id.VolumeSerialNumber);
    hash.update(std::as_bytes(std::span(id.FileId.Identifier))); put(hash,basic.CreationTime.QuadPart);
    out.id=hash.digest(); return Observation<Object>::available(std::move(out));
}
Observation<bool> private_security(HANDLE object,bool protected_root=false) {
    HANDLE raw=nullptr;
    if(!OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&raw)) {
        if(GetLastError()!=ERROR_NO_TOKEN || !OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw))
            return fail<bool>(GetLastError(),"sync_session.user_token");
    }
    Handle token(raw); DWORD size=0;
    GetTokenInformation(token.get(),TokenUser,nullptr,0,&size);
    if(!size || size>65536) return reject<bool>("sync_session.token_size",ObservationState::Denied);
    std::vector<std::byte> user(size);
    if(!GetTokenInformation(token.get(),TokenUser,user.data(),size,&size))
        return fail<bool>(GetLastError(),"sync_session.token_user");
    const auto expected=reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
    PSID owner=nullptr; PACL acl=nullptr; PSECURITY_DESCRIPTOR raw_sd=nullptr;
    const auto e=GetSecurityInfo(object,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        &owner,nullptr,&acl,nullptr,&raw_sd); Local sd(raw_sd);
    if(e!=ERROR_SUCCESS) return fail<bool>(e,"sync_session.object_security");
    if(!owner || !IsValidSid(owner) || !IsValidSid(expected) || !EqualSid(owner,expected) || !acl || !IsValidAcl(acl))
        return reject<bool>("sync_session.private_owner_acl",ObservationState::Denied);
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision=0;
    if(!GetSecurityDescriptorControl(raw_sd,&control,&revision)) return fail<bool>(GetLastError(),"sync_session.security_control");
    if(protected_root && !(control&SE_DACL_PROTECTED)) return reject<bool>("sync_session.inherited_root_acl",ObservationState::Denied);
    ACL_SIZE_INFORMATION info{};
    if(!GetAclInformation(acl,&info,sizeof(info),AclSizeInformation)) return fail<bool>(GetLastError(),"sync_session.acl_information");
    for(DWORD i=0;i<info.AceCount;++i) {
        void* raw_ace=nullptr;
        if(!GetAce(acl,i,&raw_ace)) return fail<bool>(GetLastError(),"sync_session.acl_ace");
        const auto* a=static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
        if(a->Header.AceType==ACCESS_DENIED_ACE_TYPE) continue;
        if(a->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE || a->Header.AceSize<sizeof(ACCESS_ALLOWED_ACE))
            return reject<bool>("sync_session.unqualified_acl",ObservationState::Denied);
        const auto sid=reinterpret_cast<PSID>(const_cast<DWORD*>(&a->SidStart));
        if(!IsValidSid(sid) || GetLengthSid(sid)>a->Header.AceSize- offsetof(ACCESS_ALLOWED_ACE,SidStart) ||
            (!EqualSid(sid,expected) && !IsWellKnownSid(sid,WinLocalSystemSid)))
            return reject<bool>("sync_session.nonprivate_acl",ObservationState::Denied);
    }
    return Observation<bool>::available(true);
}
struct ParentRecord {
    FILE_ID_INFO native{};
    NativeIdentifier child{},parent{};
    std::wstring name;
};
Observation<ParentRecord> parent_record(HANDLE h) {
    ParentRecord out;
    if(!GetFileInformationByHandleEx(h,FileIdInfo,&out.native,sizeof(out.native)))
        return fail<ParentRecord>(GetLastError(),"sync_session.parent_file_id");
    READ_FILE_USN_DATA request{3,3};alignas(8) std::array<std::byte,65536+80> wire{};DWORD size{};
    if(!DeviceIoControl(h,FSCTL_READ_FILE_USN_DATA,&request,sizeof(request),wire.data(),static_cast<DWORD>(wire.size()),&size,nullptr))
        return fail<ParentRecord>(GetLastError(),"sync_session.parent_record");
    if(size>wire.size())return reject<ParentRecord>("sync_session.parent_record_size",ObservationState::Failed);
    auto decoded=detail::decode_windows_parent_record(std::span<const std::byte>(wire).first(size),3);
    if(!decoded.value())return propagate<ParentRecord>(decoded);
    std::memcpy(out.child.bytes.data(),out.native.FileId.Identifier,16);out.parent=decoded.value()->parent;
    if(decoded.value()->child!=out.child||!(decoded.value()->attributes&FILE_ATTRIBUTE_DIRECTORY))
        return reject<ParentRecord>("sync_session.parent_record_identity");
    USHORT bytes{},offset{};std::memcpy(&bytes,wire.data()+72,2);std::memcpy(&offset,wire.data()+74,2);
    out.name.resize(bytes/2);if(bytes)std::memcpy(out.name.data(),wire.data()+offset,bytes);
    return Observation<ParentRecord>::available(std::move(out));
}
Observation<bool> trusted_directory(HANDLE h) {
    const auto proof=detail::prove_windows_journal_volume(h);
    if(!proof.qualified)return Observation<bool>::unavailable(proof.state,{proof.domain,proof.code,proof.operation});
    return Observation<bool>::available(true);
}
Observation<bool> match_native(const BasicMetadata& basic,const ParentRecord& record) {
    if(!basic.kind.value())return propagate<bool>(basic.kind);
    if(!basic.identity.value())return propagate<bool>(basic.identity);
    const auto& id=*basic.identity.value();
    if(*basic.kind.value()!=ObjectKind::Directory||id.scheme!=IdentityScheme::WindowsFileId128||!id.scope.is_valid())
        return reject<bool>("sync_session.native_parent_kind",ObservationState::Unsupported);
    if(id.volume!=NativeIdentifier::from_u64(record.native.VolumeSerialNumber)||id.object!=record.child)
        return reject<bool>("sync_session.native_parent_identity");
    return Observation<bool>::available(true);
}
Observation<Handle> directory_by_id(HANDLE volume,const NativeIdentifier& id,bool writable) {
    FILE_ID_DESCRIPTOR descriptor{};descriptor.dwSize=sizeof(descriptor);descriptor.Type=ExtendedFileIdType;
    std::memcpy(descriptor.ExtendedFileId.Identifier,id.bytes.data(),16);
    Handle out(OpenFileById(volume,&descriptor,FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE|
        (writable?FILE_GENERIC_WRITE:0),FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL));
    if(!out||out.get()==INVALID_HANDLE_VALUE)return fail<Handle>(GetLastError(),"sync_session.parent_by_id");
    return Observation<Handle>::available(std::move(out));
}
struct MountWitness {
    ParentRecord record;
    std::int64_t creation{};
    NativeBytes raw;
    std::u16string target;
};
Observation<MountWitness> mount_witness(HANDLE h) {
    FILE_ATTRIBUTE_TAG_INFO tag{};FILE_BASIC_INFO basic{};FILE_STANDARD_INFO standard{};
    if(!GetFileInformationByHandleEx(h,FileAttributeTagInfo,&tag,sizeof(tag))||
        !GetFileInformationByHandleEx(h,FileBasicInfo,&basic,sizeof(basic))||
        !GetFileInformationByHandleEx(h,FileStandardInfo,&standard,sizeof(standard)))
        return fail<MountWitness>(GetLastError(),"sync_session.mount_metadata");
    constexpr DWORD allowed=FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_READONLY|
        FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_ARCHIVE|FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    if(tag.ReparseTag!=IO_REPARSE_TAG_MOUNT_POINT||!(tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)||
        (tag.FileAttributes&~allowed)||standard.DeletePending)
        return reject<MountWitness>("sync_session.mount_kind",ObservationState::Unsupported);
    auto record=parent_record(h);if(!record.value())return propagate<MountWitness>(record);
    alignas(8) std::array<std::byte,detail::windows_reparse_max_bytes> wire{};DWORD size{};
    if(!DeviceIoControl(h,FSCTL_GET_REPARSE_POINT,nullptr,0,wire.data(),static_cast<DWORD>(wire.size()),&size,nullptr))
        return fail<MountWitness>(GetLastError(),"sync_session.mount_payload");
    if(size>wire.size())return reject<MountWitness>("sync_session.mount_payload_size",ObservationState::Failed);
    auto decoded=detail::decode_windows_reparse(std::span<const std::byte>(wire).first(size),{});
    if(!decoded.value())return propagate<MountWitness>(decoded);
    if(decoded.value()->kind!=WindowsReparseKind::MountPoint||!decoded.value()->names||decoded.value()->names->flags)
        return reject<MountWitness>("sync_session.mount_payload_kind",ObservationState::Unsupported);
    MountWitness out;out.record=std::move(record).take_value();out.creation=basic.CreationTime.QuadPart;
    out.raw=std::move(decoded.value()->raw);out.target=std::move(decoded.value()->names->substitute);
    return Observation<MountWitness>::available(std::move(out));
}
struct Node { Handle handle; std::wstring name; Object object; std::optional<MountWitness> mount; std::wstring namespace_root; };
using Chain=std::vector<Node>;
Observation<bool> validate(const Chain&);
Observation<Chain> physical_chain(NativeFileSystem& fs,const NativeAbsolutePath& path,bool writable,const PreparedJournalRoot::Pointer& owner) {
    CloseContext close(owner);
    return close.run<Chain>([&]() -> Observation<Chain> {
    auto cursor=fs.open_native_directory(path,DirectoryLinkPolicy::RejectFinalLink);
    if(!cursor.value())return propagate<Chain>(cursor);
    auto duplicate=detail::duplicate_windows_journal_directory(**cursor.value());
    if(!duplicate.value())return propagate<Chain>(duplicate);
    Handle volume(std::move(duplicate).take_value());
    auto trusted=trusted_directory(volume.get());if(!trusted.value())return propagate<Chain>(trusted);
    auto seed=parent_record(volume.get());if(!seed.value())return propagate<Chain>(seed);
    auto basic=(*cursor.value())->inspect_basic();if(!basic.value())return propagate<Chain>(basic);
    auto checked=match_native(*basic.value(),*seed.value());if(!checked.value())return propagate<Chain>(checked);
    auto acquired=directory_by_id(volume.get(),seed.value()->child,writable);
    if(!acquired.value())return propagate<Chain>(acquired);
    Handle current=std::move(acquired).take_value();std::unique_ptr<OpenedEntry> reference;Chain out;
    for(;;) {
        if(close.failure.operation)return close.failure.result<Chain>();
        if(out.size()>=256)return reject<Chain>("sync_session.ancestor_limit",ObservationState::Unsupported);
        trusted=trusted_directory(current.get());if(!trusted.value())return propagate<Chain>(trusted);
        auto object=identity(current.get(),true);if(!object.value())return propagate<Chain>(object);
        auto record=parent_record(current.get());if(!record.value())return propagate<Chain>(record);
        checked=match_native(*basic.value(),*record.value());if(!checked.value())return propagate<Chain>(checked);
        if(record.value()->native.VolumeSerialNumber!=seed.value()->native.VolumeSerialNumber)
            return reject<Chain>("sync_session.physical_volume_changed");
        if(std::any_of(out.begin(),out.end(),[&](const auto& n){return n.object.id==object.value()->id;}))
            return reject<Chain>("sync_session.ancestor_cycle",ObservationState::Unsupported);
        auto parent=reference?reference->open_parent_directory():(*cursor.value())->open_parent_directory();
        if(close.failure.operation)return close.failure.result<Chain>();
        if(!parent.value())return propagate<Chain>(parent);
        auto parent_basic=(*parent.value())->inspect_basic();if(!parent_basic.value())return propagate<Chain>(parent_basic);
        if(!parent_basic.value()->identity.value())return propagate<Chain>(parent_basic.value()->identity);
        const auto& parent_id=*parent_basic.value()->identity.value();
        if(parent_id.scheme!=IdentityScheme::WindowsFileId128||parent_id.volume!=basic.value()->identity.value()->volume||
            parent_id.object!=record.value()->parent||parent_id.scope!=basic.value()->identity.value()->scope)
            return reject<Chain>("sync_session.audited_parent_mismatch");
        const bool top=record.value()->parent==record.value()->child;
        if(top&&!object.value()->volume_root)return reject<Chain>("sync_session.hidden_native_ancestors",ObservationState::Unsupported);
        out.push_back({std::move(current),std::move(record.value()->name),std::move(object).take_value(),{}});
        if(top)break;
        auto next=directory_by_id(volume.get(),parent_id.object,false);if(!next.value())return propagate<Chain>(next);
        current=std::move(next).take_value();reference=std::move(parent).take_value();basic=std::move(parent_basic);
    }
    if(close.failure.operation)return close.failure.result<Chain>();
    if(!consume_transient(volume,"sync_session.cursor_duplicate_close",close))return close.failure.result<Chain>();
    std::reverse(out.begin(),out.end());checked=validate(out);if(!checked.value())return propagate<Chain>(checked);
    return Observation<Chain>::available(std::move(out));

    });
}
bool target_matches(const MountWitness& mount,const Object& root) {
    // Only an actual volume-root mount is a qualified namespace bridge.
    // No drive substitution, arbitrary junction target, or derived open path.
    const std::wstring expected=L"\\??\\"+root.volume_path.substr(4)+L"\\";
    if(mount.target.size()!=expected.size())return false;
    return CompareStringOrdinal(reinterpret_cast<const wchar_t*>(mount.target.data()),static_cast<int>(mount.target.size()),
        expected.data(),static_cast<int>(expected.size()),TRUE)==CSTR_EQUAL;
}
Observation<bool> match_suffix(const Chain& physical,std::span<const NativeName> names) {
    CloseContext close(physical.empty()?PreparedJournalRoot::Pointer{}:physical.front().handle.get_deleter().owner);
    return close.run<bool>([&]() -> Observation<bool> {
    if(physical.size()!=names.size()+1)return reject<bool>("sync_session.namespace_depth_changed");
    for(std::size_t i=0;i<names.size();++i) {
        if(!names[i].windows_units())return reject<bool>("sync_session.component_encoding",ObservationState::Failed);
        const auto& units=*names[i].windows_units();const std::wstring name(units.begin(),units.end());
        auto lookup=relative(physical[i].handle.get(),name,FILE_READ_ATTRIBUTES,FILE_OPEN,true);
        if(!lookup.value())return propagate<bool>(lookup);
        Handle lookup_handle=std::move(lookup).take_value();
        auto trusted=trusted_directory(lookup_handle.get());
        auto seen=identity(lookup_handle.get(),true);
        if(!consume_transient(lookup_handle,"sync_session.edge_lookup_close",close))return close.failure.result<bool>();
        if(!trusted.value())return trusted;if(!seen.value())return propagate<bool>(seen);
        if(seen.value()->id!=physical[i+1].object.id)return reject<bool>("sync_session.namespace_capture_changed");
    }
    return Observation<bool>::available(true);

    });
}
Observation<Chain> chain(const NativeAbsolutePath& path,bool writable,PreparedJournalRoot::Pointer owner={}) {
    CloseContext close(std::move(owner));
    return close.run<Chain>([&]() -> Observation<Chain> {
    if(!path.is_valid()||!path.windows_units())return reject<Chain>("sync_session.windows_path",ObservationState::Unsupported);
    auto root=path.namespace_root();if(!root.value())return propagate<Chain>(root);
    auto parts=path.relative_components_from(*root.value());if(!parts.value())return propagate<Chain>(parts);
    auto host=root.value()->host_path();if(!host.value())return propagate<Chain>(host);
    auto extended=windows_extended_path(host.value()->native());
    if(!extended)return reject<Chain>("sync_session.extended_namespace",ObservationState::Failed);
    if(extended->starts_with(L"\\\\?\\UNC\\"))return reject<Chain>("sync_session.unc_scope",ObservationState::Unsupported);
    NativeFileSystem fs;auto physical=physical_chain(fs,path,writable,close.owner);if(!physical.value())return physical;
    auto native_root=fs.open_native_directory(*root.value(),DirectoryLinkPolicy::RejectFinalLink);
    if(!native_root.value())return propagate<Chain>(native_root);
    auto duplicate=detail::duplicate_windows_journal_directory(**native_root.value());if(!duplicate.value())return propagate<Chain>(duplicate);
    Handle current(std::move(duplicate).take_value());auto trusted=trusted_directory(current.get());if(!trusted.value())return propagate<Chain>(trusted);
    auto object=identity(current.get(),true);if(!object.value())return propagate<Chain>(object);
    auto record=parent_record(current.get());if(!record.value())return propagate<Chain>(record);
    if(record.value()->child!=record.value()->parent)return reject<Chain>("sync_session.namespace_root_unqualified",ObservationState::Unsupported);
    if(object.value()->id==physical.value()->front().object.id) {
        if(!consume_transient(current,"sync_session.namespace_duplicate_close",close))return close.failure.result<Chain>();
        auto same=match_suffix(*physical.value(),*parts.value());if(!same.value())return propagate<Chain>(same);
        auto out=std::move(physical).take_value();out.front().namespace_root=*extended;
        same=validate(out);if(!same.value())return propagate<Chain>(same);
        return Observation<Chain>::available(std::move(out));
    }
    Chain out;out.push_back({std::move(current),{},std::move(object).take_value(),{}});
    out.front().namespace_root=*extended;
    for(std::size_t i=0;i<parts.value()->size();++i) {
        if(out.size()>=256)return reject<Chain>("sync_session.namespace_ancestor_limit",ObservationState::Unsupported);
        const auto* units=(*parts.value())[i].windows_units();if(!units)return reject<Chain>("sync_session.component_encoding",ObservationState::Failed);
        const std::wstring name(units->begin(),units->end());auto child=relative(out.back().handle.get(),name,FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|READ_CONTROL,FILE_OPEN,true);
        if(!child.value())return propagate<Chain>(child);
        Handle child_handle=std::move(child).take_value();
        FILE_ATTRIBUTE_TAG_INFO tag{};if(!GetFileInformationByHandleEx(child_handle.get(),FileAttributeTagInfo,&tag,sizeof(tag)))
            return fail<Chain>(GetLastError(),"sync_session.namespace_kind");
        if(tag.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) {
            auto mount=mount_witness(child_handle.get());
            if(!consume_transient(child_handle,"sync_session.mount_lookup_close",close))return close.failure.result<Chain>();
            if(!mount.value())return propagate<Chain>(mount);
            auto previous=parent_record(out.back().handle.get());if(!previous.value())return propagate<Chain>(previous);
            if(mount.value()->record.native.VolumeSerialNumber!=previous.value()->native.VolumeSerialNumber||mount.value()->record.parent!=previous.value()->child)
                return reject<Chain>("sync_session.mount_parent_changed");
            if(!target_matches(*mount.value(),physical.value()->front().object))
                return reject<Chain>("sync_session.unqualified_mount_target",ObservationState::Unsupported);
            auto same=match_suffix(*physical.value(),std::span<const NativeName>(*parts.value()).subspan(i+1));
            if(!same.value())return propagate<Chain>(same);
            auto leaf=std::move(physical).take_value();
            if(out.size()+leaf.size()>256)return reject<Chain>("sync_session.namespace_ancestor_limit",ObservationState::Unsupported);
            auto top=std::move(leaf.front());
            top.name=mount.value()->record.name;top.mount=std::move(mount).take_value();out.push_back(std::move(top));
            for(std::size_t n=1;n<leaf.size();++n)out.push_back(std::move(leaf[n]));
            auto valid=validate(out);if(!valid.value())return propagate<Chain>(valid);
            return Observation<Chain>::available(std::move(out));
        }
        trusted=trusted_directory(child_handle.get());if(!trusted.value())return propagate<Chain>(trusted);
        object=identity(child_handle.get(),true);if(!object.value())return propagate<Chain>(object);
        record=parent_record(child_handle.get());if(!record.value())return propagate<Chain>(record);
        auto previous=parent_record(out.back().handle.get());if(!previous.value())return propagate<Chain>(previous);
        if(record.value()->native.VolumeSerialNumber!=previous.value()->native.VolumeSerialNumber||record.value()->parent!=previous.value()->child)
            return reject<Chain>("sync_session.namespace_parent_changed");
        if(std::any_of(out.begin(),out.end(),[&](const auto& n){return n.object.id==object.value()->id;}))
            return reject<Chain>("sync_session.namespace_cycle",ObservationState::Unsupported);
        out.push_back({std::move(child_handle),std::move(record.value()->name),std::move(object).take_value(),{}});
    }
    return reject<Chain>("sync_session.namespace_bridge_missing",ObservationState::Unsupported);

    });
}
Observation<bool> validate(const Chain& c) {
    CloseContext close(c.empty()?PreparedJournalRoot::Pointer{}:c.front().handle.get_deleter().owner);
    return close.run<bool>([&]() -> Observation<bool> {
    if(c.empty())return reject<bool>("sync_session.empty_ancestry",ObservationState::Failed);
    std::optional<ParentRecord> previous;
    for(std::size_t i=0;i<c.size();++i) {
        auto trusted=trusted_directory(c[i].handle.get());if(!trusted.value())return trusted;
        auto id=identity(c[i].handle.get(),true);if(!id.value())return propagate<bool>(id);
        if(id.value()->id!=c[i].object.id)return reject<bool>("sync_session.held_identity");
        auto record=parent_record(c[i].handle.get());if(!record.value())return propagate<bool>(record);
        if(!i) {
            if(record.value()->parent!=record.value()->child||!id.value()->volume_root)return reject<bool>("sync_session.namespace_root_changed");
            if(!c[i].namespace_root.empty()) {
                // Reopen only the original namespace endpoint to VERIFY its
                // binding, as before. It is never substituted for held-node
                // authority or used to discover physical/native parents.
                Handle endpoint(CreateFileW(c[i].namespace_root.c_str(),FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL,nullptr));
                if(!endpoint||endpoint.get()==INVALID_HANDLE_VALUE)return fail<bool>(GetLastError(),"sync_session.namespace_root_check");
                auto proof=trusted_directory(endpoint.get());auto seen=identity(endpoint.get(),true);
                if(!consume_transient(endpoint,"sync_session.namespace_endpoint_close",close))return close.failure.result<bool>();
                if(!proof.value())return proof;if(!seen.value())return propagate<bool>(seen);
                if(seen.value()->id!=c[i].object.id)return reject<bool>("sync_session.namespace_root_changed");
            }
        } else if(c[i].mount) {
            auto edge=relative(c[i-1].handle.get(),c[i].name,FILE_READ_ATTRIBUTES,FILE_OPEN,true);
            if(!edge.value())return propagate<bool>(edge);
            Handle edge_handle=std::move(edge).take_value();
            auto seen=mount_witness(edge_handle.get());
            if(!consume_transient(edge_handle,"sync_session.mount_revalidate_close",close))return close.failure.result<bool>();
            if(!seen.value())return propagate<bool>(seen);
            const auto& expected=*c[i].mount;
            if(seen.value()->record.native.VolumeSerialNumber!=previous->native.VolumeSerialNumber||
                seen.value()->record.parent!=previous->child||seen.value()->record.child!=expected.record.child||
                seen.value()->record.name!=expected.record.name||seen.value()->creation!=expected.creation||
                seen.value()->raw!=expected.raw||record.value()->parent!=record.value()->child||!id.value()->volume_root||!target_matches(*seen.value(),c[i].object))
                return reject<bool>("sync_session.mount_binding_changed");
        } else {
            if(record.value()->native.VolumeSerialNumber!=previous->native.VolumeSerialNumber||record.value()->parent!=previous->child||record.value()->name!=c[i].name)
                return reject<bool>("sync_session.parent_membership_changed");
            auto edge=relative(c[i-1].handle.get(),c[i].name,FILE_READ_ATTRIBUTES,FILE_OPEN,true);
            if(!edge.value())return propagate<bool>(edge);
            Handle edge_handle=std::move(edge).take_value();
            auto seen=identity(edge_handle.get(),true);
            if(!consume_transient(edge_handle,"sync_session.edge_revalidate_close",close))return close.failure.result<bool>();
            if(!seen.value())return propagate<bool>(seen);
            if(seen.value()->id!=c[i].object.id)return reject<bool>("sync_session.namespace_changed");
        }
        previous=std::move(record).take_value();
    }
    return Observation<bool>::available(true);

    });
}
std::vector<SyncDigest> lease_scopes(const Chain& left,const Chain& right) {
    std::vector<SyncDigest> out;
    for(const auto* chain:{&left,&right})for(const auto& node:*chain)out.push_back(node.object.volume);
    return out;
}
// Read exact native parent IDs from held directory records and acquire those
// IDs on that SAME volume. A final-path string is never used as an open address.
Observation<Chain> held_storage_chain(PreparedJournalRoot::Pointer owner) {
    auto duplicate=detail::duplicate_prepared_journal_directory(*owner);
    if(!duplicate.value())return propagate<Chain>(duplicate);
    Handle current(*duplicate.value(),Close{owner});Chain out;
    for(;;) {
        if(out.size()>=256)return reject<Chain>("sync_session.storage_ancestor_limit",ObservationState::Unsupported);
        auto object=identity(current.get(),true);if(!object.value())return propagate<Chain>(object);
        if(std::any_of(out.begin(),out.end(),[&](const auto& n){return n.object.id==object.value()->id;}))
            return reject<Chain>("sync_session.storage_ancestor_cycle",ObservationState::Unsupported);
        FILE_ID_INFO id{};if(!GetFileInformationByHandleEx(current.get(),FileIdInfo,&id,sizeof(id)))
            return fail<Chain>(GetLastError(),"sync_session.storage_file_id");
        READ_FILE_USN_DATA query{3,3};alignas(8) std::array<std::byte,65536+80> wire{};DWORD size{};
        if(!DeviceIoControl(current.get(),FSCTL_READ_FILE_USN_DATA,&query,sizeof(query),wire.data(),static_cast<DWORD>(wire.size()),&size,nullptr))
            return fail<Chain>(GetLastError(),"sync_session.storage_parent_record");
        if(size>wire.size())return reject<Chain>("sync_session.storage_parent_record_size",ObservationState::Failed);
        auto record=detail::decode_windows_parent_record(std::span<const std::byte>(wire).first(size),3);
        if(!record.value())return propagate<Chain>(record);
        NativeIdentifier actual;std::memcpy(actual.bytes.data(),id.FileId.Identifier,16);
        if(record.value()->child!=actual||!(record.value()->attributes&FILE_ATTRIBUTE_DIRECTORY))
            return reject<Chain>("sync_session.storage_parent_record_changed");
        const bool top=record.value()->child==record.value()->parent;
        if(top&&!object.value()->volume_root)return reject<Chain>("sync_session.storage_hidden_ancestors",ObservationState::Unsupported);
        if(top) {out.push_back({std::move(current),{},std::move(object).take_value()});break;}
        FILE_ID_DESCRIPTOR descriptor{};descriptor.dwSize=sizeof(descriptor);descriptor.Type=ExtendedFileIdType;
        std::memcpy(descriptor.ExtendedFileId.Identifier,record.value()->parent.bytes.data(),16);
        Handle parent(OpenFileById(current.get(),&descriptor,FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|READ_CONTROL|SYNCHRONIZE,
            FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OPEN_NO_RECALL));
        parent.get_deleter().owner=owner;
        if(parent.get()==INVALID_HANDLE_VALUE)return fail<Chain>(GetLastError(),"sync_session.storage_parent_by_id");
        FILE_ID_INFO seen{};if(!GetFileInformationByHandleEx(parent.get(),FileIdInfo,&seen,sizeof(seen)))
            return fail<Chain>(GetLastError(),"sync_session.storage_parent_identity");
        if(seen.VolumeSerialNumber!=id.VolumeSerialNumber||std::memcmp(seen.FileId.Identifier,record.value()->parent.bytes.data(),16))
            return reject<Chain>("sync_session.storage_parent_changed");
        out.push_back({std::move(current),{},std::move(object).take_value()});current=std::move(parent);
    }
    std::reverse(out.begin(),out.end());auto checked=owner->revalidate();if(!checked.value())return propagate<Chain>(checked);
    return Observation<Chain>::available(std::move(out));
}
Observation<bool> validate_storage(const Chain& chain,PreparedJournalRoot& owner) {
    auto checked=owner.revalidate();if(!checked.value())return checked;
    for(const auto& node:chain) {
        auto current=identity(node.handle.get(),true);if(!current.value())return propagate<bool>(current);
        if(current.value()->id!=node.object.id)return reject<bool>("sync_session.storage_identity_changed");
    }
    return owner.revalidate();
}
bool contains(const Chain& c,const SyncDigest& id) {
    return std::any_of(c.begin(),c.end(),[&](const auto& n){return n.object.id==id;});
}
// Windows byte locks do not cover directory objects. A machine-global volume
// mutex conservatively serializes every session touching that native volume,
// including aliases and disjoint roots. This is broader than POSIX ancestry
// locks. A dedicated owner thread permits moving/destroying sessions on any
// caller thread, and abandoned mutex acquisition is safe under journal recovery.
class Lease {
    PreparedJournalRoot::Pointer owner_;
    Handle release_{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    std::thread worker_;
    std::atomic<bool> stopping_{false};
    std::atomic<DWORD> failure_{0};
    const char* operation_="sync_session.volume_lock_finish";
    void remember(DWORD code,const char* operation) noexcept {
        DWORD expected=0;
        if(code&&failure_.compare_exchange_strong(expected,code)) {
            operation_=operation;
            if(owner_)detail::record_prepared_journal_consumer_failure(*owner_,ObservationState::Failed,ErrorDomain::Win32,code,operation);
        }
    }
public:
    explicit Lease(PreparedJournalRoot::Pointer owner):owner_(std::move(owner)) {}
    ~Lease() {try{(void)finish();}catch(...){remember(ERROR_GEN_FAILURE,"sync_session.lock_thread_join");if(worker_.joinable())std::terminate();}}
    DWORD finish() {
        stopping_.store(true);
        if(release_&&!SetEvent(release_.get()))remember(GetLastError(),"sync_session.lock_event_signal");
        if(worker_.joinable())worker_.join();
        const auto event=release_.release();
        if(event&&event!=INVALID_HANDLE_VALUE&&!CloseHandle(event))remember(GetLastError(),"sync_session.lock_event_close");
        return failure_.load();
    }
    const char* finish_operation() const noexcept {return operation_;}
    Observation<bool> acquire(const SyncDigest& volume) {
        if(!release_) return fail<bool>(GetLastError(),"sync_session.lock_event");
        std::promise<DWORD> ready; auto future=ready.get_future();
        worker_=std::thread([this,name=L"Global\\ck-core-fs-sync-volume-v1-"+hex(volume),ready=std::move(ready)]() mutable {
            Handle mutex(CreateMutexW(nullptr,FALSE,name.c_str()));
            if(!mutex) { ready.set_value(GetLastError()); return; }
            auto close=[&]{const auto raw=mutex.release();if(raw&&!CloseHandle(raw))remember(GetLastError(),"sync_session.volume_mutex_close");};
            const auto status=WaitForSingleObject(mutex.get(),0);
            if(status!=WAIT_OBJECT_0 && status!=WAIT_ABANDONED) {
                ready.set_value(status==WAIT_TIMEOUT ? ERROR_LOCK_VIOLATION : GetLastError());close();return;
            }
            ready.set_value(ERROR_SUCCESS);
            // The stop flag also drains if the wakeup event itself fails.
            while(!stopping_.load()) {
                const auto wait=WaitForSingleObject(release_.get(),20);
                if(wait==WAIT_OBJECT_0)break;
                if(wait!=WAIT_TIMEOUT){remember(wait==WAIT_FAILED?GetLastError():ERROR_GEN_FAILURE,"sync_session.lock_event_wait");break;}
            }
            if(!ReleaseMutex(mutex.get()))remember(GetLastError(),"sync_session.volume_unlock");
            close();
        });
        const auto e=future.get(); if(e) return fail<bool>(e,"sync_session.volume_session_lock");
        return Observation<bool>::available(true);
    }
};
std::optional<std::wstring> basename(std::string_view n) {
    if(n.empty() || n.size()>127 || n=="." || n=="..") return {};
    std::wstring out; for(unsigned char c:n) {
        if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='-')) return {};
        out+=c;
    } return out;
}
class WindowsBackend final:public SyncSessionBackend {
public:
    PreparedJournalRoot::Pointer owner; // outlives all duplicates and leases
    Chain store,left,right;
    PreparedJournalRoot::Pointer storage_root() const noexcept override {return owner;}
    std::vector<std::unique_ptr<Lease>> leases;
    // Set only by this provider's legacy address factory. An externally
    // adopted shared root is NEVER finalized by a session consumer.
    bool owns_root_lifecycle=false,root_finished=false;
    bool closed=false;
    DWORD close_error=0;
    const char* close_operation="sync_session.directory_CloseHandle";
    void close_native() noexcept {
        if(closed)return;closed=true;
        for(auto* chain:{&store,&left,&right})for(auto& node:*chain) {
            const auto handle=node.handle.release();if(!handle||handle==INVALID_HANDLE_VALUE)continue;
            if(!CloseHandle(handle)&&!close_error)close_error=GetLastError();
            node.handle.get_deleter().owner.reset();
            try {if(faults.before&&!faults.before(SyncSessionIo::NativeHandleClose)&&!close_error)close_error=ERROR_WRITE_FAULT;}
            catch(...) {if(!close_error)close_error=ERROR_WRITE_FAULT;}
        }
        for(auto& lease:leases)try {
            const auto code=lease->finish();if(code&&!close_error){close_error=code;close_operation=lease->finish_operation();}
        }catch(...) {if(!close_error){close_error=ERROR_GEN_FAILURE;close_operation="sync_session.lock_thread_join";}}
        leases.clear();
        if(close_error&&owner)detail::record_prepared_journal_consumer_failure(*owner,ObservationState::Failed,ErrorDomain::Win32,close_error,close_operation);
    }
    ~WindowsBackend() override {
        close_native();
        if(owns_root_lifecycle&&owner&&!root_finished)try{(void)finish_owned_root();}catch(...) {
            detail::record_prepared_journal_consumer_failure(*owner,ObservationState::Unknown,ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"sync_session.root_finish_exception");
        }
    }
    Observation<bool> finish_owned_root() {
        if(!owns_root_lifecycle||root_finished)return Observation<bool>::available(true);
        auto result=owner->finish_io();
        if(result.value()) {
            if(*result.value())root_finished=true;
            else {
                detail::record_prepared_journal_consumer_failure(*owner,ObservationState::Unknown,ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"sync_session.root_finish_false");
                return Observation<bool>::unavailable(ObservationState::Unknown,{ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"sync_session.root_finish_false"});
            }
        }
        return result;
    }
    Observation<bool> finish_io() override {
        close_native();
        auto root=finish_owned_root();if(!root.value())return root;
        detail::PreparedJournalConsumerFailure first;
        if(owner&&detail::read_prepared_journal_consumer_failure(*owner,first))
            return Observation<bool>::unavailable(first.state,{first.domain,first.code,first.operation.data()});
        return close_error?fail<bool>(close_error,close_operation):Observation<bool>::available(true);
    }
    SyncSessionFaults faults;
    const SyncDigest& left_identity() const noexcept override { return left.back().object.id; }
    const SyncDigest& right_identity() const noexcept override { return right.back().object.id; }
    std::intptr_t root_handle(bool r) const noexcept override {
        return closed?-1:reinterpret_cast<std::intptr_t>((r?right:left).back().handle.get());
    }
    Observation<bool> revalidate() override {
        if(closed)return reject<bool>("sync_session.finished");
        auto held=validate_storage(store,*owner);if(!held.value())return held;
        for(const auto* c:{&left,&right}) { auto r=validate(*c); if(!r.value()) return r; }
        return private_security(store.back().handle.get(),true);
    }
    Observation<bool> before(SyncSessionIo io) {
        auto r=revalidate(); if(!r.value()) return r;
        if(faults.before && !faults.before(io)) return fail<bool>(ERROR_WRITE_FAULT,"sync_session.injected");
        return Observation<bool>::available(true);
    }
    Observation<std::optional<std::vector<std::byte>>> read(std::string_view name,std::size_t limit) override {
        using T=std::optional<std::vector<std::byte>>;
        auto n=basename(name); if(!n) return reject<T>("sync_session.basename",ObservationState::Failed);
        auto valid=revalidate(); if(!valid.value()) return propagate<T>(valid);
        auto f=relative(store.back().handle.get(),*n,FILE_GENERIC_READ,FILE_OPEN,false);
        if(!f.value()) { if(f.state()==ObservationState::Gone) return Observation<T>::available({}); return propagate<T>(f); }
        auto id=identity(f.value()->get(),false); if(!id.value()) return propagate<T>(id);
        valid=private_security(f.value()->get()); if(!valid.value()) return propagate<T>(valid);
        LARGE_INTEGER size{};
        if(!GetFileSizeEx(f.value()->get(),&size)) return fail<T>(GetLastError(),"sync_session.file_size");
        if(size.QuadPart<0 || std::uint64_t(size.QuadPart)>limit) return Observation<T>::available(std::vector<std::byte>{});
        std::vector<std::byte> bytes(static_cast<std::size_t>(size.QuadPart)); std::size_t at=0;
        while(at<bytes.size()) {
            DWORD got=0;
            if(!ReadFile(f.value()->get(),bytes.data()+at,static_cast<DWORD>(std::min<std::size_t>(bytes.size()-at,1024*1024)),&got,nullptr))
                return fail<T>(GetLastError(),"sync_session.ReadFile");
            if(!got) return reject<T>("sync_session.short_read"); at+=got;
        }
        return Observation<T>::available(std::move(bytes));
    }
    Observation<bool> remove(std::string_view name) override {
        auto n=basename(name); if(!n) return reject<bool>("sync_session.basename",ObservationState::Failed);
        auto r=before(SyncSessionIo::Remove); if(!r.value()) return r;
        auto f=relative(store.back().handle.get(),*n,DELETE|FILE_READ_ATTRIBUTES|READ_CONTROL,FILE_OPEN,false);
        if(!f.value()) { if(f.state()==ObservationState::Gone) return Observation<bool>::available(true); return propagate<bool>(f); }
        auto id=identity(f.value()->get(),false); if(!id.value()) return propagate<bool>(id);
        r=private_security(f.value()->get()); if(!r.value()) return r;
        FILE_DISPOSITION_INFO info{}; info.DeleteFile=TRUE;
        if(!SetFileInformationByHandle(f.value()->get(),FileDispositionInfo,&info,sizeof(info)))
            return fail<bool>(GetLastError(),"sync_session.delete_handle");
        return Observation<bool>::available(true);
    }
    Observation<bool> stage(std::string_view name,std::span<const std::byte> bytes) override {
        auto n=basename(name);
        if(!n || (!name.ends_with(".next") && !name.ends_with(".intent-stage")))
            return reject<bool>("sync_session.stage_name",ObservationState::Failed);
        auto r=remove(name); if(!r.value()) return r;
        PSECURITY_DESCRIPTOR raw_sd=nullptr;
        const auto security=GetSecurityInfo(store.back().handle.get(),SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,nullptr,nullptr,nullptr,nullptr,&raw_sd);
        Local descriptor(raw_sd);
        if(security!=ERROR_SUCCESS) return fail<bool>(security,"sync_session.stage_security");
        auto f=relative(store.back().handle.get(),*n,FILE_GENERIC_READ|FILE_GENERIC_WRITE,FILE_CREATE,false,raw_sd);
        if(!f.value()) return propagate<bool>(f);
        auto writable=std::move(f).take_value();
        auto id=identity(writable.get(),false); if(!id.value()) return propagate<bool>(id);
        r=private_security(writable.get()); if(!r.value()) return r;
        std::size_t at=0;
        while(at<bytes.size()) {
            r=before(SyncSessionIo::Write); if(!r.value()) return r;
            DWORD wrote=0;
            if(!WriteFile(writable.get(),bytes.data()+at,static_cast<DWORD>(std::min(bytes.size()-at,faults.max_write_bytes)),&wrote,nullptr))
                return fail<bool>(GetLastError(),"sync_session.WriteFile");
            if(!wrote) return fail<bool>(ERROR_WRITE_FAULT,"sync_session.zero_write"); at+=wrote;
        }
        r=before(SyncSessionIo::FileFlush); if(!r.value()) return r;
        if(!FlushFileBuffers(writable.get())) return fail<bool>(GetLastError(),"sync_session.file_flush");
        r=before(SyncSessionIo::FileClose);if(!r.value()) return r;
        const auto handle=writable.release();
        if(!CloseHandle(handle)) return fail<bool>(GetLastError(),"sync_session.stage_CloseHandle");
        return Observation<bool>::available(true);
    }
    Observation<bool> publish(std::string_view from,std::string_view to) override {
        auto a=basename(from),b=basename(to); if(!a || !b) return reject<bool>("sync_session.basename",ObservationState::Failed);
        auto r=before(SyncSessionIo::Publish); if(!r.value()) return r;
        auto f=relative(store.back().handle.get(),*a,DELETE|FILE_READ_ATTRIBUTES|READ_CONTROL,FILE_OPEN,false);
        if(!f.value()) return propagate<bool>(f);
        auto id=identity(f.value()->get(),false); if(!id.value()) return propagate<bool>(id);
        r=private_security(f.value()->get()); if(!r.value()) return r;
        const auto bytes=offsetof(FILE_RENAME_INFO,FileName)+b->size()*sizeof(wchar_t);
        std::vector<std::byte> buffer(std::max(bytes,sizeof(FILE_RENAME_INFO)));
        auto* info=reinterpret_cast<FILE_RENAME_INFO*>(buffer.data()); info->ReplaceIfExists=TRUE;
        info->RootDirectory=store.back().handle.get(); info->FileNameLength=static_cast<DWORD>(b->size()*sizeof(wchar_t));
        std::copy(b->begin(),b->end(),info->FileName);
        // NtSetInformationFile preserves the held RootDirectory and exact name;
        // no Win32 path reconstruction or path-based reopen fallback.
        IO_STATUS_BLOCK io{};
        using SetInformation=NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,ULONG);
        const auto module=GetModuleHandleW(L"ntdll.dll");
        const auto symbol=module?GetProcAddress(module,"NtSetInformationFile"):nullptr;
        if(!symbol) return reject<bool>("sync_session.native_rename_unavailable",ObservationState::Unsupported);
        const auto call=std::bit_cast<SetInformation>(symbol);
        const auto status=call(f.value()->get(),&io,info,static_cast<ULONG>(buffer.size()),10 /* FileRenameInformation */);
        if(status<0) return Observation<bool>::unavailable(ObservationState::Failed,{ErrorDomain::NtStatus,status,"sync_session.rename_handle"});
        return Observation<bool>::available(true);
    }
    Observation<bool> flush_directory() override {
        auto r=before(SyncSessionIo::ParentFlush); if(!r.value()) return r;
        return owner->sync();
    }
};
}
Observation<std::unique_ptr<SyncSessionBackend>> open_native_sync_session_backend(
    const NativeAbsolutePath& coordinator,const NativeAbsolutePath& left,const NativeAbsolutePath& right,SyncSessionFaults faults) {
    using P=std::unique_ptr<SyncSessionBackend>;
    auto initial=chain(coordinator,true);if(!initial.value())return propagate<P>(initial);
    auto privacy=private_security(initial.value()->back().handle.get(),true);if(!privacy.value())return propagate<P>(privacy);
    auto owner=acquire_native_sync_storage_root(coordinator);if(!owner.value())return propagate<P>(owner);
    auto checked=validate(*initial.value());if(!checked.value())return propagate<P>(checked);
    auto acquired=held_storage_chain(*owner.value());if(!acquired.value())return propagate<P>(acquired);
    if(acquired.value()->back().object.id!=initial.value()->back().object.id)return reject<P>("sync_session.initial_storage_changed");
    auto acquired_backend=open_native_sync_session_backend(std::move(owner).take_value(),left,right,std::move(faults));
    if(acquired_backend.value())static_cast<WindowsBackend*>(acquired_backend.value()->get())->owns_root_lifecycle=true;
    return acquired_backend;
}
Observation<std::unique_ptr<SyncSessionBackend>> open_native_sync_session_backend(
    PreparedJournalRoot::Pointer owner,const NativeAbsolutePath& left,const NativeAbsolutePath& right,SyncSessionFaults faults) {
    using P=std::unique_ptr<SyncSessionBackend>;
    if(!faults.max_write_bytes || faults.max_write_bytes>1024*1024)
        return reject<P>("sync_session.write_limit",ObservationState::Failed);
    if(!owner)return reject<P>("sync_session.null_storage_owner",ObservationState::Failed);
    auto s=held_storage_chain(owner); if(!s.value()) return propagate<P>(s);
    auto l=chain(left,false,owner); if(!l.value()) return propagate<P>(l);
    auto r=chain(right,false,owner); if(!r.value()) return propagate<P>(r);
    auto b=std::make_unique<WindowsBackend>(); b->owner=std::move(owner); b->store=std::move(s).take_value();
    b->left=std::move(l).take_value(); b->right=std::move(r).take_value(); b->faults=std::move(faults);
    if(contains(b->left,b->right_identity()) || contains(b->right,b->left_identity()) ||
        contains(b->store,b->left_identity()) || contains(b->store,b->right_identity()))
        return reject<P>("sync_session.overlapping_pair_or_store",ObservationState::Failed);
    auto volumes=lease_scopes(b->left,b->right);
    std::sort(volumes.begin(),volumes.end()); volumes.erase(std::unique(volumes.begin(),volumes.end()),volumes.end());
    for(const auto& v:volumes) {
        auto lease=std::make_unique<Lease>(b->owner); auto acquired=lease->acquire(v);
        if(!acquired.value()) return propagate<P>(acquired); b->leases.push_back(std::move(lease));
    }
    auto check=b->revalidate(); if(!check.value()) return propagate<P>(check);
    check=b->flush_directory(); if(!check.value()) return propagate<P>(check);
    return Observation<P>::available(std::move(b));
}
} // namespace ck::files
