// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../sync_session.hpp"
#include "../sha256.hpp"
#include "../windows_name.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <bit>
#include <algorithm>
#include <future>
#include <thread>

namespace ck::files {
namespace {
struct Close { void operator()(void* h) const noexcept { if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h); } };
using Handle=std::unique_ptr<void,Close>;
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
    return Observation<T>::unavailable(r.state(),r.unavailable_detail()->error);
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
struct Node { Handle handle; std::wstring name; Object object; };
using Chain=std::vector<Node>;
Observation<Chain> chain(const NativeAbsolutePath& path,bool writable) {
    if(!path.is_valid() || !path.windows_units()) return reject<Chain>("sync_session.windows_path",ObservationState::Unsupported);
    auto root=path.namespace_root(); if(!root.value()) return propagate<Chain>(root);
    auto components=path.relative_components_from(*root.value()); if(!components.value()) return propagate<Chain>(components);
    auto host=root.value()->host_path(); if(!host.value()) return propagate<Chain>(host);
    auto extended=windows_extended_path(host.value()->native());
    if(!extended) return reject<Chain>("sync_session.extended_namespace",ObservationState::Failed);
    // UNC/redirectors cannot establish local volume identity/ancestry durability.
    if(extended->starts_with(L"\\\\?\\UNC\\")) return reject<Chain>("sync_session.unc_scope",ObservationState::Unsupported);
    const auto root_access=FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|READ_CONTROL|
        (writable && components.value()->empty() ? FILE_GENERIC_WRITE : 0);
    Handle h(CreateFileW(extended->c_str(),root_access,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if(h.get()==INVALID_HANDLE_VALUE) return fail<Chain>(GetLastError(),"sync_session.open_namespace");
    auto id=identity(h.get(),true); if(!id.value()) return propagate<Chain>(id);
    if(!id.value()->volume_root) return reject<Chain>("sync_session.hidden_native_ancestors",ObservationState::Unsupported);
    Chain out; out.push_back({std::move(h),*extended,std::move(id).take_value()});
    for(std::size_t i=0;i<components.value()->size();++i) {
        const auto& c=(*components.value())[i];
        if(!c.windows_units()) return reject<Chain>("sync_session.component_encoding",ObservationState::Failed);
        std::wstring name; for(auto u:*c.windows_units()) name+=static_cast<wchar_t>(u);
        const auto access=FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES|READ_CONTROL|
            (writable && i+1==components.value()->size() ? FILE_GENERIC_WRITE : 0);
        auto child=relative(out.back().handle.get(),name,access,FILE_OPEN,true);
        if(!child.value()) return propagate<Chain>(child);
        auto child_id=identity(child.value()->get(),true); if(!child_id.value()) return propagate<Chain>(child_id);
        // Mounted folders are reparse points (rejected above); crossing volume
        // without a proven namespace root is never treated as ancestry proof.
        if(child_id.value()->volume!=out.front().object.volume)
            return reject<Chain>("sync_session.cross_volume_ancestry",ObservationState::Unsupported);
        out.push_back({std::move(child).take_value(),std::move(name),std::move(child_id).take_value()});
    }
    return Observation<Chain>::available(std::move(out));
}
Observation<bool> validate(const Chain& c) {
    for(std::size_t i=0;i<c.size();++i) {
        auto id=identity(c[i].handle.get(),true); if(!id.value()) return propagate<bool>(id);
        if(id.value()->id!=c[i].object.id) return reject<bool>("sync_session.held_identity");
        if(!i) {
            Handle seen_root(CreateFileW(c[i].name.c_str(),FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
            if(seen_root.get()==INVALID_HANDLE_VALUE) return fail<bool>(GetLastError(),"sync_session.namespace_root_check");
            auto seen=identity(seen_root.get(),true); if(!seen.value()) return propagate<bool>(seen);
            if(seen.value()->id!=c[i].object.id) return reject<bool>("sync_session.namespace_root_changed");
        } else {
            auto edge=relative(c[i-1].handle.get(),c[i].name,FILE_READ_ATTRIBUTES,FILE_OPEN,true);
            if(!edge.value()) return propagate<bool>(edge);
            auto seen=identity(edge.value()->get(),true); if(!seen.value()) return propagate<bool>(seen);
            if(seen.value()->id!=c[i].object.id) return reject<bool>("sync_session.namespace_changed");
        }
    }
    return Observation<bool>::available(true);
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
    Handle release_{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    std::thread worker_;
public:
    ~Lease() { if(worker_.joinable()) { SetEvent(release_.get()); worker_.join(); } }
    Observation<bool> acquire(const SyncDigest& volume) {
        if(!release_) return fail<bool>(GetLastError(),"sync_session.lock_event");
        std::promise<DWORD> ready; auto future=ready.get_future();
        worker_=std::thread([this,name=L"Global\\ck-core-fs-sync-volume-v1-"+hex(volume),ready=std::move(ready)]() mutable {
            Handle mutex(CreateMutexW(nullptr,FALSE,name.c_str()));
            if(!mutex) { ready.set_value(GetLastError()); return; }
            const auto status=WaitForSingleObject(mutex.get(),0);
            if(status!=WAIT_OBJECT_0 && status!=WAIT_ABANDONED) {
                ready.set_value(status==WAIT_TIMEOUT ? ERROR_LOCK_VIOLATION : GetLastError()); return;
            }
            ready.set_value(ERROR_SUCCESS);
            WaitForSingleObject(release_.get(),INFINITE); ReleaseMutex(mutex.get());
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
    Chain store,left,right;
    std::vector<std::unique_ptr<Lease>> leases;
    Handle volume_flush;
    SyncSessionFaults faults;
    const SyncDigest& left_identity() const noexcept override { return left.back().object.id; }
    const SyncDigest& right_identity() const noexcept override { return right.back().object.id; }
    std::intptr_t root_handle(bool r) const noexcept override {
        return reinterpret_cast<std::intptr_t>((r?right:left).back().handle.get());
    }
    Observation<bool> revalidate() override {
        for(const auto* c:{&store,&left,&right}) { auto r=validate(*c); if(!r.value()) return r; }
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
        auto id=identity(f.value()->get(),false); if(!id.value()) return propagate<bool>(id);
        r=private_security(f.value()->get()); if(!r.value()) return r;
        std::size_t at=0;
        while(at<bytes.size()) {
            r=before(SyncSessionIo::Write); if(!r.value()) return r;
            DWORD wrote=0;
            if(!WriteFile(f.value()->get(),bytes.data()+at,static_cast<DWORD>(std::min(bytes.size()-at,faults.max_write_bytes)),&wrote,nullptr))
                return fail<bool>(GetLastError(),"sync_session.WriteFile");
            if(!wrote) return fail<bool>(ERROR_WRITE_FAULT,"sync_session.zero_write"); at+=wrote;
        }
        r=before(SyncSessionIo::FileFlush); if(!r.value()) return r;
        if(!FlushFileBuffers(f.value()->get())) return fail<bool>(GetLastError(),"sync_session.file_flush");
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
        if(FlushFileBuffers(store.back().handle.get())) return Observation<bool>::available(true);
        // Windows providers commonly refuse directory flush. A held native
        // volume flush is stronger, but normally requires administrator access.
        if(volume_flush && FlushFileBuffers(volume_flush.get())) return Observation<bool>::available(true);
        return reject<bool>("sync_session.parent_durability_unavailable",ObservationState::Unsupported);
    }
};
}
Observation<std::unique_ptr<SyncSessionBackend>> open_native_sync_session_backend(
    const NativeAbsolutePath& coordinator,const NativeAbsolutePath& left,const NativeAbsolutePath& right,SyncSessionFaults faults) {
    using P=std::unique_ptr<SyncSessionBackend>;
    if(!faults.max_write_bytes || faults.max_write_bytes>1024*1024)
        return reject<P>("sync_session.write_limit",ObservationState::Failed);
    auto s=chain(coordinator,true); if(!s.value()) return propagate<P>(s);
    auto l=chain(left,false); if(!l.value()) return propagate<P>(l);
    auto r=chain(right,false); if(!r.value()) return propagate<P>(r);
    auto b=std::make_unique<WindowsBackend>(); b->store=std::move(s).take_value();
    b->left=std::move(l).take_value(); b->right=std::move(r).take_value(); b->faults=std::move(faults);
    if(contains(b->left,b->right_identity()) || contains(b->right,b->left_identity()) ||
        contains(b->store,b->left_identity()) || contains(b->store,b->right_identity()))
        return reject<P>("sync_session.overlapping_pair_or_store",ObservationState::Failed);
    std::vector<SyncDigest> volumes{b->left.back().object.volume,b->right.back().object.volume};
    std::sort(volumes.begin(),volumes.end()); volumes.erase(std::unique(volumes.begin(),volumes.end()),volumes.end());
    for(const auto& v:volumes) {
        auto lease=std::make_unique<Lease>(); auto acquired=lease->acquire(v);
        if(!acquired.value()) return propagate<P>(acquired); b->leases.push_back(std::move(lease));
    }
    auto check=b->revalidate(); if(!check.value()) return propagate<P>(check);
    // Probe parent durability without mutation. Never advertise an atomic-only
    // rename as a durable commit when the platform refuses the required flush.
    if(!FlushFileBuffers(b->store.back().handle.get())) {
        b->volume_flush.reset(CreateFileW(b->store.back().object.volume_path.c_str(),GENERIC_READ|GENERIC_WRITE,
            FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_WRITE_THROUGH,nullptr));
        if(b->volume_flush.get()==INVALID_HANDLE_VALUE) b->volume_flush.reset();
    }
    check=b->flush_directory(); if(!check.value()) return propagate<P>(check);
    return Observation<P>::available(std::move(b));
}
} // namespace ck::files
