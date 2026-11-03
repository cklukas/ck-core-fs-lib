// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Real three-item native legacy batch drainage and persistent-OOM regression.
// Executable-local failure-only seams always forward the actual native I/O.
#include "native_operation_copy_job.hpp"
#include "native_filesystem.hpp"
#include "metadata_capture_job.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <windows.h>

#include <dbghelp.h>
#include <atomic>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <new>
#include <process.h>
#include <stdexcept>
#include "windows_name.hpp"
#include <sddl.h>
#include <aclapi.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <map>
#include <string_view>
#include <utility>
#include <vector>
namespace { std::atomic<bool> persistent_oom=false; unsigned finalizers=0; void observe_oom_allocation() noexcept; void report_native_fatal() noexcept; }
void* operator new(std::size_t size) {if(persistent_oom.load()){observe_oom_allocation();throw std::bad_alloc();}if(auto* p=std::malloc(size?size:1))return p;throw std::bad_alloc();}
void* operator new[](std::size_t size){return ::operator new(size);}
void operator delete(void* p)noexcept{std::free(p);}void operator delete[](void* p)noexcept{std::free(p);}
void operator delete(void* p,std::size_t)noexcept{std::free(p);}void operator delete[](void* p,std::size_t)noexcept{std::free(p);}
using namespace ck::files;
namespace {
#define CHECK(x) do{if(!(x)){persistent_oom=false;throw std::runtime_error(#x);}}while(false)
template<class T>T take(Observation<T> value){if(!value.value()){persistent_oom=false;const auto&e=*value.unavailable_detail();throw std::runtime_error(e.error.operation+":"+std::to_string(e.error.code)+":domain="+std::to_string(unsigned(e.error.domain)));}return std::move(value).take_value();}
[[noreturn]] void fatal()noexcept {
 const bool oom=persistent_oom.exchange(false);std::fprintf(stderr,"FATAL std::terminate persistent_oom=%d finalizers=%u\n",int(oom),finalizers);report_native_fatal();
 SymSetOptions(SYMOPT_LOAD_LINES|SYMOPT_UNDNAME|SYMOPT_DEFERRED_LOADS|SYMOPT_FAIL_CRITICAL_ERRORS);
 const HANDLE process=GetCurrentProcess();
 if(SymInitializeW(process,nullptr,TRUE)) {void* frames[64]{};const auto n=CaptureStackBackTrace(0,64,frames,nullptr);
  for(USHORT i=0;i<n;++i){alignas(SYMBOL_INFOW) std::byte buf[sizeof(SYMBOL_INFOW)+1024*sizeof(wchar_t)]{};auto* sym=reinterpret_cast<SYMBOL_INFOW*>(buf);sym->SizeOfStruct=sizeof(*sym);sym->MaxNameLen=1024;DWORD64 offset=0;const auto pc=DWORD64(reinterpret_cast<std::uintptr_t>(frames[i]));IMAGEHLP_LINEW64 line{};line.SizeOfStruct=sizeof(line);DWORD d=0;const bool named=SymFromAddrW(process,pc,&offset,sym),located=SymGetLineFromAddrW64(process,pc,&d,&line);std::fprintf(stderr,"#%u 0x%llx %ls %ls:%lu\n",unsigned(i),pc,named?sym->Name:L"?",located?line.FileName:L"?",located?line.LineNumber:0);}
  SymCleanup(process);
 }
 std::fflush(stderr);_exit(3);
}
void wincheck(bool ok,const char* call){if(!ok)throw std::runtime_error(std::string(call)+" Win32="+std::to_string(GetLastError()));}
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE h) : value(h) { wincheck(h && h != INVALID_HANDLE_VALUE, "open handle"); }
    Handle(const Handle&) = delete;
    void close() { wincheck(CloseHandle(std::exchange(value, INVALID_HANDLE_VALUE)), "CloseHandle"); }
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
Handle open(const std::wstring& p, DWORD access, DWORD disposition = OPEN_EXISTING, bool directory = false) {
    return Handle(CreateFileW(p.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, disposition, FILE_FLAG_OPEN_REPARSE_POINT |
                              (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), nullptr));
}
FILE_ID_INFO id(HANDLE h) {
    FILE_ID_INFO result{};
    wincheck(GetFileInformationByHandleEx(h, FileIdInfo, &result, sizeof(result)), "FileIdInfo");
    return result;
}
bool same_id(const FILE_ID_INFO& a, const FILE_ID_INFO& b) {
    return a.VolumeSerialNumber == b.VolumeSerialNumber &&
        !std::memcmp(a.FileId.Identifier, b.FileId.Identifier, sizeof(a.FileId.Identifier));
}
std::wstring guid_path(HANDLE h) {
    constexpr DWORD flags = FILE_NAME_OPENED | VOLUME_NAME_GUID;
    DWORD size = GetFinalPathNameByHandleW(h, nullptr, 0, flags);
    wincheck(size != 0, "final path size");
    std::wstring result(size, L'\0');
    DWORD count = GetFinalPathNameByHandleW(h, result.data(), size, flags);
    wincheck(count && count < size, "final path");
    result.resize(count);
    return result;
}
std::wstring fs_name(HANDLE directory) {
    wchar_t fs[32]{};
    wincheck(GetVolumeInformationByHandleW(directory, nullptr, 0, nullptr, nullptr, nullptr, fs, 32),
             "GetVolumeInformationByHandleW");
    return fs;
}
// Windows environment strings are read through the bounded wide API. A racing
// environment update cannot trigger an unbounded allocation or a truncated path.
std::optional<std::wstring> environment(const wchar_t* variable) {
    constexpr DWORD max_units = 32767;
    for (unsigned retry = 0; retry != 3; ++retry) {
        SetLastError(ERROR_SUCCESS);
        const DWORD size = GetEnvironmentVariableW(variable, nullptr, 0);
        if (!size) {
            const DWORD error = GetLastError();
            CHECK(error == ERROR_ENVVAR_NOT_FOUND || error == ERROR_SUCCESS);
            return std::nullopt;
        }
        CHECK(size <= max_units);
        std::wstring value(size, L'\0');
        const DWORD count = GetEnvironmentVariableW(variable, value.data(), size);
        if (!count) {
            const DWORD error = GetLastError();
            CHECK(error == ERROR_ENVVAR_NOT_FOUND || error == ERROR_SUCCESS);
            return std::nullopt;
        }
        if (count >= size) continue;
        value.resize(count);
        return value;
    }
    throw std::runtime_error("environment changed repeatedly");
}
std::size_t namespace_root(std::wstring_view path) {
    CHECK(path.starts_with(L"\\\\?\\"));
    if (path.starts_with(L"\\\\?\\UNC\\")) {
        const auto server = path.find(L'\\', 8);
        CHECK(server != path.npos && server > 8);
        const auto share = path.find(L'\\', server + 1);
        CHECK(share != path.npos && share > server + 1);
        for (auto component : {path.substr(8, server - 8), path.substr(server + 1, share - server - 1)})
            CHECK(component != L"." && component != L".." && component.find(L':') == component.npos);
        return share + 1;
    }
    if (path.starts_with(L"\\\\?\\Volume{")) {
        const auto end = path.find(L"}\\", 11);
        CHECK(end == 47); // Exact counted volume GUID namespace, not a device path.
        return end + 2;
    }
    CHECK(path.size() >= 7 && path[5] == L':' && path[6] == L'\\');
    CHECK((path[4] >= L'A' && path[4] <= L'Z') || (path[4] >= L'a' && path[4] <= L'z'));
    return 7;
}
bool ordinal_equal(std::wstring_view a, std::wstring_view b) {
    CHECK(a.size() <= 32767 && b.size() <= 32767);
    return CompareStringOrdinal(a.data(), int(a.size()), b.data(), int(b.size()), TRUE) == CSTR_EQUAL;
}
std::wstring task_path(std::wstring_view input, bool require_v) {
    auto extended = windows_extended_path(input);
    CHECK(extended);
    const auto root = namespace_root(*extended);
    while (extended->size() > root && extended->ends_with(L'\\')) extended->pop_back();
    CHECK(extended->size() > root); // TEMP must name a directory below its namespace root.
    for (size_t begin = root; begin < extended->size();) {
        const auto end = extended->find(L'\\', begin);
        const auto part = std::wstring_view(*extended).substr(begin, end == extended->npos ? end : end - begin);
        CHECK(!part.empty() && part != L"." && part != L".." && part.find(L':') == part.npos);
        if (end == extended->npos) break;
        begin = end + 1;
    }
    if (require_v) {
        constexpr std::wstring_view prefix = L"\\\\?\\V:\\tmp\\";
        CHECK(extended->size() > prefix.size() && ordinal_equal(std::wstring_view(*extended).substr(0, prefix.size()), prefix));
    }
    return *extended;
}
void plain_directory(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO tag{};
    wincheck(GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)), "directory tag");
    CHECK((tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
}
// Inspect every original ancestor without following its final reparse point.
// Permit only a real volume mount, map it to its native volume GUID, and compare
// native identities on both spellings. No arbitrary junction/symlink is admitted.
// Subsequent local fixture I/O uses the checked GUID spelling; an actual UNC
// share retains its extended UNC namespace. This is test setup, never replay authority.
std::wstring checked_directory(const std::wstring& path) {
    const auto root = namespace_root(path);
    auto source_root = open(path.substr(0, root), FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
    plain_directory(source_root.value);
    auto mapped = path.starts_with(L"\\\\?\\UNC\\") ? path.substr(0, root) : guid_path(source_root.value);
    CHECK(namespace_root(mapped) == mapped.size());
    bool crossed_mount = false;
    for (size_t begin = root; begin < path.size();) {
        auto end = path.find(L'\\', begin);
        if (end == path.npos) end = path.size();
        const auto original = path.substr(0, end);
        auto h = open(original, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
        FILE_ATTRIBUTE_TAG_INFO tag{};
        wincheck(GetFileInformationByHandleEx(h.value, FileAttributeTagInfo, &tag, sizeof(tag)), "ancestor tag");
        CHECK(tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        if (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            CHECK(!crossed_mount && tag.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT);
            wchar_t volume[64]{};
            wincheck(GetVolumeNameForVolumeMountPointW((original + L"\\").c_str(), volume, 64), "real volume mount");
            mapped = volume;
            CHECK(mapped.starts_with(L"\\\\?\\Volume{") && namespace_root(mapped) == mapped.size());
            auto actual = Handle(CreateFileW(original.c_str(), FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, nullptr));
            auto volume_root = open(mapped, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
            plain_directory(volume_root.value);
            CHECK(same_id(id(actual.value), id(volume_root.value)));
            crossed_mount = true;
        } else {
            if (!mapped.ends_with(L'\\')) mapped += L'\\';
            mapped += path.substr(begin, end - begin);
            auto actual = open(mapped, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
            plain_directory(actual.value);
            CHECK(same_id(id(h.value), id(actual.value)));
        }
        begin = end + 1;
    }
    auto final = open(mapped, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
    plain_directory(final.value);
    return mapped;
}
struct FixtureOptions { std::wstring expected_fs; std::optional<std::wstring> root; };
FixtureOptions options(int argc, wchar_t** argv) {
    FixtureOptions result;
    for (int i = 1; i < argc; ++i) {
        const std::wstring_view key(argv[i]);
        CHECK(i + 1 < argc);
        if (key == L"--expect-filesystem") {
            CHECK(result.expected_fs.empty()); result.expected_fs = argv[++i];
            CHECK(result.expected_fs == L"NTFS" || result.expected_fs == L"ReFS");
        } else if (key == L"--fixture-root") {
            CHECK(!result.root); result.root = argv[++i];
        } else throw std::runtime_error("unknown fixture option");
    }
    CHECK(!result.expected_fs.empty());
    return result;
}
std::wstring test_base(const FixtureOptions& configuration) {
    const auto dev_policy = environment(L"CK_FS_REQUIRE_V_DEV_DRIVE");
    CHECK(!dev_policy || *dev_policy == L"0" || *dev_policy == L"1");
    const bool require_v = dev_policy && *dev_policy == L"1";
    const auto raw_temp = environment(L"TEMP");
    CHECK(raw_temp && !raw_temp->empty());
    const auto temp = task_path(*raw_temp, require_v);
    const auto mapped_temp = checked_directory(temp);
    auto held = open(mapped_temp, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
    if (require_v) {
        auto drive = open(L"\\\\?\\V:\\", FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
        CHECK(fs_name(drive.value) == L"NTFS" || fs_name(drive.value) == L"ReFS");
        for (const auto* variable : {L"TMP", L"TMPDIR"}) {
            const auto value = environment(variable); CHECK(value && !value->empty());
            auto h = open(checked_directory(task_path(*value, true)), FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
            CHECK(same_id(id(held.value), id(h.value)));
        }
    }
    auto base = mapped_temp;
    if (configuration.root) {
        const auto supplied = task_path(*configuration.root, require_v);
        CHECK(supplied.size() >= temp.size() && ordinal_equal(std::wstring_view(supplied).substr(0, temp.size()), temp));
        CHECK(supplied.size() == temp.size() || supplied[temp.size()] == L'\\');
        base = checked_directory(supplied);
    }
    auto directory = open(base, FILE_READ_ATTRIBUTES, OPEN_EXISTING, true);
    const auto actual_fs = fs_name(directory.value);
    CHECK(actual_fs == configuration.expected_fs);
    std::wcout << L"actual native metadata stream target filesystem=" << actual_fs
               << L" expected=" << configuration.expected_fs << L" workstation-V=" << require_v << L'\n';
    return base;
}

HANDLE effective_token(DWORD rights) {
    HANDLE h{};
    if (!OpenThreadToken(GetCurrentThread(), rights, TRUE, &h)) {
        if (GetLastError() != ERROR_NO_TOKEN || !OpenProcessToken(GetCurrentProcess(), rights, &h))
            return nullptr;
    }
    return h;
}

void mkdir_private(const std::wstring& path) {
    Handle token(effective_token(TOKEN_QUERY));
    DWORD bytes = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
    CHECK(bytes);
    std::vector<std::byte> user(bytes);
    wincheck(GetTokenInformation(token.value, TokenUser, user.data(), bytes, &bytes), "TokenUser");
    wchar_t* sid = nullptr;
    wincheck(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid), "user SID");
    const std::wstring sddl = L"O:" + std::wstring(sid) + L"D:P(A;OICI;FA;;;" + sid + L")(A;OICI;FA;;;SY)";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR sd{};
    wincheck(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr),
             "private SDDL");
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    BOOL created = CreateDirectoryW(path.c_str(), &sa);
    DWORD err = GetLastError();
    LocalFree(sd);
    SetLastError(err);
    wincheck(created, "create private directory");
}
struct Find {
    HANDLE h;
    ~Find() { if (h != INVALID_HANDLE_VALUE) FindClose(h); }
};
std::map<std::wstring, DWORD> entries(const std::wstring& dir) {
    WIN32_FIND_DATAW entry{};
    Find search{FindFirstFileW((dir + L"\\*").c_str(), &entry)};
    std::map<std::wstring, DWORD> result;
    if (search.h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) return result;
    wincheck(search.h != INVALID_HANDLE_VALUE, "FindFirstFileW");
    do {
        std::wstring name(entry.cFileName);
        if (name != L"." && name != L"..") result.emplace(std::move(name), entry.dwFileAttributes);
    } while (FindNextFileW(search.h, &entry));
    wincheck(GetLastError() == ERROR_NO_MORE_FILES, "FindNextFileW");
    return result;
}
void remove_tree(const std::wstring& dir) {
    for (const auto& [name, attr] : entries(dir)) {
        auto child = dir + L"\\" + name;
        if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            if (attr & FILE_ATTRIBUTE_REPARSE_POINT) wincheck(RemoveDirectoryW(child.c_str()), "remove reparse directory");
            else remove_tree(child);
        } else wincheck(DeleteFileW(child.c_str()), "delete fixture file");
    }
    wincheck(RemoveDirectoryW(dir.c_str()), "remove fixture directory");
}
// Only set after successful exclusive creation. Also cleans up partial fixture setup.
struct OwnedTree {
    std::wstring path;
    explicit OwnedTree(std::wstring p) : path(std::move(p)) { mkdir_private(path); }
    ~OwnedTree() {
        try { remove_tree(path); }
        catch (const std::exception& e) { std::wcerr << L"cleanup failed in " << path << L'\n'; std::cerr << e.what() << '\n'; cleanup_failed = true; }
    }
    static inline bool cleanup_failed = false;
};


NativeName name(std::u16string value){return *NativeName::from_windows(std::move(value));}
constexpr unsigned batch_items=3;
enum class BatchOwner {LegacySource,SourceChannel,BaseSource,Journal,JournalParent,Staging};
struct WatchedHandle {HANDLE handle=nullptr;FILE_ID_INFO identity{};BatchOwner kind=BatchOwner::LegacySource;unsigned item=0,closes=0;bool named_channel_read=false;};
struct BatchWatch {
 PreparedJournalRoot* root=nullptr;FILE_ID_INFO root_id{};
 std::array<FILE_ID_INFO,batch_items> source_ids{},journal_ids{},stage_ids{};std::array<std::array<std::byte,SECURITY_MAX_SID_SIZE>,batch_items> stage_owners{};std::array<DWORD,batch_items> stage_owner_bytes{},stage_owner_status{};
 std::array<HANDLE,batch_items> legacy_handles{};
 std::array<unsigned,batch_items> source_reads{},source_opens{};
 std::array<std::wstring,batch_items> journal_names{};
 std::array<LONGLONG,batch_items> journal_sizes{};
 std::array<WatchedHandle,512> handles{};unsigned handle_count=0,journal_count=0,current_item=0,journal_item=0;
 bool setup_read=false,capture_journal=false,active=false,armed=false,source_fault=false,journal_fault=false,oom=false,fault_consumed=false,reuse_guard=false,retried=false;
 unsigned io_calls=0,writes=0,denied=0,prepared_named_readers=0;
 detail::PreparedJournalConsumerFailure first_denied{};
 std::array<HANDLE,512> guarded{};unsigned guarded_count=0;const HANDLE* reserved_events=nullptr;unsigned reserved_event_count=0;
};
thread_local BatchWatch* batch_watch=nullptr;
using InfoFn=BOOL(WINAPI*)(HANDLE,FILE_INFO_BY_HANDLE_CLASS,LPVOID,DWORD);
InfoFn actual_info(){static auto f=std::bit_cast<InfoFn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"GetFileInformationByHandleEx"));return f;}
bool handle_id(HANDLE h,FILE_ID_INFO& out)noexcept{return actual_info()(h,FileIdInfo,&out,sizeof(out))!=0;}
FILE_ID_INFO batch_id(const ObjectIdentity& v){FILE_ID_INFO r{};std::memcpy(&r.VolumeSerialNumber,v.volume.bytes.data(),8);std::memcpy(r.FileId.Identifier,v.object.bytes.data(),16);return r;}
void batch_io()noexcept{if(batch_watch&&batch_watch->active)++batch_watch->io_calls;}
WatchedHandle* live_owner(HANDLE h)noexcept{if(!batch_watch)return nullptr;for(unsigned n=batch_watch->handle_count;n;--n){auto& o=batch_watch->handles[n-1];if(o.handle==h&&!o.closes)return &o;}return nullptr;}
void remember_handle(HANDLE h,const FILE_ID_INFO& id,BatchOwner kind,unsigned item)noexcept {
 auto* w=batch_watch;if(!w||live_owner(h))return;if(w->handle_count==w->handles.size()||item>=batch_items)std::abort();w->handles[w->handle_count++]={h,id,kind,item,0};
}
void observe_created_handle(HANDLE h,bool duplicated=false)noexcept{
 auto*w=batch_watch;if(!w||!h||h==INVALID_HANDLE_VALUE)return;FILE_ID_INFO identity{};FILE_ATTRIBUTE_TAG_INFO tag{};if(!handle_id(h,identity)||!actual_info()(h,FileAttributeTagInfo,&tag,sizeof(tag)))return;
 for(unsigned i=0;i<batch_items;++i)if(w->source_ids[i].VolumeSerialNumber&&same_id(identity,w->source_ids[i])){if(w->active)++w->source_opens[i];remember_handle(h,identity,w->active?BatchOwner::BaseSource:BatchOwner::SourceChannel,i);return;}
 if(w->capture_journal){if(tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY){if(duplicated&&same_id(identity,w->root_id))remember_handle(h,identity,BatchOwner::JournalParent,w->journal_item);}else{w->journal_ids[w->journal_item]=identity;remember_handle(h,identity,BatchOwner::Journal,w->journal_item);}return;}
 if(w->active&&!(tag.FileAttributes&FILE_ATTRIBUTE_DIRECTORY)){
  const auto i=w->current_item;remember_handle(h,identity,BatchOwner::Staging,i);bool known_journal=false;for(const auto& j:w->journal_ids)if(j.VolumeSerialNumber&&same_id(identity,j))known_journal=true;
  if(!known_journal&&!w->stage_owner_bytes[i]){PSID owner=nullptr;PSECURITY_DESCRIPTOR sd=nullptr;const DWORD status=GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,&owner,nullptr,nullptr,nullptr,&sd);w->stage_owner_status[i]=status;if(status==ERROR_SUCCESS&&owner&&IsValidSid(owner)){const auto bytes=GetLengthSid(owner);if(bytes<=w->stage_owners[i].size()&&CopySid(DWORD(w->stage_owners[i].size()),w->stage_owners[i].data(),owner)){w->stage_owner_bytes[i]=bytes;w->stage_ids[i]=identity;}}if(sd)LocalFree(sd);}
 }
}
void observe_oom_allocation()noexcept{if(auto*w=batch_watch){if(!w->denied++)detail::read_prepared_journal_consumer_failure(*w->root,w->first_denied);}}
void report_native_fatal()noexcept{if(auto*w=batch_watch){detail::PreparedJournalConsumerFailure e;const bool found=detail::read_prepared_journal_consumer_failure(*w->root,e);std::fprintf(stderr,"batch fatal handles=%u journals=%u io=%u writes=%u denied=%u RootError=%d domain=%u code=%lld operation=%s\n",w->handle_count,w->journal_count,w->io_calls,w->writes,w->denied,int(found),unsigned(e.domain),static_cast<long long>(e.code),e.operation.data());for(unsigned i=0;i<w->handle_count;++i){const auto&o=w->handles[i];std::fprintf(stderr,"owner%u kind=%u item=%u closes=%u\n",i,unsigned(o.kind),o.item,o.closes);}}}
BOOL WINAPI capture_read(HANDLE h,LPVOID data,DWORD size,LPDWORD count,LPOVERLAPPED ov){
 using Fn=BOOL(WINAPI*)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);static auto real=std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ReadFile"));batch_io();auto saved=GetLastError();auto*w=batch_watch;FILE_ID_INFO id{};
 if(w&&size&&handle_id(h,id))for(unsigned i=0;i<batch_items;++i)if(same_id(id,w->source_ids[i])){if(w->setup_read){w->legacy_handles[i]=h;remember_handle(h,id,BatchOwner::LegacySource,i);}else if(w->active){++w->source_reads[i];remember_handle(h,id,BatchOwner::BaseSource,i);}else {remember_handle(h,id,BatchOwner::SourceChannel,i);if(auto* owner=live_owner(h);owner&&h!=w->legacy_handles[i]&&owner->kind==BatchOwner::SourceChannel)owner->named_channel_read=true;}}
 SetLastError(saved);return real(h,data,size,count,ov);
}
BOOL WINAPI capture_write(HANDLE h,LPCVOID data,DWORD size,LPDWORD count,LPOVERLAPPED ov){using Fn=BOOL(WINAPI*)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);static auto real=std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"WriteFile"));batch_io();if(batch_watch&&batch_watch->active)++batch_watch->writes;return real(h,data,size,count,ov);}
BOOL WINAPI capture_close(HANDLE h){
 using Fn=BOOL(WINAPI*)(HANDLE);static auto real=std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CloseHandle"));batch_io();auto*w=batch_watch;auto saved=GetLastError();auto*o=live_owner(h);if(w&&!o)for(unsigned i=0;i<w->handle_count;++i)if(w->handles[i].handle==h&&w->handles[i].closes){DWORD flags=0;if(!GetHandleInformation(h,&flags)&&GetLastError()==ERROR_INVALID_HANDLE)w->retried=true;break;}
 if(w&&w->reuse_guard)for(unsigned i=0;i<w->reserved_event_count;++i)if(w->reserved_events[i]==h)w->retried=true;
 SetLastError(saved);const BOOL ok=real(h);const auto error=GetLastError();if(o){++o->closes;const bool selected=w->armed&&!w->fault_consumed&&o->item==0&&((w->source_fault&&o->kind==BatchOwner::LegacySource)||(w->journal_fault&&o->kind==BatchOwner::Journal));if(ok&&selected){w->fault_consumed=true;persistent_oom=w->oom;SetLastError(ERROR_READ_FAULT);return FALSE;}}
 SetLastError(error);return ok;
}
BOOL WINAPI capture_duplicate(HANDLE a,HANDLE b,HANDLE c,LPHANDLE out,DWORD access,BOOL inherit,DWORD flags){using Fn=BOOL(WINAPI*)(HANDLE,HANDLE,HANDLE,LPHANDLE,DWORD,BOOL,DWORD);static auto real=std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"DuplicateHandle"));batch_io();const auto ok=real(a,b,c,out,access,inherit,flags);const auto error=GetLastError();if(ok&&out)observe_created_handle(*out,true);SetLastError(error);return ok;}
using NativeCreateFileFn=LONG(NTAPI*)(PHANDLE,ACCESS_MASK,PVOID,PVOID,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
LONG NTAPI capture_nt_create(PHANDLE out,ACCESS_MASK access,PVOID attributes,PVOID io,PLARGE_INTEGER allocation,ULONG file_attributes,ULONG sharing,ULONG disposition,ULONG options,PVOID ea,ULONG ea_size){
 using Fn=NativeCreateFileFn;static auto real=std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtCreateFile"));batch_io();const auto status=real(out,access,attributes,io,allocation,file_attributes,sharing,disposition,options,ea,ea_size);const auto error=GetLastError();if(status>=0&&out)observe_created_handle(*out);SetLastError(error);return status;
}
HANDLE WINAPI capture_create(LPCWSTR path,DWORD access,DWORD sharing,LPSECURITY_ATTRIBUTES security,DWORD disposition,DWORD flags,HANDLE template_file){using Fn=decltype(&CreateFileW);static auto real=std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CreateFileW"));batch_io();const auto h=real(path,access,sharing,security,disposition,flags,template_file);const auto error=GetLastError();observe_created_handle(h);SetLastError(error);return h;}
HANDLE WINAPI capture_open_id(HANDLE volume,LPFILE_ID_DESCRIPTOR descriptor,DWORD access,DWORD sharing,LPSECURITY_ATTRIBUTES security,DWORD flags){using Fn=decltype(&OpenFileById);static auto real=std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"OpenFileById"));batch_io();const auto h=real(volume,descriptor,access,sharing,security,flags);const auto error=GetLastError();observe_created_handle(h);SetLastError(error);return h;}
BOOL WINAPI capture_info(HANDLE h,FILE_INFO_BY_HANDLE_CLASS kind,LPVOID data,DWORD size){batch_io();return actual_info()(h,kind,data,size);}
BOOL WINAPI capture_flush(HANDLE h){using Fn=decltype(&FlushFileBuffers);static auto real=std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"FlushFileBuffers"));batch_io();return real(h);}
BOOL WINAPI capture_set_info(HANDLE h,FILE_INFO_BY_HANDLE_CLASS kind,LPVOID data,DWORD size){using Fn=decltype(&SetFileInformationByHandle);static auto real=std::bit_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"SetFileInformationByHandle"));batch_io();return real(h,kind,data,size);}
struct BatchFixture {
 OwnedTree tree;std::wstring path;NativeFileSystem fs;std::shared_ptr<const DirectoryCursor> parent,source,target;PreparedJournalRoot::Pointer root;
 std::array<NativeName,batch_items> inputs{name(u"src0"),name(u"src1"),name(u"src2")},outputs{name(u"dst0"),name(u"dst1"),name(u"dst2")};
 std::array<std::byte,8193> bytes{};std::array<std::array<std::byte,7>,batch_items> ads{};std::array<LONGLONG,batch_items> write_times{};
 explicit BatchFixture(const std::wstring& base):tree(base+L"\\native-legacy-batch-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())),path(tree.path){
  for(auto c:{L'a',L'b'}){path+=L"\\"+std::wstring(110,c);mkdir_private(path);}CHECK(path.size()>260);parent=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(path)));source=std::shared_ptr<const DirectoryCursor>(take(parent->create_child_directory(name(u"sources"))));target=std::shared_ptr<const DirectoryCursor>(take(parent->create_child_directory(name(u"targets"))));PreparedJournalRootRequest r;r.parent=parent;r.child=name(u"journal");r.disposition=JournalRootDisposition::ProvisionChild;JournalRootPreparationProgress progress;root=take(prepare_native_journal_root(std::move(r),progress));bytes.fill(std::byte{0x63});
  for(unsigned i=0;i<batch_items;++i){inputs[i]=name(u"source-"+std::u16string(1,char16_t(u'0'+i))+u"-"+std::u16string(1,char16_t(0xd800+i))+u". ");outputs[i]=name(u"result-"+std::u16string(1,char16_t(u'0'+i))+u"-"+std::u16string(1,char16_t(0xd810+i))+u". ");auto writer=take(source->create_child_file(inputs[i]));CHECK(take(writer->write_content(0,bytes))==bytes.size());CHECK(take(writer->finish_content_writes()));writer.reset();ads[i].fill(std::byte(0x31+i));auto p=source_path(i)+L":batch-stream";auto stream=open(p,GENERIC_WRITE,CREATE_NEW);DWORD n=0;CHECK(WriteFile(stream.value,ads[i].data(),DWORD(ads[i].size()),&n,nullptr)&&n==ads[i].size()&&FlushFileBuffers(stream.value));stream.close();auto file=open(source_path(i),FILE_WRITE_ATTRIBUTES);FILETIME time{0x12340000u+unsigned(i),0x01d6f14fu};CHECK(SetFileTime(file.value,nullptr,&time,&time));file.close();auto observed=open(source_path(i),FILE_READ_ATTRIBUTES);FILE_BASIC_INFO basic{};CHECK(GetFileInformationByHandleEx(observed.value,FileBasicInfo,&basic,sizeof(basic)));write_times[i]=basic.LastWriteTime.QuadPart;observed.close();}
 }
 std::wstring source_path(unsigned i)const{return path+L"\\sources\\"+std::wstring(inputs[i].windows_units()->begin(),inputs[i].windows_units()->end());}
 std::wstring output_path(unsigned i)const{return path+L"\\targets\\"+std::wstring(outputs[i].windows_units()->begin(),outputs[i].windows_units()->end());}
 void verify_payload(unsigned i,bool destination){auto file=open(destination?output_path(i):source_path(i),GENERIC_READ);if(destination){FILE_BASIC_INFO basic{};CHECK(GetFileInformationByHandleEx(file.value,FileBasicInfo,&basic,sizeof(basic))&&basic.LastWriteTime.QuadPart==write_times[i]);auto*w=batch_watch;CHECK(w&&w->stage_owner_bytes[i]);FILE_ID_INFO current{};CHECK(handle_id(file.value,current)&&same_id(current,w->stage_ids[i]));PSID owner=nullptr;PSECURITY_DESCRIPTOR sd=nullptr;const DWORD status=GetSecurityInfo(file.value,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,&owner,nullptr,nullptr,nullptr,&sd);const bool same_owner=status==ERROR_SUCCESS&&owner&&EqualSid(owner,w->stage_owners[i].data());if(sd)LocalFree(sd);CHECK(same_owner);}std::array<std::byte,8193> got{};DWORD n=0;CHECK(ReadFile(file.value,got.data(),DWORD(got.size()),&n,nullptr)&&n==got.size()&&got==bytes);file.close();auto stream=open((destination?output_path(i):source_path(i))+L":batch-stream",GENERIC_READ);std::array<std::byte,7> value{};CHECK(ReadFile(stream.value,value.data(),DWORD(value.size()),&n,nullptr)&&n==value.size()&&value==ads[i]);stream.close();}
};
OperationBatchJob::Pointer create_batch(BatchFixture& f,BatchWatch& w){
 NativeOperationCopyBatchRequest request;std::vector<HeldChild::Pointer> aliases;
 for(unsigned i=0;i<batch_items;++i){auto source=take(HeldChild::observe_with_access(f.source,f.inputs[i],EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity));w.source_ids[i]=batch_id(*source->metadata().identity.value());w.setup_read=true;const auto read=take(source->read_content({1}));w.setup_read=false;CHECK(read.bytes.size()==1&&w.legacy_handles[i]);aliases.push_back(source);request.sources.push_back(std::move(source));request.destination_names.push_back(f.outputs[i]);}
 request.destination=f.target;request.destination_address=take(NativeAbsolutePath::from_host(f.path+L"\\targets"));request.journal_root=take(NativeAbsolutePath::from_host(f.path+L"\\journal"));request.journal_id.bytes[0]=std::byte{91};request.policy.copy_limits.chunk_bytes=257;MetadataReplayPolicy policy;policy.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;policy.ownership=MetadataOwnership::CurrentCaller;request.policy.metadata_scope=policy.scope;request.policy.metadata_policy=policy;request.policy.allow_unhandled_metadata_loss=false;
 request.open_journal=[&](const NativeAbsolutePath&,const NativeName& leaf,bool fresh){CHECK(fresh&&w.journal_count<batch_items&&leaf.windows_units());const auto i=w.journal_count++;w.journal_item=i;w.journal_names[i]=std::wstring(leaf.windows_units()->begin(),leaf.windows_units()->end());w.capture_journal=true;auto file=f.root->open_journal(leaf,fresh);w.capture_journal=false;return file;};
 auto job=take(create_native_operation_copy_batch(std::move(request)));request.sources.clear();aliases.clear();CHECK(w.journal_count==batch_items);
 for(unsigned i=0;i<batch_items;++i){unsigned journals=0,parents=0;for(unsigned j=0;j<w.handle_count;++j){auto& owner=w.handles[j];if(owner.item!=i)continue;if(owner.kind==BatchOwner::Journal){CHECK(GetFileSizeEx(owner.handle,reinterpret_cast<PLARGE_INTEGER>(&w.journal_sizes[i]))&&w.journal_sizes[i]>0);++journals;}if(owner.kind==BatchOwner::JournalParent&&!owner.closes)++parents;}unsigned named=0;for(unsigned j=0;j<w.handle_count;++j){const auto&o=w.handles[j];if(o.item==i&&o.named_channel_read&&!o.closes)++named;}CHECK(journals==1&&parents==1&&live_owner(w.legacy_handles[i])&&named>=1);w.prepared_named_readers+=named;}
 w.source_reads={};w.source_opens={};w.io_calls=w.writes=0;return job;
}
bool batch_terminal(OperationBatchState s){return s!=OperationBatchState::Ready&&s!=OperationBatchState::Running;}
void run_batch(const std::wstring& base,std::wstring_view mode){
 const bool complete=mode==L"complete";const bool started=mode==L"started-cancel"||mode==L"started-cancel-source-error-oom";const bool uncertain=mode==L"uncertain-first-source-error";const bool prior=mode.find(L"prior-root")!=mode.npos;const bool source_error=mode.find(L"source-error")!=mode.npos;const bool journal_error=mode.find(L"journal-error")!=mode.npos;const bool oom=mode.find(L"oom")!=mode.npos;
 BatchFixture f(base);BatchWatch w;w.root=f.root.get();w.root_id=batch_id(f.root->identity());batch_watch=&w;struct Reset{~Reset(){persistent_oom=false;batch_watch=nullptr;}}reset;auto job=create_batch(f,w);w.source_fault=source_error;w.journal_fault=journal_error;w.oom=oom;w.armed=true;if(prior)CHECK(detail::record_prepared_journal_consumer_failure(*f.root,ObservationState::Failed,ErrorDomain::Win32,ERROR_CRC,"test.batch.prior_root"));const bool pending=!complete&&!started&&!uncertain;std::stop_source stop;if(pending)stop.request_stop();if(prior&&oom)persistent_oom=true;unsigned advances=0;
 for(;advances<20000&&!batch_terminal(job->state());++advances){if(started&&w.source_reads[0])stop.request_stop();CHECK(detail::current_metadata_capture_cleanup()==nullptr);w.current_item=unsigned(job->current_item());w.active=true;job->advance(stop.get_token());w.active=false;}CHECK(advances<20000);const auto terminal=job->state();const auto calls=w.io_calls,denied=w.denied;for(unsigned i=0;i<3;++i){w.active=true;CHECK(job->advance(stop.get_token())==terminal);w.active=false;}CHECK(w.io_calls==calls&&w.denied==denied);const bool was_oom=persistent_oom.exchange(false);CHECK(!oom||was_oom);const bool fault=source_error||journal_error||prior;
 detail::PreparedJournalConsumerFailure root_error;const bool has_error=detail::read_prepared_journal_consumer_failure(*f.root,root_error);std::printf("OBSERVE batch terminal=%u handles=%u prepared=%u reads=%u/%u/%u writes=%u denied=%u RootError=%d domain=%u code=%lld pending=%d operation=%s refs=%ld\n",unsigned(terminal),w.handle_count,w.journal_count,w.source_reads[0],w.source_reads[1],w.source_reads[2],w.writes,w.denied,int(has_error),unsigned(root_error.domain),static_cast<long long>(root_error.code),int(root_error.pending),root_error.operation.data(),long(f.root.use_count()));if(w.denied)std::printf("FIRST_DENIED domain=%u code=%lld pending=%d operation=%s\n",unsigned(w.first_denied.domain),static_cast<long long>(w.first_denied.code),int(w.first_denied.pending),w.first_denied.operation.data());std::fflush(stdout);
 std::array<unsigned,6> closes{};for(unsigned i=0;i<w.handle_count;++i){auto&o=w.handles[i];CHECK(o.closes==1);++closes[unsigned(o.kind)];}CHECK(closes[unsigned(BatchOwner::LegacySource)]==3&&closes[unsigned(BatchOwner::SourceChannel)]>=3&&closes[unsigned(BatchOwner::Journal)]==3&&closes[unsigned(BatchOwner::JournalParent)]>=3&&!w.retried);
 for(unsigned i=0;i<batch_items;++i)std::printf("ITEM%u outcome=%u failurePresent=%d\n",i,unsigned(job->result().items[i].outcome),int(bool(job->result().items[i].failure)));std::fflush(stdout);
 CHECK(terminal==(fault?OperationBatchState::NeedsReconciliation:complete?OperationBatchState::Complete:OperationBatchState::Cancelled));if(pending){CHECK((w.source_reads==std::array<unsigned,batch_items>{}&&w.source_opens==std::array<unsigned,batch_items>{}&&w.writes==0));}if(started||uncertain)CHECK(w.source_reads[0]&&w.source_reads[1]==0&&w.source_reads[2]==0&&w.source_opens[1]==0&&w.source_opens[2]==0);
 if(pending&&!fault)for(const auto& item:job->result().items)CHECK(item.outcome==OperationItemOutcome::Pending);if(started||uncertain)for(unsigned i=1;i<batch_items;++i){const auto outcome=job->result().items[i].outcome;CHECK(outcome==OperationItemOutcome::Pending||(fault&&outcome==OperationItemOutcome::NeedsReconciliation));}const auto expected=prior?ERROR_CRC:ERROR_READ_FAULT;if(fault){CHECK(has_error&&!root_error.pending&&root_error.domain==ErrorDomain::Win32&&root_error.code==expected&&std::string_view(root_error.operation.data())==(prior?"test.batch.prior_root":journal_error?"journal_file.CloseHandle":"metadata_capture.temporary_CloseHandle"));if(oom)CHECK(w.denied&&!w.first_denied.pending&&w.first_denied.domain==ErrorDomain::Win32&&w.first_denied.code==expected&&std::string_view(w.first_denied.operation.data())==std::string_view(root_error.operation.data()));}else CHECK(!has_error);

 w.armed=false;for(unsigned i=0;i<batch_items;++i){const bool published=complete||(uncertain&&i==0);CHECK(take(f.target->lookup_child(f.outputs[i],ChildLookupMode::NativeDefault)).state()==(published?ChildLookupState::Found:ChildLookupState::Missing));if(published)f.verify_payload(i,true);f.verify_payload(i,false);if(pending||(i>0&&(started||uncertain))){auto journal=open(f.path+L"\\journal\\"+w.journal_names[i],FILE_READ_ATTRIBUTES);LARGE_INTEGER size{};CHECK(same_id(id(journal.value),w.journal_ids[i])&&GetFileSizeEx(journal.value,&size)&&size.QuadPart==w.journal_sizes[i]);journal.close();}}
 // Reserve actual reused numeric slots using only newly created test-owned events.
 std::array<HANDLE,8192> events{};unsigned event_count=0;for(;event_count<events.size()&&w.guarded_count<batch_items;){auto event=CreateEventW(nullptr,TRUE,FALSE,nullptr);CHECK(event);events[event_count++]=event;for(unsigned i=0;i<batch_items;++i)if(w.legacy_handles[i]==event){w.guarded[w.guarded_count++]=event;break;}}CHECK(w.guarded_count==batch_items);w.reserved_events=events.data();w.reserved_event_count=event_count;w.reuse_guard=true;w.armed=true;for(unsigned i=0;i<3;++i)CHECK(job->advance()==terminal);job.reset();CHECK(!w.retried);for(unsigned i=0;i<w.guarded_count;++i)CHECK(SetEvent(w.guarded[i])&&WaitForSingleObject(w.guarded[i],0)==WAIT_OBJECT_0&&ResetEvent(w.guarded[i]));for(unsigned i=0;i<event_count;++i){DWORD flags=0;CHECK(GetHandleInformation(events[i],&flags));}w.reuse_guard=false;w.armed=false;for(unsigned i=0;i<event_count;++i)CHECK(CloseHandle(events[i]));CHECK(f.root.use_count()==1);auto finished=f.root->finish_io();if(fault)CHECK(!finished.value()&&finished.unavailable_detail()->error.code==expected);else CHECK(take(std::move(finished)));std::printf("PASS actual legacy NativeCopyBatch prepared3 mode=%.*ls legacyClose=%u channelClose=%u baseClose=%u journalClose=%u parentClose=%u stageClose=%u preparedNamedReaders=%u BEFOREterminal=1 noCallerAlias=1 repeatNoIO/noAlloc=1 noRetry=1 OrdinaryCurrentCaller=1 sourceADSallModes=1 targetADS/mtime/creationOwnerWhenPublished=1\n",int(mode.size()),mode.data(),closes[0],closes[1],closes[2],closes[3],closes[4],closes[5],w.prepared_named_readers);
}
}
extern "C" {
decltype(&ReadFile) __imp_ReadFile=&capture_read;
decltype(&WriteFile) __imp_WriteFile=&capture_write;
decltype(&CloseHandle) __imp_CloseHandle=&capture_close;
decltype(&DuplicateHandle) __imp_DuplicateHandle=&capture_duplicate;
LONG NTAPI NtCreateFile(PHANDLE out,ACCESS_MASK access,PVOID attributes,PVOID io,PLARGE_INTEGER allocation,ULONG file_attributes,ULONG sharing,ULONG disposition,ULONG options,PVOID ea,ULONG ea_size){return capture_nt_create(out,access,attributes,io,allocation,file_attributes,sharing,disposition,options,ea,ea_size);}
NativeCreateFileFn __imp_NtCreateFile=&capture_nt_create;
decltype(&CreateFileW) __imp_CreateFileW=&capture_create;
decltype(&OpenFileById) __imp_OpenFileById=&capture_open_id;
decltype(&GetFileInformationByHandleEx) __imp_GetFileInformationByHandleEx=&capture_info;
decltype(&FlushFileBuffers) __imp_FlushFileBuffers=&capture_flush;
decltype(&SetFileInformationByHandle) __imp_SetFileInformationByHandle=&capture_set_info;
}
int wmain(int argc,wchar_t** argv){std::set_terminate(fatal);try{CHECK(argc>=4&&std::wstring_view(argv[1])==L"--mode");const std::wstring mode=argv[2];argc-=2;argv+=2;const std::array<std::wstring_view,10> modes{L"cancel-before-start",L"cancel-source-error",L"cancel-source-error-oom",L"cancel-journal-error-oom",L"cancel-prior-root-oom",L"cancel-prior-root-source-error-oom",L"started-cancel",L"started-cancel-source-error-oom",L"uncertain-first-source-error",L"complete"};CHECK(std::find(modes.begin(),modes.end(),mode)!=modes.end());run_batch(test_base(options(argc,argv)),mode);CHECK(!OwnedTree::cleanup_failed);return 0;}catch(const std::exception&e){persistent_oom=false;std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
