// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Native base-source close regression. SDK and fixture require one coherent
// compiled-hook build; no system import or runtime memory patch is used.
#ifndef CK_FS_NATIVE_CLOSE_TEST_HOOKS
#error Rebuild the complete SDK and this fixture with matching compiled native-close hooks.
#endif
#include "platform/native_close_test_faults.hpp"
#include "native_operation_copy_job.hpp"
#include "native_filesystem.hpp"
#include "metadata_capture_job.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <windows.h>
#include "windows_test_runtime_self_report.hpp"
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
template<class T>T take(Observation<T> value){if(!value.value()){persistent_oom=false;throw std::runtime_error(value.unavailable_detail()->error.operation);}return std::move(value).take_value();}
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
struct NativeWatch {
 FILE_ID_INFO source_id{},stage_id{},journal_id{};HANDLE source=nullptr,stage=nullptr,journal_handle=nullptr;
 PreparedJournalRoot* root=nullptr;OperationJournal* journal=nullptr;
 unsigned source_reads=0,source_closes=0,stage_closes=0,journal_closes=0,metadata_finishes=0,oom_allocations=0;
 bool fault=false,oom=false,consumed=false,retried=false,reuse_guard_active=false,protocol=false,protocol_triggered=false;unsigned allocations_at_stage_close=0;OperationJournalState state_at_source_close=OperationJournalState::Planned;
 detail::PreparedJournalConsumerFailure root_at_first_allocation;unsigned borrow_destroyed=0,borrow_closed=0;
};
thread_local NativeWatch* native_watch=nullptr;
void observe_oom_allocation() noexcept {
 if(auto* w=native_watch){if(!w->oom_allocations++)detail::read_prepared_journal_consumer_failure(*w->root,w->root_at_first_allocation);}
}
void report_native_fatal() noexcept {
 if(auto* w=native_watch){detail::PreparedJournalConsumerFailure e;const bool error=detail::read_prepared_journal_consumer_failure(*w->root,e);
  std::fprintf(stderr,"native fatal: source_reads=%u source_closes=%u writer_closes=%u journal_closes=%u metadata_finishes=%u root_error=%d domain=%u code=%lld operation=%s\n",w->source_reads,w->source_closes,w->stage_closes,w->journal_closes,w->metadata_finishes,int(error),unsigned(e.domain),static_cast<long long>(e.code),e.operation.data());}
}
bool matches(HANDLE h,const FILE_ID_INFO& expected)noexcept {
 if(!expected.VolumeSerialNumber)return false;FILE_ID_INFO current{};
 return GetFileInformationByHandleEx(h,FileIdInfo,&current,sizeof(current))&&same_id(current,expected);
}
void before_file(void* h,detail::NativeTestIo op,std::uint32_t count,const char*)noexcept {
 auto* w=native_watch;if(!w)return;
 if(op==detail::NativeTestIo::Read&&count&&matches(h,w->source_id)){
  if(w->source&&w->source!=h){persistent_oom=false;std::fputs("multiple base source read handles\n",stderr);std::abort();}
  w->source=h;++w->source_reads;
 }
 if(op==detail::NativeTestIo::Write){if(matches(h,w->journal_id))w->journal_handle=h;else if(matches(h,w->stage_id))w->stage=h;}
}
void after_file(void* h,detail::NativeTestIo op,bool okay,std::uint32_t,const char*)noexcept {
 // Preserve the original failure point: after the exact real journal WriteFile
 // succeeded, before its subsequent native revalidation/diagnostic allocation.
 if(auto* w=native_watch;w&&op==detail::NativeTestIo::Write&&okay&&h==w->journal_handle&&w->protocol&&w->source_reads&&!w->protocol_triggered){w->protocol_triggered=true;persistent_oom=true;}
}
thread_local NativeWatch* closing_watch=nullptr;
thread_local void* closing_handle=nullptr;
thread_local bool closing_source=false,closing_stage=false,closing_journal=false;
void before_close(void* h,const char*,const char*)noexcept {
 auto* w=native_watch;closing_watch=w;closing_handle=h;closing_source=closing_stage=closing_journal=false;
 if(!w)return;
 if(w->reuse_guard_active&&h==w->source)w->retried=true;
 if(w->consumed&&h==w->source){DWORD flags=0;if(!GetHandleInformation(h,&flags)&&GetLastError()==ERROR_INVALID_HANDLE)w->retried=true;}
 closing_source=h==w->source&&matches(h,w->source_id);
 closing_stage=h==w->stage&&matches(h,w->stage_id);
 closing_journal=h==w->journal_handle&&matches(h,w->journal_id);
}
std::uint32_t after_close(void* h,const char*,bool okay,std::uint32_t)noexcept {
 auto* w=closing_watch;const bool source=closing_source,stage=closing_stage,journal=closing_journal;
 if(closing_handle!=h||w!=native_watch){persistent_oom=false;std::abort();}
 closing_watch=nullptr;closing_handle=nullptr;closing_source=closing_stage=closing_journal=false;
 if(w){if(stage){++w->stage_closes;w->allocations_at_stage_close=w->oom_allocations;}if(journal)++w->journal_closes;if(source){++w->source_closes;w->consumed=true;if(w->journal){const auto state=w->journal->state(0);if(state)w->state_at_source_close=*state;}
   if(okay&&w->fault){persistent_oom=w->oom;return ERROR_READ_FAULT;}
 }}return 0; // A real native failure is never replaced or suppressed.
}
struct CompiledObservers final {
 CompiledObservers(){
  if(detail::native_close_test_before.load()||detail::native_close_test_after.load()||detail::native_file_test_before.load()||detail::native_file_test_after.load())throw std::runtime_error("native observer already installed");
  detail::native_file_test_before.store(before_file);detail::native_file_test_after.store(after_file);
  detail::native_close_test_before.store(before_close);detail::native_close_test_after.store(after_close);
 }
 ~CompiledObservers(){persistent_oom=false;detail::native_close_test_after.store(nullptr);detail::native_close_test_before.store(nullptr);detail::native_file_test_after.store(nullptr);detail::native_file_test_before.store(nullptr);}
 CompiledObservers(const CompiledObservers&)=delete;CompiledObservers& operator=(const CompiledObservers&)=delete;
};
FILE_ID_INFO native_id(const ObjectIdentity& value){FILE_ID_INFO result{};std::memcpy(&result.VolumeSerialNumber,value.volume.bytes.data(),8);std::memcpy(result.FileId.Identifier,value.object.bytes.data(),16);return result;}
struct BorrowProbe final {
 OpenedEntry* source;NativeWatch* watch;
 ~BorrowProbe(){try {const auto read=source->read_content({1});const auto basic=source->inspect_basic();if(!read.value()&&!basic.value())++watch->borrow_closed;}catch(...){}++watch->borrow_destroyed;}
};
unsigned process_handles(){DWORD n=0;CHECK(GetProcessHandleCount(GetCurrentProcess(),&n));return n;}
struct NativeFixture {
 static inline unsigned sequence=0;OwnedTree tree;std::wstring path;NativeFileSystem fs;std::shared_ptr<const DirectoryCursor> parent;PreparedJournalRoot::Pointer root;
 explicit NativeFixture(const std::wstring& base):tree(base+L"\\native-copy-source-close-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(++sequence)),path(tree.path){
  for(auto c:{L'a',L'b'}){path+=L"\\"+std::wstring(110,c);mkdir_private(path);}CHECK(path.size()>260);
  parent=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(path)));
  PreparedJournalRootRequest r;r.parent=parent;r.child=name(u"journal");r.disposition=JournalRootDisposition::ProvisionChild;JournalRootPreparationProgress progress;root=take(prepare_native_journal_root(std::move(r),progress));
 }
};
void native_case(const std::wstring& base,FileOperation operation,bool cancelled,bool fault,bool oom,bool protocol=false,bool prior_root=false) {
 NativeFixture f(base);const auto source_name=name(u"source-"+std::u16string(1,char16_t(0xd800))+u". ");const auto dest_name=name(u"published-"+std::u16string(1,char16_t(0xd801))+u". ");
 std::array<std::byte,8193> bytes{};bytes.fill(std::byte{0x53});
 {auto writer=take(f.parent->create_child_file(source_name));CHECK(take(writer->write_content(0,bytes))==bytes.size());CHECK(take(writer->finish_content_writes()));}
 auto held=take(HeldChild::observe(f.parent,source_name));const auto source_identity=*held->metadata().identity.value();held.reset();
 const auto handles_before=process_handles();NativeWatch watch;watch.root=f.root.get();watch.source_id=native_id(source_identity);watch.fault=fault;watch.oom=oom;watch.protocol=protocol;
 native_watch=&watch;
 struct WatchReset{~WatchReset(){persistent_oom=false;native_watch=nullptr;}} reset;
 auto file=std::shared_ptr<OperationJournalFile>(take(f.root->open_journal(name(u"base.journal"),true)));
 {auto h=open(f.path+L"\\journal\\base.journal",FILE_READ_ATTRIBUTES);watch.journal_id=id(h.value);h.close();}
 OperationJournalId identifier{};identifier.bytes[0]=std::byte{84};auto journal=take(OperationJournal::create(operation,identifier));watch.journal=journal.get();CHECK(take(append_operation_journal_file(*file,*journal,{1,0,OperationJournalState::Planned,{}})));
 const auto parent_identity=*f.parent->identity().value();
 NativeOperationCopyRequest r{.journal=journal,.journal_file=file,.item=0,.source_parent=f.parent,.source_parent_identity=parent_identity,.source_name=source_name,.source_identity=source_identity,.destination=f.parent,.destination_identity=parent_identity,.destination_address=take(NativeAbsolutePath::from_host(f.path)),.staging_name=name(u"private-stage"),.destination_name=dest_name};
 r.operation=operation;r.copy_limits.chunk_bytes=257;
 r.prepare_stream=[&](OpenedEntry& source,OpenedEntry& target,StreamCopyLimits limits){watch.stage_id=native_id(*take(target.inspect_basic()).identity.value());auto probe=std::make_shared<BorrowProbe>();probe->source=&source;probe->watch=&watch;
  StreamCopyRequest stream;stream.limits=limits;stream.read_source=[&source,probe](std::uint64_t offset,std::size_t count,std::stop_token stop){return source.read_content({count},offset,stop);};stream.write_destination=[&target,probe](std::uint64_t offset,std::span<const std::byte> bytes,std::stop_token stop){return target.write_content(offset,bytes,{},stop);};stream.read_destination=[&target,probe](std::uint64_t offset,std::size_t count,std::stop_token stop){return target.read_content({count},offset,stop);};stream.flush_destination=[&target,probe](std::stop_token){return target.flush_content();};return StreamCopyJob::create(std::move(stream));};
 r.prepare_metadata=[](OpenedEntry&,std::stop_token){OperationMetadataRequest metadata;metadata.apply_traversal_metadata=metadata.apply_security_metadata=metadata.apply_final_times=metadata.flush_destination=[](std::stop_token){return Observation<bool>::available(true);};return OperationMetadataJob::create(std::move(metadata));};
 r.finish_metadata=[&]{++watch.metadata_finishes;if(prior_root)detail::record_prepared_journal_consumer_failure(*f.root,ObservationState::Failed,ErrorDomain::Win32,ERROR_CRC,"test.prior_root");return Observation<bool>::available(true);};
 auto job=take(NativeOperationCopyJob::create(std::move(r)));file.reset();std::stop_source stop;unsigned advances=0;
 {CHECK(detail::current_metadata_capture_cleanup()==nullptr);
  for(;advances<4096&&job->state()<OperationExecutionState::Complete;++advances){if(cancelled&&watch.source_reads)stop.request_stop();job->advance(stop.get_token());}
 }
 const bool oom_active=persistent_oom.exchange(false);if(watch.oom_allocations)std::printf("FIRST_DENIED nativeDomain=%u nativeCode=%lld pending=%d operation=%s sourceClose=%u\n",unsigned(watch.root_at_first_allocation.domain),static_cast<long long>(watch.root_at_first_allocation.code),int(watch.root_at_first_allocation.pending),watch.root_at_first_allocation.operation.data(),watch.source_closes);detail::PreparedJournalConsumerFailure observed_root;const bool root_error=detail::read_prepared_journal_consumer_failure(*f.root,observed_root);
 std::printf("OBSERVE terminal=%u sourceRead=%u sourceClose=%u writerClose=%u journalClose=%u metadataFinish=%u deniedAlloc=%u RootPOD=%d nativeCode=%lld pending=%d RootRefs=%ld\n",unsigned(job->state()),watch.source_reads,watch.source_closes,watch.stage_closes,watch.journal_closes,watch.metadata_finishes,watch.oom_allocations,int(root_error),static_cast<long long>(observed_root.code),int(observed_root.pending),long(f.root.use_count()));std::fflush(stdout);CHECK(advances<4096);
 if(operation==FileOperation::Move&&!watch.source_reads){CHECK(job->state()==OperationExecutionState::Failed&&job->result().failure&&job->result().failure->state==ObservationState::Unsupported);CHECK(watch.source_closes==0&&watch.stage_closes==0&&watch.journal_closes==1&&watch.metadata_finishes==1);CHECK(take(f.parent->lookup_child(source_name,ChildLookupMode::NativeDefault)).state()==ChildLookupState::Found);CHECK(take(f.parent->lookup_child(dest_name,ChildLookupMode::NativeDefault)).state()==ChildLookupState::Missing);job.reset();file.reset();native_watch=nullptr;CHECK(take(f.root->finish_io()));std::puts("PASS Windows native MoveSource typed Unsupported before effects; no fabricated stability authority");return;}
CHECK(watch.source&&watch.source_reads>0&&watch.source_closes==1&&!watch.retried&&watch.journal_closes==1&&watch.metadata_finishes==1);
 CHECK(!oom||oom_active);CHECK(watch.stage_closes==1);CHECK(f.root.use_count()>1);
 if(fault){CHECK(job->state()==OperationExecutionState::NeedsReconciliation);detail::PreparedJournalConsumerFailure e;CHECK(detail::read_prepared_journal_consumer_failure(*f.root,e)&&e.domain==ErrorDomain::Win32&&e.code==(prior_root?ERROR_CRC:ERROR_READ_FAULT)&&std::string_view(e.operation.data())==(prior_root?"test.prior_root":"metadata_capture.source_CloseHandle"));CHECK(detail::current_metadata_capture_cleanup()==nullptr);
  if(oom&&!protocol)CHECK(watch.oom_allocations>0&&!watch.root_at_first_allocation.pending&&watch.root_at_first_allocation.domain==ErrorDomain::Win32&&watch.root_at_first_allocation.code==(prior_root?ERROR_CRC:ERROR_READ_FAULT)&&std::string_view(watch.root_at_first_allocation.operation.data())==(prior_root?"test.prior_root":"metadata_capture.source_CloseHandle"));
 }else CHECK(job->state()==(cancelled?OperationExecutionState::Cancelled:OperationExecutionState::Complete));
 if(!cancelled&&!protocol){CHECK(watch.state_at_source_close==OperationJournalState::Complete);auto output=take(f.parent->open_child(dest_name,EntryAccess::ContentRead));const auto content=take(output->read_content({16384}));CHECK(content.complete&&std::equal(bytes.begin(),bytes.end(),content.bytes.begin(),content.bytes.end()));
  const auto source=take(f.parent->lookup_child(source_name,ChildLookupMode::NativeDefault));CHECK(source.state()==(operation==FileOperation::Move?ChildLookupState::Missing:ChildLookupState::Found));
 }else {CHECK(take(f.parent->lookup_child(dest_name,ChildLookupMode::NativeDefault)).state()==ChildLookupState::Missing);CHECK(take(f.parent->lookup_child(source_name,ChildLookupMode::NativeDefault)).state()==ChildLookupState::Found);}
 if(protocol){CHECK(watch.protocol_triggered&&watch.allocations_at_stage_close==1);CHECK(watch.state_at_source_close!=OperationJournalState::SourceRemovalIntended&&watch.state_at_source_close!=OperationJournalState::SourceRetired&&watch.state_at_source_close!=OperationJournalState::Complete);}
 std::array<HANDLE,4096> reuse_handles{};unsigned reuse_count=0;bool reused=false;
 for(;reuse_count<reuse_handles.size();){auto h=CreateEventW(nullptr,TRUE,FALSE,nullptr);CHECK(h);reuse_handles[reuse_count++]=h;if(h==watch.source){reused=true;break;}}CHECK(reused);watch.reuse_guard_active=true;
 const auto terminal=job->state();const auto closes=watch.source_closes,reads=watch.source_reads;
 for(unsigned i=0;i<3;++i)CHECK(job->advance()==terminal);CHECK(watch.source_closes==closes&&watch.source_reads==reads&&!watch.retried);
 job.reset();file.reset();CHECK(watch.source_closes==closes&&!watch.retried&&watch.borrow_destroyed==1&&watch.borrow_closed==1);DWORD reuse_flags=0;CHECK(GetHandleInformation(watch.source,&reuse_flags));CHECK(SetEvent(watch.source)&&WaitForSingleObject(watch.source,0)==WAIT_OBJECT_0&&ResetEvent(watch.source)&&WaitForSingleObject(watch.source,0)==WAIT_TIMEOUT);watch.reuse_guard_active=false;for(unsigned i=0;i<reuse_count;++i)CHECK(CloseHandle(reuse_handles[i]));CHECK(process_handles()==handles_before&&f.root.use_count()==1);native_watch=nullptr;
 auto finished=f.root->finish_io();if(fault)CHECK(!finished.value()&&finished.unavailable_detail()->error.code==(prior_root?ERROR_CRC:ERROR_READ_FAULT));else CHECK(take(std::move(finished)));
 std::printf("PASS native BASE source handle op=%u cancel=%d fault=%d persistentOOM=%d protocolOOM=%d priorRootPOD=%d sourceClose=1 journalClose=1 metadataFinish=1 no-retry\n",unsigned(operation),int(cancelled),int(fault),int(oom),int(protocol),int(prior_root));
}
void upstream_oom(bool protocol) {
 OperationJournalId id{};id.bytes[0]=std::byte{83};auto journal=take(OperationJournal::create(FileOperation::Copy,id));CHECK(journal->append({1,0,OperationJournalState::Planned,{}}).value());
 OperationCopyRequest copy;copy.journal=journal;
 copy.revalidate_source=copy.revalidate_destination=[](std::stop_token){return Observation<bool>::available(true);};
 copy.prepare_copy=[](std::stop_token){return Observation<StreamCopyJob::Pointer>::unavailable(ObservationState::Unknown);};
 copy.prepare_metadata=[](std::stop_token){return Observation<OperationMetadataJob::Pointer>::unavailable(ObservationState::Unknown);};
 copy.verify_copy=[](std::stop_token){return Observation<bool>::available(true);};
 copy.append_journal=[journal,protocol](OperationJournalRecord r){if(protocol){persistent_oom=true;throw std::bad_alloc();}return journal->append(std::move(r));};
 OperationExecutionRequest request;request.copy=take(OperationCopyJob::create(std::move(copy)));
 request.prepare_commit=[](std::stop_token){return Observation<OperationCommitJob::Pointer>::unavailable(ObservationState::Unknown);};
 request.finish_io=[protocol]{++finalizers;if(!protocol){persistent_oom=true;throw std::bad_alloc();}return Observation<bool>::available(true);};
 auto job=take(OperationExecutionJob::create(std::move(request)));std::stop_source stop;stop.request_stop();
 std::fprintf(stderr,"ENTER upstream persistent OOM mode=%s\n",protocol?"protocol":"finalizer");
 const auto state=job->advance(stop.get_token());persistent_oom=false;
 CHECK(state==OperationExecutionState::NeedsReconciliation&&finalizers==1);
 for(unsigned i=0;i<3;++i)CHECK(job->advance(stop.get_token())==state);CHECK(finalizers==1);
 std::printf("PASS persistent upstream OOM mode=%s finalizer exactly once\n",protocol?"protocol":"finalizer");
}
}
int wmain(int argc,wchar_t** argv){if(!ckfs_test::report_runtime_self("native-copy"))return 1;std::set_terminate(fatal);try{CompiledObservers observers;
 CHECK(argc>=2);
 if(std::wstring_view(argv[1])==L"--upstream-finalizer-oom")upstream_oom(false);
 else if(std::wstring_view(argv[1])==L"--upstream-protocol-oom")upstream_oom(true);
 else {std::wstring selected;if(std::wstring_view(argv[1])==L"--case"){CHECK(argc>=4);selected=argv[2];argc-=2;argv+=2;}const auto base=test_base(options(argc,argv));
  if(selected==L"close-oom")native_case(base,FileOperation::Copy,false,true,true);
  else if(selected==L"cancel-oom")native_case(base,FileOperation::Copy,true,true,true);
  else if(selected==L"close-fault")native_case(base,FileOperation::Copy,false,true,false);
  else {CHECK(selected.empty());for(auto operation:{FileOperation::Copy}){native_case(base,operation,false,false,false);native_case(base,operation,true,false,false);native_case(base,operation,false,true,false);native_case(base,operation,true,true,false);native_case(base,operation,false,true,true);native_case(base,operation,true,true,true);native_case(base,operation,false,true,true,true);native_case(base,operation,false,true,false,false,true);native_case(base,operation,false,true,true,false,true);native_case(base,operation,true,true,false,false,true);native_case(base,operation,true,true,true,false,true);}native_case(base,FileOperation::Move,false,false,false);}CHECK(!OwnedTree::cleanup_failed);
 }return 0;
 }catch(const std::exception& e){persistent_oom=false;std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
