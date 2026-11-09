// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "../src/files/reviewed_tree_plan.hpp"
#include "native_filesystem.hpp"
#include "private_journal_scope.hpp"
#include "platform/journal_root_test_faults.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "metadata_semantic_digest.hpp"
#include <atomic>
#include <new>
#include <cstring>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <sddl.h>
#include <bit>
#include <cstddef>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <dlfcn.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#endif
#ifdef __linux__
namespace tree_finish_fault {
thread_local bool anonymous_writer_flush=false;
thread_local unsigned hits=0;
}
// Interpose only in this test executable. Inject one failure on the actual
// anonymous staging object; all other flushes reach the real kernel syscall.
extern "C" int fsync(int fd) {
    const int saved=errno;struct stat value{};
    if(tree_finish_fault::anonymous_writer_flush&&::fstat(fd,&value)==0&&S_ISREG(value.st_mode)&&value.st_nlink==0) {
        tree_finish_fault::anonymous_writer_flush=false;++tree_finish_fault::hits;errno=EIO;return -1;
    }
    errno=saved;return static_cast<int>(::syscall(SYS_fsync,fd));
}
#endif
namespace tree_capture_test {
thread_local bool step=false,violation=false,arm_close=false,watch_close=false,oom_on_read=false,fail_alloc=false,oom_on_close=false,defer_debug_proxy=false;
thread_local std::size_t reads=0,total_reads=0,chunk=0,close_faults=0,closed_views=0,skip_closes=0;
thread_local std::stop_source* cancel=nullptr;
#ifdef _WIN32
FILE_ID_INFO target{};
BOOL WINAPI read(HANDLE h,LPVOID data,DWORD n,LPDWORD copied,LPOVERLAPPED io){
    using F=BOOL(WINAPI*)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
    static const auto real=std::bit_cast<F>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ReadFile"));
    if(step){++reads;++total_reads;violation=violation||n>chunk;}
    const auto result=real(h,data,n,copied,io);const auto e=GetLastError();
    if(step&&oom_on_read){oom_on_read=false;fail_alloc=true;defer_debug_proxy=true;}
    if(step&&cancel){auto* saved=cancel;cancel=nullptr;saved->request_stop();}SetLastError(e);return result;
}
BOOL WINAPI close(HANDLE h){using F=BOOL(WINAPI*)(HANDLE);static const auto real=std::bit_cast<F>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CloseHandle"));
    bool selected=false;if(step&&(arm_close||watch_close)&&total_reads){FILE_ID_INFO id{};selected=GetFileInformationByHandleEx(h,FileIdInfo,&id,sizeof(id))&&id.VolumeSerialNumber==target.VolumeSerialNumber&&!std::memcmp(&id.FileId,&target.FileId,sizeof(id.FileId));}
    const auto result=real(h);const auto e=GetLastError();if(selected&&result){++closed_views;if(arm_close){if(skip_closes)--skip_closes;else{arm_close=false;++close_faults;if(oom_on_close)fail_alloc=true;SetLastError(ERROR_READ_FAULT);return FALSE;}}}SetLastError(e);return result;
}
#else
dev_t device{};ino_t inode{};
ssize_t read(int fd,void* data,size_t n,off_t off){using F=ssize_t(*)(int,void*,size_t,off_t);static const auto real=reinterpret_cast<F>(dlsym(RTLD_NEXT,"pread"));
    if(step){++reads;++total_reads;violation=violation||n>chunk;}const auto result=real(fd,data,n,off);
    if(step&&oom_on_read){oom_on_read=false;fail_alloc=true;defer_debug_proxy=true;}
    if(step&&cancel){auto* saved=cancel;cancel=nullptr;saved->request_stop();}return result;
}
int close(int fd){using F=int(*)(int);static const auto real=reinterpret_cast<F>(dlsym(RTLD_NEXT,"close"));bool selected=false;
    if(step&&(arm_close||watch_close)&&total_reads){struct stat st{};selected=!fstat(fd,&st)&&st.st_dev==device&&st.st_ino==inode;}
    const auto result=real(fd);const auto e=errno;if(selected&&!result){++closed_views;if(arm_close){if(skip_closes)--skip_closes;else{arm_close=false;++close_faults;if(oom_on_close)fail_alloc=true;errno=EIO;return -1;}}}errno=e;return result;
}
#endif
}
void* operator new(std::size_t n){
    bool inject=tree_capture_test::fail_alloc;
#if defined(_MSC_VER) && defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL>0
    // MSVC Debug string's noexcept default constructor allocates a proxy;
    // failing that vendor allocation terminates rather than throwing to us.
    // This fixture targets the next throwing APPLICATION allocation instead.
    if(tree_capture_test::defer_debug_proxy&&n==sizeof(std::_Container_proxy))inject=false;
#endif
    if(inject){tree_capture_test::fail_alloc=false;tree_capture_test::defer_debug_proxy=false;throw std::bad_alloc();}
    if(auto* p=std::malloc(n?n:1))return p;throw std::bad_alloc();
}
void operator delete(void* p)noexcept{std::free(p);}
void* operator new[](std::size_t n){return ::operator new(n);}
void operator delete[](void* p)noexcept{std::free(p);}
#ifdef __cpp_sized_deallocation
void operator delete(void* p,std::size_t)noexcept{std::free(p);}
void operator delete[](void* p,std::size_t)noexcept{std::free(p);}
#endif
#ifdef _WIN32
extern "C" {decltype(&ReadFile) __imp_ReadFile=&tree_capture_test::read;decltype(&CloseHandle) __imp_CloseHandle=&tree_capture_test::close;}
#else
extern "C" ssize_t pread(int fd,void* data,size_t n,off_t off){return tree_capture_test::read(fd,data,n,off);}
extern "C" int close(int fd){return tree_capture_test::close(fd);}
#endif
using namespace ck::files;
namespace {
unsigned checks = 0;
void check(bool ok, const char* message, int line) {
    ++checks;
    if (!ok) throw std::runtime_error(std::string("line ") + std::to_string(line) + ": " + message);
}
#define CHECK(x) check(bool(x), #x, __LINE__)
template<class T> T take(Observation<T> o) {
    if (!o.value()) throw std::runtime_error(o.unavailable_detail()->error.operation + " state=" + std::to_string(int(o.state())));
    return std::move(o).take_value();
}
NativeName name(std::string s) {
#ifdef _WIN32
    return *NativeName::from_windows(std::u16string(s.begin(), s.end()));
#else
    return *NativeName::from_posix(std::move(s));
#endif
}
#ifdef _WIN32
std::wstring extended(const std::filesystem::path& p) {
    auto s = p.native();
    std::replace(s.begin(), s.end(), L'/', L'\\');
    if (s.starts_with(L"\\\\?\\")) return s;
    if (s.starts_with(L"\\\\")) return L"\\\\?\\UNC\\" + s.substr(2);
    CHECK(s.size() > 2 && s[1] == L':' && s[2] == L'\\');
    return L"\\\\?\\" + s;
}
// Test-address policy only; never filesystem identity or operation authority.
bool fixture_on_canonical_v_tmp(const std::filesystem::path& path) {
    const auto requested=extended(path);const auto count=GetFullPathNameW(requested.c_str(),0,nullptr,nullptr);
    CHECK(count>1&&count<=32768);std::wstring canonical(count,L'\0');
    const auto written=GetFullPathNameW(requested.c_str(),count,canonical.data(),nullptr);CHECK(written>0&&written<count);canonical.resize(written);
    std::replace(canonical.begin(),canonical.end(),L'/',L'\\');
    if(canonical.size()>4&&canonical[4]==L'v')canonical[4]=L'V';
    if(!canonical.starts_with(L"\\\\?\\V:\\tmp\\"))return false;
    std::wstring_view tail(canonical);tail.remove_prefix(11);
    while(!tail.empty()){auto slash=tail.find(L'\\');const auto part=tail.substr(0,slash);
        if(part==L"."||part==L"..")return false;if(slash==tail.npos)break;tail.remove_prefix(slash+1);}
    return true;
}
struct FixtureHandle {
    HANDLE value=INVALID_HANDLE_VALUE;
    ~FixtureHandle() {if(value!=INVALID_HANDLE_VALUE&&value!=nullptr&&!CloseHandle(value))std::abort();}
    void close() {const auto raw=value;value=INVALID_HANDLE_VALUE;CHECK(CloseHandle(raw));}
};
struct FixtureLocal {
    HLOCAL value=nullptr;
    ~FixtureLocal() {if(value&&LocalFree(value))std::abort();}
};
struct FixtureSecurity {
    FixtureLocal descriptor;
    FixtureSecurity() {
        FixtureHandle token;
        CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token.value));
        DWORD count=0;
        CHECK(!GetTokenInformation(token.value,TokenUser,nullptr,0,&count)&&
            GetLastError()==ERROR_INSUFFICIENT_BUFFER&&count>=sizeof(TOKEN_USER));
        std::vector<std::byte> storage(count);
        CHECK(GetTokenInformation(token.value,TokenUser,storage.data(),count,&count));
        const auto user=reinterpret_cast<TOKEN_USER*>(storage.data())->User.Sid;
        CHECK(IsValidSid(user));
        LPWSTR raw_sid=nullptr;CHECK(ConvertSidToStringSidW(user,&raw_sid));FixtureLocal sid{raw_sid};
        const std::wstring sddl=L"O:"+std::wstring(raw_sid)+L"D:P(A;;FA;;;"+raw_sid+L")(A;;FA;;;SY)";
        PSECURITY_DESCRIPTOR raw_descriptor=nullptr;
        CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&raw_descriptor,nullptr));
        descriptor.value=raw_descriptor;token.close();
    }
    SECURITY_ATTRIBUTES attributes() const {return {sizeof(SECURITY_ATTRIBUTES),descriptor.value,FALSE};}
};
void mkdir_new(const std::filesystem::path& p) {
    FixtureSecurity security;auto attributes=security.attributes();
    CHECK(CreateDirectoryW(extended(p).c_str(),&attributes));
}
void write_file(const std::filesystem::path& p, const std::string& data, bool replace = false) {
    // Parent privacy preparation removes inherited child ACEs. Protect the
    // fixture's exact objects so postconditions still reopen and verify them.
    FixtureSecurity security;auto attributes=security.attributes();
    FixtureHandle file{CreateFileW(extended(p).c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        &attributes,replace?TRUNCATE_EXISTING:CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};
    CHECK(file.value!=INVALID_HANDLE_VALUE);
    DWORD size=0;
    CHECK(WriteFile(file.value,data.data(),DWORD(data.size()),&size,nullptr)&&size==data.size());
    file.close();
}
void rename_exact(const std::filesystem::path& a, const std::filesystem::path& b) {
    struct Handle {
        HANDLE value;
        ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    };
    auto failed = [&](const char* phase, DWORD code, NTSTATUS status = 0) {
        std::fprintf(stderr,"fixture rename failed phase=%s code=%lu ntstatus=0x%08lx source=%ls destination=%ls\n",
            phase, static_cast<unsigned long>(code), static_cast<unsigned long>(status), a.c_str(), b.c_str());
        CHECK(false);
    };
    constexpr DWORD sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    constexpr DWORD flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    Handle source{CreateFileW(extended(a).c_str(), DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        sharing, nullptr, OPEN_EXISTING, flags, nullptr)};
    if (source.value == INVALID_HANDLE_VALUE) failed("open-source", GetLastError());
    Handle parent{CreateFileW(extended(b.parent_path()).c_str(), FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        sharing, nullptr, OPEN_EXISTING, flags, nullptr)};
    if (parent.value == INVALID_HANDLE_VALUE) failed("open-parent", GetLastError());
    FILE_ATTRIBUTE_TAG_INFO source_tag{}, parent_tag{};
    if (!GetFileInformationByHandleEx(source.value, FileAttributeTagInfo, &source_tag, sizeof(source_tag)) ||
        !GetFileInformationByHandleEx(parent.value, FileAttributeTagInfo, &parent_tag, sizeof(parent_tag)))
        failed("inspect-handles", GetLastError());
    CHECK(!(source_tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
    CHECK((parent_tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(parent_tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
    const auto leaf = b.filename().native();
    CHECK(!leaf.empty() && leaf != L"." && leaf != L".." && leaf.find_first_of(L"\\/:") == leaf.npos);
    CHECK(leaf.find(L'\0') == leaf.npos && leaf.size() <= 32767);
    struct Rename { BOOLEAN replace; HANDLE root; ULONG length; WCHAR name[1]; };
    std::vector<std::byte> buffer(sizeof(Rename) + leaf.size() * sizeof(wchar_t));
    auto* info = reinterpret_cast<Rename*>(buffer.data());
    info->replace = FALSE; info->root = parent.value;
    info->length = static_cast<ULONG>(leaf.size() * sizeof(wchar_t));
    std::copy(leaf.begin(), leaf.end(), info->name);
    using Set = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
    using Cancel = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PIO_STATUS_BLOCK);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto symbol = GetProcAddress(module, "NtSetInformationFile");
    const auto cancel = GetProcAddress(module, "NtCancelIoFileEx");
    CHECK(symbol && cancel);
    IO_STATUS_BLOCK io{};
    constexpr NTSTATUS pending = 0x00000103L;
    io.Status = pending;
    const auto exact_status = [&] {
        MemoryBarrier();
        return *reinterpret_cast<volatile NTSTATUS*>(&io.Status);
    };
    const auto drain = [&](ULONGLONG milliseconds) {
        const auto deadline = GetTickCount64() + milliseconds;
        while (exact_status() == pending) {
            const auto now = GetTickCount64();
            if (now >= deadline) return false;
            const auto waited = WaitForSingleObject(source.value, static_cast<DWORD>(std::min<ULONGLONG>(50, deadline - now)));
            if (waited == WAIT_FAILED) return false;
            if (waited == WAIT_OBJECT_0 && exact_status() == pending) Sleep(1);
        }
        return true;
    };
    auto status = std::bit_cast<Set>(symbol)(source.value, &io, info, static_cast<ULONG>(buffer.size()), 10);
    bool timed_out = false;
    if (status == pending) {
        timed_out = !drain(5000);
        if (timed_out) {
            IO_STATUS_BLOCK cancelled{};
            const auto cancellation = std::bit_cast<Cancel>(cancel)(source.value, &io, &cancelled);
            if (!drain(5000)) {
                std::fprintf(stderr, "fixture rename exact IOSB still pending after cancellation status=0x%08lx\n",
                    static_cast<unsigned long>(cancellation));
                std::abort(); // Never destroy a buffer still owned by native I/O.
            }
        }
        status = exact_status();
    }
    if (status < 0 || status == pending || timed_out)
        failed("NtSetInformationFile", timed_out ? ERROR_TIMEOUT : RtlNtStatusToDosError(status), status);
}
void cleanup(const std::filesystem::path& root) {
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW((extended(root) + L"\\*").c_str(), &data);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            std::wstring component(data.cFileName);
            if (component == L"." || component == L"..") continue;
            auto child = root / component;
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) cleanup(child);
            else if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryW(extended(child).c_str());
            else DeleteFileW(extended(child).c_str());
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
    RemoveDirectoryW(extended(root).c_str());
}
#else
void mkdir_new(const std::filesystem::path& p) { CHECK(::mkdir(p.c_str(), 0700) == 0); }
void write_file(const std::filesystem::path& p, const std::string& data, bool replace = false) {
    int fd = ::open(p.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW | (replace ? O_TRUNC : O_CREAT | O_EXCL), 0600);
    if (fd < 0) std::fprintf(stderr, "fixture open failed: %s errno=%d\n", p.c_str(), errno);
    CHECK(fd >= 0);
    CHECK(::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size()));
    CHECK(::close(fd) == 0);
}
void rename_exact(const std::filesystem::path& a, const std::filesystem::path& b) { CHECK(::rename(a.c_str(), b.c_str()) == 0); }
void cleanup(const std::filesystem::path& p) { std::filesystem::remove_all(p); }
#endif
struct Fixture {
    std::filesystem::path root;
    NativeFileSystem fs;
    std::shared_ptr<const DirectoryCursor> parent;
    static unsigned sequence;
    Fixture(bool long_path = false) {
#ifdef _WIN32
        const auto length=GetEnvironmentVariableW(L"TMPDIR",nullptr,0);CHECK(length>1&&length<65536);
        std::wstring temporary(length,L'\0');CHECK(GetEnvironmentVariableW(L"TMPDIR",temporary.data(),length)==length-1);temporary.resize(length-1);
        CHECK(GetEnvironmentVariableW(L"TEMP",nullptr,0)>1&&GetEnvironmentVariableW(L"TMP",nullptr,0)>1);
        root=std::filesystem::path(temporary);
        wchar_t require_v[2]{};
        if(GetEnvironmentVariableW(L"CK_FS_REQUIRE_V_DEV_DRIVE",require_v,2)==1&&require_v[0]==L'1'){
            CHECK(GetFileAttributesW(L"V:\\")!=INVALID_FILE_ATTRIBUTES);
            CHECK(fixture_on_canonical_v_tmp(root));
        }
        root /= L"reviewed-tree-tests-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(++sequence);
        mkdir_new(root);
#else
        const auto* tmp = std::getenv("TMPDIR"); CHECK(tmp && *tmp);
#ifdef __APPLE__
        CHECK(std::string(tmp).starts_with("/Volumes/S8T/tmp/") || std::string(tmp).starts_with("/Volumes/PRO-BLADE/tmp/"));
#endif
        std::string pattern = std::string(tmp) + "/reviewed-tree-tests.XXXXXX";
        CHECK(mkdtemp(pattern.data())); root = pattern;
#endif
        auto base = root;
        if (long_path) for (unsigned i = 0; i < 18; ++i) { base /= "long-component-0123456789"; mkdir_new(base); }
        parent = std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(base)));
        // Test paths and all Windows fixture I/O use extended native paths.
        work = base;
        mkdir_new(path("s")); mkdir_new(path("d")); mkdir_new(path("journals"));
        CHECK(take(prepare_native_operation_journal_root(take(NativeAbsolutePath::from_host(path("journals"))))));
    }
    ~Fixture() { parent.reset(); cleanup(root); }
    std::filesystem::path work;
    std::filesystem::path path(const char* p) const { return work / p; }
    ReviewedTreePlanRequest request(ComparisonProfile profile = ComparisonProfile::Copy) {
        ReviewedTreePlanRequest r;
        r.source_root = take(HeldChild::observe(parent, name("s")));
        r.destination_root = take(HeldChild::observe(parent, name("d")));
        r.destination_address = take(NativeAbsolutePath::from_host(path("d")));
        r.comparison.profile = profile; r.comparison.mode = ComparisonMode::CompleteDigest;
        r.copy_policy.allow_unhandled_metadata_loss = true;
        r.copy_policy.metadata_scope = RegularMetadataScope::OrdinaryCallerVisibleV1;
        r.journal_root = take(NativeAbsolutePath::from_host(path("journals")));
        r.open_journal = open_native_operation_journal_file;
        r.digest_chunk_bytes = 7;
        r.journal_id.bytes[0] = std::byte(static_cast<unsigned char>(++sequence));
        return r;
    }
    ReviewedTreePlanJob::Pointer job(ComparisonProfile p = ComparisonProfile::Copy) {
        return take(ReviewedTreePlanJob::create(request(p)));
    }
    bool exists(const char* p) const { return fs.inspect_basic(path(p)).value() != nullptr; }
    std::string read(const char* path_name) const {
        auto path = path_name;
        const bool incoming = path[0] == 's';
        auto dir = std::shared_ptr<const DirectoryCursor>(take(parent->open_directory_child(name(incoming ? "s" : "d"))));
        std::string relative(path + 2);
        for (;;) {
            auto pos = relative.find('/');
            if (pos == std::string::npos) break;
            dir = std::shared_ptr<const DirectoryCursor>(take(dir->open_directory_child(name(relative.substr(0, pos)))));
            relative.erase(0, pos + 1);
        }
        auto entry = take(dir->open_child(name(relative), EntryAccess::ContentRead));
        std::string result;
        for(;;) {
            auto data=take(entry->read_content({4096},result.size()));
            if(data.bytes.empty())return result;
            result.append(reinterpret_cast<const char*>(data.bytes.data()),data.bytes.size());
        }
    }
};
unsigned Fixture::sequence = 0;
bool active(ReviewedTreeState s) { return s == ReviewedTreeState::Inventory || s == ReviewedTreeState::Revalidating || s == ReviewedTreeState::Executing; }
void run(ReviewedTreePlanJob& job) {
    for (unsigned i = 0; i < 100000 && active(job.state()); ++i) job.advance();
    CHECK(!active(job.state()));
}
void preview(ReviewedTreePlanJob& job) {
    run(job);
    if (job.state() != ReviewedTreeState::AwaitingReview && job.progress().failure)
        std::fprintf(stderr, "preview: %s\n", job.progress().failure->error.operation.c_str());
    CHECK(job.state() == ReviewedTreeState::AwaitingReview);
    CHECK(job.preview()); CHECK(job.progress().counts_complete);
}
ConflictRule keep_rule(ReviewedTreePlanJob& job, ConflictScope scope = ConflictScope::MatchingClassInJob) {
    ConflictRule r;
    r.plan = job.preview()->identity(); r.choice = ConflictChoice::KeepTarget;
    r.kind = ConflictClass::ExistingRegular; r.scope = scope;
    return r;
}
void start(ReviewedTreePlanJob& job) { CHECK(take(job.begin_execution(take(job.review({}))))); }

void test_private_journal_scope(unsigned placement,bool typed) {
    Fixture f;
    write_file(f.path("s/a"),"incoming");write_file(f.path("d/extra"),"retained");
    std::filesystem::path protected_path=f.path("journals");
    if(placement==0||placement==1) {
        protected_path=f.path(placement==0?"s/.dtfile-operations":"d/.dtfile-operations");mkdir_new(protected_path);
    } else if(placement==2||placement==4)protected_path=f.path("s");
    else if(placement==3||placement==5)protected_path=f.path("d");
    if(placement==4){mkdir_new(f.path("s/scan"));write_file(f.path("s/scan/a"),"incoming");}
    if(placement==5)mkdir_new(f.path("d/scan"));
    const auto address=take(NativeAbsolutePath::from_host(protected_path));
    CHECK(take(prepare_native_operation_journal_root(address)));
    write_file(protected_path/"private-marker","state must never enter a copy or deletion plan");
    if(placement==6) {
        // Matching a protected basename is not evidence of protected identity.
        mkdir_new(f.path("s/.dtfile-operations"));write_file(f.path("s/.dtfile-operations/ordinary"),"ordinary source data");
    }
    auto request=f.request();request.journal_root=address;
    if(placement==4) {
        auto parent=std::shared_ptr<const DirectoryCursor>(take(f.parent->open_directory_child(name("s"))));
        request.source_root=take(HeldChild::observe(parent,name("scan")));
    }
    if(placement==5) {
        auto parent=std::shared_ptr<const DirectoryCursor>(take(f.parent->open_directory_child(name("d"))));
        request.destination_root=take(HeldChild::observe(parent,name("scan")));
    }
    PreparedJournalRoot::Pointer root;
    if(typed) {
        root=take(acquire_native_journal_root(address,{}));
        CHECK(compare_identity(root->identity(),*request.source_root->metadata().identity.value())==IdentityComparison::Unknown);
        request.prepared_journal_root=root;
        // Deliberately different hint: the actual retained owner controls scope.
        request.journal_root=take(NativeAbsolutePath::from_host(f.path("journals")));
    }
    auto job=take(ReviewedTreePlanJob::create(std::move(request)));run(*job);
    if(placement==6) {
        if(job->state()!=ReviewedTreeState::AwaitingReview&&job->progress().failure)
            std::fprintf(stderr,"scope placement=%u typed=%u state=%u error=%s domain=%u code=%lld\n",placement,unsigned(typed),unsigned(job->state()),
                job->progress().failure->error.operation.c_str(),unsigned(job->progress().failure->error.domain),static_cast<long long>(job->progress().failure->error.code));
        CHECK(job->state()==ReviewedTreeState::AwaitingReview&&job->preview());
        bool ordinary=false;for(const auto& item:take(job->page(0,16)).items)
            if(!item.relative_components.empty()&&item.relative_components.front()==name(".dtfile-operations"))ordinary=true;
        CHECK(ordinary);std::stop_source stop;stop.request_stop();job->advance(stop.get_token());
        CHECK(job->state()==ReviewedTreeState::Cancelled);
    } else {
        CHECK(job->state()==ReviewedTreeState::Failed&&!job->preview());
        CHECK(!job->progress().counts_complete&&job->progress().failure);
        CHECK(job->progress().failure->state==ObservationState::Unsupported);
    }
    CHECK(!f.exists("d/a")&&f.read("d/extra")=="retained");
    job.reset();if(root){CHECK(take(root->revalidate()));CHECK(take(root->finish_io()));root.reset();}
}
thread_local unsigned legacy_root_close_calls=0;
std::optional<std::int64_t> legacy_root_close_fault(detail::JournalRootFaultPoint point) {
    if(point==detail::JournalRootFaultPoint::DirectoryClose){++legacy_root_close_calls;return 5;}
    return std::nullopt;
}
void test_legacy_root_terminal_close_failure() {
    Fixture f;auto job=f.job();preview(*job);
    const auto prior=detail::journal_root_test_fault;
    struct RestoreFault {detail::JournalRootFault previous;~RestoreFault(){detail::journal_root_test_fault=previous;}} restore{prior};
    legacy_root_close_calls=0;detail::journal_root_test_fault=legacy_root_close_fault;
    start(*job);run(*job);
    CHECK(job->state()==ReviewedTreeState::NeedsReconciliation&&job->progress().recovery_required);
    CHECK(job->progress().failure&&job->progress().failure->error.code==5);
    CHECK(legacy_root_close_calls>0);
    const auto closed=legacy_root_close_calls;job.reset();CHECK(legacy_root_close_calls==closed);
}
#ifdef __linux__
void test_cancel_copy_writer_finish(bool typed) {
    Fixture f;const std::string payload(3*64*1024+17,'z');write_file(f.path("s/a"),payload);
    auto request=f.request();request.digest_chunk_bytes=64*1024;
    PreparedJournalRoot::Pointer root;
    if(typed) {
        root=take(acquire_native_journal_root(*request.journal_root));request.prepared_journal_root=root;
    }
    auto job=take(ReviewedTreePlanJob::create(std::move(request)));preview(*job);start(*job);
    for(unsigned n=0;n<10000&&active(job->state())&&!job->progress().copied_bytes;++n)job->advance();
    CHECK(active(job->state())&&job->progress().copied_bytes>0&&job->progress().copied_bytes<payload.size());
    tree_finish_fault::hits=0;tree_finish_fault::anonymous_writer_flush=true;
    struct Disarm {~Disarm(){tree_finish_fault::anonymous_writer_flush=false;}} disarm;
    std::stop_source stop;stop.request_stop();job->advance(stop.get_token());
    CHECK(tree_finish_fault::hits==1);
    CHECK(job->state()==ReviewedTreeState::NeedsReconciliation&&job->progress().recovery_required);
    CHECK(job->progress().failure&&job->progress().failure->error.domain==ErrorDomain::Posix&&job->progress().failure->error.code==EIO);
    CHECK(job->progress().failure->error.operation.starts_with("content."));
    CHECK(take(job->page(0,1)).items.front().state==ReviewedTreeItemState::NeedsReconciliation);
    job->advance(stop.get_token());CHECK(tree_finish_fault::hits==1);
    // A cached terminal plan does not retain the private Root's native users.
    if(root) {
        const auto finished=root->finish_io();
        CHECK(!finished.value()&&finished.unavailable_detail());
        const auto& failure=*finished.unavailable_detail();
        CHECK(failure.error.domain==ErrorDomain::Posix&&failure.error.code==EIO);
        CHECK(failure.error.operation.starts_with("content."));
        const auto repeated=root->finish_io();
        CHECK(!repeated.value()&&repeated.unavailable_detail());
        CHECK(repeated.unavailable_detail()->error.domain==failure.error.domain&&
              repeated.unavailable_detail()->error.code==failure.error.code&&
              repeated.unavailable_detail()->error.operation==failure.error.operation);
    }
    CHECK(!f.exists("d/a")&&f.read("s/a")==payload);
    job.reset();CHECK(tree_finish_fault::hits==1);
}
#endif
void test_copy(bool long_path = false) {
    Fixture f(long_path);
    mkdir_new(f.path("s/folder")); mkdir_new(f.path("s/folder/empty"));
    write_file(f.path("s/folder/data"), std::string(299, 'a'));
    write_file(f.path("s/zero"), "");
    auto job = f.job(); preview(*job);
    auto immutable = job->preview();
    CHECK(immutable->source_entries().size() == 4);
    CHECK(immutable->aggregate().source_bytes == 299);
    CHECK(!job->page(0, 0).value());
    CHECK(!job->page(0, ComparisonLimits::hard_max_page_rows + 1).value());
    CHECK(take(job->page(0, 1)).items.size() == 1);
    start(*job); run(*job);
    if (job->state() != ReviewedTreeState::Complete && job->progress().failure)
        std::fprintf(stderr, "copy: %s state=%d\n", job->progress().failure->error.operation.c_str(), int(job->state()));
    CHECK(job->state() == ReviewedTreeState::Complete);
    CHECK(job->preview() == immutable);
    CHECK(immutable->destination_entries().empty());
    CHECK(f.exists("d/folder/empty")); CHECK(f.read("d/folder/data") == std::string(299, 'a'));
    CHECK(f.read("d/zero").empty());
    auto progress = job->progress();
    CHECK(progress.known_copy_bytes == 299 && progress.copied_bytes == 299);
    CHECK(progress.completed_items == 4 && !progress.recovery_required);
    CHECK(!job->review({}).value()); // terminal review is rejected
}
void test_receipts_and_rules() {
    Fixture f;
    mkdir_new(f.path("s/folder")); mkdir_new(f.path("d/folder"));
    write_file(f.path("s/folder/a"), "source"); write_file(f.path("d/folder/a"), "target");
    write_file(f.path("s/b"), "source-b"); write_file(f.path("d/b"), "target-b");
    write_file(f.path("s/new"), "fresh");
    auto job = f.job(); preview(*job);
    CHECK(!job->review({}).value());
    auto rule = keep_rule(*job);
    auto receipt = take(job->review(std::span(&rule, 1)));
    const auto resolved = take(job->reviewed_page(receipt, 0, 32));
    for (const auto& item : resolved.items) {
        CHECK(!item.relative_components.empty());
        if (item.row.requires_review) CHECK(item.action == ReviewedTreeAction::Skip);
        auto binding = job->native_binding(item.row.token);
        CHECK(binding.value());
        CHECK(binding.value()->relative_components == item.relative_components);
    }
    // Mutating caller rules after review must not change the resolved receipt.
    rule.choice = ConflictChoice::UseSource;
    CHECK(take(job->begin_execution(receipt))); run(*job);
    CHECK(job->state() == ReviewedTreeState::Complete);
    CHECK(f.read("d/folder/a") == "target" && f.read("d/b") == "target-b" && f.read("d/new") == "fresh");
    CHECK(job->progress().skipped_items == 2);
    auto foreign = f.job(); preview(*foreign);
    CHECK(!foreign->begin_execution(receipt).value());
    CHECK(!foreign->review(std::span(&rule, 1)).value());
    auto selected = keep_rule(*foreign, ConflictScope::Selected);
    auto rows = take(foreign->page(0, 32)).items;
    for (const auto& item : rows) if (item.row.requires_review) selected.selected_rows.push_back(item.row.id);
    CHECK(foreign->review(std::span(&selected, 1)).value());
    auto bad_selected = selected; bad_selected.selected_rows = {999999};
    CHECK(!foreign->review(std::span(&bad_selected, 1)).value());
    auto bad_kind = keep_rule(*foreign); bad_kind.kind = static_cast<ConflictClass>(999);
    CHECK(!foreign->review(std::span(&bad_kind, 1)).value());
    auto narrow = keep_rule(*foreign, ConflictScope::Subtree);
    for (const auto& item : rows) if (item.row.relation == ComparisonRelation::DirectoryPair) narrow.subtree = item.row.relative_path;
    auto all = keep_rule(*foreign);
    std::vector<ConflictRule> rules{all, narrow};
    CHECK(foreign->review(rules).value());
}
void test_deletions_and_unsupported() {
    Fixture f;
    write_file(f.path("s/new"), "fresh"); write_file(f.path("d/extra"), "keep");
    auto mirror = f.job(ComparisonProfile::Mirror); preview(*mirror);
    CHECK(!mirror->review({}).value());
    CHECK(!mirror->review_deletions({}).value());
    std::vector<ComparisonDecisionToken> deletions;
    for (const auto& item : take(mirror->page(0, 32)).items) if (item.action == ReviewedTreeAction::RemoveFile) deletions.push_back(item.row.token);
    CHECK(deletions.size() == 1);
    auto deletion = take(mirror->review_deletions(deletions));
    auto receipt = take(mirror->review({}, deletion));
    auto begin = mirror->begin_execution(receipt);
#ifdef _WIN32
    CHECK(take(std::move(begin))); run(*mirror);
    CHECK(mirror->state() == ReviewedTreeState::Complete);
    CHECK(f.read("d/new") == "fresh" && !f.exists("d/extra"));
#else
    CHECK(begin.state() == ObservationState::Unsupported);
    CHECK(!f.exists("d/new") && f.read("d/extra") == "keep");
#endif
    auto foreign = f.job(ComparisonProfile::Mirror); preview(*foreign);
    CHECK(!foreign->review_deletions(deletions).value());
    CHECK(!foreign->review({}, deletion).value());
    deletions.push_back(deletions.front()); CHECK(!mirror->review_deletions(deletions).value());

    write_file(f.path("d/new"), "old", f.exists("d/new"));
    auto replace = f.job(ComparisonProfile::Sync); preview(*replace);
    auto reviewed = replace->review({});
    if (reviewed.value()) {
        auto replace_receipt = take(std::move(reviewed));
        auto replaced = replace->begin_execution(replace_receipt);
        CHECK(take(std::move(replaced))); run(*replace);
        CHECK(replace->state() == ReviewedTreeState::Complete && f.read("d/new") == "fresh");
        bool saw_retained = false;
        for (const auto& item : take(replace->page(0, 32)).items) if (item.action == ReviewedTreeAction::Replace) {
            CHECK(item.retained_name && item.retention_journal_id);
            auto d = take(f.parent->open_directory_child(name("d")));
            auto old = take(d->open_child(*item.retained_name, EntryAccess::ContentRead));
            auto bytes = take(old->read_content({1024}));
            CHECK(std::string(reinterpret_cast<const char*>(bytes.bytes.data()), bytes.bytes.size()) == "old");
            saw_retained = true;
        }
        CHECK(saw_retained);
    } else {
        CHECK(reviewed.state() == ObservationState::Unsupported);
        auto assessment = take(replace->assessment_page(0,32));
        bool retention_refused = false;
        for (const auto& item : assessment.items) if (item.action == ReviewedTreeAction::Replace) {
            CHECK(item.decision && item.decision->reason == ConflictRuleReason::RetentionUnavailable);
            CHECK(!item.facts.retained_target_available);
            CHECK(!(item.facts.allowed_choices & (std::uint64_t{1} << static_cast<unsigned>(ConflictChoice::KeepBothTarget))));
            retention_refused = true;
        }
        CHECK(retention_refused);
        CHECK(f.read("d/new") == "old");
    }

}
void test_changed_receipts() {
    for (unsigned variant = 0; variant < 6; ++variant) {
        std::fprintf(stderr, "changed receipts variant=%u\n", variant);
        Fixture f;
        bool empty_directory_swap = false;
        bool empty_root_swap = false;
#ifdef _WIN32
        // Windows cannot rename an ancestor of an open file. An empty folder
        // keeps this case focused on directory identity substitution.
        empty_directory_swap = variant == 4;
        empty_root_swap = variant == 5;
#endif
        if (!empty_root_swap) mkdir_new(f.path("s/folder"));
        if (!empty_directory_swap && !empty_root_swap) write_file(f.path("s/folder/a"), "original");
        auto job = f.job(); preview(*job); auto receipt = take(job->review({}));
        if (variant == 0) write_file(f.path("s/folder/a"), "modified", true);
        if (variant == 1) { rename_exact(f.path("s/folder/a"), f.path("s/old")); write_file(f.path("s/folder/a"), "original"); }
        if (variant == 2) write_file(f.path("d/foreign"), "target changed");
        if (variant == 3) { rename_exact(f.path("d"), f.path("old-d")); mkdir_new(f.path("d")); }
        if (variant == 4) {
            const auto before = take(f.fs.inspect_basic(f.path("s/folder"))).identity;
            rename_exact(f.path("s/folder"), f.path("s/old")); mkdir_new(f.path("s/folder"));
            if (!empty_directory_swap) write_file(f.path("s/folder/a"), "original");
            const auto after = take(f.fs.inspect_basic(f.path("s/folder"))).identity;
            CHECK(before.value() && after.value());
            CHECK(compare_identity(*before.value(), *after.value()) == IdentityComparison::Different);
        }
        if (variant == 5) {
            const auto before = take(f.fs.inspect_basic(f.path("s"))).identity;
            rename_exact(f.path("s"), f.path("old-s")); mkdir_new(f.path("s"));
            const auto after = take(f.fs.inspect_basic(f.path("s"))).identity;
            CHECK(before.value() && after.value());
            CHECK(compare_identity(*before.value(), *after.value()) == IdentityComparison::Different);
        }
        auto begun=job->begin_execution(receipt);
        if(variant==3||variant==5) {
            // A substituted scan root is now rejected at receipt admission,
            // before the revalidation scan or any mutation can start.
            CHECK(!begun.value()&&begun.state()==ObservationState::Changed);
            CHECK(begun.unavailable_detail()->error.domain==ErrorDomain::Adapter);
            CHECK(begun.unavailable_detail()->error.code==static_cast<std::int64_t>(AdapterError::PlanDecisionStale));
            CHECK(begun.unavailable_detail()->error.operation=="reviewed_tree.private_scan_membership_changed");
            CHECK(!job->progress().partial&&!job->progress().recovery_required);
            CHECK(!job->begin_execution(receipt).value());
        } else CHECK(take(std::move(begun)));
        run(*job);
        CHECK(job->state() == ReviewedTreeState::Failed);
        CHECK(job->progress().failure.has_value());
        CHECK(!f.exists("d/folder"));
    }
}
void test_overlap_collision_and_limits() {
    Fixture f;
    mkdir_new(f.path("s/inside"));
    auto r = f.request();
    auto s = std::shared_ptr<const DirectoryCursor>(take(f.parent->open_directory_child(name("s"))));
    r.destination_root = take(HeldChild::observe(s, name("inside")));
    auto overlap = take(ReviewedTreePlanJob::create(std::move(r))); run(*overlap);
    CHECK(overlap->state() == ReviewedTreeState::Failed);
    CHECK(overlap->progress().failure->error.code == static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe));
    auto same_root = f.request(); same_root.destination_root = same_root.source_root;
    CHECK(!ReviewedTreePlanJob::create(std::move(same_root)).value());
    write_file(f.path("s/Alpha"), "a"); write_file(f.path("d/alpha"), "b");
    const char* collision_phase = "reviewed_tree.cross_tree_case_collision";
#ifdef _WIN32
    // A native case alias is rejected during name lookup, before the portable
    // folded-key check. Qualify the fixture's actual directory semantics.
    auto destination = take(f.parent->open_directory_child(name("d")));
    const auto alias = take(destination->lookup_child(name("Alpha"), ChildLookupMode::NativeDefault));
    if (alias.state() == ChildLookupState::Found) {
        const auto aliased = take(alias.entry()->inspect_basic()).identity;
        const auto exact = take(f.fs.inspect_basic(f.path("d/alpha"))).identity;
        CHECK(aliased.value() && exact.value());
        CHECK(compare_identity(*aliased.value(), *exact.value()) == IdentityComparison::Same);
        collision_phase = "reviewed_tree.native_name_collision";
    } else CHECK(alias.state() == ChildLookupState::Missing);
#endif
    auto collision = f.job(); run(*collision);
    CHECK(collision->state() == ReviewedTreeState::Failed);
    CHECK(collision->progress().failure.has_value());
    const auto collision_failure = *collision->progress().failure;
    std::fprintf(stderr, "cross-tree collision expected=%s actual=%s state=%u domain=%u code=%lld\n",
        collision_phase, collision_failure.error.operation.c_str(), unsigned(collision_failure.state),
        unsigned(collision_failure.error.domain), static_cast<long long>(collision_failure.error.code));
    CHECK(collision_failure.error.operation == collision_phase);
    CHECK(collision_failure.error.domain == ErrorDomain::Adapter);
    CHECK(collision_failure.error.code == static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe));
    auto bad = f.request(); bad.digest_chunk_bytes = 0; CHECK(!ReviewedTreePlanJob::create(std::move(bad)).value());
    bad = f.request(); bad.comparison.profile = ComparisonProfile::Move;
    CHECK(ReviewedTreePlanJob::create(std::move(bad)).state() == ObservationState::Unsupported);
    bad = f.request(); bad.limits.max_entries = 1;
    auto limit = take(ReviewedTreePlanJob::create(std::move(bad))); run(*limit);
    CHECK(limit->state() == ReviewedTreeState::Failed);
}
void test_cancellation() {
    Fixture f;
    write_file(f.path("s/a"), "data");
    auto inventory = f.job(); std::stop_source cancel; cancel.request_stop();
    CHECK(inventory->advance(cancel.get_token()) == ReviewedTreeState::Cancelled);
    CHECK(!inventory->progress().counts_complete && !f.exists("d/a"));
    auto reviewed = f.job(); preview(*reviewed);
    CHECK(reviewed->advance(cancel.get_token()) == ReviewedTreeState::Cancelled);
    CHECK(!f.exists("d/a"));
    mkdir_new(f.path("s/folder"));
    auto execution = f.job(); preview(*execution); start(*execution);
    for (unsigned i = 0; i < 10000 && execution->progress().completed_items == 0 && active(execution->state()); ++i) execution->advance();
    if (!execution->progress().completed_items) {
        const auto progress = execution->progress();
        std::fprintf(stderr, "cancellation progress state=%u completed=%llu active=%u failure=%s domain=%u code=%lld\n",
            unsigned(execution->state()), static_cast<unsigned long long>(progress.completed_items),
            unsigned(active(execution->state())), progress.failure ? progress.failure->error.operation.c_str() : "none",
            progress.failure ? unsigned(progress.failure->error.domain) : 0,
            progress.failure ? static_cast<long long>(progress.failure->error.code) : 0);
    }
    CHECK(execution->progress().completed_items > 0);
    execution->advance(cancel.get_token());
    CHECK(execution->state() == ReviewedTreeState::Partial);
    CHECK(execution->progress().partial && execution->progress().recovery_required);
}
void test_changes_during_execution() {
    Fixture f;
    write_file(f.path("s/a"), std::string(333, 'x'));
    auto copy = f.job(); preview(*copy); start(*copy);
    for (unsigned i = 0; i < 10000 && active(copy->state()); ++i) {
        copy->advance();
        auto item = take(copy->page(0, 1)).items.front();
        if (item.journal_name) break;
    }
    CHECK(take(copy->page(0, 1)).items.front().journal_name.has_value());
    write_file(f.path("s/a"), std::string(333, 'y'), true);
    run(*copy);
    CHECK(copy->state() == ReviewedTreeState::NeedsReconciliation);
    CHECK(copy->progress().recovery_required && !f.exists("d/a"));
    CHECK(f.read("s/a") == std::string(333, 'y'));
    CHECK(take(copy->page(0, 1)).items.front().recovery_required);

    Fixture g;
    mkdir_new(g.path("s/folder")); write_file(g.path("s/folder/a"), "content");
    auto ancestor = g.job(); preview(*ancestor); start(*ancestor);
    for (unsigned i = 0; i < 10000 && ancestor->progress().completed_items == 0 && active(ancestor->state()); ++i) ancestor->advance();
    CHECK(ancestor->progress().completed_items == 1);
    rename_exact(g.path("d/folder"), g.path("d/old")); mkdir_new(g.path("d/folder"));
    run(*ancestor);
    CHECK(ancestor->state() == ReviewedTreeState::Partial);
    CHECK(!g.exists("d/folder/a"));
}
void test_parent_move_into_source() {
    Fixture f;
    mkdir_new(f.path("q")); mkdir_new(f.path("q/target"));
#ifdef _WIN32
    // Windows prevents moving an ancestor while its descendant is open.
    // Establish the real overlap before taking descendant handles; the
    // receipt variants separately exercise directory/root substitution.
    rename_exact(f.path("q"), f.path("s/q"));
    auto r = f.request();
    auto source = take(f.parent->open_directory_child(name("s")));
    auto q = std::shared_ptr<const DirectoryCursor>(take(source->open_directory_child(name("q"))));
    r.destination_root = take(HeldChild::observe(q, name("target")));
    r.destination_address = take(NativeAbsolutePath::from_host(f.path("s/q/target")));
    auto job = take(ReviewedTreePlanJob::create(std::move(r))); run(*job);
    std::fprintf(stderr, "Windows overlap fixture: ancestor moved before descendant handle acquisition\n");
#else
    auto r = f.request();
    auto q = std::shared_ptr<const DirectoryCursor>(take(f.parent->open_directory_child(name("q"))));
    r.destination_root = take(HeldChild::observe(q, name("target")));
    auto job = take(ReviewedTreePlanJob::create(std::move(r))); preview(*job);
    auto receipt = take(job->review({}));
    rename_exact(f.path("q"), f.path("s/q"));
    CHECK(take(job->begin_execution(receipt))); run(*job);
#endif
    CHECK(job->state() == ReviewedTreeState::Failed);
    CHECK(job->progress().failure->error.operation == "reviewed_tree.overlap");
}
void test_assessment_and_receipt_revocation() {
    Fixture f; write_file(f.path("s/a"), "incoming"); write_file(f.path("d/a"), "existing");
    auto job = f.job(); preview(*job);
    auto unresolved = take(job->assess_rules({}, 0, 1));
    CHECK(unresolved.items.front().decision.has_value());
    CHECK(unresolved.items.front().decision->state == ConflictRuleState::NeedsReview);
    CHECK(unresolved.items.front().decision->reason == ConflictRuleReason::NoMatchingRule);
    CHECK(!job->review({}).value());
    auto keep = keep_rule(*job);
    auto receipt = take(job->review(std::span(&keep, 1)));
    auto unchanged = take(job->assess_rules(std::span(&keep, 1), 0, 1));
    CHECK(unchanged.items.front().decision->rule_index == 0);
    CHECK(unchanged.items.front().action == ReviewedTreeAction::Skip);
    auto replace = keep; replace.choice = ConflictChoice::UseSource;
    auto changed = take(job->assess_rules(std::span(&replace, 1), 0, 1));
    CHECK(changed.items.front().action == ReviewedTreeAction::Replace);
    CHECK(job->begin_execution(receipt).state() == ObservationState::Changed);
    auto invalid_rule = keep; invalid_rule.kind = static_cast<ConflictClass>(999);
    auto invalid = take(job->assess_rules(std::span(&invalid_rule, 1), 0, 1));
    CHECK(invalid.items.front().decision->state == ConflictRuleState::Invalid);
    CHECK(invalid.items.front().decision->reason == ConflictRuleReason::InvalidRule);
    CHECK(f.read("d/a") == "existing");
    auto current = take(job->review(std::span(&keep, 1)));
    CHECK(take(job->begin_execution(current))); run(*job);
    CHECK(job->state() == ReviewedTreeState::Complete);
}
#ifndef _WIN32
void test_lossless_native_names() {
    std::vector<std::string> native_names{std::string("\xc3\xa9")};
#ifdef __linux__
    native_names.push_back(std::string("invalid-\xff"));
#endif
    for (const std::string& native : native_names) {
        Fixture f; auto source = std::filesystem::path("s") / native;
        write_file(f.work / source, "exact native payload");
        auto job = f.job(); preview(*job);
        const auto row = take(job->page(0, 1)).items.front();
        const auto components = take(job->native_components(row.row.id, true));
        CHECK(components.size() == 1 && *components.front().posix_bytes() == native);
        CHECK(job->native_components(row.row.id, false).state() == ObservationState::Gone);
        start(*job); run(*job);
        CHECK(job->state() == ReviewedTreeState::Complete);
        auto directory = std::shared_ptr<const DirectoryCursor>(take(f.parent->open_directory_child(name("d"))));
        auto held = take(directory->open_child(*NativeName::from_posix(native), EntryAccess::ContentRead));
        auto bytes = take(held->read_content({1024}));
        CHECK(std::string(reinterpret_cast<const char*>(bytes.bytes.data()), bytes.bytes.size()) == "exact native payload");
    }
    Fixture f; write_file(f.work / "s" / "\xc3\xa9", "one"); write_file(f.work / "s" / "\xce\xb2", "two");
    auto job = f.job(); preview(*job);
    auto receipt = take(job->review({}));
    const auto started = job->begin_execution(receipt);
    if (!started.value()) {
        CHECK(started.state() == ObservationState::Unsupported);
        auto target = take(f.parent->open_directory_child(name("d")));
        CHECK(target->read(1).state == DirectoryReadState::End);
    } else { run(*job); CHECK(job->state() == ReviewedTreeState::Complete); }
}
#endif
void test_retention_capabilities_and_incoming_copy() {
    Fixture f;
    write_file(f.path("s/a"), "incoming data"); write_file(f.path("d/a"), "existing data");
    auto job = f.job(); preview(*job);
    const auto token = take(job->page(0, 1)).items.front().row.token;
    auto rule = keep_rule(*job); rule.choice = ConflictChoice::UseSource;
    auto replace = take(job->assess_rules(std::span(&rule, 1), 0, 1));
    const auto& fact = replace.items.front().facts;
    const auto bit = [](ConflictChoice choice) { return std::uint64_t{1} << static_cast<unsigned>(choice); };
    CHECK(fact.source_kind == ObjectKind::RegularFile && fact.destination_kind == ObjectKind::RegularFile);
    CHECK(fact.conflict_class == ConflictClass::ExistingRegular);
    CHECK(fact.allowed_choices & bit(ConflictChoice::KeepBothIncoming));
    if (!fact.retained_target_available) {
        CHECK(!(fact.allowed_choices & bit(ConflictChoice::UseSource)));
        CHECK(!(fact.allowed_choices & bit(ConflictChoice::KeepBothTarget)));
        CHECK(replace.items.front().decision->state == ConflictRuleState::NeedsReview);
        CHECK(replace.items.front().decision->reason == ConflictRuleReason::RetentionUnavailable);
        rule.choice = ConflictChoice::KeepBothTarget;
        // Retention failure is visible even before the user supplies a name.
        auto missing_name = take(job->assess_rules(std::span(&rule, 1), 0, 1));
        CHECK(missing_name.items.front().decision->reason == ConflictRuleReason::RetentionUnavailable);
        ReviewedTreeNameChoice keep_old{token, name("old-version"), ReviewedTreeNameSide::Target};
        auto named = take(job->assess_rules(std::span(&rule, 1), std::span(&keep_old, 1), 0, 1));
        CHECK(named.items.front().decision->reason == ConflictRuleReason::RetentionUnavailable);
        CHECK(!job->review(std::span(&rule, 1), std::span(&keep_old, 1)).value());
    }
    // The assessment owns facts only. A temporary DELETE/data-write guard
    // must have been released before control returns to the frontend.
#ifdef _WIN32
    HANDLE mutable_target = CreateFileW(extended(f.path("d/a")).c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    CHECK(mutable_target != INVALID_HANDLE_VALUE);
    CHECK(CloseHandle(mutable_target));
#else
    int mutable_target = ::open(f.path("d/a").c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    CHECK(mutable_target >= 0); CHECK(::close(mutable_target) == 0);
#endif
    rule.choice = ConflictChoice::KeepBothIncoming;
    ReviewedTreeNameChoice incoming{token, name("incoming-copy"), ReviewedTreeNameSide::Incoming};
    auto assessed = take(job->assess_rules(std::span(&rule, 1), std::span(&incoming, 1), 0, 1));
    CHECK(assessed.items.front().decision->state == ConflictRuleState::Apply);
    CHECK(assessed.items.front().action == ReviewedTreeAction::Copy);
    CHECK(assessed.items.front().facts.allowed_choices & bit(ConflictChoice::KeepBothIncoming));
    auto receipt = take(job->review(std::span(&rule, 1), std::span(&incoming, 1)));
    CHECK(take(job->begin_execution(receipt))); run(*job);
    CHECK(job->state() == ReviewedTreeState::Complete);
    CHECK(f.read("d/a") == "existing data");
    CHECK(f.read("d/incoming-copy") == "incoming data");
    CHECK(take(job->page(0, 1)).items.front().resulting_name == name("incoming-copy"));
}
void test_compare_acknowledges_descriptive_choices() {
    Fixture f; write_file(f.path("s/a"), "incoming"); write_file(f.path("d/a"), "existing");
    write_file(f.path("s/new"), "new source"); write_file(f.path("d/other"), "target only");
    auto request = f.request(ComparisonProfile::Compare);
    request.copy_policy.allow_unhandled_metadata_loss = false;
    request.copy_policy.metadata_scope = RegularMetadataScope::CompleteMetadataV1;
    request.copy_policy.metadata_policy = MetadataReplayPolicy{};
    request.journal_root.reset(); request.open_journal = {};
    auto job = take(ReviewedTreePlanJob::create(std::move(request))); preview(*job);
    auto ask = keep_rule(*job); ask.choice = ConflictChoice::Ask;
    ask.protect_nonempty = true; ask.retain_replaced = true;
    auto assessed = take(job->assess_rules(std::span(&ask, 1), 0, 32));
    bool saw_ask = false;
    for (const auto& item : assessed.items) {
        CHECK(item.action == ReviewedTreeAction::Report && item.row.action == ComparisonAction::Report);
        CHECK(!item.facts.retained_target_available);
        if (item.facts.source_present && item.facts.destination_present) {
            CHECK(item.decision && item.decision->state == ConflictRuleState::NeedsReview);
            CHECK(item.decision->reason == ConflictRuleReason::AwaitingChoice); saw_ask = true;
        }
    }
    CHECK(saw_ask);
    auto receipt = take(job->review(std::span(&ask, 1)));
    const auto frozen = take(job->reviewed_page(receipt, 0, 32));
    CHECK(frozen.items.size() == assessed.items.size());
    for (std::size_t i = 0; i < frozen.items.size(); ++i) {
        CHECK(frozen.items[i].action == ReviewedTreeAction::Report);
        CHECK(frozen.items[i].decision->state == assessed.items[i].decision->state);
        CHECK(frozen.items[i].decision->reason == assessed.items[i].decision->reason);
    }
    // A mutation preference must also stay descriptive in Compare, with its
    // factual retention refusal intact, never manufactured into availability.
    auto replace = ask; replace.choice = ConflictChoice::UseSource;
    auto mutation_preference = take(job->assess_rules(std::span(&replace, 1), 0, 32));
    for (const auto& item : mutation_preference.items) {
        CHECK(item.action == ReviewedTreeAction::Report && !item.facts.retained_target_available);
        if (item.facts.source_present && item.facts.destination_present) {
            CHECK(item.decision->state == ConflictRuleState::NeedsReview);
            if(item.row.relation==ComparisonRelation::Unknown){
                CHECK(item.decision->reason==ConflictRuleReason::UnqualifiedObjects);
                CHECK(item.facts.source_metadata&&item.facts.destination_metadata);
                CHECK(item.facts.source_metadata->state!=ComparisonDigestState::CompleteStable||item.facts.destination_metadata->state!=ComparisonDigestState::CompleteStable);
            }else CHECK(item.decision->reason==ConflictRuleReason::RetentionUnavailable);
        }
    }
    CHECK(!job->begin_execution(receipt).value()); // changed rules revoked it
    auto descriptive = take(job->review(std::span(&replace, 1)));
    auto invalid = ask; invalid.kind = static_cast<ConflictClass>(999);
    CHECK(!job->review(std::span(&invalid, 1)).value());
    CHECK(!job->begin_execution(descriptive).value());
    receipt = take(job->review(std::span(&ask, 1)));
    // Compare remains root-free. Mutating previews must bind a private Root
    // before inventory, even when they are only foreign-receipt test probes.
    auto missing_root=f.request(ComparisonProfile::Copy);
    missing_root.journal_root.reset();missing_root.open_journal={};
    auto denied=take(ReviewedTreePlanJob::create(std::move(missing_root)));run(*denied);
    CHECK(denied->state()==ReviewedTreeState::Failed&&!denied->preview());
    CHECK(denied->progress().failure&&denied->progress().failure->state==ObservationState::Unsupported);
    for (auto profile : {ComparisonProfile::Copy, ComparisonProfile::Sync}) {
        auto mutating_request = f.request(profile);
        mutating_request.copy_policy.allow_unhandled_metadata_loss = false;
        mutating_request.copy_policy.metadata_scope = RegularMetadataScope::CompleteMetadataV1;
        auto mutating = take(ReviewedTreePlanJob::create(std::move(mutating_request))); preview(*mutating);
        CHECK(mutating->begin_execution(receipt).state() == ObservationState::Changed);
        CHECK(!mutating->reviewed_page(receipt, 0, 32).value());
        auto copy_ask = ask; copy_ask.plan = mutating->preview()->identity();
        CHECK(!mutating->review(std::span(&copy_ask, 1)).value());
        std::stop_source stop;stop.request_stop();
        CHECK(mutating->advance(stop.get_token())==ReviewedTreeState::Cancelled);
    }
    auto other_instance = f.job(ComparisonProfile::Compare); preview(*other_instance);
    CHECK(other_instance->begin_execution(receipt).state() == ObservationState::Changed);
    CHECK(take(job->begin_execution(receipt))); run(*job);
    CHECK(job->state() == ReviewedTreeState::Complete);
    CHECK(!job->progress().partial && !job->progress().recovery_required && job->progress().known_copy_bytes == 0);
    CHECK(f.read("s/a") == "incoming" && f.read("d/a") == "existing");
    CHECK(!f.exists("d/new") && f.read("d/other") == "target only");
    for (const auto& item : take(job->page(0, 32)).items) {
        CHECK(item.action == ReviewedTreeAction::Report);
        CHECK(!item.journal_id && !item.retention_journal_id && !item.staging_name && !item.target_retained);
    }
    auto journals = take(f.parent->open_directory_child(name("journals")));
    CHECK(journals->read(32).state == DirectoryReadState::End);
}
void test_profiles() {
    for (auto profile : {ComparisonProfile::Update, ComparisonProfile::MissingOnly, ComparisonProfile::Sync, ComparisonProfile::Mirror, ComparisonProfile::Compare}) {
        Fixture f; write_file(f.path("s/a"), "content");
        auto job = f.job(profile); preview(*job); start(*job); run(*job);
        CHECK(job->state() == ReviewedTreeState::Complete);
        CHECK(f.exists("d/a") == (profile != ComparisonProfile::Compare));
    }
}
#ifndef _WIN32
void test_exact_names_links_and_fifo() {
    Fixture f;
    write_file(f.path("s/back\\slash"), "exact");
    auto exact = f.job(); preview(*exact); start(*exact); run(*exact);
    CHECK(exact->state() == ReviewedTreeState::Complete && f.read("d/back\\slash") == "exact");
    CHECK(::symlink("back\\slash", f.path("s/link").c_str()) == 0);
    auto link = f.job(); run(*link);
    CHECK(link->state() == ReviewedTreeState::Failed && link->progress().failure->state == ObservationState::Unsupported);
    CHECK(::unlink(f.path("s/link").c_str()) == 0);
    CHECK(::mkfifo(f.path("s/pipe").c_str(), 0600) == 0);
    auto fifo = f.job(); run(*fifo);
    CHECK(fifo->state() == ReviewedTreeState::Failed && fifo->progress().failure->state == ObservationState::Unsupported);
}
#endif
}
namespace {
ReviewedTreeState bounded_advance(ReviewedTreePlanJob& job,std::size_t chunk,std::stop_token stop={}) {
    tree_capture_test::reads=0;tree_capture_test::chunk=chunk;tree_capture_test::step=true;
    ReviewedTreeState state;try{state=job.advance(stop);}catch(...){tree_capture_test::step=false;throw;}tree_capture_test::step=false;
    CHECK(tree_capture_test::reads<=1);CHECK(!tree_capture_test::violation);return state;
}
void bounded_preview(ReviewedTreePlanJob& job,std::size_t chunk) {
    for(unsigned i=0;i<500000&&job.state()==ReviewedTreeState::Inventory;++i)bounded_advance(job,chunk);
    CHECK(job.state()==ReviewedTreeState::AwaitingReview);
}
void attribute(const std::filesystem::path& path,char value){
#ifdef _WIN32
    // Exact native ADS I/O; the manifest and hash must affect metadata facts.
    FixtureHandle h{CreateFileW((extended(path)+L":native-stream:$DATA").c_str(),GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,CREATE_ALWAYS,FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};
    CHECK(h.value!=INVALID_HANDLE_VALUE);const std::string data(1537,value);DWORD copied=0;
    CHECK(WriteFile(h.value,data.data(),DWORD(data.size()),&copied,nullptr)&&copied==data.size());h.close();
#elif defined(__APPLE__)
    CHECK(::setxattr(path.c_str(),"user.ck.reviewed-tree",&value,1,0,0)==0);
#else
    CHECK(::setxattr(path.c_str(),"user.ck.reviewed-tree",&value,1,0)==0);
#endif
}
void match_times(const std::filesystem::path& source,const std::filesystem::path& dest){
#ifdef _WIN32
    FixtureHandle a{CreateFileW(extended(source).c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};
    FixtureHandle b{CreateFileW(extended(dest).c_str(),FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};
    FILE_BASIC_INFO info{};CHECK(a.value!=INVALID_HANDLE_VALUE&&b.value!=INVALID_HANDLE_VALUE);
    CHECK(GetFileInformationByHandleEx(a.value,FileBasicInfo,&info,sizeof(info))&&SetFileInformationByHandle(b.value,FileBasicInfo,&info,sizeof(info)));a.close();b.close();
#else
    struct stat st{};CHECK(!::stat(source.c_str(),&st));
#ifdef __APPLE__
    timespec times[]{st.st_atimespec,st.st_mtimespec};
#else
    timespec times[]{st.st_atim,st.st_mtim};
#endif
    CHECK(!utimensat(AT_FDCWD,dest.c_str(),times,AT_SYMLINK_NOFOLLOW));
#endif
}
void test_explicit_loss_main(){
    Fixture f;write_file(f.path("s/a"),std::string(2049,'p'));write_file(f.path("d/a"),std::string(2049,'p'));
    match_times(f.path("s/a"),f.path("d/a"));
#ifdef _WIN32
    FixtureHandle token;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&token.value));
    TOKEN_PRIVILEGES disabled{},old{};disabled.PrivilegeCount=1;CHECK(LookupPrivilegeValueW(nullptr,L"SeSecurityPrivilege",&disabled.Privileges[0].Luid));
    DWORD bytes=sizeof(old);CHECK(AdjustTokenPrivileges(token.value,FALSE,&disabled,sizeof(old),&old,&bytes));
#endif
    auto request=f.request(ComparisonProfile::Compare);request.copy_policy.metadata_scope=RegularMetadataScope::CompleteMetadataV1;
    request.copy_policy.allow_unhandled_metadata_loss=true;request.digest_chunk_bytes=31;
    auto job=take(ReviewedTreePlanJob::create(std::move(request)));tree_capture_test::total_reads=0;bounded_preview(*job,31);
    const auto page=take(job->page(0,8));CHECK(page.items.size()==1);const auto& item=page.items.front();
    CHECK(item.facts.source_metadata&&item.facts.destination_metadata);
    CHECK(item.facts.source_metadata->state==ComparisonDigestState::Unknown&&item.facts.destination_metadata->state==ComparisonDigestState::Unknown);
    CHECK(item.facts.source_metadata_failure&&item.facts.destination_metadata_failure);
    CHECK(item.row.relation!=ComparisonRelation::Unknown);auto binding=take(job->native_binding(item.row.token));
    CHECK(binding.source_digest&&binding.destination_digest&&binding.source_digest==binding.destination_digest);
    CHECK(tree_capture_test::total_reads>=4*((2049+30)/31));binding={};
    // Whole preexecution scan must use the same content producer. A changed
    // main cannot pass merely because Complete metadata remains unavailable.
    auto receipt=take(job->review({}));CHECK(take(job->begin_execution(receipt)));write_file(f.path("s/a"),std::string(2049,'x'),true);
    for(unsigned i=0;i<500000&&job->state()<ReviewedTreeState::Complete;++i)bounded_advance(*job,31);
    CHECK(job->state()==ReviewedTreeState::Failed&&job->progress().failure&&job->progress().failure->error.code==static_cast<std::int64_t>(AdapterError::PlanDecisionStale));
    request=f.request(ComparisonProfile::Compare);request.copy_policy.metadata_scope=RegularMetadataScope::CompleteMetadataV1;
    request.copy_policy.allow_unhandled_metadata_loss=false;request.digest_chunk_bytes=31;
    job=take(ReviewedTreePlanJob::create(std::move(request)));bounded_preview(*job,31);
    CHECK(take(job->page(0,8)).items.front().row.relation==ComparisonRelation::Unknown);
    request=f.request(ComparisonProfile::Compare);request.copy_policy.metadata_scope=RegularMetadataScope::CompleteMetadataV1;
    request.copy_policy.allow_unhandled_metadata_loss=true;request.digest_chunk_bytes=31;request.metadata_limits.max_logical_bytes=128;
    job=take(ReviewedTreePlanJob::create(std::move(request)));tree_capture_test::total_reads=0;
    for(unsigned i=0;i<2000&&job->state()<ReviewedTreeState::Complete;++i)bounded_advance(*job,31);
    CHECK(job->state()==ReviewedTreeState::Failed&&tree_capture_test::total_reads==0);
#ifdef _WIN32
    CHECK(AdjustTokenPrivileges(token.value,FALSE,&old,0,nullptr,nullptr));token.close();
#endif
    std::printf("explicit-loss Complete unavailable: closed main-only proof, honest metadata Unknown, bounded two scans/preexecution and prehash cap PASS\n");
}
void test_progressive_metadata(){
    Fixture f;write_file(f.path("s/a"),std::string(2049,'p'));write_file(f.path("d/a"),std::string(2049,'p'));
    attribute(f.path("s/a"),'a');attribute(f.path("d/a"),'b');match_times(f.path("s/a"),f.path("d/a"));
    auto request=f.request(ComparisonProfile::Compare);request.copy_policy.allow_unhandled_metadata_loss=false;
    request.digest_chunk_bytes=31;auto job=take(ReviewedTreePlanJob::create(std::move(request)));bounded_preview(*job,31);
    auto page=take(job->page(0,8));CHECK(page.items.size()==1);const auto& facts=page.items[0].facts;
    CHECK(facts.source_metadata&&facts.destination_metadata);
    CHECK(facts.source_metadata->state==ComparisonDigestState::CompleteStable);
    CHECK(facts.source_metadata->ownership==ComparisonMetadataOwnership::CurrentCaller&&facts.source_metadata->canonical_owner_digest);
    CHECK((facts.source_metadata->schema!=std::array<std::byte,32>{}));
    CHECK(facts.source_metadata->policy_binding==facts.destination_metadata->policy_binding);
    CHECK(facts.source_metadata->bytes!=facts.destination_metadata->bytes);
    CHECK(page.items[0].row.relation==ComparisonRelation::MetadataDifferent);
    auto binding=take(job->native_binding(page.items[0].row.token));CHECK(binding.source_digest==binding.destination_digest);
    binding={};auto receipt=take(job->review({}));CHECK(take(job->begin_execution(receipt)));
    // Whole-tree preexecution revalidation must include xattr/ADS bytes.
    attribute(f.path("s/a"),'c');match_times(f.path("d/a"),f.path("s/a"));
    for(unsigned i=0;i<500000&&job->state()<ReviewedTreeState::Complete;++i)bounded_advance(*job,31);
    CHECK(job->state()==ReviewedTreeState::Failed);CHECK(job->progress().failure);
    CHECK(job->progress().failure->error.code==static_cast<std::int64_t>(AdapterError::PlanDecisionStale));
    CHECK(!job->native_binding(page.items[0].row.token).value());
    // Required Complete coverage unavailable on POSIX is honest typed unknown.
#ifndef _WIN32
    request=f.request(ComparisonProfile::Compare);request.copy_policy.allow_unhandled_metadata_loss=false;
    request.copy_policy.metadata_scope=RegularMetadataScope::CompleteMetadataV1;request.digest_chunk_bytes=29;
    job=take(ReviewedTreePlanJob::create(std::move(request)));bounded_preview(*job,29);page=take(job->page(0,8));
    CHECK(page.items[0].facts.source_metadata->state!=ComparisonDigestState::CompleteStable);
    CHECK(page.items[0].facts.source_metadata_failure&&page.items[0].facts.source_metadata_failure->state==ObservationState::Unsupported);
    CHECK(page.items[0].row.relation==ComparisonRelation::Unknown&&page.items[0].action==ReviewedTreeAction::Report);
#endif
    // A requested all-stream logical cap is admitted before any content read.
    request=f.request(ComparisonProfile::Compare);request.copy_policy.allow_unhandled_metadata_loss=false;
    request.digest_chunk_bytes=31;
#ifdef _WIN32
    request.metadata_limits.max_logical_bytes=2113; // Main fits; main+ADS does not.
#else
    request.metadata_limits.max_logical_bytes=128;
#endif
    job=take(ReviewedTreePlanJob::create(std::move(request)));tree_capture_test::total_reads=0;
    for(unsigned i=0;i<2000&&job->state()<ReviewedTreeState::Complete;++i)bounded_advance(*job,31);
    CHECK(job->state()==ReviewedTreeState::Failed);CHECK(tree_capture_test::total_reads==0);
    // Cancellation drains capture owners, including a stop during native read.
    request=f.request(ComparisonProfile::Compare);request.copy_policy.allow_unhandled_metadata_loss=false;request.digest_chunk_bytes=31;
    std::weak_ptr<const HeldChild> source_root=request.source_root,destination_root=request.destination_root;
    job=take(ReviewedTreePlanJob::create(std::move(request)));std::stop_source cancel;tree_capture_test::cancel=&cancel;
    for(unsigned i=0;i<2000&&job->state()<ReviewedTreeState::Complete;++i)bounded_advance(*job,31,cancel.get_token());
    tree_capture_test::cancel=nullptr;CHECK(job->state()==ReviewedTreeState::Cancelled);
    CHECK(source_root.expired()&&destination_root.expired());
    std::printf("progressive Scanner source facts, bounded reads, V3/current owner, metadata/ADS revalidation, unknown coverage, budgets and terminal drain PASS\n");
}
void select_close_target(const std::filesystem::path& path){
#ifdef _WIN32
    HANDLE h=CreateFileW(extended(path).c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    CHECK(h!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(h,FileIdInfo,&tree_capture_test::target,sizeof(tree_capture_test::target)));CHECK(CloseHandle(h));
#else
    struct stat st{};CHECK(!::stat(path.c_str(),&st));tree_capture_test::device=st.st_dev;tree_capture_test::inode=st.st_ino;
#endif
}
void test_progressive_exception(){
    Fixture f;write_file(f.path("s/a"),std::string(2049,'p'));auto request=f.request();request.copy_policy.allow_unhandled_metadata_loss=false;request.digest_chunk_bytes=31;
    auto root=take(acquire_native_journal_root(*request.journal_root));request.prepared_journal_root=root;
    std::weak_ptr<const HeldChild> source_root=request.source_root,destination_root=request.destination_root;
    auto job=take(ReviewedTreePlanJob::create(std::move(request)));select_close_target(f.path("s/a"));
    tree_capture_test::closed_views=0;tree_capture_test::total_reads=0;tree_capture_test::watch_close=true;tree_capture_test::oom_on_read=true;bool threw=false;
    try{for(unsigned i=0;i<10000&&job->state()<ReviewedTreeState::Complete;++i)bounded_advance(*job,31);}catch(const std::bad_alloc&){threw=true;}
    tree_capture_test::watch_close=false;tree_capture_test::fail_alloc=false;tree_capture_test::defer_debug_proxy=false;tree_capture_test::oom_on_read=false;
    CHECK(threw);CHECK(tree_capture_test::closed_views>0);CHECK(source_root.expired()&&destination_root.expired());
    CHECK(job->state()==ReviewedTreeState::Failed);CHECK(take(root->finish_io()));
    std::printf("progressive Scanner allocation exception after actual native read explicitly drains source owners PASS\n");
}
void test_original_scan_close(bool oom=false){
    Fixture f;write_file(f.path("s/a"),std::string(2049,'p'));auto request=f.request();request.copy_policy.allow_unhandled_metadata_loss=false;request.digest_chunk_bytes=31;
    auto root=take(acquire_native_journal_root(*request.journal_root));request.prepared_journal_root=root;
    std::weak_ptr<const HeldChild> source_root=request.source_root,destination_root=request.destination_root;
    auto job=take(ReviewedTreePlanJob::create(std::move(request)));select_close_target(f.path("s/a"));
    tree_capture_test::total_reads=0;
    for(unsigned i=0;i<10000&&!tree_capture_test::total_reads&&job->state()==ReviewedTreeState::Inventory;++i)bounded_advance(*job,31);
    CHECK(tree_capture_test::total_reads>0&&job->state()==ReviewedTreeState::Inventory);
    tree_capture_test::closed_views=0;tree_capture_test::close_faults=0;tree_capture_test::skip_closes=1;tree_capture_test::arm_close=true;
    std::stop_source stop;stop.request_stop();tree_capture_test::oom_on_close=oom;bool threw=false;
    try{bounded_advance(*job,31,stop.get_token());}catch(const std::bad_alloc&){threw=true;}
    tree_capture_test::arm_close=false;tree_capture_test::oom_on_close=false;tree_capture_test::fail_alloc=false;CHECK(threw==oom);
    CHECK(tree_capture_test::close_faults==1&&tree_capture_test::closed_views>=2);CHECK(job->state()==ReviewedTreeState::NeedsReconciliation);
    CHECK(source_root.expired()&&destination_root.expired());detail::PreparedJournalConsumerFailure failure;
    CHECK(detail::read_prepared_journal_consumer_failure(*root,failure));
#ifdef _WIN32
    CHECK(failure.domain==ErrorDomain::Win32&&failure.code==ERROR_READ_FAULT);
    CHECK(std::string_view(failure.operation.data())=="metadata_capture.temporary_CloseHandle");
#else
    CHECK(failure.domain==ErrorDomain::Posix&&failure.code==EIO);
    CHECK(std::string_view(failure.operation.data())=="metadata_capture.temporary_close");
#endif
    CHECK(job->progress().failure&&job->progress().failure->error.code==failure.code);
    CHECK(!root->finish_io().value());
    std::printf("original Scanner HeldChild close after successful capture-duplicate close reaches borrowed Root before cached terminal PASS\n");
}
#ifdef _WIN32
void test_reviewed_metadata_capture_binding(){
    Fixture f;write_file(f.path("s/a"),std::string(2049,'p'));write_file(f.path("shadow"),"times");
    attribute(f.path("s/a"),'a');match_times(f.path("s/a"),f.path("shadow"));
    auto request=f.request();request.copy_policy.allow_unhandled_metadata_loss=false;request.digest_chunk_bytes=31;
    auto job=take(ReviewedTreePlanJob::create(std::move(request)));bounded_preview(*job,31);
    CHECK(take(job->begin_execution(take(job->review({})))));
    for(unsigned i=0;i<10000&&job->state()==ReviewedTreeState::Revalidating;++i)bounded_advance(*job,31);
    CHECK(job->state()==ReviewedTreeState::Executing);
    attribute(f.path("s/a"),'b');match_times(f.path("shadow"),f.path("s/a"));
    job->advance();CHECK(job->state()==ReviewedTreeState::Failed);CHECK(!f.exists("d/a"));
    CHECK(job->progress().failure&&job->progress().failure->error.operation=="reviewed_tree.source_metadata_capture_changed");
    std::printf("post-revalidation ADS mutation with restored Basic times cannot supersede reviewed metadata before journal/staging effects PASS\n");
}
#endif
void test_loss_root_close(){
    Fixture f;write_file(f.path("s/a"),std::string(2049,'p'));auto request=f.request();
    request.copy_policy.allow_unhandled_metadata_loss=true;request.copy_policy.metadata_scope=RegularMetadataScope::CompleteMetadataV1;request.digest_chunk_bytes=31;
#ifdef _WIN32
    FixtureHandle token;CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&token.value));
    TOKEN_PRIVILEGES disabled{},old{};disabled.PrivilegeCount=1;CHECK(LookupPrivilegeValueW(nullptr,L"SeSecurityPrivilege",&disabled.Privileges[0].Luid));
    DWORD bytes=sizeof(old);CHECK(AdjustTokenPrivileges(token.value,FALSE,&disabled,sizeof(old),&old,&bytes));
#endif
    auto root=take(acquire_native_journal_root(*request.journal_root));request.prepared_journal_root=root;
    std::weak_ptr<const HeldChild> source_root=request.source_root,destination_root=request.destination_root;
    auto job=take(ReviewedTreePlanJob::create(std::move(request)));select_close_target(f.path("s/a"));tree_capture_test::total_reads=0;
    for(unsigned i=0;i<10000&&!tree_capture_test::total_reads&&job->state()==ReviewedTreeState::Inventory;++i)bounded_advance(*job,31);
    CHECK(tree_capture_test::total_reads>0&&job->state()==ReviewedTreeState::Inventory);
    tree_capture_test::closed_views=0;tree_capture_test::close_faults=0;tree_capture_test::skip_closes=0;tree_capture_test::arm_close=true;tree_capture_test::watch_close=true;
    std::stop_source stop;stop.request_stop();bounded_advance(*job,31,stop.get_token());tree_capture_test::arm_close=false;tree_capture_test::watch_close=false;
    CHECK(tree_capture_test::close_faults==1&&tree_capture_test::closed_views>=2);CHECK(job->state()==ReviewedTreeState::NeedsReconciliation);
    CHECK(source_root.expired()&&destination_root.expired());
    detail::PreparedJournalConsumerFailure failure;CHECK(detail::read_prepared_journal_consumer_failure(*root,failure));
#ifdef _WIN32
    CHECK(failure.domain==ErrorDomain::Win32&&failure.code==ERROR_READ_FAULT);
    CHECK(AdjustTokenPrivileges(token.value,FALSE,&old,0,nullptr,nullptr));token.close();
#else
    CHECK(failure.domain==ErrorDomain::Posix&&failure.code==EIO);
#endif
    CHECK(job->progress().failure&&job->progress().failure->error.code==failure.code);CHECK(!root->finish_io().value());
    std::printf("explicit-loss Scanner cancel drains native content clone/original inputs and preserves genuine borrowed Root first close failure PASS\n");
}
void test_progressive_root_close(){
    Fixture f;write_file(f.path("s/a"),std::string(2049,'p'));
    auto request=f.request();request.copy_policy.allow_unhandled_metadata_loss=false;request.digest_chunk_bytes=31;
    auto root=take(acquire_native_journal_root(*request.journal_root));request.prepared_journal_root=root;
    auto job=take(ReviewedTreePlanJob::create(std::move(request)));
    select_close_target(f.path("s/a"));
    tree_capture_test::total_reads=0;tree_capture_test::close_faults=0;tree_capture_test::arm_close=true;
    for(unsigned i=0;i<10000&&job->state()<ReviewedTreeState::Complete;++i)bounded_advance(*job,31);
    tree_capture_test::arm_close=false;CHECK(tree_capture_test::close_faults==1);CHECK(job->state()==ReviewedTreeState::NeedsReconciliation);
    detail::PreparedJournalConsumerFailure failure;CHECK(detail::read_prepared_journal_consumer_failure(*root,failure));
#ifdef _WIN32
    CHECK(failure.domain==ErrorDomain::Win32&&failure.code==ERROR_READ_FAULT);
#else
    CHECK(failure.domain==ErrorDomain::Posix&&failure.code==EIO);
#endif
    CHECK(!root->revalidate().value());CHECK(!root->finish_io().value());
    std::printf("progressive Scanner actual consumed-close error reaches genuine Root first-error latch PASS\n");
}
}
#ifndef CKFS_TREE_EXECUTION_TEST_SUPPORT
int main(int argc, char** argv) {
    try {
        if(argc==2&&std::string_view(argv[1])=="--loss-main") {test_explicit_loss_main();test_loss_root_close();std::printf("explicit loss Scanner: %u checks passed\n",checks);return 0;}
        if(argc==2&&std::string_view(argv[1])=="--progressive-metadata") {
            test_progressive_metadata();test_progressive_root_close();test_original_scan_close();test_original_scan_close(true);test_progressive_exception();
#ifdef _WIN32
            test_reviewed_metadata_capture_binding();
#endif
            std::printf("reviewed_tree progressive metadata: %u checks passed\n",checks);return 0;
        }
        if(argc==2&&std::string_view(argv[1])=="--changed-receipts-only") {
            test_changed_receipts();
            std::printf("reviewed_tree_plan stale receipts: %u checks passed\n",checks);return 0;
        }
#ifdef __linux__
        if(argc==2&&std::string_view(argv[1])=="--cancel-writer-finish") {
            for(bool typed:{false,true})test_cancel_copy_writer_finish(typed);
            std::printf("reviewed_tree_plan cancelled writer finish: %u checks passed\n",checks);return 0;
        }
#endif
        if(argc==2&&std::string_view(argv[1])=="--private-journal-scope") {
            for(unsigned placement=0;placement<7;++placement)for(bool typed:{false,true})test_private_journal_scope(placement,typed);
            test_legacy_root_terminal_close_failure();
            std::printf("reviewed_tree_plan protected journal scope: %u checks passed\n",checks);return 0;
        }
        if (argc == 2 && std::string_view(argv[1]) == "--compare-review-only") {
            test_compare_acknowledges_descriptive_choices();
            std::printf("reviewed_tree_plan Compare review: %u checks passed\n", checks); return 0;
        }
        test_compare_acknowledges_descriptive_choices();
        test_copy(); test_copy(true); test_receipts_and_rules(); test_deletions_and_unsupported();
        test_changed_receipts(); test_overlap_collision_and_limits(); test_cancellation(); test_profiles();
        test_changes_during_execution(); test_parent_move_into_source(); test_assessment_and_receipt_revocation(); test_retention_capabilities_and_incoming_copy();
#ifndef _WIN32
        test_exact_names_links_and_fifo(); test_lossless_native_names();
#endif
        std::printf("reviewed_tree_plan: %u checks passed\n", checks);
        return 0;
    } catch (const std::exception& e) { std::fprintf(stderr, "reviewed_tree_plan: %s\n", e.what()); return 1; }
}

#endif
