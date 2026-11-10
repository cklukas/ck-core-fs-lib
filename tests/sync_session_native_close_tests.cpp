// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "sync_session.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "windows_name.hpp"
#include <algorithm>
#include <atomic>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#else
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <dlfcn.h>
#include <sys/mount.h>
#else
#include <sys/syscall.h>
#endif
#endif
using namespace ck::files;
namespace {
unsigned checks=0;
#define CHECK(x) do {++checks;if(!(x)){std::fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x);std::abort();}}while(false)
template<class T>T take(Observation<T> value){if(!value.value()){std::fprintf(stderr,"unexpected %s code=%lld\n",value.unavailable_detail()->error.operation.c_str(),static_cast<long long>(value.unavailable_detail()->error.code));std::abort();}return std::move(value).take_value();}
#ifndef _WIN32
struct Fixture {
    std::string base,store,left,right,other,child;
    explicit Fixture(const char* selected_root=nullptr) {
        const char* temp=selected_root?selected_root:std::getenv("TMPDIR"); CHECK(temp && *temp);
#ifdef __APPLE__
        const std::string_view temporary_root(temp);
        CHECK(temporary_root=="/Volumes/S8T/tmp" || temporary_root.starts_with("/Volumes/S8T/tmp/") ||
              temporary_root=="/Volumes/PRO-BLADE/tmp" || temporary_root.starts_with("/Volumes/PRO-BLADE/tmp/"));
        struct statfs fs{};CHECK(statfs(temp,&fs)==0);
        // Positive private-storage fixtures use ONLY the explicitly selected
        // TMPDIR. The qualification runner selects an ownership-enforcing root
        // independently of its build directory; never choose another volume.
        if(!selected_root) CHECK(!(fs.f_flags&MNT_IGNORE_OWNERSHIP));
#endif
        std::string pattern=std::string(temp)+"/native.XXXXXX";
        CHECK(mkdtemp(pattern.data())); base=pattern; store=base+"/store"; left=base+"/left";
        right=base+"/right"; other=base+"/other"; child=left+"/child";
        for(const auto& p:{store,left,right,other,child,base+"/store2",right+"/child"}) CHECK(mkdir(p.c_str(),0700)==0);
    }
    static void cleanup(const std::string& p) {
        DIR* d=opendir(p.c_str()); if(!d) { unlink(p.c_str()); return; }
        while(auto* e=readdir(d)) { if(!std::strcmp(e->d_name,".")||!std::strcmp(e->d_name,"..")) continue;
            std::string child=p+"/"+e->d_name; struct stat st{}; CHECK(lstat(child.c_str(),&st)==0);
            if(S_ISDIR(st.st_mode)) cleanup(child); else CHECK(unlink(child.c_str())==0);
        } closedir(d); CHECK(rmdir(p.c_str())==0);
    }
    ~Fixture() { cleanup(base); }
};
NativeAbsolutePath address(const std::string& s) {
    auto p=NativeAbsolutePath::from_posix(s); CHECK(p.value()); return std::move(p).take_value();
}
#else
struct Fixture {
    std::wstring base,store,left,right,other;
    std::vector<std::wstring> directories;
    static std::wstring extended(const std::wstring& p) { auto e=windows_extended_path(p); CHECK(e); return *e; }
    explicit Fixture() {
        wchar_t temp[32768]{},tmp[32768]{};
        const auto temp_length=GetEnvironmentVariableW(L"TEMP",temp,32768);
        const auto tmp_length=GetEnvironmentVariableW(L"TMP",tmp,32768);
        CHECK(temp_length>0 && temp_length<32768 && tmp_length>0 && tmp_length<32768);
        const auto normalized=[](std::wstring path) {
            std::replace(path.begin(),path.end(),L'/',L'\\');
            const auto letter=[](wchar_t c){return (c>=L'A'&&c<=L'Z')||(c>=L'a'&&c<=L'z');};
            // Strip only an extended DOS prefix, never UNC/device namespaces.
            if(path.size()>=7&&path.starts_with(L"\\\\?\\")&&letter(path[4])&&path[5]==L':'&&path[6]==L'\\')path.erase(0,4);
            if(path.size()>=3&&path[1]==L':'&&path[2]==L'\\'&&path[0]>=L'a'&&path[0]<=L'z')path[0]-=L'a'-L'A';
            return path;
        };
        const auto temp_path=normalized(std::wstring(temp,temp_length)),tmp_path=normalized(std::wstring(tmp,tmp_length));
        CHECK(temp_path==tmp_path && windows_extended_path(temp_path).has_value());
        if(const auto* require_v=std::getenv("CK_FS_REQUIRE_V_DEV_DRIVE"); require_v && std::string_view(require_v)=="1") {
            const auto drive=GetFileAttributesW(L"V:\\");
            CHECK(drive!=INVALID_FILE_ATTRIBUTES && (drive&FILE_ATTRIBUTE_DIRECTORY));
            CHECK(std::wstring_view(temp_path).starts_with(L"V:\\tmp\\"));
        }
        static unsigned serial=0;
        base=temp_path+L"\\native-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(++serial)+L"-"+std::to_wstring(GetTickCount64());
        add(base); store=base+L"\\store"; left=base+L"\\left"; right=base+L"\\right"; other=base+L"\\other";
        add(left); add(right); add(other);
        HANDLE raw=nullptr; CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw));
        DWORD size=0; GetTokenInformation(raw,TokenUser,nullptr,0,&size); std::vector<std::byte> token(size);
        CHECK(GetTokenInformation(raw,TokenUser,token.data(),size,&size)); CloseHandle(raw);
        wchar_t* sid=nullptr; CHECK(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(token.data())->User.Sid,&sid));
        std::wstring sddl=L"O:"+std::wstring(sid)+L"D:P(A;;FA;;;"+sid+L")(A;;FA;;;SY)"; LocalFree(sid);
        PSECURITY_DESCRIPTOR sd=nullptr; CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr));
        SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE}; CHECK(CreateDirectoryW(extended(store).c_str(),&sa)); LocalFree(sd);
        directories.push_back(store);
    }
    void add(const std::wstring& p) { CHECK(CreateDirectoryW(extended(p).c_str(),nullptr)); directories.push_back(p); }
    ~Fixture() {
        WIN32_FIND_DATAW data{}; HANDLE find=FindFirstFileW((extended(store)+L"\\*").c_str(),&data);
        if(find!=INVALID_HANDLE_VALUE) {
            do { if(std::wstring_view(data.cFileName)==L"." || std::wstring_view(data.cFileName)==L"..") continue;
                CHECK(DeleteFileW((extended(store)+L"\\"+data.cFileName).c_str()));
            } while(FindNextFileW(find,&data)); FindClose(find);
        }
        for(auto i=directories.rbegin();i!=directories.rend();++i) CHECK(RemoveDirectoryW(extended(*i).c_str()));
    }
};
NativeAbsolutePath address(const std::wstring& p) {
    std::u16string units; for(auto c:p) units+=static_cast<char16_t>(c);
    auto path=NativeAbsolutePath::from_windows(units); CHECK(path.value()); return std::move(path).take_value();
}
#endif
}
namespace watch {
thread_local bool armed=false,oom_on_close=false,oom=false,retried=false;
thread_local unsigned hits=0,close_calls=0,oom_attempts=0;
thread_local PreparedJournalRoot* root=nullptr;
thread_local detail::PreparedJournalConsumerFailure first_allocation;
#ifdef _WIN32
FILE_ID_INFO selected{};
std::atomic<bool> arm_mutex=false;
std::atomic<HANDLE> closing_mutex=nullptr;
std::atomic<unsigned> mutex_closes=0;
BOOL WINAPI release_mutex(HANDLE h){using F=BOOL(WINAPI*)(HANDLE);static auto real=std::bit_cast<F>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ReleaseMutex"));const auto ok=real(h);if(ok&&arm_mutex.exchange(false))closing_mutex=h;return ok;}
thread_local HANDLE consumed=nullptr;
constexpr auto native_error=ERROR_READ_FAULT;
auto real_close(){using F=BOOL(WINAPI*)(HANDLE);static auto f=std::bit_cast<F>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CloseHandle"));return f;}
BOOL WINAPI close_handle(HANDLE h){
 if(h==consumed&&consumed){retried=true;++close_calls;}
 FILE_ID_INFO id{};const bool selected_handle=armed&&GetFileInformationByHandleEx(h,FileIdInfo,&id,sizeof(id))&&id.VolumeSerialNumber==selected.VolumeSerialNumber&&!std::memcmp(&id.FileId,&selected.FileId,sizeof(id.FileId));
 const auto ok=real_close()(h);const auto error=GetLastError();
 if(h==closing_mutex.load()&&ok){++mutex_closes;closing_mutex=nullptr;SetLastError(native_error);return FALSE;}
 if(selected_handle&&ok){armed=false;consumed=h;++hits;close_calls=1;oom=oom_on_close;SetLastError(native_error);return FALSE;}
 SetLastError(error);return ok;
}
void pin(const std::wstring& p){auto h=CreateFileW(Fixture::extended(p).c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);CHECK(h!=INVALID_HANDLE_VALUE);CHECK(GetFileInformationByHandleEx(h,FileIdInfo,&selected,sizeof(selected)));CHECK(real_close()(h));}
#else
struct stat selected{};
thread_local int consumed=-1,reuse=-1;
constexpr auto native_error=EIO;
int real_close(int fd){
#ifdef __linux__
 return static_cast<int>(syscall(SYS_close,fd));
#else
 using F=int(*)(int);static auto f=std::bit_cast<F>(dlsym(RTLD_NEXT,"close"));return f(fd);
#endif
}
int close_file(int fd) noexcept {
 if(fd==consumed&&consumed>=0){retried=true;++close_calls;}
 struct stat st{};const bool selected_handle=armed&&fstat(fd,&st)==0&&st.st_dev==selected.st_dev&&st.st_ino==selected.st_ino;
 const int result=real_close(fd),error=errno;
 if(selected_handle&&result==0){armed=false;consumed=fd;++hits;close_calls=1;reuse=open("/dev/null",O_RDONLY|O_CLOEXEC);
 if(reuse>=0&&reuse!=fd){const int low=reuse;reuse=fcntl(low,F_DUPFD_CLOEXEC,fd);(void)real_close(low);}
 oom=oom_on_close;errno=native_error;return -1;}
 errno=error;return result;
}
void pin(const std::string& p){CHECK(stat(p.c_str(),&selected)==0);}
#endif
void reset(PreparedJournalRoot* owner,bool fail_alloc){armed=false;oom=false;oom_on_close=fail_alloc;hits=close_calls=oom_attempts=0;retried=false;root=owner;first_allocation={};
#ifdef _WIN32
 consumed=nullptr;
#else
 consumed=reuse=-1;
#endif
}
void allocation(){if(oom){if(!oom_attempts++&&root)(void)detail::read_prepared_journal_consumer_failure(*root,first_allocation);throw std::bad_alloc();}}
}
void* operator new(std::size_t n){watch::allocation();if(auto* p=std::malloc(n?n:1))return p;throw std::bad_alloc();}
void* operator new[](std::size_t n){return ::operator new(n);}
void operator delete(void* p)noexcept{std::free(p);}
void operator delete[](void* p)noexcept{std::free(p);}
void operator delete(void* p,std::size_t)noexcept{std::free(p);}
void operator delete[](void* p,std::size_t)noexcept{std::free(p);}
#ifdef _WIN32
extern "C" {decltype(&CloseHandle) __imp_CloseHandle=&watch::close_handle;decltype(&ReleaseMutex) __imp_ReleaseMutex=&watch::release_mutex;}
#else
extern "C" int close(int fd) noexcept(noexcept(::close(fd)))
{return watch::close_file(fd);}
#endif
namespace {
#ifdef _WIN32
std::wstring stored(const Fixture& f,std::string_view suffix){WIN32_FIND_DATAW d{};auto find=FindFirstFileW((Fixture::extended(f.store)+L"\\*").c_str(),&d);CHECK(find!=INVALID_HANDLE_VALUE);std::wstring result;do{std::wstring n=d.cFileName;std::wstring end(suffix.begin(),suffix.end());if(n.ends_with(end)){CHECK(result.empty());result=f.store+L"\\"+n;}}while(FindNextFileW(find,&d));CHECK(FindClose(find));CHECK(!result.empty());return result;}
#else
std::string stored(const Fixture& f,std::string_view suffix){auto* d=opendir(f.store.c_str());CHECK(d);std::string result;while(auto* e=readdir(d)){if(std::string_view(e->d_name).ends_with(suffix)){CHECK(result.empty());result=f.store+"/"+e->d_name;}}CHECK(closedir(d)==0);CHECK(!result.empty());return result;}
#endif
void assert_first(const PreparedJournalRoot::Pointer& root){detail::PreparedJournalConsumerFailure first;CHECK(detail::read_prepared_journal_consumer_failure(*root,first));CHECK(first.code==watch::native_error&&first.state==ObservationState::Failed);}
void reuse_check(){
#ifdef _WIN32
 HANDLE held[4096]{};unsigned n=0;bool found=false;while(n<4096){auto h=CreateEventW(nullptr,TRUE,FALSE,nullptr);CHECK(h);held[n++]=h;if(h==watch::consumed){found=true;break;}}CHECK(found);for(unsigned i=0;i<n;++i)CHECK(watch::real_close()(held[i]));
#else
 CHECK(watch::reuse==watch::consumed&&fcntl(watch::reuse,F_GETFD)>=0);CHECK(watch::real_close(watch::reuse)==0);
#endif
 CHECK(!watch::retried&&watch::close_calls==1);
#ifdef _WIN32
 watch::consumed=nullptr;
#else
 watch::consumed=-1;
#endif
}
void read_case(bool allocation_failure,bool oversized){
 Fixture f;auto root=take(acquire_native_sync_storage_root(address(f.store)));auto backend=take(open_native_sync_session_backend(root,address(f.left),address(f.right)));auto* raw=backend.get();SyncDigest policy{};policy[0]=std::byte{31};auto session=take(SyncSession::open(std::move(backend),policy));CHECK(session->commit(0,{},true).value());CHECK(session->snapshot().generation==1);
 const auto baseline=stored(f,".baseline");watch::reset(root.get(),allocation_failure);watch::pin(baseline);watch::armed=true;bool threw=false,accepted=false;
 try{if(oversized){
#ifdef _WIN32
 auto units=baseline.substr(baseline.find_last_of(L'\\')+1);std::string name(units.begin(),units.end());
#else
 auto name=baseline.substr(baseline.find_last_of('/')+1);
#endif
 auto result=raw->read(name,0);accepted=result.value()!=nullptr;}else {auto result=session->refresh();accepted=result.value()!=nullptr;}}catch(const std::bad_alloc&){threw=true;}
 watch::oom=false;CHECK(watch::hits==1&&!accepted);CHECK(threw==allocation_failure);assert_first(root);if(allocation_failure){CHECK(watch::oom_attempts>0&&watch::first_allocation.code==watch::native_error);}
 CHECK(session->snapshot().generation==1);CHECK(!session->commit(1,{}).value());CHECK(!session->finish_io().value());CHECK(!session->finish_io().value());session.reset();reuse_check();CHECK(!root->finish_io().value());
 auto reopened=take(open_native_sync_session_backend(address(f.store),address(f.left),address(f.right)));
 auto loaded=take(SyncSession::open(std::move(reopened),policy));CHECK(loaded->snapshot().generation==1);CHECK(loaded->finish_io().value());
 std::printf("PASS native baseline read close consumed once oom=%d oversized=%d Root-first no cache advance\n",allocation_failure,oversized);
}
void stage_case(bool allocation_failure){
 Fixture f;auto root=take(acquire_native_sync_storage_root(address(f.store)));watch::reset(root.get(),allocation_failure);
 SyncSessionFaults faults;faults.before=[&](SyncSessionIo io){if(io==SyncSessionIo::FileClose){
#ifdef _WIN32
 watch::pin(f.store+L"\\probe.next");
#else
 watch::pin(f.store+"/probe.next");
#endif
 watch::armed=true;}return true;};
 auto backend=take(open_native_sync_session_backend(root,address(f.left),address(f.right),faults));
 std::array<std::byte,3> bytes{std::byte{1},std::byte{2},std::byte{3}};bool threw=false,accepted=false;
 try{auto result=backend->stage("probe.next",bytes);accepted=result.value()!=nullptr;}catch(const std::bad_alloc&){threw=true;}
 watch::oom=false;CHECK(watch::hits==1&&!accepted&&threw==allocation_failure);assert_first(root);
 if(allocation_failure)CHECK(watch::oom_attempts>0&&watch::first_allocation.code==watch::native_error);
 CHECK(!backend->publish("probe.next","probe.baseline").value());CHECK(!backend->finish_io().value());backend.reset();reuse_check();CHECK(!root->finish_io().value());
 std::printf("PASS native flushed writer close consumed once oom=%d Root-first publication blocked\n",allocation_failure);
}
#ifdef _WIN32
void lock_case(){
 Fixture f;auto root=take(acquire_native_sync_storage_root(address(f.store)));auto backend=take(open_native_sync_session_backend(root,address(f.left),address(f.right)));
 watch::reset(root.get(),false);watch::mutex_closes=0;watch::arm_mutex=true;
 CHECK(!backend->finish_io().value());CHECK(!watch::arm_mutex&&watch::mutex_closes==1);assert_first(root);
 CHECK(!backend->finish_io().value());CHECK(watch::mutex_closes==1);backend.reset();CHECK(!root->finish_io().value());
 Fixture other;auto next=take(open_native_sync_session_backend(address(other.store),address(f.left),address(f.right)));CHECK(next->finish_io().value());std::puts("PASS native released volume mutex close failure Root-first cached and lock reacquired");
}
#endif
void terminal_case(){
 Fixture f;auto root=take(acquire_native_sync_storage_root(address(f.store)));bool observed=false;SyncSessionFaults faults;faults.before=[&](SyncSessionIo io){if(io==SyncSessionIo::NativeHandleClose&&watch::hits){assert_first(root);observed=true;detail::record_prepared_journal_consumer_failure(*root,ObservationState::Failed,ErrorDomain::Adapter,99,"test.later_callback");throw std::bad_alloc();}return true;};
 auto backend=take(open_native_sync_session_backend(root,address(f.left),address(f.right),faults));watch::reset(root.get(),false);watch::pin(f.left);watch::armed=true;CHECK(!backend->finish_io().value());CHECK(observed&&watch::hits==1);assert_first(root);CHECK(!backend->finish_io().value());backend.reset();reuse_check();CHECK(!root->finish_io().value());
 Fixture other;auto next=take(open_native_sync_session_backend(address(other.store),address(f.left),address(f.right)));CHECK(next->finish_io().value());std::puts("PASS native directory close Root-first before throwing callback and locks released");
}
}
int main(){try{read_case(false,false);read_case(true,false);read_case(false,true);read_case(true,true);stage_case(false);stage_case(true);terminal_case();
#ifdef _WIN32
lock_case();
#endif
std::printf("sync_session close: %u checks PASS\n",checks);return 0;}catch(const std::exception& e){watch::oom=false;std::fprintf(stderr,"session close: %s\n",e.what());return 1;}}
