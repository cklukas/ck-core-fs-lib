// SOURCE-ONLY DRAFT: exact fc56 base; no runtime qualification.
#pragma once
#ifndef _WIN32
#error Windows native test only
#endif
#ifndef CK_FS_NATIVE_CLOSE_TEST_HOOKS
#error Rebuild the ENTIRE SDK and every client TU with BUILD_TESTING=ON
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include "operation_journal_file.hpp"
#include "directory_cursor.hpp"
#include "platform/native_close_test_faults.hpp"
#include "windows_name.hpp"
#include "platform/native_journal_directory_bridge.hpp"
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <new>
#include <filesystem>
#include <string>
#include <vector>

namespace reader_fault {
using namespace ck::files;
inline std::atomic<unsigned> checks{0};
inline void check(bool okay,const char* text,unsigned line) noexcept {
    ++checks;if(!okay){std::fprintf(stderr,"FAIL reader_close line=%u %s win32=%lu\n",line,text,GetLastError());std::abort();}
}
#define REQUIRE(x) ::reader_fault::check(bool(x),#x,__LINE__)
template<class T>T take(Observation<T> value){REQUIRE(value.value());return std::move(value).take_value();}
inline void okay(Observation<bool> value){REQUIRE(value.value()&&*value.value());}
inline std::wstring extended(const std::wstring& value){auto path=windows_extended_path(value);REQUIRE(path);return *path;}
inline NativeAbsolutePath address(const std::wstring& value){return take(NativeAbsolutePath::from_host(std::filesystem::path(value)));}
inline NativeName basename(){return *NativeName::from_windows(u".ck-copy-journal-close-test");}
inline constexpr char file_tag[]="journal_reader.CloseHandle";
inline constexpr char parent_tag[]="journal_reader.parent_CloseHandle";
inline constexpr char root_tag[]="journal_reader.root_CloseHandle";
inline bool final_tag(const char* value)noexcept{return !std::strcmp(value,file_tag)||!std::strcmp(value,parent_tag)||!std::strcmp(value,root_tag);}
inline bool same_id(const FILE_ID_INFO& a,const FILE_ID_INFO& b)noexcept{
    return a.VolumeSerialNumber==b.VolumeSerialNumber&&!std::memcmp(a.FileId.Identifier,b.FileId.Identifier,16);
}
inline FILE_ID_INFO identity(HANDLE handle){FILE_ID_INFO value{};REQUIRE(GetFileInformationByHandleEx(handle,FileIdInfo,&value,sizeof(value)));return value;}
inline std::atomic<DWORD> failing_thread{0};
inline std::atomic<unsigned> allocation_failures{0};
inline void allocation(){if(failing_thread.load(std::memory_order_acquire)==GetCurrentThreadId()){
    allocation_failures.fetch_add(1,std::memory_order_relaxed);throw std::bad_alloc();}}
inline void stop_oom()noexcept{failing_thread.store(0,std::memory_order_release);}

struct Fixture {
    std::wstring root,file,provider;
    FILE_ID_INFO root_id{},file_id{};
    HANDLE security_owner=INVALID_HANDLE_VALUE;
    std::vector<std::byte> descriptor;
    std::vector<std::wstring> created;
    bool privacy_dirty=false;
    explicit Fixture(std::wstring parent,std::wstring expected,bool long_raw):provider(std::move(expected)){
        REQUIRE(!IsDebuggerPresent());REQUIRE(provider==L"NTFS"||provider==L"ReFS");
        auto p=extended(parent);wchar_t volume[32]{};
        HANDLE base=CreateFileW(p.c_str(),FILE_READ_ATTRIBUTES,7,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        REQUIRE(base!=INVALID_HANDLE_VALUE);REQUIRE(GetVolumeInformationByHandleW(base,nullptr,0,nullptr,nullptr,nullptr,volume,32));REQUIRE(provider==volume);REQUIRE(CloseHandle(base));
        wchar_t require_v[4]{};if(GetEnvironmentVariableW(L"CK_FS_REQUIRE_V_DEV_DRIVE",require_v,4)==1&&require_v[0]==L'1')REQUIRE(p.starts_with(L"\\\\?\\V:\\tmp\\"));
        HANDLE token=nullptr;REQUIRE(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token));DWORD count=0;
        GetTokenInformation(token,TokenUser,nullptr,0,&count);std::vector<std::byte> token_bytes(count);
        REQUIRE(GetTokenInformation(token,TokenUser,token_bytes.data(),count,&count));REQUIRE(CloseHandle(token));
        wchar_t* sid=nullptr;REQUIRE(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(token_bytes.data())->User.Sid,&sid));
        const auto sddl=L"O:"+std::wstring(sid)+L"D:P(A;;FA;;;"+sid+L")(A;;FA;;;SY)";LocalFree(sid);
        PSECURITY_DESCRIPTOR sd=nullptr;REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr));
        descriptor.assign(static_cast<std::byte*>(sd),static_cast<std::byte*>(sd)+GetSecurityDescriptorLength(sd));LocalFree(sd);
        root=p+L"\\reader-close-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());add(root);
        if(long_raw){for(unsigned i=0;root.size()<420;++i){root+=L"\\native-\u03bb-"+std::wstring(64,L'x')+std::to_wstring(i);add(root);}root+=L"\\raw-";root.push_back(wchar_t(0xd800));add(root);REQUIRE(root.size()>420);}
        security_owner=CreateFileW(root.c_str(),FILE_READ_ATTRIBUTES|READ_CONTROL|WRITE_DAC,7,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        REQUIRE(security_owner!=INVALID_HANDLE_VALUE);root_id=identity(security_owner);
        okay(prepare_native_operation_journal_root(address(root)));
        auto writer=take(open_native_operation_journal_file(address(root),basename(),true));
        const std::array<std::byte,16> torn{};REQUIRE(take(writer->write_at(0,torn))==torn.size());okay(writer->flush());okay(writer->finish_io());
        file=root+L"\\.ck-copy-journal-close-test";
        HANDLE pin=CreateFileW(file.c_str(),FILE_READ_ATTRIBUTES,7,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        REQUIRE(pin!=INVALID_HANDLE_VALUE);file_id=identity(pin);REQUIRE(CloseHandle(pin));
    }
    void add(const std::wstring& value){SECURITY_ATTRIBUTES sa{sizeof(sa),descriptor.data(),FALSE};REQUIRE(CreateDirectoryW(value.c_str(),&sa));created.push_back(value);}
    void invalidate_privacy(){REQUIRE(SetSecurityInfo(security_owner,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS);privacy_dirty=true;}
    void restore_privacy(){if(!privacy_dirty)return;BOOL present=FALSE,defaulted=FALSE;PACL acl=nullptr;REQUIRE(GetSecurityDescriptorDacl(descriptor.data(),&present,&acl,&defaulted)&&present);REQUIRE(SetSecurityInfo(security_owner,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,acl,nullptr)==ERROR_SUCCESS);privacy_dirty=false;}
    ~Fixture(){stop_oom();restore_privacy();REQUIRE(CloseHandle(security_owner));REQUIRE(DeleteFileW(file.c_str()));for(auto i=created.rbegin();i!=created.rend();++i)REQUIRE(RemoveDirectoryW(i->c_str()));}
};

struct Watch {
    FILE_ID_INFO expected{},seen{};
    const char* operation=nullptr;
    const wchar_t* provider=nullptr;
    bool native_failure=false,oom=false,control=false;
    HANDLE selected=nullptr,reused=nullptr;
    unsigned selected_before=0,selected_after=0,final_closes=0,retries=0;
    unsigned test_repairs=0;
    bool real_ok=false;DWORD real_error=0;
    std::atomic<unsigned> writes{0},flushes{0};
    static inline std::atomic<Watch*> current{nullptr};
    static void io(detail::NativeTestIo kind)noexcept{
        if(auto* self=current.load(std::memory_order_acquire)){if(kind==detail::NativeTestIo::Write)++self->writes;if(kind==detail::NativeTestIo::Flush)++self->flushes;}
    }
    static void before(void* raw,const char* tag,const char*)noexcept{
        auto* self=current.load(std::memory_order_acquire);if(!self)return;
        if(final_tag(tag))++self->final_closes;
        if(self->reused&&raw==self->reused)++self->retries;
        if(std::strcmp(tag,self->operation))return;
        FILE_ID_INFO id{};if(!GetFileInformationByHandleEx(raw,FileIdInfo,&id,sizeof(id))||!same_id(id,self->expected))return;
        FILE_STANDARD_INFO standard{};wchar_t fs[32]{};
        REQUIRE(GetFileInformationByHandleEx(raw,FileStandardInfo,&standard,sizeof(standard)));
        REQUIRE(bool(standard.Directory)==bool(std::strcmp(tag,file_tag)));
        REQUIRE(GetVolumeInformationByHandleW(raw,nullptr,0,nullptr,nullptr,nullptr,fs,32)&&std::wcscmp(fs,self->provider)==0);
        self->selected=raw;self->seen=id;++self->selected_before;
        if(self->native_failure)REQUIRE(SetHandleInformation(raw,HANDLE_FLAG_PROTECT_FROM_CLOSE,HANDLE_FLAG_PROTECT_FROM_CLOSE));
    }
    static std::uint32_t after(void* raw,const char* tag,bool real_ok,std::uint32_t real_error)noexcept{
        auto* self=current.load(std::memory_order_acquire);if(!self||raw!=self->selected||std::strcmp(tag,self->operation))return 0;
        ++self->selected_after;self->real_ok=real_ok;self->real_error=real_error;
        if(real_ok&&!self->control)self->reuse();
        if(self->oom)failing_thread.store(GetCurrentThreadId(),std::memory_order_release);
        return self->control?0:ERROR_WRITE_FAULT; // Real failure6 must beat injected29.
    }
    void reuse()noexcept{
        HANDLE candidates[512]{};unsigned count=0;
        while(count<512){auto h=CreateEventW(nullptr,TRUE,FALSE,nullptr);REQUIRE(h);candidates[count++]=h;if(h==selected){reused=h;break;}}
        REQUIRE(reused);for(unsigned i=0;i<count;++i)if(candidates[i]!=reused)REQUIRE(CloseHandle(candidates[i]));
    }
    void begin(const Fixture& fixture,const char* tag,bool native,bool fail_alloc,bool pass){
        expected=std::strcmp(tag,file_tag)==0?fixture.file_id:fixture.root_id;operation=tag;provider=fixture.provider.c_str();native_failure=native;oom=fail_alloc;control=pass;
        allocation_failures=0;current.store(this,std::memory_order_release);
        detail::native_test_io_observer.store(io);detail::native_close_test_before.store(before);detail::native_close_test_after.store(after);
    }
    void recover_failed_native_handle()noexcept{
        REQUIRE(native_failure&&!real_ok&&real_error==ERROR_INVALID_HANDLE);
        DWORD flags=0;REQUIRE(GetHandleInformation(selected,&flags)&&(flags&HANDLE_FLAG_PROTECT_FROM_CLOSE));
        // Fixture repair ONLY after adapter disowned it. Production must never retry.
        REQUIRE(SetHandleInformation(selected,HANDLE_FLAG_PROTECT_FROM_CLOSE,0));REQUIRE(CloseHandle(selected));++test_repairs;reuse();
    }
    void assert_no_retry(unsigned closes)noexcept{REQUIRE(final_closes==closes&&selected_before==1&&selected_after==1&&retries==0);}
    void assert_event()const noexcept{REQUIRE(reused&&SetEvent(reused)&&WaitForSingleObject(reused,0)==WAIT_OBJECT_0);}
    void end()noexcept{current.store(nullptr);detail::native_test_io_observer.store(nullptr);detail::native_close_test_before.store(nullptr);detail::native_close_test_after.store(nullptr);stop_oom();if(reused){REQUIRE(CloseHandle(reused));reused=nullptr;}}
};
inline void writer_counter_control(Fixture& fixture){
    Watch count;count.begin(fixture,file_tag,false,false,true);
    auto writer=take(open_native_operation_journal_file(address(fixture.root),basename(),false));
    const std::array<std::byte,16> value{};REQUIRE(take(writer->write_at(0,value))==value.size());okay(writer->flush());okay(writer->finish_io());
    REQUIRE(count.writes>0&&count.flushes>0);count.end();
}
inline void expect_failure(const Observation<bool>& result,DWORD code,const char* operation){REQUIRE(!result.value());const auto& e=*result.unavailable_detail();REQUIRE(e.state==ObservationState::Failed&&e.error.domain==ErrorDomain::Win32&&e.error.code==code&&e.error.operation==operation);}
// Captured from genuine native provider validation, never a caller-synthesized
// authority. This is diagnostic POD only and remains readable during C++ OOM.
struct FailureTuple {
    ObservationState state=ObservationState::Unknown;
    ErrorDomain domain=ErrorDomain::None;
    std::int64_t code=0;
    std::array<char,192> operation{};
};
FailureTuple capture_failure(const UnavailableObservation& error) noexcept;
void expect_same_failure(const Observation<bool>& result,const FailureTuple& first) noexcept;
void report_first_validation(const FailureTuple& first) noexcept;
// Before repair: selected protected OS HANDLE must still exist; the adapter
// has relinquished ownership but the OS did NOT consume this failed close.
void assert_physical_close_state(const Watch& watch) noexcept;
void report_binding(const Watch& watch) noexcept;
} // namespace reader_fault
