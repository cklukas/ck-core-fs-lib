// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_capture_job.hpp"
#include "native_main_content_job.hpp"
#include "sha256.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "held_child.hpp"
#ifdef _WIN32
#include "platform/native_journal_directory_bridge.hpp"
#include "native_read_close_capture_fixture.hpp"
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
#include "platform/legacy_native_fixture_observation.hpp"
#endif
#endif
#include "metadata_semantic_digest.hpp"
#include "native_sync_observation.hpp"
#include "native_filesystem.hpp"
#include "windows_name.hpp"
#include <atomic>
#include <bit>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>
#ifdef _WIN32
#include <windows.h>
#include "windows_test_runtime_self_report.hpp"
#include <sddl.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <dlfcn.h>
#ifdef __APPLE__
#include <sys/mount.h>
#endif
#endif
using namespace ck::files;
namespace {
void check(bool b,const char*m){if(!b)throw std::runtime_error(m);}
template<class T>T take(Observation<T>o){if(!o.value()){const auto&e=*o.unavailable_detail();throw std::runtime_error(e.error.operation+":"+std::to_string(e.error.code));}return std::move(o).take_value();}
std::atomic<bool> throw_after_read{false};
std::atomic<unsigned> native_reads{0},advance_reads{0};std::atomic<bool> frame{false};std::atomic<std::size_t> frame_limit{0};
#ifdef _WIN32
std::stop_source* cancel_read=nullptr;
FILE_ID_INFO close_target{};std::atomic<bool> close_armed{false},close_watch{false};std::atomic<unsigned> close_hits{0},selected_closes{0};
// This job is advanced on the invoking thread. The callback only records a
// successful real read and arms a later ordinary C++ allocation; it never
// allocates, throws, changes native results, or exempts vendor allocations.
thread_local bool allocation_after_native_read=false,allocation_denied_in_step=false;
thread_local unsigned allocation_denials=0,allocation_read_arms=0,allocation_reader_closes=0;
thread_local void* allocation_read_handle=nullptr;
thread_local std::uint32_t allocation_read_requested=0,allocation_read_copied=0;
thread_local bool selected_close_pending=false;
void capture_close_before(void* raw,const char*,const char*) noexcept {
 selected_close_pending=false;
 if(close_watch){FILE_ID_INFO id{};selected_close_pending=GetFileInformationByHandleEx(static_cast<HANDLE>(raw),FileIdInfo,&id,sizeof(id))&&id.VolumeSerialNumber==close_target.VolumeSerialNumber&&!std::memcmp(id.FileId.Identifier,close_target.FileId.Identifier,16);}
}
std::uint32_t capture_close_after(void* raw,const char* operation,bool succeeded,std::uint32_t) noexcept {
 const bool selected=std::exchange(selected_close_pending,false);
 if(selected&&succeeded){
  ++selected_closes;
  if(raw==allocation_read_handle&&std::strcmp(operation,"metadata_capture.source_CloseHandle")==0)++allocation_reader_closes;
  if(close_armed.exchange(false)){++close_hits;return ERROR_READ_FAULT;}
 }
 return 0; // The adapter keeps a real failure even if a callback requests a fault.
}
std::atomic<bool> native_read_violation{false};
void capture_read_after(void* raw,detail::NativeReadPhase phase,std::uint32_t requested,std::uint32_t copied,bool succeeded,std::uint32_t,const char*) noexcept {
 if(phase==detail::NativeReadPhase::Request){
  ++native_reads;
  if(frame){++advance_reads;if(requested>frame_limit)native_read_violation=true;}
  // Preserve request-boundary cancellation, including FALSE/ERROR_IO_PENDING.
  if(cancel_read&&frame){auto* source=cancel_read;cancel_read=nullptr;source->request_stop();}
 }
 if(phase==detail::NativeReadPhase::Completion&&succeeded&&frame&&throw_after_read.exchange(false)){
  allocation_read_handle=raw;allocation_read_requested=requested;allocation_read_copied=copied;
  ++allocation_read_arms;allocation_after_native_read=true; // No code here allocates.
 }
}


#endif
#ifndef _WIN32
std::atomic<bool> close_armed{false},close_watch{false};std::atomic<unsigned> close_hits{0},selected_closes{0};dev_t close_device{};ino_t close_inode{};
ssize_t watched_pread(int fd,void* data,size_t n,off_t offset){using F=ssize_t(*)(int,void*,size_t,off_t);static const auto fn=std::bit_cast<F>(dlsym(RTLD_NEXT,"pread"));check(fn!=nullptr,"native pread resolve");++native_reads;if(frame){++advance_reads;check(n<=frame_limit,"native pread exceeded chunk");}const auto result=fn(fd,data,n,offset);if(frame&&throw_after_read.exchange(false))throw std::bad_alloc();return result;}
int watched_close(int fd){using F=int(*)(int);static const auto fn=std::bit_cast<F>(dlsym(RTLD_NEXT,"close"));bool selected=false;if(close_watch){struct stat s{};selected=!fstat(fd,&s)&&s.st_dev==close_device&&s.st_ino==close_inode;}const auto r=fn(fd);const auto e=errno;if(selected&&r==0){++selected_closes;if(close_armed.exchange(false)){++close_hits;errno=EIO;return -1;}}errno=e;return r;}
#endif
#ifdef _WIN32
std::optional<std::wstring> wide_environment(const wchar_t* name) {
 SetLastError(ERROR_SUCCESS);const DWORD size=GetEnvironmentVariableW(name,nullptr,0);
 if(!size) {
  check(GetLastError()==ERROR_SUCCESS||GetLastError()==ERROR_ENVVAR_NOT_FOUND,"environment size query");
  return std::nullopt;
 }
 check(size<=32768,"environment value exceeds native bound");
 std::wstring value(size,L'\0');const DWORD count=GetEnvironmentVariableW(name,value.data(),size);
 check(count>0&&count<size,"environment changed during capture");value.resize(count);return value;
}
#endif
struct Fixture{
 NativeFileSystem fs;std::shared_ptr<const DirectoryCursor> directory;std::vector<std::byte> main;
#ifdef _WIN32
 std::wstring root;std::vector<std::wstring> parents;
 Fixture(){const auto t=wide_environment(L"TEMP"),u=wide_environment(L"TMP");check(t&&u,"explicit Windows TEMP/TMP required");root=*windows_extended_path(*t);const auto tmp=*windows_extended_path(*u);if(const auto v=wide_environment(L"CK_FS_REQUIRE_V_DEV_DRIVE");v&&*v==L"1")check(root.starts_with(L"\\\\?\\V:\\tmp\\")&&tmp.starts_with(L"\\\\?\\V:\\tmp\\"),"V temp required");static unsigned sequence=0;root+=L"\\progressive-metadata-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(sequence++);for(unsigned i=0;i<5;++i){if(i)root+=L"\\"+std::wstring(70,wchar_t(L'a'+i));check(CreateDirectoryW(root.c_str(),nullptr)!=0,"fixture mkdir");parents.push_back(root);}directory=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(root)));WCHAR name[32]{};HANDLE h=CreateFileW(root.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE&&GetVolumeInformationByHandleW(h,nullptr,0,nullptr,nullptr,nullptr,name,32),"fixture volume");check(CloseHandle(h)!=0,"fixture volume close");const auto expected=wide_environment(L"CK_METADATA_CAPTURE_EXPECT_FS");check((!expected||*expected==name)&&(std::wstring_view(name)==L"NTFS"||std::wstring_view(name)==L"ReFS"),"fixture filesystem mismatch");std::cout<<"actual progressive provider=";for(auto*p=name;*p;++p)std::cout<<char(*p);std::cout<<" path="<<root.size()<<'\n';init();}
 void data(std::u16string suffix,std::span<const std::byte>b){const auto p=root+L"\\a"+std::wstring(suffix.begin(),suffix.end());HANDLE h=CreateFileW(p.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,CREATE_ALWAYS,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE,"fixture data create");DWORD n=0;check(b.size()<=MAXDWORD&&WriteFile(h,b.data(),DWORD(b.size()),&n,nullptr)&&n==b.size()&&FlushFileBuffers(h),"fixture data write");check(CloseHandle(h)!=0,"fixture data close");}
 FILE_BASIC_INFO times(){HANDLE h=CreateFileW((root+L"\\a").c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);FILE_BASIC_INFO t{};check(h!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(h,FileBasicInfo,&t,sizeof(t)),"fixture times");check(CloseHandle(h)!=0,"times close");return t;}
 void restore(FILE_BASIC_INFO t){HANDLE h=CreateFileW((root+L"\\a").c_str(),FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE&&SetFileInformationByHandle(h,FileBasicInfo,&t,sizeof(t)),"fixture restore");check(CloseHandle(h)!=0,"restore close");}
 ~Fixture(){directory.reset();DeleteFileW((root+L"\\moved").c_str());check(DeleteFileW((root+L"\\a").c_str())!=0,"fixture delete");for(auto p=parents.rbegin();p!=parents.rend();++p)check(RemoveDirectoryW(p->c_str())!=0,"fixture rmdir");}
#else
 std::string root;
 Fixture(){const auto*t=std::getenv("TMPDIR");check(t&&*t,"explicit TMPDIR required");root=std::string(t)+"/progressive-metadata.XXXXXX";check(mkdtemp(root.data())!=nullptr,"fixture mkdtemp");directory=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(root)));init();}
 void data(std::u16string suffix,std::span<const std::byte>b){check(suffix.empty(),"POSIX named stream fixture unsupported");int fd=open((root+"/a").c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);check(fd>=0,"fixture data open");std::size_t n=0;while(n<b.size()){auto wrote=write(fd,b.data()+n,b.size()-n);check(wrote>0,"fixture write");n+=std::size_t(wrote);}check(!fsync(fd)&&!close(fd),"fixture finish");}
 ~Fixture(){directory.reset();unlink((root+"/moved").c_str());check(!unlink((root+"/a").c_str())&&!rmdir(root.c_str()),"fixture cleanup");}
#endif
 void init(){main.resize(131073);for(std::size_t i=0;i<main.size();++i)main[i]=std::byte(i%251);data({},main);
#ifdef _WIN32

#endif
 }
 std::shared_ptr<const OpenedEntry> source(bool full=false){auto access=EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity;if(full)access=access|EntryAccess::MetadataAndFullSecurity;
#ifdef _WIN32
 auto n=*NativeName::from_windows(u"a");
#else
 auto n=*NativeName::from_posix("a");
#endif
 return std::shared_ptr<const OpenedEntry>(take(directory->open_child(n,access)));}
};
#ifndef _WIN32
// Exact POSIX name construction for the native fixture above.
#endif

NativeName name(){
#ifdef _WIN32
 return *NativeName::from_windows(u"a");
#else
 return *NativeName::from_posix("a");
#endif
}
HeldChild::Pointer held(Fixture&f){return take(HeldChild::observe_with_access(f.directory,name(),EntryAccess::ContentRead));}
struct RootLatch final:MetadataCaptureFailureLatch{
 PreparedJournalRoot::Pointer root;
 mutable std::optional<MetadataCaptureCleanupError> first;
 explicit RootLatch(PreparedJournalRoot::Pointer r):root(std::move(r)){}
 void record_first(MetadataCaptureCleanupError e)const noexcept override{
  if(!first)first=e;
  if(root)detail::record_prepared_journal_consumer_failure(*root,e.state,e.domain,e.code,e.operation);
 }
};
Observation<NativeMainContentAdvance> step(NativeMainContentJob&j,std::stop_token token={}){
 advance_reads=0;frame_limit=1024;frame=true;
 try{auto r=j.advance(token);frame=false;
#ifdef _WIN32
check(!native_read_violation,"native read exceeded configured chunk");
#endif
check(advance_reads<=1,"more than one actual native read per advance");
 if(r.value())check(r.value()->content_reads==advance_reads&&r.value()->content_bytes<=1024,"reported read bound mismatch");return r;
 }catch(...){frame=false;throw;}
}
void ready(NativeMainContentJob&j){for(unsigned i=0;i<200000;++i){take(step(j));if(j.progress().phase==NativeMainContentPhase::DataReady)return;}throw std::runtime_error("producer did not finish");}
void basic_test(){Fixture f;auto h=held(f);auto j=take(NativeMainContentJob::begin_held(h,{{1024},f.main.size()}));
 check(!j->result().value(),"proof before read/close");ready(*j);check(!j->result().value(),"data-ready leaked proof before fallible close");
 check(j->progress().read_bytes==f.main.size()*2,"two passes not read");const auto calls=native_reads.load();take(j->finish_read());auto proof=take(j->result());
 Sha256 sha;sha.update(f.main);check(proof->main_digest()==sha.digest()&&proof->main_bytes()==f.main.size()&&proof->schema()==1,"main content proof wrong");
 take(j->finish_read());j.reset();check(proof->main_digest()==sha.digest()&&native_reads==calls,"closed value proof did I/O");
 auto l=NativeMainContentLimits{{1024},f.main.size()-1};const auto before=native_reads.load();check(!NativeMainContentJob::begin_held(h,l).value()&&native_reads==before,"budget hashed before admission");
 auto metadata_only=take(HeldChild::observe(f.directory,name()));check(!NativeMainContentJob::begin_held(metadata_only).value(),"missing content access accepted");
 f.main.clear();f.data({},{});h=held(f);j=take(NativeMainContentJob::begin_held(h));ready(*j);take(j->finish_read());Sha256 empty;check(take(j->result())->main_digest()==empty.digest(),"empty SHA wrong");
 std::cout<<"two-pass bounded main-only native proof, prehash budget, closed no-I/O values, access refusal and empty main PASS\n";
}
void changed_test(){Fixture f;auto h=held(f);auto j=take(NativeMainContentJob::begin_held(h,{{1024},f.main.size()}));
 while(j->progress().pass!=2)take(step(*j));
#ifdef _WIN32
 const auto times=f.times();
#endif
 f.main[0]^=std::byte{1};f.data({},f.main);
#ifdef _WIN32
 f.restore(times);
#endif
 Observation<NativeMainContentAdvance> result=Observation<NativeMainContentAdvance>::available({NativeMainContentPhase::Basic});
 for(unsigned i=0;i<200000&&result.value()&&j->progress().phase!=NativeMainContentPhase::DataReady;++i)result=step(*j);
 check(!result.value()&&!j->result().value(),"changed between passes accepted");take(j->finish_read());
 j.reset();h=held(f);j=take(NativeMainContentJob::begin_held(h,{{1024},f.main.size()}));take(step(*j));
#ifdef _WIN32
 check(MoveFileExW((f.root+L"\\a").c_str(),(f.root+L"\\moved").c_str(),0),"replace held rename");
#else
 check(!rename((f.root+"/a").c_str(),(f.root+"/moved").c_str()),"replace held rename");
#endif
 f.data({},f.main);auto replaced=step(*j);check(!replaced.value()&&!j->result().value(),"membership replacement accepted");take(j->finish_read());
 std::cout<<"between-pass mutation and held-family replacement refused; actual source drained PASS\n";
}
void factory_close_test(){Fixture f;auto h=held(f);auto latch=std::make_shared<RootLatch>(nullptr);
#ifdef _WIN32
 HANDLE file=CreateFileW((f.root+L"\\a").c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
 check(file!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(file,FileIdInfo,&close_target,sizeof(close_target)),"factory-close target");check(CloseHandle(file),"factory-close setup close");
#else
 struct stat st{};check(!stat((f.root+"/a").c_str(),&st),"factory-close target");close_device=st.st_dev;close_inode=st.st_ino;
#endif
 close_hits=0;selected_closes=0;close_watch=true;close_armed=true;
 auto job=NativeMainContentJob::begin_held(h,{{1024},0},{},latch);close_armed=false;close_watch=false;
 check(!job.value()&&close_hits==1&&latch->first,"factory admission failure lost actual reader close error");
 check(job.unavailable_detail()->error.domain==latch->first->domain&&job.unavailable_detail()->error.code==latch->first->code,"factory admission error masked first native close failure");
 std::cout<<"factory failure explicitly drains clone; native close failure precedes admission error without allocation-dependent sink PASS\n";
}
void close_test(bool cancel){Fixture f;auto h=held(f);
#ifdef _WIN32
 const auto root_path=f.root+L"\\private";check(CreateDirectoryW(root_path.c_str(),nullptr),"Root fixture mkdir");
#else
 const auto root_path=f.root+"/private";check(!mkdir(root_path.c_str(),0700),"Root fixture mkdir");
#endif
 auto root_address=take(NativeAbsolutePath::from_host(root_path));
 take(prepare_native_operation_journal_root(root_address));auto root=take(acquire_native_journal_root(root_address));
 auto scope=take(JournalScopeGuard::create_for_entry(root,*h));
 auto latch=std::make_shared<RootLatch>(root);auto j=take(NativeMainContentJob::begin_held(h,{{1024},f.main.size()},scope,latch));
 if(!cancel)ready(*j);else {take(step(*j));take(step(*j));}
#ifdef _WIN32
 HANDLE file=CreateFileW((f.root+L"\\a").c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
 check(file!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(file,FileIdInfo,&close_target,sizeof(close_target)),"close fault target");check(CloseHandle(file),"close fault setup close");
#else
 struct stat st{};check(!stat((f.root+"/a").c_str(),&st),"close fault target");close_device=st.st_dev;close_inode=st.st_ino;
#endif
 close_hits=0;selected_closes=0;close_watch=true;close_armed=true;
 if(cancel){std::stop_source stop;stop.request_stop();check(!step(*j,stop.get_token()).value(),"cancel accepted");}
 auto closed=j->finish_read();close_armed=false;close_watch=false;
 check(!closed.value()&&close_hits==1&&latch->first,"actual consumed close failure not latched");const auto consumed=selected_closes.load();
 check(!j->finish_read().value()&&!j->result().value()&&selected_closes==consumed,"close retried/failed proof escaped");
 detail::PreparedJournalConsumerFailure failure;check(detail::read_prepared_journal_consumer_failure(*root,failure)&&failure.code==latch->first->code,"genuine Root first POD missing");
 j.reset();latch.reset();scope.reset();h.reset();check(!root->finish_io().value(),"Root first consumer failure disappeared");root.reset();
#ifdef _WIN32
 check(RemoveDirectoryW(root_path.c_str()),"Root fixture rmdir");
#else
 check(!rmdir(root_path.c_str()),"Root fixture rmdir");
#endif
 std::cout<<"actual consumed close failure, idempotent drain, genuine Root first-POD latch and cancel precedence PASS cancel="<<cancel<<'\n';
}
#ifdef _WIN32
namespace dirty_native_observer {
thread_local DWORD incoming_error=0,post_error=0,close_post_error=0;
thread_local int incoming_errno=0,post_errno=0,close_post_errno=0;
thread_local unsigned before_calls=0,after_calls=0,detail_calls=0,completion_calls=0,close_calls=0;
thread_local bool matches=true,native_success=false,close_success=false;
void before(void*,detail::NativeTestIo op,std::uint32_t,const char*)noexcept {
 if(op!=detail::NativeTestIo::Read)return;
 ++before_calls;matches=matches&&GetLastError()==incoming_error&&errno==incoming_errno;
 SetLastError(ERROR_BAD_ENVIRONMENT);errno=ERANGE;
}
void after(void*,detail::NativeTestIo op,bool succeeded,std::uint32_t error,const char*)noexcept {
 if(op!=detail::NativeTestIo::Read)return;
 ++after_calls;post_error=GetLastError();post_errno=errno;native_success=succeeded;
 matches=matches&&(succeeded||error==post_error);
 SetLastError(ERROR_BAD_LENGTH);errno=EDOM;
}
void read_detail(void*,detail::NativeReadPhase phase,std::uint32_t,std::uint32_t,bool succeeded,std::uint32_t error,const char*)noexcept {
 if(phase==detail::NativeReadPhase::Request)++detail_calls;else if(phase==detail::NativeReadPhase::Completion)++completion_calls;else matches=false;
 matches=matches&&GetLastError()==post_error&&errno==post_errno&&succeeded==native_success&&
  (succeeded||error==post_error);
 SetLastError(ERROR_INVALID_NAME);errno=EINVAL;
}
void close_before(void*,const char*,const char*)noexcept {
 matches=matches&&GetLastError()==incoming_error&&errno==incoming_errno;
 SetLastError(ERROR_BAD_ENVIRONMENT);errno=ERANGE;
}
std::uint32_t close_after(void*,const char*,bool succeeded,std::uint32_t error)noexcept {
 ++close_calls;close_post_error=GetLastError();close_post_errno=errno;close_success=succeeded;
 matches=matches&&(succeeded||error==close_post_error);
 SetLastError(ERROR_BAD_LENGTH);errno=EDOM;
 return ERROR_WRITE_FAULT; // Additional failure ONLY after a genuine successful close.
}
struct Slots final {
 detail::NativeFileIoBefore old_before=detail::native_file_test_before.exchange(before);
 detail::NativeFileIoAfter old_after=detail::native_file_test_after.exchange(after);
 NativeCaptureFixtureScope capture{read_detail,close_before,close_after};
 ~Slots(){detail::native_file_test_before.store(old_before);detail::native_file_test_after.store(old_after);}
};
void reset()noexcept {
 incoming_error=ERROR_BUSY;incoming_errno=EBUSY;matches=true;
 before_calls=0;after_calls=0;detail_calls=0;completion_calls=0;close_calls=0;
 errno=incoming_errno;SetLastError(incoming_error);
}
} // namespace dirty_native_observer
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
namespace nested_legacy_observer {
thread_local unsigned before_count=0,after_count=0,pending_count=0;
thread_local bool pair_ok=true,raw_success=false;
thread_local DWORD raw_post_error=0;
thread_local int raw_post_errno=0;
thread_local std::uint32_t semantic_error=0;
void observe(const detail::LegacyNativeEvent& event)noexcept {
 using Op=detail::LegacyNativeOperation;using Phase=detail::LegacyNativePhase;
 if(event.operation!=Op::Read&&event.operation!=Op::Close)return;
 const DWORD actual_error=GetLastError();const int actual_errno=errno;
 if(event.phase==Phase::Before){++before_count;pair_ok=pair_ok&&actual_error==ERROR_BUSY&&actual_errno==EBUSY;}
 else if(event.phase==Phase::After){
  ++after_count;if(event.pending)++pending_count;
  raw_success=event.succeeded;semantic_error=event.native_error;raw_post_error=actual_error;raw_post_errno=actual_errno;
  pair_ok=pair_ok&&(event.succeeded||event.native_error==actual_error);
 }
 SetLastError(ERROR_INVALID_NAME);errno=EINVAL; // Deliberate observer damage only.
}
void reset()noexcept {before_count=0;after_count=0;pending_count=0;pair_ok=true;raw_success=false;semantic_error=0;}
struct Scope final {
 detail::LegacyNativeObserver previous=detail::legacy_native_test_observer.exchange(observe);
 ~Scope(){detail::legacy_native_test_observer.store(previous);}
};
}
#endif
// Deterministic pending I/O is kernel IPC, not a filesystem/provider claim.
// It uses the SAME checked ReadFile/GetOverlappedResult adapter helpers. No
// import/result substitution, clocks, sleeps, payload files or C:/D: writes.
namespace pending_native_observer {
struct Event {detail::NativeReadPhase phase;std::uint32_t requested,copied,error;bool succeeded;DWORD raw_error;int crt_error;};
thread_local Event events[8]{};
thread_local unsigned count=0,requests=0,completions=0,drains=0;
thread_local bool overflow=false;
void after(void*,detail::NativeReadPhase phase,std::uint32_t requested,std::uint32_t copied,bool succeeded,std::uint32_t error,const char*)noexcept {
 const DWORD raw=GetLastError();const int crt=errno;
 if(count<8)events[count++]={phase,requested,copied,error,succeeded,raw,crt};else overflow=true;
 if(phase==detail::NativeReadPhase::Request)++requests;
 if(phase==detail::NativeReadPhase::Completion&&succeeded)++completions;
 if(phase==detail::NativeReadPhase::Drain)++drains;
 SetLastError(ERROR_BAD_ENVIRONMENT);errno=ERANGE;
}
struct Pipe final {
 HANDLE server=INVALID_HANDLE_VALUE,client=INVALID_HANDLE_VALUE,event=nullptr;
 OVERLAPPED read{};std::byte bytes[16]{};bool pending=false;DWORD first_close_error=ERROR_SUCCESS;
 void finish()noexcept {
  if(pending){CancelIoEx(server,&read);DWORD ignored=0;GetOverlappedResult(server,&read,&ignored,TRUE);pending=false;}
  for(HANDLE* slot:{&event,&client,&server}){
   const HANDLE h=*slot;*slot=INVALID_HANDLE_VALUE;
   if(h&&h!=INVALID_HANDLE_VALUE&&!CloseHandle(h)&&first_close_error==ERROR_SUCCESS)first_close_error=GetLastError();
  }
 }
 ~Pipe(){finish();}
};
} // namespace pending_native_observer
void native_pending_phase_test(){
 using detail::NativeReadPhase;
 pending_native_observer::Pipe p;
 // A unique local named pipe is only an OS IPC endpoint; no on-disk test data.
 const std::wstring name=L"\\\\.\\pipe\\ckfs-capture-phase-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
 p.server=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
  PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,4096,4096,0,nullptr);
 check(p.server!=INVALID_HANDLE_VALUE,"genuine pending pipe create");
 p.event=CreateEventW(nullptr,TRUE,FALSE,nullptr);check(p.event!=nullptr,"genuine pending pipe event");
 p.client=CreateFileW(name.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
 check(p.client!=INVALID_HANDLE_VALUE,"genuine pending pipe connect client");
 OVERLAPPED connection{};connection.hEvent=p.event;
 const BOOL connected=ConnectNamedPipe(p.server,&connection);const DWORD connect_error=GetLastError();
 if(!connected&&connect_error==ERROR_IO_PENDING){DWORD ignored=0;check(GetOverlappedResult(p.server,&connection,&ignored,TRUE)!=0,"genuine pipe connection completion");}
 else check(connected||connect_error==ERROR_PIPE_CONNECTED,"genuine pipe connected state");
 check(ResetEvent(p.event)!=0,"pending event reset");p.read.hEvent=p.event;
 pending_native_observer::count=0;pending_native_observer::requests=0;pending_native_observer::completions=0;pending_native_observer::drains=0;pending_native_observer::overflow=false;
 {
  NativeCaptureFixtureScope observations(pending_native_observer::after);
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  nested_legacy_observer::Scope legacy_scope;nested_legacy_observer::reset();
#endif
  std::uint32_t copied=0;errno=EBUSY;SetLastError(ERROR_BUSY);
  const bool issued=detail::probe_native_capture_read(p.server,p.bytes,16,&copied,&p.read);
  const DWORD issue_error=GetLastError();const int issue_errno=errno;
  p.pending=!issued&&issue_error==ERROR_IO_PENDING;
  check(p.pending&&pending_native_observer::count==1&&pending_native_observer::requests==1&&pending_native_observer::completions==0,
   "genuine pending request was presented as completed data");
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  check(nested_legacy_observer::before_count==1&&nested_legacy_observer::after_count==1&&nested_legacy_observer::pending_count==1&&
   nested_legacy_observer::pair_ok&&!nested_legacy_observer::raw_success&&nested_legacy_observer::semantic_error==ERROR_IO_PENDING,
   "legacy layer turned the genuine pending request into completion");
#endif
  const auto issued_event=pending_native_observer::events[0];
  check(issued_event.phase==NativeReadPhase::Request&&!issued_event.succeeded&&issued_event.copied==0&&
   issued_event.error==ERROR_IO_PENDING&&issued_event.raw_error==issue_error&&issued_event.crt_error==issue_errno&&issue_errno==EBUSY,"pending native request pair changed by observer");
  errno=EBUSY;SetLastError(ERROR_BUSY);
  const bool early=detail::probe_native_capture_read_completion(p.server,&p.read,16,&copied,false,NativeReadPhase::Completion);
  const DWORD early_error=GetLastError();const int early_errno=errno;
  check(!early&&early_error==ERROR_IO_INCOMPLETE&&pending_native_observer::count==2&&pending_native_observer::requests==1&&pending_native_observer::completions==0,
   "incomplete GetOverlappedResult was double-counted/completed");
  const auto early_event=pending_native_observer::events[1];
  check(early_event.phase==NativeReadPhase::Pending&&!early_event.succeeded&&early_event.copied==0&&
   early_event.error==early_error&&early_event.raw_error==early_error&&early_event.crt_error==early_errno&&early_errno==EBUSY,"incomplete native pair changed by observer");
  const std::byte payload[16]{std::byte{1},std::byte{2},std::byte{3}};DWORD written=0;
  check(WriteFile(p.client,payload,sizeof(payload),&written,nullptr)&&written==sizeof(payload),"actual pending pipe write");
  errno=EBUSY;SetLastError(ERROR_BUSY);
  const bool completed=detail::probe_native_capture_read_completion(p.server,&p.read,16,&copied,true,NativeReadPhase::Completion);
  const DWORD completion_error=GetLastError();const int completion_errno=errno;p.pending=false;
  check(completed&&copied==16&&std::memcmp(p.bytes,payload,sizeof(payload))==0&&pending_native_observer::count==3&&
   pending_native_observer::requests==1&&pending_native_observer::completions==1,"genuine completion lost/double-counted native read");
  const auto completion=pending_native_observer::events[2];
  check(completion.phase==NativeReadPhase::Completion&&completion.succeeded&&completion.copied==16&&completion.raw_error==completion_error&&
   completion.crt_error==completion_errno&&completion_errno==EBUSY,"completed native pair changed by observer");
  check(ResetEvent(p.event)!=0,"cancel event reset");p.read={};p.read.hEvent=p.event;
  errno=EBUSY;SetLastError(ERROR_BUSY);
  const bool cancel_issued=detail::probe_native_capture_read(p.server,p.bytes,16,&copied,&p.read);
  const DWORD cancel_issue_error=GetLastError();p.pending=!cancel_issued&&cancel_issue_error==ERROR_IO_PENDING;
  check(p.pending&&pending_native_observer::requests==2&&pending_native_observer::completions==1,"cancel setup did not issue a genuine pending read");
  check(CancelIoEx(p.server,&p.read)!=0,"actual pending read cancellation request");
  errno=EBUSY;SetLastError(ERROR_BUSY);
  const bool drained=detail::probe_native_capture_read_completion(p.server,&p.read,16,&copied,true,NativeReadPhase::Drain);
  const DWORD drain_error=GetLastError();const int drain_errno=errno;p.pending=false;
  check(!drained&&drain_error==ERROR_OPERATION_ABORTED&&pending_native_observer::count==5&&pending_native_observer::requests==2&&
   pending_native_observer::completions==1&&pending_native_observer::drains==1&&!pending_native_observer::overflow,
   "cancel drain became completed content or another native read");
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  check(nested_legacy_observer::before_count==2&&nested_legacy_observer::after_count==2&&nested_legacy_observer::pending_count==2&&
   nested_legacy_observer::pair_ok,"legacy layer double-counted completion/drain as another ReadFile");
#endif
  const auto drain=pending_native_observer::events[4];
  check(drain.phase==NativeReadPhase::Drain&&!drain.succeeded&&drain.copied==0&&drain.error==drain_error&&
   drain.raw_error==drain_error&&drain.crt_error==drain_errno&&drain_errno==EBUSY,"drained native pair changed by observer");
 }
 p.finish();check(p.first_close_error==ERROR_SUCCESS,"pending control native handles failed close");
 std::cout<<"real pending/incomplete/completion/cancel-drain phases; request counted once, no early completion action, native error pairs PASS\n";
}
void native_error_state_test(){
 struct ProbeHandle final {
  HANDLE value;
  bool protected_from_close=false;
  bool finish() noexcept {
   if(value==INVALID_HANDLE_VALUE)return true;
   if(protected_from_close&&!SetHandleInformation(value,HANDLE_FLAG_PROTECT_FROM_CLOSE,0))return false;
   protected_from_close=false;
   return CloseHandle(std::exchange(value,INVALID_HANDLE_VALUE))!=FALSE;
  }
  ~ProbeHandle(){(void)finish();}
 };
 Fixture f;
 ProbeHandle readable{CreateFileW((f.root+L"\\a").c_str(),GENERIC_READ,
  FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};
 ProbeHandle attributes{CreateFileW((f.root+L"\\a").c_str(),FILE_READ_ATTRIBUTES,
  FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr)};
 check(readable.value!=INVALID_HANDLE_VALUE&&attributes.value!=INVALID_HANDLE_VALUE,"dirty observer genuine handles");
 {
  dirty_native_observer::Slots slots;
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  nested_legacy_observer::Scope legacy_scope;
#endif
  std::byte bytes[16]{};std::uint32_t copied=0;
  dirty_native_observer::reset();
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  nested_legacy_observer::reset();
#endif
  const bool read=detail::probe_native_capture_read(readable.value,bytes,static_cast<std::uint32_t>(sizeof(bytes)),&copied);
  const DWORD read_error=GetLastError();const int read_errno=errno;
  check(read&&copied==sizeof(bytes)&&std::memcmp(bytes,f.main.data(),sizeof(bytes))==0,"dirty observer changed genuine read bytes/result");
  check(dirty_native_observer::matches&&dirty_native_observer::native_success&&dirty_native_observer::before_calls==1&&
   dirty_native_observer::after_calls==1&&dirty_native_observer::detail_calls==1&&dirty_native_observer::completion_calls==1,"read observers did not see incoming/post-native pair");
  check(read_error==dirty_native_observer::post_error&&read_errno==dirty_native_observer::post_errno&&read_errno==EBUSY,"dirty read observers leaked LastError/errno");
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  check(nested_legacy_observer::pair_ok&&nested_legacy_observer::before_count==1&&nested_legacy_observer::after_count==1&&
   nested_legacy_observer::raw_success&&nested_legacy_observer::raw_post_error==dirty_native_observer::post_error&&
   nested_legacy_observer::raw_post_errno==dirty_native_observer::post_errno,"nested legacy read observer changed raw native pair/count");
#endif
  dirty_native_observer::reset();
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  nested_legacy_observer::reset();
#endif
  const bool denied=detail::probe_native_capture_read(attributes.value,bytes,static_cast<std::uint32_t>(sizeof(bytes)),&copied);
  const DWORD denied_error=GetLastError();const int denied_errno=errno;
  check(!denied&&!dirty_native_observer::native_success&&denied_error==ERROR_ACCESS_DENIED,"real attribute-only ReadFile refusal changed");
  check(dirty_native_observer::matches&&dirty_native_observer::before_calls==1&&dirty_native_observer::after_calls==1&&
   dirty_native_observer::detail_calls==1&&dirty_native_observer::completion_calls==1&&denied_error==dirty_native_observer::post_error&&
   denied_errno==dirty_native_observer::post_errno&&denied_errno==EBUSY,"real read error pair lost to observer");
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  check(nested_legacy_observer::pair_ok&&nested_legacy_observer::before_count==1&&nested_legacy_observer::after_count==1&&
   !nested_legacy_observer::raw_success&&nested_legacy_observer::semantic_error==ERROR_ACCESS_DENIED&&
   nested_legacy_observer::raw_post_error==denied_error&&nested_legacy_observer::raw_post_errno==denied_errno,"nested legacy observer lost real read denial");
#endif
  dirty_native_observer::reset();
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  nested_legacy_observer::reset();
#endif
  // Transfer the native owner before the adapter's consuming close.
  const auto owned=std::exchange(readable.value,INVALID_HANDLE_VALUE);
  const bool consumed=detail::probe_native_capture_close(owned);
  const DWORD consumed_error=GetLastError();const int consumed_errno=errno;
  check(!consumed&&consumed_error==ERROR_WRITE_FAULT&&dirty_native_observer::close_success,"post-real-close failure not surfaced");
  check(dirty_native_observer::matches&&dirty_native_observer::close_calls==1&&consumed_errno==dirty_native_observer::close_post_errno&&
   consumed_errno==EBUSY,"dirty close observers leaked native errno/incoming pair");
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  check(nested_legacy_observer::pair_ok&&nested_legacy_observer::before_count==1&&nested_legacy_observer::after_count==1&&
   nested_legacy_observer::raw_success&&nested_legacy_observer::semantic_error==ERROR_SUCCESS&&
   nested_legacy_observer::raw_post_error==dirty_native_observer::close_post_error&&
   nested_legacy_observer::raw_post_errno==consumed_errno,"legacy close event confused raw success with effective injected failure");
#endif
  // INVALID_HANDLE_VALUE also denotes the current-process pseudo-handle.
  // Use an owned file with native close protection for the real failure.
  check(SetHandleInformation(attributes.value,HANDLE_FLAG_PROTECT_FROM_CLOSE,HANDLE_FLAG_PROTECT_FROM_CLOSE)!=0,
   "protect genuine close probe handle");
  attributes.protected_from_close=true;
  dirty_native_observer::reset();
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  nested_legacy_observer::reset();
#endif
  const bool invalid=detail::probe_native_capture_close(attributes.value);
  const DWORD invalid_error=GetLastError();const int invalid_errno=errno;
  // If native close unexpectedly succeeded, retire the value before any check
  // or cleanup. On native refusal the fixture still owns the protected handle.
  if(dirty_native_observer::close_success)attributes.value=INVALID_HANDLE_VALUE;
  check(!invalid&&!dirty_native_observer::close_success&&invalid_error==ERROR_INVALID_HANDLE,"real CloseHandle error did not beat injected ERROR_WRITE_FAULT");
  check(dirty_native_observer::matches&&dirty_native_observer::close_calls==1&&invalid_error==dirty_native_observer::close_post_error&&
   invalid_errno==dirty_native_observer::close_post_errno&&invalid_errno==EBUSY,"real close error pair lost to observer");
#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
  check(nested_legacy_observer::pair_ok&&nested_legacy_observer::before_count==1&&nested_legacy_observer::after_count==1&&
   !nested_legacy_observer::raw_success&&nested_legacy_observer::semantic_error==ERROR_INVALID_HANDLE&&
   nested_legacy_observer::raw_post_error==invalid_error&&nested_legacy_observer::raw_post_errno==invalid_errno,"nested legacy observer masked real close failure");
#endif
  DWORD flags=0;
  check(GetHandleInformation(attributes.value,&flags)&&(flags&HANDLE_FLAG_PROTECT_FROM_CLOSE),
   "refused close did not leave the fixture's protected owner live");
 }
 check(attributes.finish(),"dirty observer setup owner close");
 std::cout<<"actual helper dirty-observer read/close LastError+errno pairs, native failure precedence and real-close consumption PASS\n";
}
#endif
void exception_test(){Fixture f;auto j=take(NativeMainContentJob::begin_held(held(f),{{1024},f.main.size()}));take(step(*j));
 bool caught=false;
#ifdef _WIN32
 // Select the genuine source identity BEFORE enabling allocation denial.
 HANDLE file=CreateFileW((f.root+L"\\a").c_str(),FILE_READ_ATTRIBUTES,
  FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
 check(file!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(file,FileIdInfo,&close_target,sizeof(close_target)),"allocation-phase source identity");
 check(CloseHandle(file)!=0,"allocation-phase setup close");
 allocation_after_native_read=false;allocation_denied_in_step=false;allocation_read_handle=nullptr;
 allocation_denials=0;allocation_read_arms=0;allocation_reader_closes=0;selected_closes=0;
 const auto reads_before=native_reads.load();close_watch=true;
#endif
 throw_after_read=true;try{(void)step(*j);}catch(const std::bad_alloc&){caught=true;}
 throw_after_read=false;
#ifdef _WIN32
 // Disarm before constructing any assertion/diagnostic. A phase with no real
 // allocator rejection must FAIL here, never manufacture a follow-up throw.
 allocation_after_native_read=false;
 check(allocation_read_arms==1&&native_reads==reads_before+1,"allocator phase requires exactly one successful real read");
 check(allocation_read_requested==1024&&allocation_read_copied==1024,"allocator phase did not follow the actual bounded read");
 check(allocation_denials>0&&allocation_denied_in_step,"real post-read allocator denial did not occur inside advance");
 check(!native_read_violation,"native read exceeded configured chunk");
 check(allocation_reader_closes==1,"actual read owner was not consumed before allocation exception propagation");
 const auto consumed=selected_closes.load();
#endif
 check(caught,"native-read allocation exception not propagated");take(j->finish_read());check(!j->result().value(),"exception exposed proof");
#ifdef _WIN32
 take(j->finish_read());check(selected_closes==consumed&&allocation_reader_closes==1,"allocation exception drain retried native close");
 check(j->progress().phase==NativeMainContentPhase::Failed,"allocation exception left a successful producer phase");
 j.reset();check(selected_closes==consumed&&allocation_reader_closes==1,"allocation exception destructor retried native close");
 close_watch=false;allocation_read_handle=nullptr;
 std::cout<<"one real bounded read, persistent post-read ordinary-new denial, consumed reader before propagation, cached finish/no proof PASS\n";
#else
 std::cout<<"exception after actual native read drains source before propagation PASS\n";
#endif
}

void cancel_test(){Fixture f;auto j=take(NativeMainContentJob::begin_held(held(f),{{1024},f.main.size()}));take(step(*j));take(step(*j));std::stop_source stop;stop.request_stop();
 const auto before=native_reads.load();check(!step(*j,stop.get_token()).value()&&native_reads==before&&!j->result().value(),"cancellation continued reading/exposed proof");take(j->finish_read());
 std::cout<<"cancel drains source and withholds proof PASS\n";
}
}
#ifdef _WIN32
// Persistent ordinary C++ allocation failure after successful native completion.
// Only the owning exception_test catch/reset disarms it; no one-shot fallback.
// The observer is noexcept and only arms this allocator; it never throws as
// a fake ReadFile result. No debug-CRT allocation exemption is introduced.
void* operator new(std::size_t count){
 if(allocation_after_native_read){++allocation_denials;allocation_denied_in_step=frame.load();throw std::bad_alloc();}
 if(void* p=std::malloc(count?count:1))return p;throw std::bad_alloc();
}
void* operator new[](std::size_t count){return ::operator new(count);}
void operator delete(void* p)noexcept{std::free(p);}
void operator delete[](void* p)noexcept{std::free(p);}
#ifdef __cpp_sized_deallocation
void operator delete(void* p,std::size_t)noexcept{std::free(p);}
void operator delete[](void* p,std::size_t)noexcept{std::free(p);}
#endif
// Native callbacks are installed by main; no Windows import replacement.
#else
extern "C" ssize_t pread(int fd,void* data,size_t n,off_t offset){return watched_pread(fd,data,n,offset);}
extern "C" int close(int fd){return watched_close(fd);}
#endif
int main(){
#ifdef _WIN32
 if(!ckfs_test::report_runtime_self("native-main-content"))return 1;
 NativeCaptureFixtureScope native_capture_scope(capture_read_after,capture_close_before,capture_close_after);
#endif
try {
#ifdef _WIN32
native_error_state_test();native_pending_phase_test();
#endif
basic_test();changed_test();exception_test();cancel_test();factory_close_test();close_test(false);close_test(true);return 0;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
