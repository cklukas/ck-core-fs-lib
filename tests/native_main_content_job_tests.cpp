// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_capture_job.hpp"
#include "native_main_content_job.hpp"
#include "sha256.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "held_child.hpp"
#ifdef _WIN32
#include "platform/native_journal_directory_bridge.hpp"
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
#include <stdexcept>
#include <type_traits>
#ifdef _WIN32
#include <windows.h>
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
BOOL WINAPI watched_close(HANDLE h){using F=BOOL(WINAPI*)(HANDLE);static const auto fn=std::bit_cast<F>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"CloseHandle"));bool selected=false;
 if(close_watch){FILE_ID_INFO id{};selected=GetFileInformationByHandleEx(h,FileIdInfo,&id,sizeof(id))&&id.VolumeSerialNumber==close_target.VolumeSerialNumber&&!std::memcmp(id.FileId.Identifier,close_target.FileId.Identifier,16);}
 const auto result=fn(h);const auto error=GetLastError();if(selected&&result){++selected_closes;if(close_armed.exchange(false)){++close_hits;SetLastError(ERROR_READ_FAULT);return FALSE;}}SetLastError(error);return result;
}
#endif
#ifdef _WIN32
BOOL WINAPI watched_read(HANDLE h,LPVOID bytes,DWORD n,LPDWORD copied,LPOVERLAPPED io){using F=BOOL(WINAPI*)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);static const auto fn=std::bit_cast<F>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ReadFile"));++native_reads;if(frame){++advance_reads;check(n<=frame_limit,"native read exceeded configured chunk");}const auto result=fn(h,bytes,n,copied,io);const auto error=GetLastError();if(frame&&throw_after_read.exchange(false))throw std::bad_alloc();if(cancel_read&&frame){auto* s=cancel_read;cancel_read=nullptr;s->request_stop();}SetLastError(error);return result;}
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
 try{auto r=j.advance(token);frame=false;check(advance_reads<=1,"more than one actual native read per advance");
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
void exception_test(){Fixture f;auto j=take(NativeMainContentJob::begin_held(held(f),{{1024},f.main.size()}));take(step(*j));
 bool caught=false;throw_after_read=true;try{(void)step(*j);}catch(const std::bad_alloc&){caught=true;}
 throw_after_read=false;check(caught,"native-read allocation exception not propagated");take(j->finish_read());check(!j->result().value(),"exception exposed proof");
 std::cout<<"exception after actual native read drains source before propagation PASS\n";
}
void cancel_test(){Fixture f;auto j=take(NativeMainContentJob::begin_held(held(f),{{1024},f.main.size()}));take(step(*j));take(step(*j));std::stop_source stop;stop.request_stop();
 const auto before=native_reads.load();check(!step(*j,stop.get_token()).value()&&native_reads==before&&!j->result().value(),"cancellation continued reading/exposed proof");take(j->finish_read());
 std::cout<<"cancel drains source and withholds proof PASS\n";
}
}
#ifdef _WIN32
extern "C" {decltype(&ReadFile) __imp_ReadFile=&watched_read;decltype(&CloseHandle) __imp_CloseHandle=&watched_close;}
#else
extern "C" ssize_t pread(int fd,void* data,size_t n,off_t offset){return watched_pread(fd,data,n,offset);}
extern "C" int close(int fd){return watched_close(fd);}
#endif
int main(){try{basic_test();changed_test();exception_test();cancel_test();factory_close_test();close_test(false);close_test(true);return 0;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
