// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "regular_execution_source.hpp"
#include "metadata_capture_job.hpp"
#include "metadata_ownership_digest.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "sha256.hpp"
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
BOOL WINAPI watched_read(HANDLE h,LPVOID bytes,DWORD n,LPDWORD copied,LPOVERLAPPED io){using F=BOOL(WINAPI*)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);static const auto fn=std::bit_cast<F>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"ReadFile"));++native_reads;if(frame){++advance_reads;check(n<=frame_limit,"native read exceeded configured chunk");}const auto result=fn(h,bytes,n,copied,io);const auto error=GetLastError();if(cancel_read&&frame){auto* s=cancel_read;cancel_read=nullptr;s->request_stop();}SetLastError(error);return result;}
#endif
#ifndef _WIN32
std::stop_source* cancel_read=nullptr;
std::atomic<bool> close_armed{false},close_watch{false};std::atomic<unsigned> close_hits{0},selected_closes{0};dev_t close_device{};ino_t close_inode{};
ssize_t watched_pread(int fd,void* data,size_t n,off_t offset){using F=ssize_t(*)(int,void*,size_t,off_t);static const auto fn=std::bit_cast<F>(dlsym(RTLD_NEXT,"pread"));check(fn!=nullptr,"native pread resolve");++native_reads;if(frame){++advance_reads;check(n<=frame_limit,"native pread exceeded chunk");}const auto result=fn(fd,data,n,offset);const auto error=errno;if(cancel_read&&frame){auto* stop=cancel_read;cancel_read=nullptr;stop->request_stop();}errno=error;return result;}
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
 Fixture(){const auto t=wide_environment(L"TEMP"),u=wide_environment(L"TMP");check(t&&u,"explicit Windows TEMP/TMP required");const auto path=windows_extended_path(*t),other=windows_extended_path(*u);check(path&&other,"absolute native Windows TEMP/TMP required");root=*path;const auto tmp=*other;if(const auto v=wide_environment(L"CK_FS_REQUIRE_V_DEV_DRIVE");v&&*v==L"1")check(root.starts_with(L"\\\\?\\V:\\tmp\\")&&tmp.starts_with(L"\\\\?\\V:\\tmp\\"),"V temp required");static unsigned sequence=0;root+=L"\\regular-execution-source-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(sequence++);for(unsigned i=0;i<5;++i){if(i)root+=L"\\"+std::wstring(70,wchar_t(L'a'+i));check(CreateDirectoryW(root.c_str(),nullptr)!=0,"fixture mkdir");parents.push_back(root);}directory=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(root)));WCHAR name[32]{};HANDLE h=CreateFileW(root.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE&&GetVolumeInformationByHandleW(h,nullptr,0,nullptr,nullptr,nullptr,name,32),"fixture volume");check(CloseHandle(h)!=0,"fixture volume close");const auto expected=wide_environment(L"CK_METADATA_CAPTURE_EXPECT_FS");check((!expected||*expected==name)&&(std::wstring_view(name)==L"NTFS"||std::wstring_view(name)==L"ReFS"),"fixture filesystem mismatch");std::cout<<"actual progressive provider=";for(auto*p=name;*p;++p)std::cout<<char(*p);std::cout<<" path="<<root.size()<<'\n';init();}
 void data(std::u16string suffix,std::span<const std::byte>b){const auto p=root+L"\\a"+std::wstring(suffix.begin(),suffix.end());HANDLE h=CreateFileW(p.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,CREATE_ALWAYS,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE,"fixture data create");DWORD n=0;check(b.size()<=MAXDWORD&&WriteFile(h,b.data(),DWORD(b.size()),&n,nullptr)&&n==b.size()&&FlushFileBuffers(h),"fixture data write");check(CloseHandle(h)!=0,"fixture data close");}
 FILE_BASIC_INFO times(){HANDLE h=CreateFileW((root+L"\\a").c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);FILE_BASIC_INFO t{};check(h!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(h,FileBasicInfo,&t,sizeof(t)),"fixture times");check(CloseHandle(h)!=0,"times close");return t;}
 void restore(FILE_BASIC_INFO t){HANDLE h=CreateFileW((root+L"\\a").c_str(),FILE_WRITE_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE&&SetFileInformationByHandle(h,FileBasicInfo,&t,sizeof(t)),"fixture restore");check(CloseHandle(h)!=0,"restore close");}
 ~Fixture(){directory.reset();DeleteFileW((root+L"\\moved").c_str());check(DeleteFileW((root+L"\\a").c_str())!=0,"fixture delete");for(auto p=parents.rbegin();p!=parents.rend();++p)check(RemoveDirectoryW(p->c_str())!=0,"fixture rmdir");}
#else
 std::string root;
 Fixture(){const auto*t=std::getenv("TMPDIR");check(t&&*t,"explicit TMPDIR required");
#ifdef __APPLE__
 check(std::string_view(t).starts_with("/Volumes/PRO-BLADE/tmp/")||std::string_view(t).starts_with("/Volumes/S8T/tmp/"),"approved Mac temporary volume required");
#endif
 root=std::string(t)+"/regular-execution-source.XXXXXX";check(mkdtemp(root.data())!=nullptr,"fixture mkdtemp");directory=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(root)));init();}
 void data(std::u16string suffix,std::span<const std::byte>b){check(suffix.empty(),"POSIX named stream fixture unsupported");int fd=open((root+"/a").c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);check(fd>=0,"fixture data open");std::size_t n=0;while(n<b.size()){auto wrote=write(fd,b.data()+n,b.size()-n);check(wrote>0,"fixture write");n+=std::size_t(wrote);}check(!fsync(fd)&&!close(fd),"fixture finish");}
 ~Fixture(){directory.reset();unlink((root+"/moved").c_str());check(!unlink((root+"/a").c_str())&&!rmdir(root.c_str()),"fixture cleanup");}
#endif
 void init(){main.resize(8193);for(std::size_t i=0;i<main.size();++i)main[i]=std::byte(i%251);data({},main);
#ifdef _WIN32
 std::vector<std::byte> stream(4099);for(std::size_t i=0;i<stream.size();++i)stream[i]=std::byte(i%239);data(u":large:$DATA",stream);data(u":empty:$DATA",{});std::u16string raw=u":exact_";raw.push_back(char16_t(0xd800));raw+=u". :$DATA";data(raw,std::span(main).first(17));
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
MetadataReplayPolicy policy(bool full=false){MetadataReplayPolicy p;p.scope=full?RegularMetadataScope::CompleteMetadataV1:RegularMetadataScope::OrdinaryCallerVisibleV1;p.ownership=MetadataOwnership::Original;p.allow_privilege_metadata=full;return p;}
MetadataCaptureLimits limits(){MetadataCaptureLimits p;p.read.max_bytes=1024;return p;}
Observation<MetadataCaptureAdvance> advance(MetadataCaptureJob&j,std::stop_token stop={}){advance_reads=0;frame_limit=1024;frame=true;auto r=j.advance(stop);frame=false;check(advance_reads<=1,"more than one actual native read/advance");if(r.value()){check(r.value()->content_reads<=1&&r.value()->content_bytes<=1024,"advance reported unbounded I/O");
 check(r.value()->content_reads>=advance_reads,"hidden native bulk read in metadata/finalization phase");
 }return r;}
std::shared_ptr<const NativeMetadataProof> drain(MetadataCaptureJob&job){for(unsigned i=0;i<100000;++i){take(advance(job));if(job.progress().phase==MetadataCapturePhase::Complete)return take(job.result());}throw std::runtime_error("progressive producer did not finish");}

NativeName name(const char* value) {
#ifdef _WIN32
 std::u16string wide;for(;*value;++value)wide.push_back(char16_t(*value));return *NativeName::from_windows(std::move(wide));
#else
 return *NativeName::from_posix(value);
#endif
}
std::array<std::byte,32> schema() {
 Sha256 h;constexpr char domain[]="ck-core-fs-lib/native-preserved-metadata";
 h.update(std::as_bytes(std::span(domain,sizeof(domain)-1)));std::array<std::byte,8> version{};
 for(unsigned i=0;i<8;++i)version[i]=std::byte((metadata_semantic_digest_version>>(8*i))&255);
 h.update(version);return h.digest();
}
std::array<std::byte,32> binding(const MetadataReplayPolicy& p) {
 Sha256 h;constexpr char domain[]="ck-core-fs-lib/reviewed-tree-preservation";
 h.update(std::as_bytes(std::span(domain,sizeof(domain)-1)));return native_sync_policy_binding(h.digest(),p);
}
ComparisonObject object(const BasicMetadata& m) {
 ComparisonObject o;o.state=ComparisonObjectState::Stable;o.identity=*m.identity.value();o.kind=*m.kind.value();
 o.size=*m.logical_size.value();o.modified=*m.modified.value();o.timestamp_quantum_ns=1;return o;
}
struct RegularFixture:Fixture {
 PreparedJournalRoot::Pointer journal;
 bool dirty=false;
 RegularFixture() {
  PreparedJournalRootRequest r;r.parent=directory;r.child=name("private-state");r.disposition=JournalRootDisposition::ProvisionChild;
  JournalRootPreparationProgress progress;journal=take(prepare_native_journal_root(std::move(r),progress));
 }
 ~RegularFixture() {
  if(journal){auto done=journal->finish_io();check(dirty?!done.value():(done.value()&&*done.value()),"borrowed Root final result");journal.reset();}
#ifdef _WIN32
  check(RemoveDirectoryW((root+L"\\private-state").c_str())!=0,"private fixture cleanup");
#else
  check(!rmdir((root+"/private-state").c_str()),"private fixture cleanup");
#endif
 }
 RegularExecutionSourceRequest request(MetadataOwnership owner=MetadataOwnership::Original) {
  RegularExecutionSourceRequest r;
  r.source=take(HeldChild::observe_with_access(directory,name("a"),EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity));
  r.policy=policy();r.policy.ownership=owner;r.limits=limits();r.journal_root=journal;
  auto capture=take(MetadataCaptureJob::begin_held(r.source,r.policy,r.limits));auto proof=drain(*capture);
  auto& fact=r.reviewed;fact.state=ComparisonDigestState::CompleteStable;fact.algorithm=ComparisonDigestAlgorithm::Sha256;
  fact.schema=schema();fact.policy_binding=binding(r.policy);fact.bytes=take(native_metadata_proof_digest(*proof));
  fact.ownership=owner==MetadataOwnership::Original?ComparisonMetadataOwnership::Original:ComparisonMetadataOwnership::CurrentCaller;
  if(owner==MetadataOwnership::CurrentCaller)fact.canonical_owner_digest=take(metadata_ownership_digest(proof->snapshot()));
  fact.before=fact.after=object(proof->snapshot().basic);
  r.reviewed_main.state=ComparisonDigestState::CompleteStable;r.reviewed_main.algorithm=ComparisonDigestAlgorithm::Sha256;
  r.reviewed_main.bytes=*proof->main_digest();r.reviewed_main.bytes_read=*proof->progress().main_logical_bytes;
  r.reviewed_main.before=r.reviewed_main.after=fact.before;
  check(take(capture->finish_io())&&proof->io_finished(),"review was not explicitly closed");
  r.verify_review=[](std::stop_token){return Observation<bool>::available(true);};return r;
 }
 void select_close() {
#ifdef _WIN32
  HANDLE h=CreateFileW((root+L"\\a").c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
  check(h!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(h,FileIdInfo,&close_target,sizeof(close_target)),"fault target ID");check(CloseHandle(h),"fault target close");
#else
  struct stat s{};check(!stat((root+"/a").c_str(),&s),"fault target ID");close_device=s.st_dev;close_inode=s.st_ino;
#endif
 }
};
RegularSourceProgress step(RegularExecutionSourceJob& job,std::stop_token stop={}) {
 const auto before=job.progress();advance_reads=0;frame_limit=1024;frame=true;
 RegularSourceProgress after;
 try {after=job.advance(stop);}catch(...){frame=false;throw;}
 frame=false;check(advance_reads<=1,"regular worker performed multiple content reads");
 check(after.read_calls-before.read_calls>=advance_reads,"regular worker hid a native content read");
 check(after.read_calls-before.read_calls<=1&&after.read_bytes-before.read_bytes<=1024,"regular worker exceeded bounded progress");return after;
}
RegularSourceProgress ready(RegularExecutionSourceJob& job) {
 for(unsigned i=0;i<100000;++i){const auto p=step(job);if(p.phase==RegularSourcePhase::Ready||p.worker_drained)return p;}
 throw std::runtime_error("regular execution source did not reach Ready");
}
void terminal(RegularExecutionSourceJob& job,RegularSourcePhase phase) {
 const auto p=job.progress();check(p.phase==phase&&p.worker_drained,"terminal before complete native drain");
 const auto reads=native_reads.load();const auto again=step(job);
 check(again.phase==phase&&again.worker_drained&&native_reads==reads,"terminal source job revived native work");
 check(!job.proof().value(),"terminal source job returned proof");
}
void positive(MetadataOwnership owner) {
 RegularFixture f;auto request=f.request(owner);request.budget=std::make_shared<MetadataCaptureBudget>(limits());auto budget=request.budget;
 std::weak_ptr<const HeldChild> weak=request.source;auto job=take(RegularExecutionSourceJob::create(std::move(request)));
 check(ready(*job).phase==RegularSourcePhase::Ready,"fresh source capture rejected valid reviewed data");
 auto proof=take(job->proof());check(!proof->io_finished()&&budget->retained_handle_reservations()>0,"Ready closed source proof");
 for(unsigned recheck=0;recheck<2;++recheck) {
  const auto before=native_reads.load();check(take(job->start_revalidation()),"start source revalidation");
  check(native_reads==before&&!proof->io_finished(),"revalidation start read content or closed original proof");
  check(ready(*job).phase==RegularSourcePhase::Ready&&native_reads>before,"revalidation did not fresh-read native content");
  check(take(job->proof()).get()==proof.get()&&!proof->io_finished(),"revalidation replaced/closed original replay authority");
 }
 check(take(job->finish_io())&&take(job->finish_io()),"success close not idempotent");terminal(*job,RegularSourcePhase::Complete);
 check(proof->io_finished()&&weak.expired()&&budget->retained_handle_reservations()==0,"terminal retained source handles/consumer");
 check(take(f.journal->revalidate()),"source job finished borrowed Root");
 std::cout<<(owner==MetadataOwnership::Original?"Original":"CurrentCaller")<<" actual native V3/main-SHA source and TWO fresh revalidations preserving original OPEN proof PASS\n";
}
void review_negatives() {
 RegularFixture f;
 for(unsigned variant=0;variant<10;++variant) {
  auto r=f.request(MetadataOwnership::CurrentCaller);
  switch(variant) {
   case 0:r.reviewed.schema[0]^=std::byte{1};break;
   case 1:r.reviewed.policy_binding[0]^=std::byte{1};break;
   case 2:r.reviewed.canonical_owner_digest.reset();break;
   case 3:r.reviewed.ownership=ComparisonMetadataOwnership::Unknown;break;
   case 4:r.reviewed_main.state=ComparisonDigestState::Incomplete;break;
   case 5:r.reviewed_main.algorithm=ComparisonDigestAlgorithm::Unknown;break;
   case 6:r.reviewed_main.after.identity->object.bytes[0]^=std::byte{1};break;
   case 7:r.reviewed.after.size=*r.reviewed.after.size+1;break;
   case 8:r.reviewed.before.change_cookie=1;break;
   case 9:r.reviewed_main.bytes_read++;break;
  }
  const auto reads=native_reads.load();check(!RegularExecutionSourceJob::create(std::move(r)).value(),"invalid reviewed authority admitted");
  check(native_reads==reads,"invalid schema/owner/main facts read content");
 }
 for(unsigned variant=0;variant<3;++variant) {
  auto r=f.request(MetadataOwnership::CurrentCaller);
  if(variant==0)r.reviewed_main.bytes[0]^=std::byte{1};
  if(variant==1)r.reviewed.bytes[0]^=std::byte{1};
  if(variant==2)(*r.reviewed.canonical_owner_digest)[0]^=std::byte{1};
  auto job=take(RegularExecutionSourceJob::create(std::move(r)));ready(*job);terminal(*job,RegularSourcePhase::Failed);
  check(take(job->finish_io()),"review mismatch cleanup failed");check(take(f.journal->revalidate()),"review mismatch poisoned healthy Root");
 }
 std::cout<<"unknown schema/policy/owner/version and wrong native metadata/main digest refused PASS\n";
}
void changed_and_closed() {
 {
  RegularFixture f;auto r=f.request();auto job=take(RegularExecutionSourceJob::create(std::move(r)));
  ready(*job);auto proof=take(job->proof());f.main[0]^=std::byte{1};f.data({},f.main);
  const auto reads=native_reads.load();const auto started=job->start_revalidation();
  if(started.value())ready(*job);
  terminal(*job,RegularSourcePhase::Failed);check(proof->io_finished(),"changed source left proof open");
  check(take(job->finish_io()),"changed source cleanup");check(take(f.journal->revalidate()),"changed source finished borrowed Root");
  check(native_reads>=reads,"native read count regressed");
 }
 {
  RegularFixture f;auto job=take(RegularExecutionSourceJob::create(f.request()));ready(*job);auto proof=take(job->proof());
  check(take(proof->finish_io()),"external proof close");check(!job->start_revalidation().value(),"closed proof accepted for revalidation");
  terminal(*job,RegularSourcePhase::Failed);check(take(job->finish_io()),"closed proof cleanup");
 }
 std::cout<<"fresh native source mutation and externally closed proof refused PASS\n";
}
void cancel_and_exception() {
 for(unsigned variant=0;variant<4;++variant) {
  RegularFixture f;auto r=f.request();std::weak_ptr<const HeldChild> weak=r.source;
  auto marker=std::make_shared<int>();std::weak_ptr<int> captured=marker;r.verify_review=[marker](std::stop_token){return Observation<bool>::available(true);};marker.reset();
  auto job=take(RegularExecutionSourceJob::create(std::move(r)));
  // A moved-from std::function is valid but may retain its callable (libc++).
  // This external request is not a worker-owned consumer.
  r.verify_review={};
  if(variant==1) {const auto before=native_reads.load();while(native_reads==before&&!job->progress().worker_drained)step(*job);}
  if(variant>=2)ready(*job);
  if(variant==3){take(job->start_revalidation());const auto before=native_reads.load();while(native_reads==before&&!job->progress().worker_drained)step(*job);}
  std::stop_source stop;stop.request_stop();step(*job,stop.get_token());terminal(*job,RegularSourcePhase::Cancelled);
  if(!weak.expired()||!captured.expired())throw std::runtime_error("cancellation consumer variant="+std::to_string(variant)+" held="+std::to_string(weak.use_count())+" callback="+std::to_string(captured.use_count())+" caller_callable="+std::to_string(bool(r.verify_review)));
  check(take(job->finish_io()),"cancellation finish failed");
  check(take(f.journal->revalidate()),"cancel finished borrowed Root");
 }
 {
  RegularFixture f;auto r=f.request();std::weak_ptr<const HeldChild> weak=r.source;
  r.verify_review=[](std::stop_token)->Observation<bool>{throw std::bad_alloc();};
  auto job=take(RegularExecutionSourceJob::create(std::move(r)));step(*job);terminal(*job,RegularSourcePhase::Failed);
  check(weak.expired()&&take(job->finish_io())&&take(f.journal->revalidate()),"callback exception escaped native drain");
 }
 {
  RegularFixture f;auto r=f.request();std::weak_ptr<const HeldChild> weak=r.source;
  auto job=take(RegularExecutionSourceJob::create(std::move(r)));std::stop_source stop;cancel_read=&stop;
  for(unsigned i=0;i<100000&&!job->progress().worker_drained;++i)step(*job,stop.get_token());
  cancel_read=nullptr;terminal(*job,RegularSourcePhase::Cancelled);
  check(stop.stop_requested()&&weak.expired()&&take(job->finish_io())&&take(f.journal->revalidate()),"actual read cancellation did not drain before terminal");
 }
 std::cout<<"cancel in Opening/Capturing/Ready/Rechecking/during actual read and allocation exception drain PASS\n";
}
void budget_tests() {
 {
  RegularFixture f;auto r=f.request();r.limits.max_logical_bytes=f.main.size()-1;
  auto job=take(RegularExecutionSourceJob::create(std::move(r)));const auto reads=native_reads.load();ready(*job);
  terminal(*job,RegularSourcePhase::Failed);check(native_reads==reads&&take(job->finish_io()),"logical admission read before refusing");
 }
 {
  RegularFixture f;auto r=f.request();r.limits.max_retained_handles=
#ifdef _WIN32
   11; // Base view reservation plus the three exact retained named streams.
#else
   8;
#endif
  r.budget=std::make_shared<MetadataCaptureBudget>(r.limits);auto budget=r.budget;
  auto job=take(RegularExecutionSourceJob::create(std::move(r)));check(ready(*job).phase==RegularSourcePhase::Ready,"first bounded handle lease");
  const auto reads=native_reads.load();check(!job->start_revalidation().value(),"second observation exceeded shared active-handle budget");
  terminal(*job,RegularSourcePhase::Failed);check(native_reads==reads&&budget->retained_handle_reservations()==0,"budget rejection read/leaked active handles");
  check(take(job->finish_io())&&take(f.journal->revalidate()),"budget rejection poisoned/finalized Root");
 }
 std::cout<<"pre-read logical budget and cumulative active handle budget PASS\n";
}
class ForeignEntry final:public OpenedEntry {
 BasicMetadata metadata_;
public:explicit ForeignEntry(BasicMetadata m):metadata_(std::move(m)){}
 Observation<BasicMetadata>inspect_basic()const override{return Observation<BasicMetadata>::available(metadata_);}
};
class ForeignCursor final:public DirectoryCursor {
 BasicMetadata metadata_;
public:explicit ForeignCursor(BasicMetadata m):DirectoryCursor(m.identity),metadata_(std::move(m)){}
 Observation<std::unique_ptr<OpenedEntry>>open_child(const NativeName&,EntryAccess)const override {
  return Observation<std::unique_ptr<OpenedEntry>>::available(std::make_unique<ForeignEntry>(metadata_));
 }
protected:Observation<DirectoryStep>next_step()override{return Observation<DirectoryStep>::available(DirectoryEnd{});}
};
void foreign_and_root_first() {
 {
  RegularFixture f;auto r=f.request();auto foreign=std::make_shared<ForeignCursor>(r.source->metadata());
  r.source=take(HeldChild::observe_with_access(foreign,name("a"),EntryAccess::ContentRead));
  auto job=take(RegularExecutionSourceJob::create(std::move(r)));const auto reads=native_reads.load();step(*job);
  terminal(*job,RegularSourcePhase::Failed);check(native_reads==reads&&take(job->finish_io()),"foreign cursor manufactured native authority");
 }
 {
  RegularFixture f;auto r=f.request();unsigned callbacks=0;r.verify_review=[&](std::stop_token){++callbacks;return Observation<bool>::available(true);};
  check(detail::record_prepared_journal_consumer_failure(*f.journal,ObservationState::Failed,ErrorDomain::Posix,5,"source.test_sticky"),"genuine Root latch bridge");
  f.dirty=true;const auto reads=native_reads.load();check(!RegularExecutionSourceJob::create(std::move(r)).value()&&callbacks==0&&native_reads==reads,"dirty Root permitted worker activity");
 }
 std::cout<<"foreign native source refused and sticky Root failure precedes worker activity PASS\n";
}
void close_errors() {
 for(unsigned variant=0;variant<4;++variant) {
  RegularFixture f;auto r=f.request();std::weak_ptr<const HeldChild> weak=r.source;f.select_close();
  RegularExecutionSourceJob::Pointer job;
  if(variant) {job=take(RegularExecutionSourceJob::create(std::move(r)));if(variant<3)ready(*job);}
  else r.reviewed.schema[0]^=std::byte{1};
  selected_closes=0;close_hits=0;close_watch=true;close_armed=true;f.dirty=true;
  if(variant==0)check(!RegularExecutionSourceJob::create(std::move(r)).value(),"invalid request close failure lost");
  else if(variant==1)check(!job->finish_io().value(),"finish ignored consumed native close failure");
  else if(variant==2) {std::stop_source stop;stop.request_stop();step(*job,stop.get_token());}
  else {const auto reads=native_reads.load();step(*job);check(native_reads==reads,"temporary membership close failure allowed content read");}
  close_armed=false;close_watch=false;
  check(close_hits==1&&weak.expired(),"native close fault or consumer drop missing");
  detail::PreparedJournalConsumerFailure error;check(detail::read_prepared_journal_consumer_failure(*f.journal,error)&&!error.pending,"close failure absent from borrowed Root latch");
  check(error.domain==
#ifdef _WIN32
   ErrorDomain::Win32
#else
   ErrorDomain::Posix
#endif
   ,"Root lost actual close error domain");
  if(job){terminal(*job,RegularSourcePhase::Failed);const auto closes=selected_closes.load();check(!job->finish_io().value()&&selected_closes==closes,"failed close retried or cleared");}
 }
 std::cout<<"actual consumed close failure on rejected request/success/cancel/membership reaches Root before terminal PASS\n";
}
}
#ifdef _WIN32
extern "C" {decltype(&ReadFile) __imp_ReadFile=&watched_read;decltype(&CloseHandle) __imp_CloseHandle=&watched_close;}
#else
extern "C" ssize_t pread(int fd,void* data,size_t n,off_t offset){return watched_pread(fd,data,n,offset);}
extern "C" int close(int fd){return watched_close(fd);}
#endif
int main(){try {positive(MetadataOwnership::Original);positive(MetadataOwnership::CurrentCaller);review_negatives();changed_and_closed();
 cancel_and_exception();budget_tests();foreign_and_root_first();close_errors();std::cout<<"regular_execution_source_tests passed\n";return 0;
 }catch(const std::exception& e){frame=false;close_watch=false;close_armed=false;std::cerr<<e.what()<<'\n';return 1;}}
