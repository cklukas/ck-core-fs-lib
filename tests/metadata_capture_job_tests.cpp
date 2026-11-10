// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_capture_job.hpp"
#include "held_child.hpp"
#ifdef _WIN32
#include "platform/native_journal_directory_bridge.hpp"
#include "native_read_close_capture_fixture.hpp"
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
std::atomic<unsigned> native_reads{0},advance_reads{0};std::atomic<bool> frame{false};std::atomic<std::size_t> frame_limit{0};
#ifdef _WIN32
std::stop_source* cancel_read=nullptr;
FILE_ID_INFO close_target{};std::atomic<bool> close_armed{false},close_watch{false};std::atomic<unsigned> close_hits{0},selected_closes{0};
thread_local bool selected_close_pending=false;
void capture_close_before(void* raw,const char*,const char*) noexcept {
 selected_close_pending=false;
 if(close_watch){FILE_ID_INFO id{};selected_close_pending=GetFileInformationByHandleEx(static_cast<HANDLE>(raw),FileIdInfo,&id,sizeof(id))&&id.VolumeSerialNumber==close_target.VolumeSerialNumber&&!std::memcmp(id.FileId.Identifier,close_target.FileId.Identifier,16);}
}
std::uint32_t capture_close_after(void*,const char*,bool succeeded,std::uint32_t) noexcept {
 const bool selected=std::exchange(selected_close_pending,false);
 if(selected&&succeeded){++selected_closes;if(close_armed.exchange(false)){++close_hits;return ERROR_READ_FAULT;}}
 return 0; // A native failure is never replaced; the adapter retains its exact error.
}

#endif
#ifdef _WIN32
std::atomic<bool> native_read_violation{false};
void capture_read_after(void*,detail::NativeReadPhase phase,std::uint32_t requested,std::uint32_t,bool,std::uint32_t,const char*) noexcept {
 if(phase!=detail::NativeReadPhase::Request)return;
 ++native_reads;
 if(frame){++advance_reads;if(requested>frame_limit)native_read_violation=true;}

 if(cancel_read&&frame){auto* source=cancel_read;cancel_read=nullptr;source->request_stop();}
}

#endif
#ifndef _WIN32
std::atomic<bool> close_armed{false},close_watch{false};std::atomic<unsigned> close_hits{0},selected_closes{0};dev_t close_device{};ino_t close_inode{};
ssize_t watched_pread(int fd,void* data,size_t n,off_t offset){using F=ssize_t(*)(int,void*,size_t,off_t);static const auto fn=std::bit_cast<F>(dlsym(RTLD_NEXT,"pread"));check(fn!=nullptr,"native pread resolve");++native_reads;if(frame){++advance_reads;check(n<=frame_limit,"native pread exceeded chunk");}return fn(fd,data,n,offset);}
int watched_close(int fd){using F=int(*)(int);static const auto fn=std::bit_cast<F>(dlsym(RTLD_NEXT,"close"));bool selected=false;if(close_watch){struct stat s{};selected=!fstat(fd,&s)&&s.st_dev==close_device&&s.st_ino==close_inode;}const auto r=fn(fd);const auto e=errno;if(selected&&r==0){++selected_closes;if(close_armed.exchange(false)){++close_hits;errno=EIO;return -1;}}errno=e;return r;}
#endif
struct Fixture{
 NativeFileSystem fs;std::shared_ptr<const DirectoryCursor> directory;std::vector<std::byte> main;
#ifdef _WIN32
 std::wstring root;std::vector<std::wstring> parents;
 Fixture(){const auto*t=_wgetenv(L"TEMP"),*u=_wgetenv(L"TMP");check(t&&u,"explicit Windows TEMP/TMP required");root=*windows_extended_path(t);const auto tmp=*windows_extended_path(u);if(const auto*v=_wgetenv(L"CK_FS_REQUIRE_V_DEV_DRIVE");v&&std::wstring_view(v)==L"1")check(root.starts_with(L"\\\\?\\V:\\tmp\\")&&tmp.starts_with(L"\\\\?\\V:\\tmp\\"),"V temp required");static unsigned sequence=0;root+=L"\\progressive-metadata-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(sequence++);for(unsigned i=0;i<5;++i){if(i)root+=L"\\"+std::wstring(70,wchar_t(L'a'+i));check(CreateDirectoryW(root.c_str(),nullptr)!=0,"fixture mkdir");parents.push_back(root);}directory=std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(root)));WCHAR name[32]{};HANDLE h=CreateFileW(root.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE&&GetVolumeInformationByHandleW(h,nullptr,0,nullptr,nullptr,nullptr,name,32),"fixture volume");check(CloseHandle(h)!=0,"fixture volume close");const auto* expected=_wgetenv(L"CK_METADATA_CAPTURE_EXPECT_FS");check((!expected||std::wstring_view(expected)==name)&&(std::wstring_view(name)==L"NTFS"||std::wstring_view(name)==L"ReFS"),"fixture filesystem mismatch");std::cout<<"actual progressive provider=";for(auto*p=name;*p;++p)std::cout<<char(*p);std::cout<<" path="<<root.size()<<'\n';init();}
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
 std::vector<std::byte> stream(1537*1024);for(std::size_t i=0;i<stream.size();++i)stream[i]=std::byte(i%239);data(u":large:$DATA",stream);data(u":empty:$DATA",{});std::u16string raw=u":exact_";raw.push_back(char16_t(0xd800));raw+=u". :$DATA";data(raw,std::span(main).first(17));
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
Observation<MetadataCaptureAdvance> advance(MetadataCaptureJob&j,std::stop_token stop={}){advance_reads=0;frame_limit=1024;frame=true;auto r=j.advance(stop);frame=false;
#ifdef _WIN32
check(!native_read_violation,"native read exceeded configured chunk");
#endif
check(advance_reads<=1,"more than one actual native read/advance");if(r.value()){check(r.value()->content_reads<=1&&r.value()->content_bytes<=1024,"advance reported unbounded I/O");
 check(r.value()->content_reads>=advance_reads,"hidden native bulk read in metadata/finalization phase");
 }return r;}
std::shared_ptr<const NativeMetadataProof> drain(MetadataCaptureJob&job){for(unsigned i=0;i<100000;++i){take(advance(job));if(job.progress().phase==MetadataCapturePhase::Complete)return take(job.result());}throw std::runtime_error("progressive producer did not finish");}
class FakeSource final:public OpenedEntry{public:Observation<BasicMetadata>inspect_basic()const override{return Observation<BasicMetadata>::unavailable(ObservationState::Unknown,{ErrorDomain::Adapter,0,"fake"});}};
void capture_and_verify(bool full){Fixture f;auto source=f.source(full);auto budget=std::make_shared<MetadataCaptureBudget>(limits());auto job=take(MetadataCaptureJob::begin(source,policy(full),limits(),budget));check(detail::seal_native_metadata_capture(*job).state()==ObservationState::Unsupported,"unfinished producer sealed native evidence");auto proof=drain(*job);check(proof->main_digest().has_value(),"main SHA absent");
#ifdef _WIN32
 check(proof->progress().all_stream_logical_bytes==f.main.size()+1537*1024+17&&proof->snapshot().channels.size()==3,"all-stream admission facts wrong");check(proof->snapshot().channel_evidence!=nullptr,"native channel evidence absent");if(full)check(proof->snapshot().security_coverage!=nullptr,"Full native security evidence absent");
#else
 check(!proof->progress().all_stream_logical_bytes&&proof->snapshot().channel_coverage==DataChannelCoverage::Unknown,"ordinary POSIX claimed hidden channel absence");
#endif
#ifdef _WIN32
 const auto ds=f.root+L":directory-data:$DATA";HANDLE dh=CreateFileW(ds.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,CREATE_ALWAYS,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(dh!=INVALID_HANDLE_VALUE,"directory ADS fixture open");DWORD dw=0;check(WriteFile(dh,f.main.data(),DWORD(f.main.size()),&dw,nullptr)&&dw==f.main.size()&&FlushFileBuffers(dh),"directory ADS fixture write");check(CloseHandle(dh),"directory ADS fixture close");
#endif
 auto directory_job=take(MetadataCaptureJob::begin_directory(f.directory,policy(full),limits()));auto directory_proof=drain(*directory_job);check(!directory_proof->main_digest(),"directory manufactured unnamed main digest");
#ifdef _WIN32
 check(directory_proof->snapshot().channels.size()==1&&directory_proof->progress().all_stream_logical_bytes==f.main.size(),"directory ADS zero-main manifest omitted");
#endif
const auto directory_digest=take(native_metadata_proof_digest(*directory_proof));auto directory_verify=take(MetadataCaptureJob::verify(directory_proof,limits()));check(take(native_metadata_proof_digest(*drain(*directory_verify)))==directory_digest,"directory progressive verification mismatch");
 const auto count=native_reads.load();frame=true;frame_limit=1024;const auto digest=take(native_metadata_proof_digest(*proof));frame=false;check(native_reads==count,"sealed proof semantic digest did source I/O");check(digest==take(native_sync_metadata_digest(*source,proof->snapshot())),"progressive/legacy semantic wire diverged");auto verify=take(MetadataCaptureJob::verify(proof,limits()));auto verified=drain(*verify);check(take(native_metadata_proof_digest(*verified))==digest,"progressive revalidation changed stable digest");check(proof->progress().read_calls>128,"large stream was hidden in one advance");check(take(verify->finish_io())&&take(verified->finish_io()),"verification close failed");verify.reset();verified.reset();check(budget->retained_handle_reservations()>0,"proof lost native reservations");check(take(proof->finish_io())&&take(job->finish_io()),"capture explicit close failed");check(budget->retained_handle_reservations()==0,"native handle reservations leaked after explicit close");check(!MetadataCaptureJob::verify(proof,limits()).value(),"closed source silently reused");auto fresh=take(MetadataCaptureJob::verify(source,proof,limits()));auto fresh_proof=drain(*fresh);check(take(native_metadata_proof_digest(*fresh_proof))==digest,"fresh source verification after close failed");check(take(fresh->finish_io()),"fresh verification close failed");check(take(directory_verify->finish_io())&&take(directory_job->finish_io()),"directory explicit close failed");job.reset();proof.reset();std::cout<<"native progressive capture, two passes, no-I/O V3 digest, legacy wire, verifier and lifetime budgets PASS Full="<<full<<'\n';}
#ifdef __APPLE__
void noowners_negative(){Fixture f;struct statfs mount{};check(!statfs(f.root.c_str(),&mount)&&(mount.f_flags&MNT_UNKNOWNPERMISSIONS),"negative fixture mount must actually ignore ownership");const auto reads=native_reads.load();auto job=take(MetadataCaptureJob::begin(f.source(),policy(),limits()));Observation<MetadataCaptureAdvance> step=Observation<MetadataCaptureAdvance>::available({MetadataCapturePhase::Basic});for(unsigned i=0;i<32&&step.value();++i)step=advance(*job);check(!step.value()&&step.state()==ObservationState::Unsupported&&native_reads==reads,"NoOwners source was qualified/hashed");check(take(job->finish_io()),"NoOwners cleanup");std::cout<<"actual MountedNoOwners strict refusal before content reads PASS\n";}
#endif
void held_identity(){Fixture f;
#ifdef _WIN32
 auto n=*NativeName::from_windows(u"a");
#else
 auto n=*NativeName::from_posix("a");
#endif
 auto held=take(HeldChild::observe_with_access(f.directory,n,EntryAccess::ContentRead|EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity));
 const auto original=held->metadata().identity;
#ifdef _WIN32
 check(MoveFileExW((f.root+L"\\a").c_str(),(f.root+L"\\moved").c_str(),0),"fixture held rename");
#else
 check(!rename((f.root+"/a").c_str(),(f.root+"/moved").c_str()),"fixture held rename");
#endif
 const std::byte replacement[]{std::byte{'X'}};f.data({},replacement);
 auto job=take(MetadataCaptureJob::begin_held(held,policy(),limits()));auto proof=drain(*job);
 check(proof->snapshot().basic.identity.value()&&compare_identity(*original.value(),*proof->snapshot().basic.identity.value())==IdentityComparison::Same&&proof->progress().main_logical_bytes==f.main.size(),"begin_held reopened/adopted replacement name");
 auto member=take(held->refresh());check(!member->continues(*held),"fixture failed to replace membership");check(take(job->finish_io()),"held source close");std::cout<<"private begin_held exact object after name replacement, separate membership refusal PASS\n";
}
void negative_tests(){check(!MetadataCaptureJob::begin(std::make_shared<FakeSource>(),policy()).value(),"fake adapter minted native capture job");Fixture f;auto source=f.source();auto l=limits();l.max_logical_bytes=f.main.size()-1;
#ifdef _WIN32
 l.max_logical_bytes=f.main.size()+1024; // Main fits: ADS must be admitted before hashing.
#endif
auto job=take(MetadataCaptureJob::begin(source,policy(),l));const auto before=native_reads.load();Observation<MetadataCaptureAdvance> last=Observation<MetadataCaptureAdvance>::available({MetadataCapturePhase::Basic});for(unsigned i=0;i<64&&last.value();++i)last=advance(*job);check(!last.value()&&native_reads==before,"logical budget refused only after content read");
#ifdef _WIN32
 l=limits();l.max_retained_handles=10;check(take(job->finish_io()),"budget failure close");job=take(MetadataCaptureJob::begin(source,policy(),l));const auto reads=native_reads.load();last=Observation<MetadataCaptureAdvance>::available({MetadataCapturePhase::Basic});for(unsigned i=0;i<64&&last.value();++i)last=advance(*job);check(!last.value()&&native_reads==reads,"native handle budget ignored before stream reads");
#endif
 check(take(job->finish_io()),"failed admission close");job.reset();l=limits();job=take(MetadataCaptureJob::begin(source,policy(),l));std::stop_source stop;for(unsigned i=0;i<128&&job->progress().phase!=MetadataCapturePhase::ReadData;++i)take(advance(*job));
#ifdef _WIN32
 cancel_read=&stop;last=advance(*job,stop.get_token());cancel_read=nullptr;
#else
 stop.request_stop();last=advance(*job,stop.get_token());
#endif
 check(!last.value()&&!job->result().value()&&job->progress().phase==MetadataCapturePhase::Cancelled,"cancel minted completed native proof");check(take(job->finish_io()),"cancel cleanup failed");check(!job->advance().value()&&job->progress().phase==MetadataCapturePhase::Cancelled,"cancel terminal was revived");std::cout<<"native forgery, prehash logical/handle budgets and read cancellation PASS\n";}
struct Latch final:MetadataCaptureFailureLatch{mutable unsigned calls=0;mutable std::optional<MetadataCaptureCleanupError> first;void record_first(MetadataCaptureCleanupError e)const noexcept override{++calls;if(!first)first=e;}};
void cleanup_failure(){Fixture f;auto source=f.source();auto budget=std::make_shared<MetadataCaptureBudget>(limits());auto latch=std::make_shared<Latch>();auto job=take(MetadataCaptureJob::begin(source,policy(),limits(),budget,latch));auto proof=drain(*job);
#ifdef _WIN32
 HANDLE h=CreateFileW((f.root+L"\\a").c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(h,FileIdInfo,&close_target,sizeof(close_target)),"fault ID");check(CloseHandle(h),"fault ID close");
#else
 struct stat s{};check(!stat((f.root+"/a").c_str(),&s),"fault ID");close_device=s.st_dev;close_inode=s.st_ino;
#endif

#ifdef _WIN32
 struct Observer{unsigned calls=0;static void record(void* p,std::uint32_t,const char*)noexcept{++static_cast<Observer*>(p)->calls;}} observer;
 const auto previous=detail::exchange_windows_journal_close_observer({&observer,&Observer::record});
#endif
 close_hits=0;selected_closes=0;close_armed=true;close_watch=true;const auto reads=native_reads.load();auto failed=proof->finish_io();close_armed=false;close_watch=false;
#ifdef _WIN32
 detail::exchange_windows_journal_close_observer(previous);check(observer.calls==1,"Main journal close observer lost/duplicated");
#endif
check(!failed.value()&&close_hits==1&&latch->first&&latch->calls==1,"fallible reader close error lost or Root first-error latch duplicated");check(native_reads==reads,"cleanup performed content reads");const auto attempts=selected_closes.load();
#ifdef _WIN32
 check(attempts==proof->snapshot().channels.size()+2,"cleanup stopped before all native channel/manifest/source closes");
#else
 check(attempts==1,"source read descriptor close missing");
#endif
check(!proof->finish_io().value()&&!job->finish_io().value()&&selected_closes==attempts,"consumed close retried or cached failure cleared");check(!native_metadata_proof_digest(*proof).value()&&!job->result().value(),"close failure still exposed usable qualified digest/proof");check(!MetadataCaptureJob::begin(source,policy(),limits(),budget,latch).value(),"dirty budget allowed another capture");check(budget->retained_handle_reservations()==0,"cleanup did not consume owned read handles");std::cout<<"actual consumed reader-close EIO, cached all-terminal cleanup and Root first-error latch PASS\n";
}
#ifdef _WIN32
void temporary_close_failure(){Fixture f;auto latch=std::make_shared<Latch>();auto budget=std::make_shared<MetadataCaptureBudget>(limits());HANDLE h=CreateFileW(f.root.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);check(h!=INVALID_HANDLE_VALUE&&GetFileInformationByHandleEx(h,FileIdInfo,&close_target,sizeof(close_target)),"temporary-close ID");check(CloseHandle(h),"temporary-close ID close");close_hits=0;selected_closes=0;close_armed=true;close_watch=true;const auto before=native_reads.load();auto job=MetadataCaptureJob::begin_directory(f.directory,policy(),limits(),budget,latch);close_armed=false;close_watch=false;check(!job.value()&&latch->first&&latch->calls==1&&close_hits==1&&native_reads==before,"temporary descriptor close failure escaped startup/Root latch");check(selected_closes>=2&&budget->retained_handle_reservations()==0,"temporary failure did not close newly acquired source view");std::cout<<"native temporary-source close failure refuses capture before hashing and latches Root PASS\n";}
#endif
#ifdef _WIN32
void mutations(){Fixture f;auto source=f.source();auto job=take(MetadataCaptureJob::begin(source,policy(),limits()));while(job->progress().data_pass!=2)take(advance(*job));const auto times=f.times();f.main[0]^=std::byte{1};f.data({},f.main);f.restore(times);Observation<MetadataCaptureAdvance> last=Observation<MetadataCaptureAdvance>::available({MetadataCapturePhase::Basic});for(unsigned i=0;i<100000&&last.value()&&job->progress().phase!=MetadataCapturePhase::Complete;++i)last=advance(*job);check(!last.value()&&!job->result().value(),"between-pass mutation with restored clock accepted");
 check(take(job->finish_io()),"mutated source close failed");Fixture added;auto s=added.source();job=take(MetadataCaptureJob::begin(s,policy(),limits()));while(job->progress().phase!=MetadataCapturePhase::VerifyChannels)take(advance(*job));const auto old=added.times();added.data(u":late:$DATA",std::span(added.main).first(31));added.restore(old);last=advance(*job);check(!last.value()&&!job->result().value(),"late stream catalog addition accepted");check(take(job->finish_io()),"late catalog source close failed");std::cout<<"native between-pass content and late catalog changes despite restored Basic times refused PASS\n";}
struct Privilege{HANDLE token=nullptr;TOKEN_PRIVILEGES old{};bool enabled=false;Privilege(){check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES,&token)!=0,"token");TOKEN_PRIVILEGES p{};p.PrivilegeCount=1;p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;check(LookupPrivilegeValueW(nullptr,L"SeSecurityPrivilege",&p.Privileges[0].Luid),"LUID");DWORD n=sizeof(old);SetLastError(0);enabled=AdjustTokenPrivileges(token,FALSE,&p,sizeof(old),&old,&n)&&GetLastError()==0;check(enabled,"Full privilege unavailable");}~Privilege(){if(token){if(enabled)AdjustTokenPrivileges(token,FALSE,&old,0,nullptr,nullptr);CloseHandle(token);}}};
#endif
}
#ifdef _WIN32
// Native callbacks are installed by main; no Windows import replacement.
#else
extern "C" ssize_t pread(int fd,void* data,size_t n,off_t offset){return watched_pread(fd,data,n,offset);}
extern "C" int close(int fd){return watched_close(fd);}
#endif
int main(){
#ifdef _WIN32
 if(!ckfs_test::report_runtime_self("metadata-capture"))return 1;
 NativeCaptureFixtureScope native_capture_scope(capture_read_after,capture_close_before,capture_close_after);
#endif
try {
#ifdef __APPLE__
 if(std::getenv("CK_METADATA_CAPTURE_NOOWNERS")){noowners_negative();return 0;}
#endif
 static_assert(!std::is_default_constructible_v<NativeMetadataProof>);static_assert(!std::is_copy_constructible_v<NativeMetadataProof>);capture_and_verify(false);held_identity();negative_tests();cleanup_failure();
#ifdef _WIN32
 temporary_close_failure();mutations();Privilege privilege;capture_and_verify(true);
#endif
std::cout<<"metadata_capture_job_tests passed\n";return 0;}catch(const std::exception&e){frame=false;std::cerr<<e.what()<<'\n';return 1;}}
