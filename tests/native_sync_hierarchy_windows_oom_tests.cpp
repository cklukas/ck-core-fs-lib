// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef CK_FS_NATIVE_CLOSE_TEST_HOOKS
#error This fixture and its complete SDK closure require matching compiled native-close hooks.
#endif
#include "platform/native_close_test_faults.hpp"
#include "platform/journal_root_test_faults.hpp"
#include "native_sync_hierarchy_binding.hpp"
#include "native_sync_coordinator.hpp"
#include "native_sync_resolution.hpp"
#include "native_filesystem.hpp"
#include "windows_name.hpp"
#include "platform/native_sync_session_lease.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "windows_test_runtime_self_report.hpp"
#include <cstring>
#include <stdexcept>
#include <malloc.h>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <exception>
#include <optional>
#include <string_view>
#include <type_traits>
using namespace ck::files;
namespace heap_fault {
thread_local bool persistent=false;
thread_local unsigned allow=0,failures=0;
void before(){if(persistent){if(allow){--allow;return;}++failures;throw std::bad_alloc();}}
}
void* operator new(std::size_t n){heap_fault::before();if(void* p=std::malloc(n?n:1))return p;throw std::bad_alloc();}
void* operator new[](std::size_t n){return ::operator new(n);}
void operator delete(void* p)noexcept{std::free(p);}void operator delete(void* p,std::size_t)noexcept{std::free(p);}
void operator delete[](void* p)noexcept{std::free(p);}void operator delete[](void* p,std::size_t)noexcept{std::free(p);}
void* operator new(std::size_t n,std::align_val_t a){heap_fault::before();if(void* p=_aligned_malloc(n?n:1,static_cast<std::size_t>(a)))return p;throw std::bad_alloc();}
void* operator new[](std::size_t n,std::align_val_t a){return ::operator new(n,a);}
void operator delete(void* p,std::align_val_t)noexcept{_aligned_free(p);}void operator delete(void* p,std::size_t,std::align_val_t)noexcept{_aligned_free(p);}
void operator delete[](void* p,std::align_val_t)noexcept{_aligned_free(p);}void operator delete[](void* p,std::size_t,std::align_val_t)noexcept{_aligned_free(p);}
namespace close_fault {
// The hierarchy and its finalizers run on the arming thread. Independent native
// lock-worker closes cannot select this fault or arm OOM on the wrong thread.
thread_local bool armed=false,selected=false,native_selected_ok=false;
thread_local FILE_ID_INFO target{};
thread_local unsigned hits=0,calls=0,root_closes=0;
thread_local HANDLE pending=nullptr,consumed=nullptr;
thread_local std::uint32_t native_selected_error=0;
void before(void* handle,const char*,const char*)noexcept {
 ++calls;pending=nullptr;selected=false;
 FILE_ID_INFO id{};
 if(armed&&GetFileInformationByHandleEx(handle,FileIdInfo,&id,sizeof(id))&&
    id.VolumeSerialNumber==target.VolumeSerialNumber&&
    std::memcmp(id.FileId.Identifier,target.FileId.Identifier,16)==0){pending=handle;selected=true;}
}
std::uint32_t after(void* handle,const char*,bool native_ok,std::uint32_t native_error)noexcept {
 const bool match=selected&&pending==handle;selected=false;pending=nullptr;
 if(!match)return 0;
 native_selected_ok=native_ok;native_selected_error=native_error;
 // The adapter has already consumed the real native handle. Only a successful
 // native close may acquire this later failure; its own error always wins.
 if(!native_ok)return 0;
 armed=false;consumed=handle;++hits;
 heap_fault::persistent=true; // no allocation or intervening native operation
 return ERROR_WRITE_FAULT;
}
std::optional<std::int64_t> root_close(detail::JournalRootFaultPoint point)noexcept {
 // Root's direct chain closes use their existing post-native observation seam,
 // not the temporary-handle seam. Count both, retaining the repeated-finalizer
 // no-close checks without replacing any system import or dropping Root I/O.
 if(point==detail::JournalRootFaultPoint::DirectoryClose||point==detail::JournalRootFaultPoint::JournalClose){++root_closes;++calls;}
 return std::nullopt; // observation only: never inject or suppress a Root error
}
struct ScopedObservers final {
 ScopedObservers(){
  if(detail::native_close_test_before.load()||detail::native_close_test_after.load()||detail::journal_root_test_fault)
   throw std::runtime_error("native close observer already installed");
  detail::native_close_test_before.store(before);
  detail::native_close_test_after.store(after);
  detail::journal_root_test_fault=root_close;
 }
 ~ScopedObservers(){
  armed=false;heap_fault::persistent=false;
  detail::native_close_test_after.store(nullptr);
  detail::native_close_test_before.store(nullptr);
  detail::journal_root_test_fault=nullptr;
 }
 ScopedObservers(const ScopedObservers&)=delete;
 ScopedObservers& operator=(const ScopedObservers&)=delete;
};
}
namespace {
unsigned checks=0;
#define CHECK(x) do{++checks;if(!(x))throw std::runtime_error(#x);}while(false)
template<class T>T get(Observation<T> o){if(auto e=o.unavailable_detail())throw std::runtime_error(e->error.operation+" code="+std::to_string(e->error.code));return std::move(o).take_value();}
void yes(Observation<bool> o){CHECK(get(std::move(o)));}
NativeName name(const wchar_t* s){std::u16string units;while(*s)units.push_back(static_cast<char16_t>(*s++));return *NativeName::from_windows(std::move(units));}
std::optional<std::wstring> env(const wchar_t* n){SetLastError(0);const DWORD size=GetEnvironmentVariableW(n,nullptr,0);if(!size){CHECK(GetLastError()==0||GetLastError()==ERROR_ENVVAR_NOT_FOUND);return{};}CHECK(size<=32768);std::wstring value(size,L'\0');const auto count=GetEnvironmentVariableW(n,value.data(),size);CHECK(count>0&&count<size);value.resize(count);return value;}
std::filesystem::path ext(std::filesystem::path p){auto s=windows_extended_path(p.native());CHECK(s.has_value());return std::filesystem::path(*s);}
DWORD handles(){DWORD count=0;CHECK(GetProcessHandleCount(GetCurrentProcess(),&count));return count;}
struct Fixture {
 std::filesystem::path root;PreparedJournalRoot::Pointer journal;std::vector<std::filesystem::path> dirs;bool nested;
 explicit Fixture(bool with_nested = true) : nested(with_nested) {
  const auto temp = env(L"TEMP");
  CHECK(temp);
  root = ext(*temp);
  // Hosted CTest supplies its explicit runner fixture root.
  if (const auto require_v = env(L"CK_FS_REQUIRE_V_DEV_DRIVE"); require_v && *require_v == L"1")
   CHECK(root.native().starts_with(L"\\\\?\\V:\\tmp\\"));
  static unsigned sequence = 0;
  root /= L"hierarchy-oom-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
      std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(sequence++);
  mkdir(root);
  mkdir(root/L"left");
  mkdir(root/L"right");
  NativeFileSystem fs;
  PreparedJournalRootRequest request;
  request.parent = std::shared_ptr<const DirectoryCursor>(get(fs.open_directory(root)));
  request.child = name(L"store");
  request.disposition = JournalRootDisposition::ProvisionChild;
  request.navigation_hint = address(L"store");
  JournalRootPreparationProgress progress;
  journal = get(prepare_native_journal_root(std::move(request), progress));
  dirs.push_back(root/L"store");
  if (nested) {
   add_nested();
  } else {
   write(root/L"left/a");
   write(root/L"right/a");
  }
 }
 void mkdir(std::filesystem::path p){p=ext(std::move(p));CHECK(CreateDirectoryW(p.c_str(),nullptr));dirs.push_back(std::move(p));}
 void write(std::filesystem::path p){p=ext(std::move(p));HANDLE h=CreateFileW(p.c_str(),GENERIC_WRITE|FILE_READ_ATTRIBUTES,7,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);CHECK(h!=INVALID_HANDLE_VALUE);DWORD written=0;const char b='x';CHECK(WriteFile(h,&b,1,&written,nullptr)&&written==1&&FlushFileBuffers(h));CHECK(CloseHandle(h));}
 void add_nested(){mkdir(root/L"left/d");mkdir(root/L"left/d/e");write(root/L"left/d/e/file");nested=true;}
 NativeAbsolutePath address(const wchar_t* p){return get(NativeAbsolutePath::from_host(ext(root/p)));}
 std::vector<NativeName> components(){return {name(L"d"),name(L"e"),name(L"file")};}
 void arm(){HANDLE h=CreateFileW(ext(root/L"left/d/e/file").c_str(),FILE_READ_ATTRIBUTES,7,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);CHECK(h!=INVALID_HANDLE_VALUE);CHECK(GetFileInformationByHandleEx(h,FileIdInfo,&close_fault::target,sizeof(close_fault::target)));CHECK(CloseHandle(h));close_fault::hits=0;close_fault::consumed=nullptr;close_fault::pending=nullptr;close_fault::selected=false;close_fault::native_selected_ok=false;close_fault::native_selected_error=0;heap_fault::failures=0;heap_fault::allow=0;close_fault::armed=true;}
 ~Fixture(){close_fault::armed=false;heap_fault::persistent=false;detail::session_epoch_before_construct_test=nullptr;if(journal)try{(void)journal->finish_io();}catch(...){ }journal.reset();for(auto p:{root/L"left/d/e/file",root/L"left/a",root/L"right/a"})DeleteFileW(ext(p).c_str());for(auto p=dirs.rbegin();p!=dirs.rend();++p)RemoveDirectoryW(ext(*p).c_str());}
};
std::unique_ptr<SyncSession> session(Fixture& f){return get(SyncSession::open(get(open_native_sync_session_backend(f.journal,f.address(L"left"),f.address(L"right"))),SyncDigest{}));}
NativeSyncCoordinatorRequest request(Fixture& f){NativeSyncCoordinatorRequest r{f.address(L"store"),f.address(L"left"),f.address(L"right"),{},{},{},{},{},{},{}};r.prepared_journal_root=f.journal;r.metadata.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;r.metadata.ownership=MetadataOwnership::CurrentCaller;return r;}
void verify_raw(const NativeHierarchyFailure& helper,const detail::SessionReaderFailure& reader,bool caught,DWORD before,DWORD after){CHECK(caught&&heap_fault::failures>0&&close_fault::hits==1);CHECK(close_fault::native_selected_ok&&close_fault::native_selected_error==ERROR_SUCCESS&&close_fault::consumed);CHECK(helper.present&&helper.domain==ErrorDomain::Win32&&helper.code==ERROR_WRITE_FAULT);if(reader.failed)CHECK(reader.domain==ErrorDomain::Win32&&reader.code==ERROR_WRITE_FAULT);CHECK(before==after);}
void root_sticky_finalization(Fixture& f) {
 detail::PreparedJournalConsumerFailure initial{};
 CHECK(detail::read_prepared_journal_consumer_failure(*f.journal,initial)&&!initial.pending&&initial.domain==ErrorDomain::Win32&&initial.code==ERROR_WRITE_FAULT);
 CHECK(f.journal.use_count()==1);
 bool first_caught=false,second_caught=false;
 const auto initial_root_closes=close_fault::root_closes;
 heap_fault::allow=0;heap_fault::persistent=true;
 try{(void)f.journal->finish_io();}catch(const std::bad_alloc&){first_caught=true;}
 const auto consumed_calls=close_fault::calls;
 const auto consumed_root_closes=close_fault::root_closes;
 const DWORD after_first=handles();
 try{(void)f.journal->finish_io();}catch(const std::bad_alloc&){second_caught=true;}
 const auto repeated_calls=close_fault::calls;
 const DWORD after_second=handles();
 detail::PreparedJournalConsumerFailure sticky{};const bool present=detail::read_prepared_journal_consumer_failure(*f.journal,sticky);
 heap_fault::persistent=false;
 CHECK(first_caught&&second_caught&&present&&!sticky.pending&&sticky.domain==initial.domain&&sticky.code==initial.code&&sticky.operation==initial.operation);
 CHECK(consumed_calls==repeated_calls&&after_first==after_second&&close_fault::hits==1);
 CHECK(consumed_root_closes>initial_root_closes&&close_fault::root_closes==consumed_root_closes);
 auto repeated=f.journal->finish_io();CHECK(!repeated.value()&&repeated.unavailable_detail()->error.domain==initial.domain&&repeated.unavailable_detail()->error.code==initial.code&&close_fault::calls==repeated_calls);
 std::puts("PASS genuine Root sticky + persistentOOM finalizer drain + repeated no native retry");
}
void session_failure(bool commit){Fixture f;const auto before=handles();auto s=session(f);auto c=get(NativeHierarchyContext::borrow(*s));auto b=get(c->bind(false,f.components()));f.arm();bool caught=false;NativeHierarchyFailure pod{};detail::SessionReaderFailure reader{};DWORD after=0;
 try{if(commit)(void)s->commit(s->snapshot().generation,{},true);else (void)s->finish_io();}
 catch(const std::bad_alloc&){pod=c->drain();reader=s->reader_failure();if(s->root_handle(false)!=-1)try{(void)s->finish_io();}catch(...){ }after=handles();caught=true;}
 const bool persistent=heap_fault::persistent;heap_fault::persistent=false;CHECK(persistent);verify_raw(pod,reader,caught,before,after);CHECK(reader.failed&&s->snapshot().generation==0&&s->root_handle(false)==-1);const auto finished_calls=close_fault::calls;auto repeated=s->finish_io();CHECK(!repeated.value()&&repeated.unavailable_detail()->error.code==ERROR_WRITE_FAULT&&close_fault::hits==1&&close_fault::calls==finished_calls);CHECK(handles()==after);std::printf("PASS native session persistentOOM commit=%d actualClose=%u\n",commit,close_fault::hits);b.reset();c.reset();s.reset();root_sticky_finalization(f);}
void context_failure(bool transient){Fixture f;const auto before=handles();auto c=get(NativeHierarchyContext::open(f.journal,f.address(L"left"),f.address(L"right")));NativeHierarchyBinding::Pointer b;if(!transient)b=get(c->bind(false,f.components()));f.arm();bool caught=false;NativeHierarchyFailure pod{};DWORD after=0;
 try{if(transient)(void)c->bind(false,f.components());else (void)b->finish_io();}
 catch(const std::bad_alloc&){pod=c->drain();after=handles();caught=true;}
 heap_fault::persistent=false;verify_raw(pod,{},caught,before,after);const auto finished_calls=close_fault::calls;auto repeated=c->finish_io();CHECK(!repeated.value()&&repeated.unavailable_detail()->error.code==ERROR_WRITE_FAULT&&close_fault::hits==1&&close_fault::calls==finished_calls);CHECK(handles()==after);std::printf("PASS context persistentOOM transient=%d\n",transient);b.reset();c.reset();root_sticky_finalization(f);}
template<class Worker>void worker_failure(){Fixture f(false);const auto before=handles();auto w=get(Worker::open(request(f)));auto c=get(NativeHierarchyContext::borrow(*w));f.add_nested();auto b=get(c->bind(false,f.components()));f.arm();bool caught=false;NativeHierarchyFailure pod{};DWORD after=0;
 try{(void)b->revalidate();}catch(const std::bad_alloc&){pod=c->drain();try{(void)w->finish_io();}catch(...){ }after=handles();caught=true;}
 heap_fault::persistent=false;verify_raw(pod,{},caught,before,after);auto closed=NativeHierarchyContext::borrow(*w);CHECK(!closed.value()&&closed.unavailable_detail()->error.operation=="hierarchy.worker_closed");std::puts("PASS actual worker borrow persistentOOM drain");b.reset();c.reset();w.reset();root_sticky_finalization(f);}
void epoch_constructor(){Fixture f;const auto before=handles();auto s=session(f);bool caught=false;heap_fault::failures=0;detail::session_epoch_before_construct_test=+[]()noexcept{heap_fault::allow=1;heap_fault::persistent=true;};
 try{(void)NativeHierarchyContext::borrow(*s);}catch(const std::bad_alloc&){if(s->root_handle(false)!=-1)try{(void)s->finish_io();}catch(...){ }caught=true;}
 detail::session_epoch_before_construct_test=nullptr;heap_fault::persistent=false;CHECK(caught&&heap_fault::failures>0&&handles()==before);std::puts("PASS genuine epoch vector proxy persistentOOM noTerminate");}
static_assert(!noexcept(std::declval<NativeHierarchyContext&>().finish_io()));
static_assert(!noexcept(std::declval<const detail::SessionReaderFailure&>().result()));
}
void raw_text(const char* text){DWORD written=0;WriteFile(GetStdHandle(STD_ERROR_HANDLE),text,static_cast<DWORD>(std::strlen(text)),&written,nullptr);}
void terminate_stack()noexcept {
 raw_text("TERMINATE persistentOOM stack_rvas\n");
 void* frames[64]{};const auto count=CaptureStackBackTrace(0,64,frames,nullptr);const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
 for(USHORT i=0;i<count;++i){std::uintptr_t value=reinterpret_cast<std::uintptr_t>(frames[i]);if(value>=base)value-=base;char line[20]="0x0000000000000000\n";for(unsigned n=0;n<16;++n){const auto x=static_cast<unsigned>(value&15);line[17-n]="0123456789abcdef"[x];value>>=4;}DWORD wrote=0;WriteFile(GetStdHandle(STD_ERROR_HANDLE),line,19,&wrote,nullptr);}
 ExitProcess(91);
}
int main(){if(!ckfs_test::report_runtime_self("sync-hierarchy"))return 1;std::set_terminate(terminate_stack);try{close_fault::ScopedObservers observers;
 raw_text("BEGIN epoch_constructor\n");epoch_constructor();
 raw_text("BEGIN session_finish\n");session_failure(false);
 raw_text("BEGIN session_commit\n");session_failure(true);
 raw_text("BEGIN context_finish\n");context_failure(false);
 raw_text("BEGIN context_transient\n");context_failure(true);
 raw_text("BEGIN coordinator\n");worker_failure<NativeSyncCoordinator>();
 raw_text("BEGIN resolution\n");worker_failure<NativeSyncResolution>();
 std::printf("WINDOWS_NATIVE_PERSISTENT_OOM checks=%u PASS\n",checks);return 0;}catch(const std::exception& e){heap_fault::persistent=false;close_fault::armed=false;std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
