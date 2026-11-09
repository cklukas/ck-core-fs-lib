// SPDX-License-Identifier: LGPL-2.0-or-later
// Real native cursor + public C Action worker close-boundary qualification.
// Compiled failure-only native test hooks run after the real consumed close.
// No system symbol replacement, external cleanup scope, or fake Root.
#include "native_filesystem.hpp"
#include "held_child.hpp"
#include "operation_journal.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "journal_root_handles.hpp"
#include "ck_fs_actions.h"
#include "windows_name.hpp"
#include "platform/action_final_drain_test_hooks.hpp"
#include "platform/native_close_test_faults.hpp"
#include "platform/journal_root_test_faults.hpp"
#include <windows.h>
#include <atomic>
#include <array>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <algorithm>
#include <thread>
#include <malloc.h>
using namespace ck::files;
namespace {
std::atomic<bool> deny_new=false;
void denied_allocation()noexcept;
}
void* operator new(std::size_t n){if(deny_new){denied_allocation();throw std::bad_alloc();}if(auto*p=std::malloc(n?n:1))return p;throw std::bad_alloc();}
void* operator new[](std::size_t n){return ::operator new(n);}
void operator delete(void*p)noexcept{std::free(p);}void operator delete[](void*p)noexcept{std::free(p);}
void operator delete(void*p,std::size_t)noexcept{std::free(p);}void operator delete[](void*p,std::size_t)noexcept{std::free(p);}
void* operator new(std::size_t n,std::align_val_t a){if(deny_new){denied_allocation();throw std::bad_alloc();}if(auto*p=_aligned_malloc(n?n:1,std::size_t(a)))return p;throw std::bad_alloc();}
void* operator new[](std::size_t n,std::align_val_t a){return ::operator new(n,a);}
void operator delete(void*p,std::align_val_t)noexcept{_aligned_free(p);}void operator delete[](void*p,std::align_val_t)noexcept{_aligned_free(p);}
void operator delete(void*p,std::size_t,std::align_val_t)noexcept{_aligned_free(p);}void operator delete[](void*p,std::size_t,std::align_val_t)noexcept{_aligned_free(p);}
namespace {
unsigned checks=0;
#define CHECK(x) do{++checks;if(!(x)){deny_new=false;throw std::runtime_error("line "+std::to_string(__LINE__)+": "+#x);}}while(false)
template<class T>T take(Observation<T> o){if(!o.value()){deny_new=false;throw std::runtime_error(o.unavailable_detail()->error.operation);}return std::move(o).take_value();}
template<class T>T output(){T v{};v.version=1;v.struct_size=sizeof(T);return v;}
std::wstring env(const wchar_t* key){auto n=GetEnvironmentVariableW(key,nullptr,0);CHECK(n&&n<=32768);std::wstring s(n,L'\0');CHECK(GetEnvironmentVariableW(key,s.data(),n)==n-1);s.resize(n-1);return s;}
NativeName name(std::u16string s){auto n=NativeName::from_windows(std::move(s));CHECK(n);return std::move(*n);}
std::wstring units(const NativeName& n){return {n.windows_units()->begin(),n.windows_units()->end()};}
const auto real_close=&CloseHandle;
const auto real_info=&GetFileInformationByHandleEx;
const auto real_create=&CreateFileW;
const auto real_read=&ReadFile;
bool same(const FILE_ID_INFO&a,const FILE_ID_INFO&b)noexcept{return a.VolumeSerialNumber==b.VolumeSerialNumber&&!std::memcmp(a.FileId.Identifier,b.FileId.Identifier,16);}
FILE_ID_INFO id(HANDLE h){FILE_ID_INFO v{};CHECK(real_info(h,FileIdInfo,&v,sizeof(v)));return v;}
HANDLE open(const std::wstring&p,DWORD access,DWORD disposition=OPEN_EXISTING,bool directory=false){auto h=real_create(p.c_str(),access,7,nullptr,disposition,FILE_FLAG_OPEN_REPARSE_POINT|(directory?FILE_FLAG_BACKUP_SEMANTICS:0),nullptr);CHECK(h&&h!=INVALID_HANDLE_VALUE);return h;}
void mkdir(const std::wstring&p){CHECK(CreateDirectoryW(p.c_str(),nullptr));}
void erase_tree(const std::wstring&p){WIN32_FIND_DATAW d{};auto f=FindFirstFileExW((p+L"\\*").c_str(),FindExInfoBasic,&d,FindExSearchNameMatch,nullptr,0);if(f!=INVALID_HANDLE_VALUE){do{if(!std::wcscmp(d.cFileName,L".")||!std::wcscmp(d.cFileName,L".."))continue;auto child=p+L"\\"+d.cFileName;if(d.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)erase_tree(child);else CHECK(DeleteFileW(child.c_str()));}while(FindNextFileW(f,&d));CHECK(FindClose(f));}CHECK(RemoveDirectoryW(p.c_str()));}
enum class Role:unsigned {Other,Input,InputParent,RenameSource,CaseProbe,Published,Verification,Journal,RootDuplicate,RenameParent};
enum class Phase:unsigned {Setup,Inputs,Preview,Execute,Terminal};
struct Owner{HANDLE handle=nullptr;FILE_ID_INFO id{};Role role=Role::Other;unsigned item=0,closes=0;};
struct Watch {
    std::atomic_flag lock=ATOMIC_FLAG_INIT;
    std::atomic<Phase> phase=Phase::Setup;
    std::array<FILE_ID_INFO,3> sources{};FILE_ID_INFO parent{},root_id{};
    std::array<Owner,4096> owners{};unsigned owners_used=0;
    std::array<unsigned,3> rename_opens{},reads_with_rename{};
    std::array<bool,3> source_live{};
    std::array<HANDLE,8192> reserved{};unsigned reserved_count=0;HANDLE retired=nullptr,sentinel=nullptr;
    std::atomic<unsigned> io=0,writes=0,writes_after_fault=0,denials=0,journal_closes=0;
    std::atomic<bool> fault_used=false,stale_close=false;
    Role inject=Role::Other;bool oom=false,prior=false,case_only=false,pending=false,late=false;
    std::atomic<bool> publication_entered=false,release_publication=false,start_publication=false,drain_entered=false;
    std::atomic<const char*> stage="setup";
    PreparedJournalRoot* root=nullptr;detail::PreparedJournalConsumerFailure first_denied{};
};
std::atomic<Watch*> watching=nullptr;
struct Lock{Watch&w;explicit Lock(Watch&v):w(v){while(w.lock.test_and_set(std::memory_order_acquire))YieldProcessor();}~Lock(){w.lock.clear(std::memory_order_release);}};
void denied_allocation()noexcept{if(auto*w=watching.load())if(!w->denials.fetch_add(1)&&w->root)detail::read_prepared_journal_consumer_failure(*w->root,w->first_denied);}
Owner* live(Watch&w,HANDLE h)noexcept{for(unsigned i=w.owners_used;i;--i)if(w.owners[i-1].handle==h&&!w.owners[i-1].closes)return &w.owners[i-1];return nullptr;}
void before_native_close(void* h,const char* operation,const char* context)noexcept {
    auto*w=watching.load();if(!w)return;++w->io;
    Lock guard(*w);for(unsigned i=0;i<w->reserved_count;++i)if(w->reserved[i]==h)w->stale_close=true;
    FILE_ID_INFO identity{};if(!real_info(h,FileIdInfo,&identity,sizeof(identity)))return;
    Role role=Role::Other;unsigned item=0;const std::string_view tag=operation?operation:"",scope=context?context:"";
    for(unsigned i=0;i<3;++i)if(same(identity,w->sources[i])) {
        item=i;
        if(tag.find(".source_CloseHandle")!=tag.npos&&tag.starts_with("rename_child_")){role=Role::RenameSource;++w->rename_opens[i];}
        else if(tag.find(".published_CloseHandle")!=tag.npos||tag.find(".renamed_CloseHandle")!=tag.npos)role=Role::Published;
        else if(tag.find("rename_child_case_only.destination_CloseHandle")!=tag.npos)role=Role::CaseProbe;
        else if(scope=="actions.verification")role=Role::Verification;
        else if(scope=="actions.inputs")role=Role::Input;
        break;
    }
    if(role==Role::Other&&same(identity,w->parent)) {
        if(tag.starts_with("rename_child_"))role=Role::RenameParent;
        else if(scope=="actions.inputs")role=Role::InputParent;
    }
    if(role==Role::Other)return;if(w->owners_used==w->owners.size())std::abort();w->owners[w->owners_used++]={h,identity,role,item,0};
}
std::uint32_t after_native_close(void* h,const char*,bool native_ok,std::uint32_t)noexcept {
    auto*w=watching.load();if(!w)return 0;Lock guard(*w);auto*owner=live(*w,h);
    if(owner){++owner->closes;
        if(native_ok&&w->phase==Phase::Execute&&!w->fault_used&&owner->item==0&&owner->role==w->inject){
            w->fault_used=true;w->retired=h;
            if(w->prior&&w->root)detail::record_prepared_journal_consumer_failure(*w->root,ObservationState::Failed,ErrorDomain::Win32,ERROR_CRC,"test.rename.prior_root");
            while(w->reserved_count<w->reserved.size()&&!w->sentinel){auto event=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!event)std::abort();w->reserved[w->reserved_count++]=event;if(event==h)w->sentinel=event;}
            deny_new=w->oom;return ERROR_READ_FAULT;
        }
    }
    return 0;
}
std::optional<std::int64_t> observe_journal_close(detail::JournalRootFaultPoint point){
    if(auto*w=watching.load()){++w->io;if(point==detail::JournalRootFaultPoint::JournalClose)++w->journal_closes;}
    return std::nullopt;
}
void fatal_test_terminate()noexcept {
    deny_new=false;auto*w=watching.load();std::fprintf(stderr,"FAIL terminate thread=%lu stage=%s pending=%u first_denied_pending=%u denials=%u\n",GetCurrentThreadId(),w?w->stage.load():"no-watch",unsigned(w&&w->pending),unsigned(w&&w->first_denied.pending),w?w->denials.load():0);
    if(const auto exception=std::current_exception())try{std::rethrow_exception(exception);}catch(const std::exception&e){std::fprintf(stderr,"active exception: %s\n",e.what());}catch(...){std::fputs("active nonstandard exception\n",stderr);}
    std::fflush(stderr);std::_Exit(3);
}
void observe_native_io(detail::NativeTestIo op)noexcept{if(op==detail::NativeTestIo::WorkerStart){std::set_terminate(fatal_test_terminate);return;}if(auto*w=watching.load()){if(op==detail::NativeTestIo::PendingWait){w->stage="worker-publication-wait";return;}if(op==detail::NativeTestIo::InputDrain){w->stage="worker-input-drain";return;}++w->io;if(op==detail::NativeTestIo::Write){++w->writes;if(w->fault_used)++w->writes_after_fault;}}}
void observe_final_drain()noexcept{if(auto*w=watching.load())w->drain_entered=true;}
void install_watch(Watch&w){detail::native_test_io_observer=observe_native_io;watching=&w;detail::native_close_test_before=before_native_close;detail::native_close_test_after=after_native_close;detail::journal_root_test_worker_fault=observe_journal_close;}
void no_retry_and_closed(Watch&w){for(unsigned i=0;i<w.owners_used;++i)CHECK(w.owners[i].closes==1);CHECK(!w.stale_close);if(w.fault_used){CHECK(w.sentinel==w.retired&&w.sentinel);CHECK(SetEvent(w.sentinel)&&WaitForSingleObject(w.sentinel,0)==WAIT_OBJECT_0&&ResetEvent(w.sentinel));} }
void clear_watch(Watch&w){detail::action_final_drain_test_hold=false;detail::action_final_drain_test_observe=nullptr;detail::native_test_io_observer=nullptr;detail::native_close_test_before=nullptr;detail::native_close_test_after=nullptr;detail::journal_root_test_worker_fault=nullptr;watching=nullptr;deny_new=false;for(unsigned i=0;i<w.reserved_count;++i)CHECK(real_close(w.reserved[i]));}
ckfea_native_text text(const NativeName&n){auto v=output<ckfea_native_text>();v.encoding=CKFEA_WINDOWS_UTF16;v.data=n.windows_units()->data();v.byte_count=n.windows_units()->size()*2;return v;}
struct Fixture {
    std::wstring top,data;std::array<NativeName,3> from{name(u"source-0"),name(u"source-1"),name(u"source-2")},to{name(u"target-0"),name(u"target-1"),name(u"target-2")};
    std::array<FILE_ID_INFO,3> ids{};FILE_ID_INFO parent{};
    Fixture(bool case_only,bool raw){auto base=windows_extended_path(env(L"TEMP"));CHECK(base);wchar_t policy[2]{};if(GetEnvironmentVariableW(L"CK_FS_REQUIRE_V_DEV_DRIVE",policy,2)==1&&policy[0]==L'1')CHECK(base->starts_with(L"\\\\?\\V:\\tmp\\"));top=*base+L"\\rename-close-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());mkdir(top);data=top+L"\\data";mkdir(data);
        auto dir=open(data,FILE_READ_ATTRIBUTES,OPEN_EXISTING,true);parent=id(dir);wchar_t fs[32]{};CHECK(GetVolumeInformationByHandleW(dir,nullptr,0,nullptr,nullptr,nullptr,fs,32));CHECK(fs==env(L"CK_FS_EXPECT_NATIVE_FS"));std::printf("NATIVE_PROVIDER fs=%ls parent_utf16_units=%zu\n",fs,data.size());CHECK(real_close(dir));
        if(!case_only&&!raw){to[1]=from[0];to[2]=from[1];}
        for(unsigned i=0;i<3;++i){if(case_only)to[i]=name(u"SOURCE-"+std::u16string(1,char16_t(u'0'+i)));if(raw){from[i]=name(u"source-"+std::u16string(1,char16_t(u'0'+i))+std::u16string(1,char16_t(0xd800+i))+u". ");to[i]=name((case_only?u"SOURCE-":u"target-")+std::u16string(1,char16_t(u'0'+i))+std::u16string(1,char16_t(0xd800+i))+u". ");}auto h=open(data+L"\\"+units(from[i]),GENERIC_WRITE|FILE_READ_ATTRIBUTES,CREATE_NEW);DWORD n{};const char bytes[]="rename-fixture";CHECK(WriteFile(h,bytes,sizeof(bytes),&n,nullptr)&&n==sizeof(bytes)&&FlushFileBuffers(h));ids[i]=id(h);CHECK(real_close(h));}}
    ~Fixture(){deny_new=false;watching=nullptr;try{erase_tree(top);}catch(...){std::fprintf(stderr,"OWNED_FIXTURE_CLEANUP_FAILED\n");}}
};
void inspect_names(const Fixture&f,const Watch&w,unsigned count){
    std::vector<std::wstring> names;WIN32_FIND_DATAW d{};auto search=FindFirstFileExW((f.data+L"\\*").c_str(),FindExInfoBasic,&d,FindExSearchNameMatch,nullptr,0);CHECK(search!=INVALID_HANDLE_VALUE);
    do{if(std::wcscmp(d.cFileName,L".")&&std::wcscmp(d.cFileName,L".."))names.emplace_back(d.cFileName);}while(FindNextFileW(search,&d));CHECK(GetLastError()==ERROR_NO_MORE_FILES);CHECK(FindClose(search));CHECK(names.size()==3);
    for(unsigned i=0;i<3;++i){const bool moved=i<count&&w.rename_opens[i]>0;const auto expected=units(moved?f.to[i]:f.from[i]);CHECK(std::count(names.begin(),names.end(),expected)==1);auto h=open(f.data+L"\\"+expected,FILE_READ_ATTRIBUTES);CHECK(same(id(h),f.ids[i]));CHECK(real_close(h));}
}
ckfea_summary wait_action(ckfea_job*job,bool terminal){for(unsigned n=0;n<6000;++n){auto s=output<ckfea_summary>();CHECK(ckfea_job_summary(job,&s)==CKFEA_OK);if(terminal?(s.state>=CKFEA_FINISHED):(s.state!=CKFEA_PREVIEWING))return s;const auto status=ckfea_job_wait(job,10);CHECK(status==CKFEA_OK||status==CKFEA_NOT_READY);}CHECK(false);return {};}
ckfjr_snapshot_v1 wait_root(ckfjr_root*root,bool finish){for(unsigned n=0;n<6000;++n){auto s=output<ckfjr_snapshot_v1>();CHECK(ckfjr_poll_v1(root,&s)==CKFE_API_OK);if(finish?s.worker_drained:(s.state!=CKFJR_PREPARING))return s;CHECK(ckfjr_wait_v1(root,10)==CKFE_API_OK);}CHECK(false);return {};}
void inspect_journal(const std::wstring&p,bool complete,unsigned items){auto h=open(p,GENERIC_READ);LARGE_INTEGER size{};CHECK(GetFileSizeEx(h,&size)&&size.QuadPart>0&&size.QuadPart<8*1024*1024);std::vector<std::byte> bytes(std::size_t(size.QuadPart));DWORD read{};CHECK(real_read(h,bytes.data(),DWORD(bytes.size()),&read,nullptr)&&read==bytes.size());CHECK(real_close(h));auto decoded=take(decode_operation_journal(bytes));CHECK(decoded.journal&&!decoded.tail);unsigned completed=0;for(const auto&r:decoded.journal->records())completed+=r.state==OperationJournalState::Complete;CHECK(complete?completed==items:completed==0);}
void pause_root_publication()noexcept {
    std::set_terminate(fatal_test_terminate);
    if(auto*w=watching.load()){w->publication_entered=true;while(!w->release_publication.load())Sleep(1);}
}
struct PendingPublisher final {
    Watch& watch;std::jthread thread;
    PendingPublisher(Watch&w,PreparedJournalRoot::Pointer root):watch(w) {
        detail::journal_root_test_publication_pause=pause_root_publication;
        if(!w.late)w.start_publication=true;
        thread=std::jthread([root=std::move(root),&w]{while(!w.start_publication.load())Sleep(1);detail::record_prepared_journal_consumer_failure(*root,ObservationState::Failed,ErrorDomain::Win32,ERROR_CRC,"test.rename.pending_first");});
    }
    void release(){watch.start_publication=true;watch.release_publication=true;detail::action_final_drain_test_hold=false;if(thread.joinable())thread.join();detail::journal_root_test_publication_pause=nullptr;}
    ~PendingPublisher(){release();}
};
void worker(Fixture&f,Watch&w,unsigned count){
    ckfe_engine*engine=nullptr;CHECK(ckfe_engine_create(&engine)==CKFE_API_OK);ckfe_error error;ckfe_error_init(&error);ckfe_directory*top=nullptr;CHECK(ckfe_directory_open_utf16(engine,reinterpret_cast<const uint16_t*>(f.top.data()),f.top.size(),0,&top,&error)==CKFE_API_OK);
    const auto journal_name=name(u"journal");ckfjr_options_v1 opts;ckfjr_options_init_v1(&opts);opts.parent=top;opts.disposition=CKFJR_PROVISION_CHILD;opts.child.encoding=CKFJR_UTF16;opts.child.data=journal_name.windows_units()->data();opts.child.byte_count=journal_name.windows_units()->size()*2;ckfjr_root*cap=nullptr;CHECK(ckfjr_start_v1(&opts,&cap)==CKFE_API_OK);ckfe_directory_destroy(top);auto ready=wait_root(cap,false);CHECK(ready.state==CKFJR_READY);
    auto retained=retain_prepared_journal_root(cap);CHECK(retained.value());auto root=std::move(retained).take_value();w.root=root.get();auto rh=open(f.top+L"\\journal",FILE_READ_ATTRIBUTES,OPEN_EXISTING,true);w.root_id=id(rh);CHECK(real_close(rh));w.sources=f.ids;w.parent=f.parent;install_watch(w);w.phase=Phase::Inputs;
    ckfe_directory*data=nullptr;CHECK(ckfe_directory_open_utf16(engine,reinterpret_cast<const uint16_t*>(f.data.data()),f.data.size(),0,&data,&error)==CKFE_API_OK);std::array<ckfe_entry*,3> inputs{};std::array<ckfea_item,3> items{};
    for(unsigned i=0;i<count;++i){CHECK(ckfe_entry_open_utf16(data,reinterpret_cast<const uint16_t*>(f.from[i].windows_units()->data()),f.from[i].windows_units()->size(),&inputs[i],&error)==CKFE_API_OK);ckfea_item_init(&items[i]);items[i].source=inputs[i];items[i].destination_name=text(f.to[i]);items[i].flags=w.case_only?CKFEA_CASE_ONLY:0;}
    ckfea_request request;ckfea_request_init(&request);request.items=items.data();request.item_count=count;request.retry_limit=2;const auto file_name=name(u"rename.journal");request.journal_name=text(file_name);w.phase=Phase::Preview;ckfea_job*job=nullptr;CHECK(ckfea_job_create_with_journal_root(&request,cap,&job)==CKFEA_OK);for(unsigned i=0;i<count;++i)ckfe_entry_destroy(inputs[i]);ckfe_directory_destroy(data);
    auto preview=wait_action(job,false);CHECK(preview.state==CKFEA_AWAITING_RECEIPT&&preview.ready_count==count);auto receipt=output<ckfea_receipt>();CHECK(ckfea_job_receipt(job,&receipt)==CKFEA_OK);std::optional<PendingPublisher> publisher;
    if(w.pending){publisher.emplace(w,root);if(w.late){detail::action_final_drain_test_hold=true;detail::action_final_drain_test_observe=observe_final_drain;}else{for(unsigned n=0;n<10000&&!w.publication_entered;++n)Sleep(1);CHECK(w.publication_entered);detail::PreparedJournalConsumerFailure pending;CHECK(detail::read_prepared_journal_consumer_failure(*w.root,pending)&&pending.pending);deny_new=w.oom;}}
    w.phase=Phase::Execute;CHECK(ckfea_job_execute(job,&receipt)==CKFEA_OK);
    if(w.pending){
        if(w.late){for(unsigned n=0;n<10000&&!w.drain_entered;++n)Sleep(1);CHECK(w.drain_entered);w.start_publication=true;for(unsigned n=0;n<10000&&!w.publication_entered;++n)Sleep(1);CHECK(w.publication_entered);deny_new=w.oom;detail::action_final_drain_test_hold=false;Sleep(10);auto observed=output<ckfea_summary>();CHECK(ckfea_job_summary(job,&observed)==CKFEA_OK);detail::PreparedJournalConsumerFailure pending;CHECK(detail::read_prepared_journal_consumer_failure(*w.root,pending)&&pending.pending);std::printf("ACTUAL_LATE_ROOT state=%u verified=%u Root_pending=%u Root_alive=1 finalizers_returned=1\n",observed.state,observed.verified_count,unsigned(pending.pending));std::fflush(stdout);}
        for(unsigned n=0;n<30;++n){auto snapshot=output<ckfea_summary>();CHECK(ckfea_job_summary(job,&snapshot)==CKFEA_OK);if(w.late&&snapshot.state!=CKFEA_RUNNING){detail::PreparedJournalConsumerFailure observed;CHECK(detail::read_prepared_journal_consumer_failure(*w.root,observed));std::printf("ACTUAL_LATE_EARLY_TERMINAL state=%u verified=%u Root_pending=%u\n",snapshot.state,snapshot.verified_count,unsigned(observed.pending));std::fflush(stdout);}CHECK(snapshot.state==CKFEA_RUNNING&&!snapshot.verified_count);detail::PreparedJournalConsumerFailure pending;CHECK(detail::read_prepared_journal_consumer_failure(*w.root,pending)&&pending.pending);Sleep(1);}
        publisher->release();const auto terminal=wait_action(job,true);w.phase=Phase::Terminal;CHECK(terminal.state==CKFEA_JOB_FAILED&&!terminal.verified_count&&!w.fault_used);
        detail::PreparedJournalConsumerFailure first;CHECK(detail::read_prepared_journal_consumer_failure(*w.root,first)&&!first.pending&&first.code==ERROR_CRC&&first.domain==ErrorDomain::Win32);CHECK(!std::strcmp(first.operation.data(),"test.rename.pending_first"));if(w.oom&&!w.late)CHECK(w.denials&&w.first_denied.pending);
        for(unsigned i=0;i<count;++i){auto result=output<ckfea_result>();CHECK(ckfea_job_item(job,i,&result)==CKFEA_OK&&result.state==CKFEA_REVIEW_REQUIRED&&result.observation==unsigned(ObservationState::Unknown)&&result.error_code==ERROR_CRC&&result.error_domain==unsigned(ErrorDomain::Win32)&&result.attempts==(w.late?1u:0u));CHECK(w.rename_opens[i]==(w.late?1u:0u));}
        no_retry_and_closed(w);CHECK(w.journal_closes==(w.late?1u:0u));const auto io=w.io.load(),denials=w.denials.load();for(unsigned n=0;n<20;++n){auto snapshot=output<ckfea_summary>();CHECK(ckfea_job_summary(job,&snapshot)==CKFEA_OK&&snapshot.state==CKFEA_JOB_FAILED);CHECK(ckfea_job_wait(job,0)==CKFEA_OK);}CHECK(w.io==io&&w.denials==denials);
        root.reset();CHECK(ckfjr_finish_v1(cap)==CKFE_API_OK);auto final_root=wait_root(cap,true);CHECK(final_root.worker_drained&&final_root.state==CKFJR_FAILED&&final_root.failure_domain==unsigned(ErrorDomain::Win32)&&final_root.failure_code==ERROR_CRC);CHECK(final_root.failure_state==unsigned(first.state)&&!std::strcmp(final_root.failure_operation,first.operation.data()));if(w.oom&&w.late)CHECK(w.denials&&!w.first_denied.pending&&w.first_denied.state==first.state&&w.first_denied.domain==first.domain&&w.first_denied.code==first.code&&!std::strcmp(w.first_denied.operation.data(),first.operation.data()));
        const auto after=w.io.load();ckfea_job_destroy(job);CHECK(w.io==after);no_retry_and_closed(w);ckfjr_release(cap);ckfe_engine_destroy(engine);ckfe_error_free(&error);deny_new=false;inspect_names(f,w,count);if(w.late)inspect_journal(f.top+L"\\journal\\rename.journal",true,count);else CHECK(GetFileAttributesW((f.top+L"\\journal\\rename.journal").c_str())==INVALID_FILE_ATTRIBUTES&&GetLastError()==ERROR_FILE_NOT_FOUND);
        std::printf("PUBLIC_C_WORKER pending_publication=1 no_early_terminal=1 genuine_Root_retained=1 exact_first=23 OOM=%u consumer_drain_before_terminal=1 cached_poll_no_native_io_or_alloc=1 PASS\n",unsigned(w.oom));clear_watch(w);return;
    }
    const auto terminal=wait_action(job,true);w.phase=Phase::Terminal;
    const bool fault=w.inject!=Role::Other;CHECK(w.fault_used==fault);CHECK(terminal.state==(fault?CKFEA_JOB_FAILED:CKFEA_FINISHED));CHECK(fault?terminal.verified_count==0:terminal.verified_count==count);if(fault)CHECK(w.writes_after_fault==0);
    const auto expected=w.prior?ERROR_CRC:ERROR_READ_FAULT;detail::PreparedJournalConsumerFailure first;const bool found=detail::read_prepared_journal_consumer_failure(*w.root,first);CHECK(found==fault);if(fault){CHECK(!first.pending&&first.domain==ErrorDomain::Win32&&first.code==expected);if(w.oom)CHECK(w.denials&&w.first_denied.domain==ErrorDomain::Win32&&w.first_denied.code==expected&&!w.first_denied.pending&&w.first_denied.state==first.state&&!std::strcmp(w.first_denied.operation.data(),first.operation.data()));}
    for(unsigned i=0;i<count;++i){auto row=output<ckfea_result>();CHECK(ckfea_job_item(job,i,&row)==CKFEA_OK);if(fault){CHECK(row.state==CKFEA_REVIEW_REQUIRED);if(i==0||w.inject==Role::Input||w.inject==Role::InputParent)CHECK(row.error_domain==unsigned(ErrorDomain::Win32)&&row.error_code==expected&&row.observation==unsigned(ObservationState::Unknown));if(i&&w.inject!=Role::Input&&w.inject!=Role::InputParent)CHECK(row.attempts==0);}else CHECK(row.state==CKFEA_VERIFIED&&row.attempts==1);}
    CHECK(w.journal_closes==1);unsigned retries=0;for(std::uint64_t n=0;n<terminal.evidence_count;++n){auto event=output<ckfea_evidence>();CHECK(ckfea_job_evidence(job,n,&event)==CKFEA_OK);retries+=event.kind==CKFEA_EVIDENCE_RETRY;}CHECK(retries==0);no_retry_and_closed(w);
    const auto io=w.io.load(),denials=w.denials.load();for(unsigned i=0;i<20;++i){auto s=output<ckfea_summary>();auto row=output<ckfea_result>();CHECK(ckfea_job_summary(job,&s)==CKFEA_OK&&s.state==terminal.state);CHECK(ckfea_job_item(job,0,&row)==CKFEA_OK);CHECK(ckfea_job_wait(job,0)==CKFEA_OK);}CHECK(w.io==io&&w.denials==denials);
    root.reset();CHECK(ckfjr_finish_v1(cap)==CKFE_API_OK);auto finished=wait_root(cap,true);CHECK(finished.worker_drained);if(fault)CHECK(finished.state==CKFJR_FAILED&&finished.failure_domain==unsigned(ErrorDomain::Win32)&&finished.failure_code==expected);else CHECK(finished.state==CKFJR_COMPLETE&&!finished.failure_domain);
    auto after_root=w.io.load();ckfea_job_destroy(job);CHECK(w.io==after_root);no_retry_and_closed(w);ckfjr_release(cap);ckfe_engine_destroy(engine);ckfe_error_free(&error);deny_new=false;inspect_journal(f.top+L"\\journal\\rename.journal",!fault,count);inspect_names(f,w,count);
    if(fault&&w.inject!=Role::Input&&w.inject!=Role::InputParent)for(unsigned i=1;i<count;++i)CHECK(w.rename_opens[i]==0);
    std::printf("PUBLIC_C_WORKER native_close=%u Root_first=%lld OOM=%u cached_terminal=%u noComplete_on_consumer_failure=1 noRetry=1 real_handle_reuse=%u no_external_scope=1 PASS\n",unsigned(w.inject),static_cast<long long>(found?first.code:0),unsigned(w.oom),terminal.state,unsigned(w.sentinel!=nullptr));clear_watch(w);
}
void direct(Fixture&f,Watch&w){NativeFileSystem fs;auto parent=std::shared_ptr<const DirectoryCursor>(take(fs.open_native_directory(take(NativeAbsolutePath::from_host(std::filesystem::path(f.data))))));auto held=take(HeldChild::observe(parent,f.from[0]));auto expected=*held->metadata().identity.value();held.reset();w.sources=f.ids;w.parent=f.parent;install_watch(w);w.phase=Phase::Execute;bool threw=false;std::optional<Observation<bool>> result;
    try{result=w.case_only?parent->rename_child_case_only(f.from[0],expected,f.to[0]):parent->rename_child_noreplace(f.from[0],expected,*parent,f.to[0]);}catch(const std::bad_alloc&){threw=true;}
    w.phase=Phase::Terminal;CHECK(w.fault_used==(w.inject!=Role::Other));if(w.oom){CHECK(threw&&w.denials);}else if(w.inject!=Role::Other){CHECK(result&&!result->value()&&result->state()==ObservationState::Unknown&&result->unavailable_detail()->error.code==ERROR_READ_FAULT);}else CHECK(result&&result->value()&&*result->value());no_retry_and_closed(w);deny_new=false;inspect_names(f,w,1);std::printf("DIRECT_NATIVE_CURSOR Root_required=0 case_only=%u OOM=%u explicit_consumer_drain=1 noRetry=1 real_handle_reuse=%u PASS\n",unsigned(w.case_only),unsigned(w.oom),unsigned(w.sentinel!=nullptr));clear_watch(w);}
}
int wmain(int argc,wchar_t**argv){std::set_terminate(fatal_test_terminate);try{CHECK(argc==2);DWORD_PTR actual_mask{},system_mask{};CHECK(GetProcessAffinityMask(GetCurrentProcess(),&actual_mask,&system_mask));std::printf("ACTUAL_PROCESS_AFFINITY mask=%llu\n",static_cast<unsigned long long>(actual_mask));const std::wstring_view mode=argv[1];Watch w;w.case_only=mode.find(L"case")!=mode.npos;w.oom=mode.find(L"oom")!=mode.npos;w.prior=mode.find(L"prior")!=mode.npos;w.late=mode.find(L"late")!=mode.npos;w.pending=w.late||mode.find(L"pending")!=mode.npos;const bool is_direct=mode.starts_with(L"direct"),raw=mode.find(L"raw")!=mode.npos;
    if(mode.find(L"source")!=mode.npos)w.inject=Role::RenameSource;else if(mode.find(L"published")!=mode.npos)w.inject=Role::Published;else if(mode.find(L"verify")!=mode.npos)w.inject=Role::Verification;else if(mode.find(L"nativeparent")!=mode.npos)w.inject=Role::RenameParent;else if(mode.find(L"parent")!=mode.npos)w.inject=Role::InputParent;else if(mode.find(L"input")!=mode.npos)w.inject=Role::Input;
    CHECK(!is_direct||w.inject==Role::Other||w.inject==Role::RenameSource||w.inject==Role::Published||w.inject==Role::RenameParent);Fixture fixture(w.case_only,raw);if(is_direct)direct(fixture,w);else worker(fixture,w,raw?1:3);std::printf("NATIVE_RENAME_CLOSE checks=%u mode=%.*ls PASS\n",checks,int(mode.size()),mode.data());return 0;}catch(const std::exception&e){deny_new=false;watching=nullptr;std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
