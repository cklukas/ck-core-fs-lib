// SPDX-License-Identifier: LGPL-2.0-or-later
#include "action_jobs.hpp"
#include "native_filesystem.hpp"
#include "platform/journal_root_test_faults.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "windows_name.hpp"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <source_location>
#include <thread>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
using namespace ck::files;
namespace {
unsigned checks=0;
#define CHECK(x) do {++checks;if(!(x)){std::fprintf(stderr,"action_private_scope:%d: %s\n",__LINE__,#x);std::abort();}}while(false)
template<class T>T take(Observation<T> value,const std::source_location location=std::source_location::current()) {
    if(!value.value()) {const auto& e=*value.unavailable_detail();std::fprintf(stderr,"native line=%u: %s state=%u code=%lld\n",
        unsigned(location.line()),e.error.operation.c_str(),unsigned(e.state),static_cast<long long>(e.error.code));}
    CHECK(value.value());return std::move(value).take_value();
}
NativeName name(const char* text) {
#ifdef _WIN32
    return *NativeName::from_windows(std::u16string(text,text+std::char_traits<char>::length(text)));
#else
    return *NativeName::from_posix(text);
#endif
}
#ifdef _WIN32
std::wstring extended(const std::filesystem::path& path) {
    auto result=windows_extended_path(path.native());CHECK(result);
    return std::move(*result);
}
void mkdir_private(const std::filesystem::path& path){CHECK(CreateDirectoryW(extended(path).c_str(),nullptr));}
void create_file(const std::filesystem::path& path) {
    auto h=CreateFileW(extended(path).c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,CREATE_NEW,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);CHECK(h!=INVALID_HANDLE_VALUE);CHECK(CloseHandle(h));
}
void unlink_file(const std::filesystem::path& path){CHECK(DeleteFileW(extended(path).c_str()));}
void rmdir_private(const std::filesystem::path& path){CHECK(RemoveDirectoryW(extended(path).c_str()));}
#else
void mkdir_private(const std::filesystem::path& path){CHECK(::mkdir(path.c_str(),0700)==0);}
void create_file(const std::filesystem::path& path){const int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);CHECK(fd>=0);CHECK(::close(fd)==0);}
void unlink_file(const std::filesystem::path& path){CHECK(::unlink(path.c_str())==0);}
void rmdir_private(const std::filesystem::path& path){CHECK(::rmdir(path.c_str())==0);}
#endif
struct Fixture {
    std::filesystem::path path;
    NativeFileSystem fs;
    Fixture() {
#ifdef _WIN32
        const auto size=GetEnvironmentVariableW(L"TMPDIR",nullptr,0);CHECK(size>1);
        std::wstring temp(size,L'\0');CHECK(GetEnvironmentVariableW(L"TMPDIR",temp.data(),size)==size-1);temp.pop_back();
        CHECK(GetEnvironmentVariableW(L"TEMP",nullptr,0)>1&&GetEnvironmentVariableW(L"TMP",nullptr,0)>1);
        auto normalized=windows_extended_path(temp);CHECK(normalized);temp=std::move(*normalized);
        // Hosted CTest supplies its explicit runner fixture root.
        wchar_t require_v[2]{};
        if(GetEnvironmentVariableW(L"CK_FS_REQUIRE_V_DEV_DRIVE",require_v,2)==1&&require_v[0]==L'1')
            CHECK(temp.starts_with(L"\\\\?\\V:\\tmp\\"));
        path=std::filesystem::path(temp)/(L"action-private-scope-"+std::to_wstring(GetCurrentProcessId()));mkdir_private(path);
#else
        const auto* temp=std::getenv("TMPDIR");CHECK(temp&&*temp);
        std::string pattern=std::string(temp)+"/action-private-scope.XXXXXX";CHECK(::mkdtemp(pattern.data()));path=pattern;
#endif
        mkdir_private(path/"home");mkdir_private(path/"home"/"private");mkdir_private(path/"outside");
        create_file(path/"home"/"ordinary");
        CHECK(take(prepare_native_operation_journal_root(address())));
        // Tightening a Windows directory's DACL can remove inherited child
        // grants. Create this input afterwards so the test can obtain its
        // genuine native held entry before testing the independent scope gate.
        create_file(path/"home"/"private"/"state");
    }
    ~Fixture() {
        unlink_file(path/"home"/"ordinary");unlink_file(path/"home"/"private"/"state");
        rmdir_private(path/"home"/"private");rmdir_private(path/"home");rmdir_private(path/"outside");rmdir_private(path);
    }
    NativeAbsolutePath address(){return take(NativeAbsolutePath::from_host(path/"home"/"private"));}
    std::shared_ptr<const DirectoryCursor> directory(const char* relative) {
#ifdef _WIN32
        return std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(std::filesystem::path(extended(path/relative)))));
#else
        return std::shared_ptr<const DirectoryCursor>(take(fs.open_directory(path/relative)));
#endif
    }
    PreparedJournalRoot::Pointer root(){return take(acquire_native_journal_root(address()));}
};
std::atomic<unsigned> close_fault_calls{0};
std::optional<std::int64_t> close_fault(detail::JournalRootFaultPoint point) {
    if(point==detail::JournalRootFaultPoint::DirectoryClose){++close_fault_calls;return 5;}
    return std::nullopt;
}
struct Boundary final:ActionNativeBoundary {
    mutable std::atomic<unsigned> qualifications{0},mutations{0};
    bool allow=false,inject_close_fault=false;
    bool source_bound_rename()const noexcept override{return true;}
    Observation<bool> qualify(const HeldChild&)const override {
        ++qualifications;
        if(inject_close_fault)detail::journal_root_test_fault=close_fault;
        return Observation<bool>::available(allow);
    }
    Observation<bool> rename(const HeldChild&,const NativeName&,bool)const override {
        ++mutations;return Observation<bool>::unavailable(ObservationState::Unsupported);
    }
};
struct Trash final:NativeTrashBackend {
    mutable std::atomic<unsigned> previews{0};
    Observation<std::unique_ptr<NativeTrashTransaction>> prepare_trash(HeldChild::Pointer,std::stop_token)const override {
        ++previews;return Observation<std::unique_ptr<NativeTrashTransaction>>::unavailable(ObservationState::Unsupported);
    }
    Observation<std::unique_ptr<NativeTrashTransaction>> prepare_restore(const NativeTrashReceipt&,
        std::shared_ptr<const DirectoryCursor>,std::stop_token)const override {
        ++previews;return Observation<std::unique_ptr<NativeTrashTransaction>>::unavailable(ObservationState::Unsupported);
    }
    Observation<std::unique_ptr<NativeTrashTransaction>> prepare_trash_scoped(HeldChild::Pointer source,
        std::shared_ptr<PreparedJournalRoot>,std::stop_token stop)const override {
        return prepare_trash(std::move(source),stop); // Probe only; grants no transaction authority.
    }
    Observation<std::unique_ptr<NativeTrashTransaction>> prepare_restore_scoped(const NativeTrashReceipt& receipt,
        std::shared_ptr<const DirectoryCursor> parent,std::shared_ptr<PreparedJournalRoot> root,std::stop_token stop)const override {
        auto guarded=JournalScopeGuard::create(std::move(root),parent,stop);
        if(!guarded.value())return Observation<std::unique_ptr<NativeTrashTransaction>>::unavailable(guarded.state(),guarded.unavailable_detail()->error);
        return prepare_restore(receipt,std::move(parent),stop);
    }
};
void await(const std::shared_ptr<ActionJob>& job,bool terminal=false) {
    const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    for(;;) {
        const auto phase=job->summary().state;
        if(terminal?(phase==CKFEA_FINISHED||phase==CKFEA_CANCELLED||phase==CKFEA_JOB_FAILED):phase==CKFEA_AWAITING_RECEIPT)return;
        if(std::chrono::steady_clock::now()>=until){std::fprintf(stderr,"action worker timed out\n");std::abort();}
        job->wait(10);
        if(terminal)std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
void selected_case(Fixture& f,bool legacy,unsigned selection,uint32_t operation) {
    auto boundary=std::make_shared<Boundary>();auto trash=std::make_shared<Trash>();
    auto root=legacy?PreparedJournalRoot::Pointer{}:f.root();
    ActionRequest request;request.operation=operation;request.capabilities=CKFEA_ALLOW_NATIVE_TRASH;
    request.journal_directory=f.address();request.journal_name=name("action-journal");request.prepared_journal_root=root;
    auto parent=f.directory(selection==0?"home":selection==1?"home/private":selection==2?"home":"");
    auto source=take(HeldChild::observe(parent,name(selection==0?"ordinary":selection==1?"state":selection==2?"private":"home")));
    std::weak_ptr<const HeldChild> weak=source;
    request.items.push_back({std::move(source),name("renamed"),false});
    // A legacy injected path opener cannot supersede the adopted native owner.
    std::atomic<unsigned> path_reopens{0};
    request.open_journal=[&](const NativeAbsolutePath&,const NativeName&,bool){++path_reopens;
        return Observation<std::unique_ptr<OperationJournalFile>>::unavailable(ObservationState::Unsupported);};
    auto job=std::make_shared<ActionJob>(std::move(request),boundary,trash);job->start();await(job);
    ckfea_result row{};CHECK(job->item(0,row)==CKFEA_OK);CHECK(row.state==CKFEA_UNSUPPORTED);
    CHECK(boundary->mutations==0);CHECK(path_reopens==0);
    if(operation==CKFEA_RENAME)CHECK(boundary->qualifications==(selection==0?1u:0u));
    else CHECK(trash->previews==(selection==0?1u:0u));
    job->cancel();await(job,true);CHECK(weak.expired());
    if(root){CHECK(take(root->finish_io()));root.reset();}
    CHECK(job->item(0,row)==CKFEA_OK); // Terminal handle holds cached rows only.
}
void restore_case(Fixture& f,bool inside) {
    auto trash=std::make_shared<Trash>();auto root=f.root();
    ActionRequest request;request.operation=CKFEA_RESTORE;request.capabilities=CKFEA_ALLOW_NATIVE_RESTORE;
    request.prepared_journal_root=root;request.journal_directory=f.address();request.journal_name=name("restore-journal");
    auto receipt=std::make_shared<NativeTrashReceipt>(NativeTrashReceipt{name("ordinary"),name("data"),name("info"),name("sid"),{},{},{},{},{},{}});
    request.restore_items.push_back({std::move(receipt),f.directory(inside?"home/private":"outside")});
    auto job=std::make_shared<ActionJob>(std::move(request),std::make_shared<Boundary>(),trash);job->start();await(job);
    ckfea_result row{};CHECK(job->item(0,row)==CKFEA_OK);CHECK(row.state==CKFEA_UNSUPPORTED);CHECK(trash->previews==(inside?0u:1u));
    job->cancel();await(job,true);CHECK(take(root->finish_io()));CHECK(job->item(0,row)==CKFEA_OK);
}
void stale_after_review(Fixture& f) {
    auto boundary=std::make_shared<Boundary>();boundary->allow=true;
    auto root=f.root();ActionRequest request;
    request.prepared_journal_root=root;request.journal_directory=f.address();request.journal_name=name("stale-journal");
    request.items.push_back({take(HeldChild::observe(f.directory("home"),name("ordinary"))),name("renamed"),false});
    auto job=std::make_shared<ActionJob>(std::move(request),boundary);job->start();await(job);
    ckfea_result row{};CHECK(job->item(0,row)==CKFEA_OK&&row.state==CKFEA_READY);
    ckfea_receipt receipt{};CHECK(job->receipt(receipt)==CKFEA_OK);
    // A root cannot finish while this worker still retains consumer owners.
    CHECK(!root->finish_io().value());
    detail::record_prepared_journal_consumer_failure(*root,ObservationState::Failed,ErrorDomain::Posix,5,"test.action_root_error");
    CHECK(job->execute(receipt)==CKFEA_OK);await(job,true);
    CHECK(job->item(0,row)==CKFEA_OK&&row.state!=CKFEA_VERIFIED&&row.state!=CKFEA_READY);
    CHECK(boundary->mutations==0);
    CHECK(!f.fs.inspect_basic(f.path/"home"/"private"/"stale-journal").value());
    const auto closed=root->finish_io();CHECK(!closed.value()&&closed.unavailable_detail()->error.code==5);
}
void legacy_finish_failure(Fixture& f) {
    auto boundary=std::make_shared<Boundary>();boundary->inject_close_fault=true;
    ActionRequest request;request.journal_directory=f.address();request.journal_name=name("close-journal");
    request.items.push_back({take(HeldChild::observe(f.directory("home"),name("ordinary"))),name("renamed"),false});
    close_fault_calls=0;
    auto job=std::make_shared<ActionJob>(std::move(request),boundary);job->start();await(job);job->cancel();await(job,true);
    CHECK(job->summary().state==CKFEA_JOB_FAILED);
    ckfea_result row{};CHECK(job->item(0,row)==CKFEA_OK&&row.state==CKFEA_REVIEW_REQUIRED&&row.error_code==5);
    CHECK(close_fault_calls>0);const auto calls=close_fault_calls.load();job.reset();CHECK(close_fault_calls==calls);
}
}
int main() {
    Fixture fixture;
    for(bool legacy:{false,true})for(unsigned selection=0;selection<4;++selection)
        for(auto operation:{CKFEA_RENAME,CKFEA_TRASH})selected_case(fixture,legacy,selection,operation);
    restore_case(fixture,true);restore_case(fixture,false);
    stale_after_review(fixture);legacy_finish_failure(fixture);
    std::printf("action_private_scope: %u checks passed (native selected-entry gates; probes grant no native transaction authority)\n",checks);
}
