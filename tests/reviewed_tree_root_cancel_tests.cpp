// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Reuse the native fixture, not a fake provider. This TU has its own entry point.
#define main reviewed_tree_existing_tests_main
#include "reviewed_tree_plan_tests.cpp"
#undef main
#include "platform/prepared_journal_root_bridge.hpp"
#ifndef _WIN32
#include <dlfcn.h>
#endif
namespace root_cancel_hook {
thread_local std::stop_source* armed=nullptr;
thread_local unsigned hits=0;
thread_local bool closed_error=false;
std::optional<std::int64_t> close_fault(ck::files::detail::JournalRootFaultPoint point){
    if(point==ck::files::detail::JournalRootFaultPoint::JournalClose)return 5;
    return std::nullopt;
}
void after_query()noexcept {
    if(!armed)return;
    auto* stop=armed;armed=nullptr;++hits;stop->request_stop();
}
#ifdef _WIN32
BOOL WINAPI query(HANDLE h,FILE_INFO_BY_HANDLE_CLASS kind,LPVOID out,DWORD n){
    using F=BOOL(WINAPI*)(HANDLE,FILE_INFO_BY_HANDLE_CLASS,LPVOID,DWORD);
    static const auto real=std::bit_cast<F>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"GetFileInformationByHandleEx"));
    const auto result=real(h,kind,out,n);const auto error=GetLastError();after_query();SetLastError(error);return result;
}
#else
int query(int fd,struct stat* out)noexcept {
    using F=int(*)(int,struct stat*);static const auto real=reinterpret_cast<F>(dlsym(RTLD_NEXT,"fstat"));
    const auto result=real(fd,out);const auto error=errno;after_query();errno=error;return result;
}
#endif
}
#ifdef _WIN32
extern "C" {decltype(&GetFileInformationByHandleEx) __imp_GetFileInformationByHandleEx=&root_cancel_hook::query;}
#else
extern "C" int fstat(int fd,struct stat* out)
#ifdef __linux__
noexcept
#endif
{return root_cancel_hook::query(fd,out);}
#endif
int main(){try{
    for(bool during_scope:{false,true})for(bool native_close_error:{false,true}){
        if(!during_scope&&native_close_error)continue;
        Fixture fixture;auto request=fixture.request();PreparedJournalRoot::Pointer root;
        std::unique_ptr<OperationJournalFile> journal;
        if(during_scope){root=take(acquire_native_journal_root(*request.journal_root));request.prepared_journal_root=root;}
        auto job=take(ReviewedTreePlanJob::create(std::move(request)));
        if(during_scope){CHECK(job->advance()==ReviewedTreeState::Inventory);}
        const auto previous=detail::journal_root_test_fault;
        struct Restore{detail::JournalRootFault previous;~Restore(){root_cancel_hook::armed=nullptr;detail::journal_root_test_fault=previous;}} restore{previous};
        std::stop_source stop;root_cancel_hook::hits=0;root_cancel_hook::closed_error=false;
        if(native_close_error){
            // Consume the real close before cancellation. Native query hooks
            // must never reenter a Root while its validation mutex is held.
            journal=take(root->open_journal(name(".ck-root-cancel-probe"),true));
            detail::journal_root_test_fault=root_cancel_hook::close_fault;
            auto closed=journal->finish_io();root_cancel_hook::closed_error=!closed.value()&&closed.unavailable_detail()->error.code==5;
            journal.reset();stop.request_stop();
        }else root_cancel_hook::armed=&stop;
        const auto state=job->advance(stop.get_token());CHECK(root_cancel_hook::hits==(native_close_error?0U:1U)&&stop.stop_requested());
        CHECK(!fixture.exists("d/a"));CHECK(job->progress().failed_items==0);
        if(native_close_error){
            CHECK(root_cancel_hook::closed_error);CHECK(state==ReviewedTreeState::NeedsReconciliation);
            CHECK(job->progress().failure&&job->progress().failure->error.code==5);
            detail::PreparedJournalConsumerFailure first;CHECK(detail::read_prepared_journal_consumer_failure(*root,first)&&first.code==5);
            CHECK(!root->finish_io().value());
        }else{
            CHECK(state==ReviewedTreeState::Cancelled);CHECK(!job->progress().failure);CHECK(!job->progress().recovery_required);
            if(root)CHECK(take(root->finish_io()));
        }
        std::printf("deterministic Root cancellation prep=%d scope=%d real-close-error=%d PASS\n",!during_scope,during_scope,native_close_error);
    }
    std::printf("reviewed_tree Root cancellation: %u checks passed\n",checks);return 0;
}catch(const std::exception& e){std::fprintf(stderr,"reviewed_tree Root cancellation: %s\n",e.what());return 1;}}
