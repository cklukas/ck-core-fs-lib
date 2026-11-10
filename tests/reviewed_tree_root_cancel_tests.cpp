// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Genuine native fixture only; no other executable's override/allocator body.
#include "reviewed_tree_root_cancel_fixture.hpp"
#include "platform/journal_root_test_faults.hpp"
#include "platform/legacy_native_fixture_observation.hpp"
#ifndef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
#error Rebuild the entire matching SDK and client cohort with compiled native observation
#endif
namespace root_cancel_hook {
thread_local std::stop_source* armed=nullptr;
thread_local unsigned hits=0;
thread_local bool closed_error=false;
std::optional<std::int64_t> close_fault(ck::files::detail::JournalRootFaultPoint point)noexcept{
    if(point==ck::files::detail::JournalRootFaultPoint::JournalClose)return 5;
    return std::nullopt;
}
void after_query(const ck::files::detail::LegacyNativeEvent& event)noexcept {
    using namespace ck::files::detail;
    if(event.operation!=LegacyNativeOperation::Query||event.phase!=LegacyNativePhase::After)return;
    if(!armed)return;
    auto* stop=armed;armed=nullptr;++hits;stop->request_stop();
}
}
int main(){try{
    constexpr auto query=detail::legacy_operation_bit(detail::LegacyNativeOperation::Query);
    CHECK((detail::legacy_native_metadata_coverage()&query)==query);
    CHECK((detail::legacy_native_journal_coverage()&query)==query);
    CHECK((detail::legacy_native_scope_coverage()&query)==query);
    const auto previous_query=detail::legacy_native_test_observer.exchange(root_cancel_hook::after_query);
    struct RestoreQuery {detail::LegacyNativeObserver previous;~RestoreQuery(){root_cancel_hook::armed=nullptr;detail::legacy_native_test_observer.store(previous);}} restore_query{previous_query};
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
