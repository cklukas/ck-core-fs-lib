// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "operation_commit_job.hpp"
#include "operation_execution_job.hpp"
#include <cassert>
#include <cstdio>
#include <new>
#include <stdexcept>

using namespace ck::files;
namespace {
void cancellation_close(unsigned fault,bool prior_failure,bool protocol_throw=false) {
    OperationJournalId id{};id.bytes[0]=std::byte{81};
    auto created=OperationJournal::create(FileOperation::Copy,id);assert(created.value());
    auto journal=*created.value();
    assert(journal->append({1,0,OperationJournalState::Planned,{}}).value());
    OperationCopyRequest copy;
    copy.journal=journal;
    copy.revalidate_source=copy.revalidate_destination=[&](std::stop_token) {
        if(prior_failure)return Observation<bool>::unavailable(ObservationState::Failed,
            {ErrorDomain::Posix,28,"test.original_failure"});
        return Observation<bool>::available(true);
    };
    copy.prepare_copy=[](std::stop_token) {return Observation<StreamCopyJob::Pointer>::unavailable(ObservationState::Unknown);};
    copy.prepare_metadata=[](std::stop_token) {return Observation<OperationMetadataJob::Pointer>::unavailable(ObservationState::Unknown);};
    copy.verify_copy=[](std::stop_token) {return Observation<bool>::available(true);};
    copy.append_journal=[&](OperationJournalRecord record) {
        if(protocol_throw)throw std::bad_alloc();
        return journal->append(std::move(record));
    };
    auto prepared=OperationCopyJob::create(std::move(copy));assert(prepared.value());
    OperationExecutionRequest request;
    request.copy=std::move(prepared).take_value();
    unsigned commits=0,finishes=0;
    request.prepare_commit=[&](std::stop_token) {++commits;return Observation<OperationCommitJob::Pointer>::unavailable(ObservationState::Unknown);};
    request.finish_io=[&] {
        ++finishes;
        if(fault==1)return Observation<bool>::unavailable(ObservationState::Unknown,{ErrorDomain::Posix,5,"test.cancel_close"});
        if(fault==2)return Observation<bool>::available(false);
        if(fault==3)throw std::runtime_error("test.cancel_close");
        if(fault==4)throw std::bad_alloc();
        return Observation<bool>::available(true);
    };
    auto made=OperationExecutionJob::create(std::move(request));assert(made.value());auto job=std::move(made).take_value();
    std::stop_source stop;if(!prior_failure)stop.request_stop();
    job->advance(stop.get_token());assert(finishes==1&&commits==0);
    assert(job->state()==(fault||protocol_throw?OperationExecutionState::NeedsReconciliation:
        prior_failure?OperationExecutionState::Failed:OperationExecutionState::Cancelled));
    if(prior_failure)assert(job->failure()&&job->failure()->error.code==28&&job->failure()->error.operation=="test.original_failure");
    else if(protocol_throw)assert(job->failure()&&job->failure()->state==ObservationState::Unknown&&
        job->failure()->error.domain==ErrorDomain::Adapter&&
        job->failure()->error.code==static_cast<std::int64_t>(AdapterError::InvalidNativeResult));
    else if(fault==1)assert(job->failure()&&job->failure()->error.code==5);
    else if(fault||protocol_throw)assert(job->failure());
    else assert(!job->failure());
    for(unsigned i=0;i<3;++i)job->advance(stop.get_token());
    assert(finishes==1&&commits==0);
}
void close_boundary(FileOperation operation, unsigned fault) {
    OperationJournalId id{}; id.bytes[0]=std::byte{77};
    auto journal=*OperationJournal::create(operation,id).value();
    for (auto state : {OperationJournalState::Planned,OperationJournalState::Prepared,
                       OperationJournalState::Copied,OperationJournalState::Verified})
        assert(journal->append({journal->records().size()+1,0,state,{}}).value());
    unsigned publications=0, finishes=0, removals=0;
    OperationCommitRequest request;
    request.operation=operation; request.journal=journal;
    request.revalidate_source=request.revalidate_destination=[](std::stop_token) { return Observation<bool>::available(true); };
    request.commit_destination=[&](std::stop_token) { ++publications; return Observation<bool>::available(true); };
    request.finalize_destination=[&] {
        ++finishes;
        // At this boundary the publication is durable, but no source-removal
        // intent may exist. A delayed close error must preserve the source.
        assert(journal->state(0)==OperationJournalState::DestinationCommitted);
        if (fault==1) return Observation<bool>::unavailable(ObservationState::Failed,{ErrorDomain::Posix,5,"test.delayed_close"});
        if (fault==2) return Observation<bool>::available(false);
        if (fault==3) throw std::runtime_error("test close exception");
        return Observation<bool>::available(true);
    };
    request.verify_source_stability=[](std::stop_token) { return Observation<SourceStabilityGuarantee>::available(SourceStabilityGuarantee::Snapshot); };
    request.retire_source=[&](std::stop_token) { assert(finishes==1); ++removals; return Observation<bool>::available(true); };
    request.append_journal=[&](OperationJournalRecord r) { return journal->append(std::move(r)); };
    auto made=OperationCommitJob::create(std::move(request)); assert(made.value());
    auto job=std::move(made).take_value();
    for (unsigned i=0;i<8 && job->state()<OperationCommitState::Complete;++i) job->advance();
    assert(publications==1 && finishes==1);
    if (fault) {
        assert(job->state()==OperationCommitState::NeedsReconciliation && job->failure());
        assert(removals==0 && journal->state(0)==OperationJournalState::DestinationCommitted);
    } else {
        assert(job->state()==OperationCommitState::Complete && !job->failure());
        assert(removals==(operation==FileOperation::Move?1u:0u));
        assert(journal->state(0)==OperationJournalState::Complete);
    }
    for (unsigned i=0;i<3;++i) job->advance();
    assert(finishes==1); // A consumed descriptor is never closed a second time.
}
}
int main() {
    for(unsigned fault=0;fault<5;++fault)for(bool prior:{false,true})cancellation_close(fault,prior);
    for(unsigned fault=0;fault<5;++fault)cancellation_close(fault,false,true);
    for (auto operation:{FileOperation::Copy,FileOperation::Move})
        for (unsigned fault=0;fault<4;++fault) close_boundary(operation,fault);
    std::puts("io_finalization: delayed close failures preserve source and cannot publish success");
}
