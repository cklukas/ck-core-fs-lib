// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "operation_commit_job.hpp"
#include <cassert>
#include <cstdio>
#include <stdexcept>

using namespace ck::files;
namespace {
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
    for (auto operation:{FileOperation::Copy,FileOperation::Move})
        for (unsigned fault=0;fault<4;++fault) close_boundary(operation,fault);
    std::puts("io_finalization: delayed close failures preserve source and cannot publish success");
}
