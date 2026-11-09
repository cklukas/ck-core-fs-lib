// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "prepared_journal_root_bridge.hpp"
#include "journal_root_test_faults.hpp"
#include <algorithm>
#include <atomic>
#include <cstring>
namespace ck::files::detail {
// One immutable publication. Read/normal publication needs no mutex, allocation
// or native I/O. The optional failure-only test hook pauses publication.
// Callers retain the root owner until record() completes; finalization cannot
// race a legitimate writer after all consumer owners have been released.
class PreparedJournalFailureLatch final {
public:
    void record(ObservationState state,ErrorDomain domain,std::int64_t code,
        std::string_view operation) noexcept {
        unsigned empty=0;
        if(!state_.compare_exchange_strong(empty,1,std::memory_order_acq_rel))return;
        if(const auto pause=journal_root_test_publication_pause.load(std::memory_order_acquire))pause();
        if(state==ObservationState::Available||static_cast<unsigned>(state)>static_cast<unsigned>(ObservationState::Failed)||
            domain==ErrorDomain::None||static_cast<unsigned>(domain)>static_cast<unsigned>(ErrorDomain::NtStatus)) {
            state=ObservationState::Failed;domain=ErrorDomain::Adapter;
            code=static_cast<std::int64_t>(AdapterError::InvalidNativeResult);
            operation="journal_root.invalid_consumer_failure";
        }
        failure_.state=state;failure_.domain=domain;failure_.code=code;
        const auto count=std::min(operation.size(),failure_.operation.size()-1);
        if(count)std::memcpy(failure_.operation.data(),operation.data(),count);
        state_.store(2,std::memory_order_release);
    }
    bool read(PreparedJournalConsumerFailure& out) const noexcept {
        out={};const auto state=state_.load(std::memory_order_acquire);
        if(!state)return false;
        if(state==1) {
            out.pending=true;out.state=ObservationState::Changed;out.domain=ErrorDomain::Adapter;
            out.code=static_cast<std::int64_t>(AdapterError::InvalidAccess);
            constexpr char operation[]="journal_root.consumer_failure_pending";
            std::memcpy(out.operation.data(),operation,sizeof(operation));return true;
        }
        out=failure_;return true;
    }
    Observation<bool> result() const {
        PreparedJournalConsumerFailure failure;
        if(!read(failure))return Observation<bool>::available(true);
        // The pending POD already has a nonempty operation tag. Avoid the
        // allocating noexcept default-string constructor in MSVC Debug.
        return Observation<bool>::unavailable(failure.state,
            {failure.domain,failure.code,failure.operation.data()});
    }
private:
    std::atomic<unsigned> state_{0};
    PreparedJournalConsumerFailure failure_{};
};
} // namespace ck::files::detail
