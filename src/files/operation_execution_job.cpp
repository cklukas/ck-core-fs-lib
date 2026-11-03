// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "operation_execution_job.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <new>
#include <string_view>

namespace ck::files {
namespace {
UnavailableObservation error(AdapterError code, const char* operation,
                              ObservationState state = ObservationState::Failed) {
    return {state, {ErrorDomain::Adapter, static_cast<std::int64_t>(code), operation}};
}

template <class T>
Observation<T> rejected(AdapterError code, const char* operation) {
    return Observation<T>::unavailable(ObservationState::Failed,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(code), operation});
}

// Finalization must retain a scalar first error without allocating. The public
// result still owns an optional std::string diagnostic, so publishing it is
// best effort only after every native close has been attempted. On OOM the
// caller receives NeedsReconciliation with no fabricated empty diagnostic.
struct FixedFailure final {
    bool recorded = false;
    ObservationState state = ObservationState::Unknown;
    ErrorDomain domain = ErrorDomain::Adapter;
    std::int64_t code = static_cast<std::int64_t>(AdapterError::InvalidNativeResult);
    std::array<char, 128> operation{};

    void record(ObservationState next_state, ErrorDomain next_domain,
                std::int64_t next_code, std::string_view next_operation) noexcept {
        if (recorded) return;
        recorded = true;
        state = next_state;
        domain = next_domain;
        code = next_code;
        const auto count = std::min(next_operation.size(), operation.size() - 1);
        if (count) std::memcpy(operation.data(), next_operation.data(), count);
        operation[count] = '\0';
    }

    void publish(std::optional<UnavailableObservation>& destination) const noexcept {
        if (!recorded || destination) return;
        try {
            destination.emplace(UnavailableObservation{state, {domain, code, operation.data()}});
        } catch (...) {
            // The scalar state remains authoritative. Never retry with an
            // empty std::string: MSVC debug string construction can allocate.
        }
    }
};
}

Observation<OperationExecutionJob::Pointer> OperationExecutionJob::create(OperationExecutionRequest request) {
    if (!request.copy || !request.prepare_commit)
        return rejected<Pointer>(AdapterError::PlanInvalid, "operation_execution.request");
    return Observation<Pointer>::available(Pointer(new OperationExecutionJob(std::move(request))));
}

void OperationExecutionJob::fail(UnavailableObservation detail, OperationExecutionState state) noexcept {
    result_.failure = std::move(detail);
    result_.state = state;
}

OperationProgress OperationExecutionJob::progress() const noexcept {
    OperationProgress progress{result_.state, 0, std::nullopt};
    if (request_.copy) {
        const auto& copy = request_.copy->result();
        progress.observed_bytes = copy.observed_bytes;
        if (copy.state == OperationCopyState::Verified)
            progress.total_bytes = copy.observed_bytes;
    }
    return progress;
}

OperationExecutionState OperationExecutionJob::advance(std::stop_token stop) {
    // A completed child can advance its parent to the next nonterminal phase
    // even with stop requested. Drain those synchronous transitions before
    // releasing native owners or exposing a cancelled result.
    FixedFailure protocol_failure;
    try {
        do {
            advance_protocol(stop);
        } while(stop.stop_requested()&&result_.state<OperationExecutionState::Complete);
    } catch (...) {
        // Even an allocation/provider exception must reach native finalizers.
        // Keep only fixed scalar diagnostics until all finalizers have run.
        protocol_failure.record(ObservationState::Unknown, ErrorDomain::Adapter,
            static_cast<std::int64_t>(AdapterError::InvalidNativeResult),
            "operation_execution.protocol_exception");
        result_.state=OperationExecutionState::NeedsReconciliation;
    }
    if (result_.state < OperationExecutionState::Complete)
        return result_.state;
    if (io_finished_) {
        // The native owners were consumed by an earlier call. There is no
        // finalizer left to run, so publishing this call's POD diagnostic is
        // now safe; never manufacture an empty fallback.
        protocol_failure.publish(result_.failure);
        return result_.state;
    }
    // Consume the finalizer before calling external/native code. A throw can
    // mean a handle was already consumed and must never trigger a close retry.
    io_finished_ = true;
    FixedFailure finish_failure;
    if (request_.finish_io) {
        try {
            auto finished = request_.finish_io();
            if(const auto* detail=finished.unavailable_detail()) {
                finish_failure.record(detail->state, detail->error.domain, detail->error.code,
                    detail->error.operation);
            } else if(!*finished.value()) {
                finish_failure.record(ObservationState::Unknown, ErrorDomain::Adapter,
                    static_cast<std::int64_t>(AdapterError::InvalidNativeResult),
                    "operation_execution.finish_false");
            }
        } catch (...) {
            finish_failure.record(ObservationState::Unknown, ErrorDomain::Adapter,
                static_cast<std::int64_t>(AdapterError::InvalidNativeResult),
                "operation_execution.finish_exception");
        }
    }
    // All native finalizers have now returned or thrown. Only this point may
    // allocate the public std::string diagnostic. OOM leaves the optional
    // failure unset but never turns a cleanup failure into success.
    protocol_failure.publish(result_.failure);
    finish_failure.publish(result_.failure);
    if (protocol_failure.recorded || finish_failure.recorded)
        result_.state = OperationExecutionState::NeedsReconciliation;
    return result_.state;
}

OperationExecutionState OperationExecutionJob::advance_protocol(std::stop_token stop) {
    if (result_.state == OperationExecutionState::Complete || result_.state == OperationExecutionState::Failed ||
        result_.state == OperationExecutionState::Cancelled || result_.state == OperationExecutionState::RetainedSource ||
        result_.state == OperationExecutionState::NeedsReconciliation)
        return result_.state;

    if (result_.state == OperationExecutionState::Copying) {
        const auto copy_state = request_.copy->advance(stop);
        switch (copy_state) {
        case OperationCopyState::Verified:
            result_.state = OperationExecutionState::PreparingCommit;
            return result_.state;
        case OperationCopyState::Failed:
            if (request_.copy->failure()) result_.failure = request_.copy->failure();
            result_.state = OperationExecutionState::Failed;
            return result_.state;
        case OperationCopyState::Cancelled:
            if (request_.copy->failure()) result_.failure = request_.copy->failure();
            result_.state = OperationExecutionState::Cancelled;
            return result_.state;
        case OperationCopyState::NeedsReconciliation:
            if (request_.copy->failure()) result_.failure = request_.copy->failure();
            result_.state = OperationExecutionState::NeedsReconciliation;
            return result_.state;
        default:
            return result_.state;
        }
    }

    if (result_.state == OperationExecutionState::PreparingCommit) {
        if (stop.stop_requested()) {
            const auto cancelled = request_.copy->cancel_after_verification();
            if (cancelled == OperationCopyState::Cancelled) {
                result_.state = OperationExecutionState::Cancelled;
            } else if (cancelled == OperationCopyState::NeedsReconciliation) {
                if (request_.copy->failure()) result_.failure = request_.copy->failure();
                result_.state = OperationExecutionState::NeedsReconciliation;
            } else {
                fail(error(AdapterError::InvalidNativeResult, "operation_execution.cancel_verified"),
                     OperationExecutionState::NeedsReconciliation);
            }
            return result_.state;
        }
        try {
            auto prepared = request_.prepare_commit(stop);
            if (!prepared.value()) {
                fail(*prepared.unavailable_detail(), OperationExecutionState::NeedsReconciliation);
                return result_.state;
            }
            commit_ = std::move(prepared).take_value();
            if (!commit_ || commit_->state() != OperationCommitState::Ready) {
                fail(error(AdapterError::InvalidNativeResult, "operation_execution.commit_prepare"),
                     OperationExecutionState::NeedsReconciliation);
                return result_.state;
            }
        } catch (...) {
            fail(error(AdapterError::InvalidNativeResult, "operation_execution.commit_prepare_exception"),
                 OperationExecutionState::NeedsReconciliation);
            return result_.state;
        }
        result_.state = OperationExecutionState::Committing;
        return result_.state;
    }

    const auto commit_state = commit_->advance(stop);
    switch (commit_state) {
    case OperationCommitState::Complete:
        result_.state = OperationExecutionState::Complete;
        break;
    case OperationCommitState::Failed:
        if (commit_->failure()) result_.failure = commit_->failure();
        result_.state = OperationExecutionState::Failed;
        break;
    case OperationCommitState::Cancelled:
        if (commit_->failure()) result_.failure = commit_->failure();
        result_.state = OperationExecutionState::Cancelled;
        break;
    case OperationCommitState::RetainedSource:
        if (commit_->failure()) result_.failure = commit_->failure();
        result_.state = OperationExecutionState::RetainedSource;
        break;
    case OperationCommitState::NeedsReconciliation:
        if (commit_->failure()) result_.failure = commit_->failure();
        result_.state = OperationExecutionState::NeedsReconciliation;
        break;
    default:
        break;
    }
    return result_.state;
}

Observation<bool> OperationExecutionJob::cleanup_unpublished_staging() {
    if (result_.state != OperationExecutionState::Failed &&
        result_.state != OperationExecutionState::Cancelled)
        return rejected<bool>(AdapterError::PlanDecisionStale, "operation_execution.cleanup_state");
    if (!request_.cleanup_unpublished_staging)
        return Observation<bool>::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::UnsupportedQuery),
             "operation_execution.cleanup_unavailable"});
    try {
        return request_.cleanup_unpublished_staging();
    } catch (...) {
        return Observation<bool>::unavailable(ObservationState::Unknown,
            {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidNativeResult),
             "operation_execution.cleanup_exception"});
    }
}

} // namespace ck::files
