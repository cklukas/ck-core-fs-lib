// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "operation_metadata_job.hpp"
#include <array>
#include <cstdio>
#include <stdexcept>

using namespace ck::files;
namespace {
unsigned checks = 0;
#define CHECK(v) do { ++checks; if (!(v)) throw std::runtime_error(#v); } while (false)
using Step = OperationMetadataStep;
using State = OperationMetadataState;
auto ready(Step step) { return Observation<Step>::available(step); }
OperationMetadataJob::Pointer take(OperationMetadataRequest request) {
    auto result = OperationMetadataJob::create(std::move(request)); CHECK(result.value());
    return std::move(result).take_value();
}
OperationMetadataRequest single() {
    OperationMetadataRequest request;
    request.apply_traversal_metadata = request.apply_security_metadata = request.apply_final_times =
        request.flush_destination = [](std::stop_token) { return Observation<bool>::available(true); };
    return request;
}
void phases() {
    constexpr std::array order{State::ApplyingTraversal, State::ApplyingSecurity, State::ApplyingTimes, State::Flushing};
    unsigned calls = 0;
    OperationMetadataRequest request;
    request.advance_phase = [&](State phase, std::stop_token) {
        CHECK(calls < 12); CHECK(phase == order[calls / 3]);
        return ready(++calls % 3 ? Step::Pending : Step::Complete);
    };
    auto job = take(std::move(request)); CHECK(job->state() == State::Ready);
    for (unsigned i = 0; i < 12; ++i) {
        const auto state = job->advance(); CHECK(calls == i + 1);
        const auto completed_phases = calls / 3;
        CHECK(state == (completed_phases == 4 ? State::Complete : order[completed_phases]));
    }
    CHECK(!job->failure()); CHECK(job->advance() == State::Complete); CHECK(calls == 12);
}
void cancellation() {
    for (bool during : {false, true}) {
        std::stop_source stop; unsigned calls = 0;
        OperationMetadataRequest request;
        request.advance_phase = [&](State, std::stop_token token) {
            CHECK(token.stop_possible()); ++calls; stop.request_stop(); return ready(Step::Complete);
        };
        auto job = take(std::move(request)); if (!during) stop.request_stop();
        CHECK(job->advance(stop.get_token()) == State::Cancelled); CHECK(calls == (during ? 1U : 0U));
        CHECK(job->failure()->error.code == static_cast<std::int64_t>(AdapterError::InterruptedRead));
        CHECK(job->advance() == State::Cancelled); CHECK(calls == (during ? 1U : 0U));
    }
}
void failures() {
    for (unsigned kind = 0; kind != 3; ++kind) {
        unsigned calls = 0; std::stop_source stop;
        OperationMetadataRequest request;
        request.advance_phase = [&](State, std::stop_token) -> Observation<Step> {
            ++calls;
            if (kind == 0) { stop.request_stop(); return Observation<Step>::unavailable(ObservationState::Denied,
                {ErrorDomain::Posix, 13, "test.native_failure"}); }
            if (kind == 1) throw std::runtime_error("native worker exception");
            return ready(static_cast<Step>(91));
        };
        auto job = take(std::move(request)); CHECK(job->advance(stop.get_token()) == State::Failed);
        CHECK(job->failure());
        if (kind == 0) { CHECK(job->failure()->state == ObservationState::Denied); CHECK(job->failure()->error.code == 13); }
        else CHECK(job->failure()->error.code == static_cast<std::int64_t>(AdapterError::InvalidNativeResult));
        CHECK(job->advance() == State::Failed); CHECK(calls == 1);
    }
}
void adapters() {
    CHECK(!OperationMetadataJob::create({}).value());
    auto mixed = single(); mixed.advance_phase = [](State, std::stop_token) { return ready(Step::Complete); };
    CHECK(!OperationMetadataJob::create(std::move(mixed)).value());
    auto partial = single(); partial.flush_destination = {}; CHECK(!OperationMetadataJob::create(std::move(partial)).value());
    auto job = take(single());
    for (const auto expected : {State::ApplyingSecurity, State::ApplyingTimes, State::Flushing, State::Complete})
        CHECK(job->advance() == expected);
    auto false_result = single();
    false_result.apply_security_metadata = [](std::stop_token) { return Observation<bool>::available(false); };
    job = take(std::move(false_result)); CHECK(job->advance() == State::ApplyingSecurity);
    CHECK(job->advance() == State::Failed); CHECK(job->failure()->error.operation == "metadata_job.security");
}
}
int main() {
    try { phases(); cancellation(); failures(); adapters(); std::printf("cooperative metadata job: %u checks passed\n", checks); return 0; }
    catch (const std::exception& e) { std::fprintf(stderr, "cooperative metadata job: %s\n", e.what()); return 1; }
}
