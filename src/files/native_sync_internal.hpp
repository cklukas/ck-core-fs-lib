// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "observation.hpp"
#include <string_view>
#include <stop_token>
namespace ck::files::sync_detail {
struct Failure { UnavailableObservation detail; };
[[noreturn]] inline void fail(const char* operation, ObservationState state=ObservationState::Changed,
    AdapterError error=AdapterError::PlanDecisionStale) {
    throw Failure{{state,{ErrorDomain::Adapter,static_cast<std::int64_t>(error),operation}}};
}
template<class T> T value(Observation<T> observation) {
    if(!observation.value()) throw Failure{*observation.unavailable_detail()};
    return std::move(observation).take_value();
}
inline void require(Observation<bool> observation) {
    if(!value(std::move(observation))) fail("native_sync.false_result",ObservationState::Unknown,AdapterError::InvalidNativeResult);
}
template<class T,class F> Observation<T> attempt(F&& function) {
    try { return Observation<T>::available(function()); }
    catch(const Failure& e) { return Observation<T>::unavailable(e.detail.state,e.detail.error); }
}
inline void stop(std::stop_token token) {
    if(token.stop_requested()) fail("native_sync.cancelled",ObservationState::Changed,AdapterError::InterruptedRead);
}
} // namespace ck::files::sync_detail
