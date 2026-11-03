// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "observation.hpp"

#include <functional>
#include <memory>
#include <optional>
#include <stop_token>

namespace ck::files {

enum class OperationMetadataState { Ready, ApplyingTraversal, ApplyingSecurity, ApplyingTimes, Flushing,
                                    Complete, Failed, Cancelled };
enum class OperationMetadataStep { Pending, Complete, Cancelled };

struct OperationMetadataRequest final {
    // Every phase is required, including explicit no-op callbacks.
    std::function<Observation<bool>(std::stop_token)> apply_traversal_metadata;
    std::function<Observation<bool>(std::stop_token)> apply_security_metadata;
    std::function<Observation<bool>(std::stop_token)> apply_final_times;
    std::function<Observation<bool>(std::stop_token)> flush_destination;
    // Alternative to the four single-call adapters. One worker invocation
    // advances only the current phase; Pending preserves that phase without
    // granting completion. Never combine this with a single-call adapter.
    // The native producer owns its bounded reads and all retained handles.
    std::function<Observation<OperationMetadataStep>(OperationMetadataState, std::stop_token)> advance_phase;
};

struct OperationMetadataResult final {
    OperationMetadataState state = OperationMetadataState::Ready;
    std::optional<UnavailableObservation> failure;
};

// Worker-only ordered metadata application. The destination remains private
// until a caller separately completes verification and publication.
class OperationMetadataJob final {
public:
    using Pointer = std::unique_ptr<OperationMetadataJob>;
    static Observation<Pointer> create(OperationMetadataRequest request);
    OperationMetadataState state() const noexcept { return result_.state; }
    const OperationMetadataResult& result() const noexcept { return result_; }
    const std::optional<UnavailableObservation>& failure() const noexcept { return result_.failure; }
    OperationMetadataState advance(std::stop_token stop = {});

private:
    explicit OperationMetadataJob(OperationMetadataRequest request) noexcept : request_(std::move(request)) {}
    void fail(UnavailableObservation detail) noexcept;
    void cancel() noexcept;
    OperationMetadataState invoke(const std::function<Observation<bool>(std::stop_token)>& callback,
                                  const char* operation, std::stop_token stop);
    OperationMetadataState advance_cooperative(std::stop_token);
    OperationMetadataRequest request_;
    OperationMetadataResult result_;
};

} // namespace ck::files
