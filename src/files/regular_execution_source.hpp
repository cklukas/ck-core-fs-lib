// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "comparison_plan.hpp"
#include "held_child.hpp"
#include "metadata_capture_job.hpp"
#include "private_journal_scope.hpp"
#include <functional>
namespace ck::files {
// Closed review facts are comparison values. Only this worker's fresh native
// capture supplies live replay readers; neither values nor journal IDs do so.
struct RegularExecutionSourceRequest final {
    HeldChild::Pointer source;
    ComparisonMetadataDigest reviewed;
    // CompleteStable SHA-256, with exact before/after regular-file facts.
    ComparisonDigest reviewed_main;
    MetadataReplayPolicy policy;
    MetadataCaptureLimits limits{};
    std::shared_ptr<MetadataCaptureBudget> budget;
    PreparedJournalRoot::Pointer journal_root;
    // Memory/native-membership checks only. Must not read content or call bulk
    // metadata capture. The enclosing Tree binds the exact receipt/row here.
    std::function<Observation<bool>(std::stop_token)> verify_review;
};
enum class RegularSourcePhase { Opening, Capturing, Ready, Rechecking, Complete, Cancelled, Failed };
struct RegularSourceFailure final {
    bool present=false;
    ObservationState state=ObservationState::Unknown;
    ErrorDomain domain=ErrorDomain::None;
    std::int64_t code=0;
    std::array<char,128> operation{};
};
struct RegularSourceProgress final {
    RegularSourcePhase phase=RegularSourcePhase::Opening;
    std::uint64_t read_calls=0,read_bytes=0;
    bool worker_drained=false;
    RegularSourceFailure failure,finish_failure;
};
// Every method and destruction belongs on the owning native worker.
// This consumer never calls finish_io on the borrowed journal Root.
class RegularExecutionSourceJob final {
public:
    using Pointer=std::unique_ptr<RegularExecutionSourceJob>;
    static Observation<Pointer> create(RegularExecutionSourceRequest);
    ~RegularExecutionSourceJob();
    // At most one bounded content read. Ready deliberately retains OPEN proof
    // authority across the enclosing copy/replay/independent target verification.
    RegularSourceProgress advance(std::stop_token={});
    const RegularSourceProgress& progress()const noexcept{return progress_;}
    Observation<std::shared_ptr<const NativeMetadataProof>> proof()const;
    // A new bounded full observation through the retained native source. Its
    // successful finish does not close the original proof used for replay.
    // The enclosing executor starts/advances this before publication; this
    // job itself grants no target mutation or cross-root atomicity authority.
    Observation<bool> start_revalidation();
    // Required on every terminal path. Always attempts every native release,
    // caches first close failure, and drops Root consumers before returning.
    Observation<bool> finish_io();
private:
    class Latch;
    explicit RegularExecutionSourceJob(RegularExecutionSourceRequest);
    Observation<bool> membership(std::stop_token);
    Observation<bool> compare(const NativeMetadataProof&,std::stop_token)const;
    void remember(const UnavailableObservation&,bool finish=false)noexcept;
    void remember(ObservationState,ErrorDomain,std::int64_t,std::string_view,bool finish=false)noexcept;
    void read_latch()noexcept;
    void close_all(bool cancelled)noexcept;
    void close_capture(std::unique_ptr<MetadataCaptureJob>&)noexcept;
    RegularExecutionSourceRequest request_;
    RegularSourceProgress progress_;
    std::shared_ptr<Latch> latch_;
    JournalScopeGuard::Pointer scope_;
    std::unique_ptr<MetadataCaptureJob> capture_,recheck_;
    std::shared_ptr<const NativeMetadataProof> proof_;
};
} // namespace ck::files
