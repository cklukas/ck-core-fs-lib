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
struct DirectoryExecutionSourceRequest final {
    HeldChild::Pointer source;
    ComparisonMetadataDigest reviewed;
    MetadataReplayPolicy policy;
    MetadataCaptureLimits limits{};
    std::shared_ptr<MetadataCaptureBudget> budget;
    PreparedJournalRoot::Pointer journal_root;
    // Memory/native-membership checks only. Must not read content or call bulk
    // metadata capture. The enclosing Tree binds the exact receipt/row here.
    std::function<Observation<bool>(std::stop_token)> verify_review;
};
enum class DirectorySourcePhase { Opening, Capturing, Ready, Rechecking, Complete, Cancelled, Failed };
struct DirectorySourceFailure final {
    bool present=false;
    ObservationState state=ObservationState::Unknown;
    ErrorDomain domain=ErrorDomain::None;
    std::int64_t code=0;
    std::array<char,128> operation{};
};
struct DirectorySourceProgress final {
    DirectorySourcePhase phase=DirectorySourcePhase::Opening;
    std::uint64_t read_calls=0,read_bytes=0;
    bool worker_drained=false;
    DirectorySourceFailure failure,finish_failure;
};
class DirectoryExecutionSourceJob final {
public:
    using Pointer=std::unique_ptr<DirectoryExecutionSourceJob>;
    static Observation<Pointer> create(DirectoryExecutionSourceRequest);
    ~DirectoryExecutionSourceJob();
    // At most one bounded content read. Ready deliberately retains OPEN proof
    // authority across children/replay/independent target verification.
    DirectorySourceProgress advance(std::stop_token={});
    const DirectorySourceProgress& progress()const noexcept{return progress_;}
    Observation<std::shared_ptr<const NativeMetadataProof>> proof()const;
    // A new bounded full observation through the retained native source. Its
    // successful finish does not close the original proof used for replay.
    Observation<bool> start_revalidation();
    // Required on every terminal path. Always attempts every native release,
    // caches first close failure, and drops Root consumers before returning.
    Observation<bool> finish_io();
private:
    class Latch;
    explicit DirectoryExecutionSourceJob(DirectoryExecutionSourceRequest);
    Observation<bool> membership(std::stop_token);
    Observation<bool> compare(const NativeMetadataProof&,std::stop_token)const;
    void remember(const UnavailableObservation&,bool finish=false)noexcept;
    void remember(ObservationState,ErrorDomain,std::int64_t,std::string_view,bool finish=false)noexcept;
    void read_latch()noexcept;
    void close_all(bool cancelled)noexcept;
    void close_capture(std::unique_ptr<MetadataCaptureJob>&)noexcept;
    DirectoryExecutionSourceRequest request_;
    DirectorySourceProgress progress_;
    std::shared_ptr<Latch> latch_;
    JournalScopeGuard::Pointer scope_;
    std::unique_ptr<MetadataCaptureJob> capture_,recheck_;
    std::shared_ptr<const NativeMetadataProof> proof_;
};
} // namespace ck::files
