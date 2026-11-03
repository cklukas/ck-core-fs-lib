// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "held_child.hpp"
#include "metadata_replay.hpp"
#include "prepared_journal_root.hpp"
#include "private_journal_scope.hpp"
#include "native_directory_replay_verifier.hpp"
#include "metadata_capture_job.hpp"
#include <array>
#include <functional>
#include <string_view>

namespace ck::files {
enum class DirectoryReplayPhase : std::uint8_t {
    Preparing, AwaitingChildren, ReplayingMetadata, ClosingWriter, Verifying, ClosingVerifier,
    Finalizing, Complete, Cancelled, Unsupported, ReviewRequired,
    CapturingDestination, RecheckingSource, RecheckingDestination, ApplyingBoundedMetadata,
    VerifyingBoundedMetadata, RecheckingFinalSource
};
struct DirectoryReplayFailure final {
    bool present = false;
    ObservationState state = ObservationState::Unknown;
    ErrorDomain domain = ErrorDomain::None;
    std::int64_t code = 0;
    std::array<char,128> operation{};
};
struct DirectoryReplayProgress final {
    DirectoryReplayPhase phase = DirectoryReplayPhase::Preparing;
    bool creation_attempted = false, created = false, metadata_attempted = false;
    bool recovery_required = false, worker_drained = false;
    DirectoryReplayFailure failure, finish_failure;
    // Cooperative proof-backed mode only. Failed reads may have unreported
    // partial bytes; read_calls records attempts. Legacy mode has no bound.
    std::uint64_t content_reads=0,content_bytes=0,write_calls=0,write_bytes=0;
};
struct NativeDirectoryReplayRequest final {
    HeldChild::Pointer source;
    MetadataReplaySnapshot reviewed_metadata;
    // Existing targets retain their original held identity. An absent target
    // uses only the native creator factory, never mkdir plus a name reopen.
    HeldChild::Pointer existing_destination;
    std::shared_ptr<const DirectoryCursor> destination_parent;
    std::optional<NativeName> destination_name;
    PreparedJournalRoot::Pointer journal_root;
    std::optional<NativeName> journal_name;
    OperationJournalId journal_id{};
    std::array<std::byte,32> review_digest{};
    // The enclosing reviewed Tree binds its exact receipt/row and disjoint
    // source/destination topology here. Root scope alone is not that proof.
    std::function<Observation<bool>(std::stop_token)> verify_plan;
    // Internal Tree-worker hook, never a C/UI callback. It must validate the
    // reviewed child jobs and current exact child bindings, not just a count.
    // Available(false) means children have not finished; it grants no effects.
    std::function<Observation<bool>(std::stop_token)> verify_children;
    // Cooperative Tree execution supplies a fresh OPEN proof whose V3 values
    // were checked against the exact reviewed row before journal/effects.
    // Omitted only for the legacy standalone native composition contract.
    std::shared_ptr<const NativeMetadataProof> source_proof;
    std::shared_ptr<const NativeMetadataProof> destination_review_proof;
    MetadataCaptureLimits metadata_limits{};
    std::shared_ptr<MetadataCaptureBudget> metadata_budget;
};
// One native worker owns this cooperative job. Every advance performs one
// phase; the enclosing Tree worker supplies threading and cancellation.
// Journal bytes/IDs never rehydrate creation, mutation or cleanup authority.
class NativeDirectoryReplayJob final {
public:
    using Pointer = std::unique_ptr<NativeDirectoryReplayJob>;
    static Observation<Pointer> create(NativeDirectoryReplayRequest);
    ~NativeDirectoryReplayJob();
    NativeDirectoryReplayJob(const NativeDirectoryReplayJob&) = delete;
    NativeDirectoryReplayJob& operator=(const NativeDirectoryReplayJob&) = delete;
    const DirectoryReplayProgress& progress() const noexcept { return progress_; }
    DirectoryReplayProgress advance(std::stop_token = {});
    Observation<std::shared_ptr<const DirectoryCursor>> child_cursor() const;
    Observation<bool> children_finished(std::stop_token = {});
    // Cached actual target values after native data verification, reader/writer
    // close, source revalidation and durable journal finish. No native owners
    // or replay authority survive in this values-only result.
    const MetadataReplaySnapshot* verified_target_values()const noexcept {
        return progress_.phase==DirectoryReplayPhase::Complete&&progress_.worker_drained&&verified_values_?&*verified_values_:nullptr;
    }
private:
    explicit NativeDirectoryReplayJob(NativeDirectoryReplayRequest);
    Observation<bool> prepare(std::stop_token);
    Observation<bool> revalidate(std::stop_token, bool children);
    Observation<bool> append(OperationJournalState, std::uint8_t);
    Observation<bool> close_writer();
    Observation<bool> bounded_step(std::stop_token);
    void finish_bounded()noexcept;
    struct Bounded;
    std::unique_ptr<Bounded> bounded_;
    void remember(const UnavailableObservation&, bool finish = false) noexcept;
    void remember_raw(ObservationState,ErrorDomain,std::int64_t,std::string_view,bool finish = false) noexcept;
    void finish_exception(const char*) noexcept;
    void finish(bool success, bool cancelled);
    void release_inputs() noexcept;
    bool terminal() const noexcept;
    NativeDirectoryReplayRequest request_;
    DirectoryReplayProgress progress_;
    JournalScopeGuard::Pointer source_scope_, target_scope_;
    std::unique_ptr<NativeCreatedDirectory> creator_;
    HeldChild::Pointer destination_;
    std::shared_ptr<const DirectoryCursor> cursor_;
    std::unique_ptr<OpenedEntry> writer_, verifier_;
    std::unique_ptr<DirectoryReplayVerifier> stream_verifier_;
    std::unique_ptr<OperationJournalFile> journal_file_;
    OperationJournal::Pointer journal_;
    BasicMetadata applied_;
    std::optional<MetadataReplaySnapshot> verified_values_;
    bool children_finished_ = false, writer_finish_observed_ = false;
};
} // namespace ck::files
