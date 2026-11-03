// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "native_operation_copy_job.hpp"
#include "native_operation_recovery_evidence.hpp"
#include "prepared_journal_root.hpp"
#include "sha256.hpp"
#include <string_view>

namespace ck::files {
// This is an explicitly reviewed NEW copy, not adoption of a reopened stage.
// The old journal/staging object is never changed, cleaned or replayed. An
// existing destination or any historical publication intent requires review.
struct VerifiedCopyRetryRequest final {
    VerifiedCopyRetryRequest(NativeAbsolutePath original_root,NativeName original_name,
        NativeAbsolutePath attempt_root,NativeName attempt_name,NativeName hint,NativeName final_name)
        :original_journal_root(std::move(original_root)),original_journal_name(std::move(original_name)),
         attempt_journal_root(std::move(attempt_root)),attempt_journal_name(std::move(attempt_name)),
         staging_hint(std::move(hint)),destination_name(std::move(final_name)){}
    VerifiedCopyRetryRequest(PreparedJournalRoot::Pointer original_root,NativeName original_name,
        PreparedJournalRoot::Pointer attempt_root,NativeName attempt_name,NativeName hint,NativeName final_name)
        :original_journal_name(std::move(original_name)),attempt_journal_name(std::move(attempt_name)),
         staging_hint(std::move(hint)),destination_name(std::move(final_name)),
         original_prepared_root(std::move(original_root)),attempt_prepared_root(std::move(attempt_root)){}
    std::optional<NativeAbsolutePath> original_journal_root;
    NativeName original_journal_name;
    std::optional<NativeAbsolutePath> attempt_journal_root;
    NativeName attempt_journal_name;
    NativeName staging_hint;
    NativeName destination_name;
    HeldChild::Pointer source;
    HeldChild::Pointer candidate; // explicitly selected read-only object
    std::uint64_t candidate_prefix_bytes = 0; // exact reviewed extent; no EOF inference
    std::shared_ptr<const DirectoryCursor> destination;
    std::optional<NativeAbsolutePath> destination_address;
    OperationJournalId attempt_id{};
    std::size_t original_item = 0;
    std::uint64_t max_content_bytes = 4ULL*1024*1024*1024;
    std::size_t max_journal_bytes = 4*1024*1024;
    MetadataReplayPolicy metadata_policy;
    PreparedJournalRoot::Pointer original_prepared_root,attempt_prepared_root;
};
enum class VerifiedCopyRetryState {
    LoadingJournal, ReviewingSource, AwaitingReview, RevalidatingSource,
    Copying, Complete, ReviewRequired, Cancelled
};
// Serialized worker only. Native owners, including the ORIGINAL selected
// source, survive review/execution. No factory accepts rehydrated value IDs as
// native ownership. NativeCopy alone creates and owns the new staging object.
class VerifiedCopyRetryJob final {
public:
    using Pointer=std::unique_ptr<VerifiedCopyRetryJob>;
    static Observation<Pointer> create(VerifiedCopyRetryRequest);
    ~VerifiedCopyRetryJob();
    VerifiedCopyRetryState state() const noexcept { return phase_; }
    const std::optional<UnavailableObservation>& failure() const noexcept { return failure_; }
    std::string_view finish_operation() const noexcept { return finish_operation_.data(); }
    VerifiedCopyRetryState advance(std::stop_token stop={});
    Observation<bool> approve();
    std::uint64_t reviewed_bytes() const noexcept { return source_offset_; }
    std::uint64_t source_bytes() const noexcept { return source_size_; }
    std::uint64_t prefix_bytes() const noexcept { return request_.candidate_prefix_bytes; }
    std::uint64_t copied_prefix_bytes() const noexcept { return copied_prefix_bytes_; }
    bool has_attempt() const noexcept { return bool(attempt_file_); }
    OperationProgress progress() const noexcept;
    std::optional<std::array<std::byte,32>> reviewed_digest() const noexcept { return reviewed_digest_; }
    std::optional<std::array<std::byte,32>> origin_digest() const noexcept { return origin_digest_; }
    // Always called before a public terminal state, including cancellation.
    Observation<bool> finish_io();
private:
    explicit VerifiedCopyRetryJob(VerifiedCopyRetryRequest request):request_(std::move(request)){}
    Observation<bool> load_original_step();
    Observation<bool> revalidate_roots() const;
    Observation<bool> check_original() const;
    Observation<bool> validate_history();
    Observation<bool> source_step(std::stop_token);
    Observation<bool> check_membership(std::stop_token) const;
    Observation<bool> check_destination() const;
    Observation<bool> begin_copy(std::stop_token);
    VerifiedCopyRetryState reject(const UnavailableObservation&);
    VerifiedCopyRetryRequest request_;
    VerifiedCopyRetryState phase_=VerifiedCopyRetryState::LoadingJournal;
    std::optional<UnavailableObservation> failure_;
    std::unique_ptr<OperationJournalFile> original_file_;
    std::vector<std::byte> original_bytes_;
    std::uint64_t original_size_=0,source_offset_=0,source_size_=0;
    OperationJournal::Pointer original_journal_;
    std::optional<NativeOperationRecoveryEvidence> original_evidence_;
    std::optional<ObjectIdentity> destination_identity_;
    HeldChild::Pointer readable_source_;
    HeldChild::Pointer readable_candidate_;
    RegularMetadataPreservation::Pointer metadata_;
    Sha256 source_hash_;
    std::optional<std::array<std::byte,32>> reviewed_digest_;
    std::optional<std::array<std::byte,32>> origin_digest_;
    std::uint64_t copied_prefix_bytes_=0;
    std::shared_ptr<OperationJournalFile> attempt_file_;
    NativeOperationCopyJob::Pointer copy_;
    OpenedEntry* attempt_stage_=nullptr; // borrowed only while copy_ owns it
    bool finished_=false;
    std::optional<UnavailableObservation> finish_failure_;
    std::array<char,96> finish_operation_{};
};
} // namespace ck::files
