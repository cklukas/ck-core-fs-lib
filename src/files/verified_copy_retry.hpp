// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "native_operation_copy_job.hpp"
#include "native_operation_recovery_evidence.hpp"
#include "prepared_journal_root.hpp"
#include "private_journal_scope.hpp"
#include "sha256.hpp"
#include <string_view>
#include <type_traits>
#include <atomic>

namespace ck::files {
namespace detail {
// Failure-only worker seam for native contract tests. Invoked after all retry
// finalizers return; tests can start a genuine Root failure writer here. No
// public C callback, native success, or authority can be supplied through it.
#if defined(CK_FS_INTERNAL_TEST_HOOKS) && CK_FS_INTERNAL_TEST_HOOKS
using VerifiedCopyRetryAfterDrain=void(*)()noexcept;
inline std::atomic<VerifiedCopyRetryAfterDrain> verified_copy_retry_test_after_drain{nullptr};
inline void verified_copy_retry_after_drain_checkpoint() noexcept {
    if(const auto hook=verified_copy_retry_test_after_drain.load(std::memory_order_acquire))hook();
}
#else
inline void verified_copy_retry_after_drain_checkpoint() noexcept {}
#endif
}
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
// Diagnostic only. Fixed native first-error storage remains readable even if
// constructing an Observation/string throws AFTER all owners were drained.
struct VerifiedCopyRetryFinishFailure final {
    bool present=false;
    ObservationState state=ObservationState::Unknown;
    ErrorDomain domain=ErrorDomain::None;
    std::int64_t code=0;
    std::array<char,96> operation{};
};
static_assert(std::is_trivially_copyable_v<VerifiedCopyRetryFinishFailure>);
static_assert(std::is_nothrow_default_constructible_v<VerifiedCopyRetryFinishFailure>);
enum class VerifiedCopyRetryState {
    LoadingJournal, ReviewingSource, AwaitingReview, RevalidatingSource,
    Copying, Complete, ReviewRequired, Cancelled
};
// Serialized worker only. Native owners, including the ORIGINAL selected
// source, survive review/execution. No factory accepts rehydrated value IDs as
// native ownership. NativeCopy alone creates and owns the new staging object.
// Both genuine journal Roots are excluded from selected inputs and the new
// destination namespace before attempt creation, then checked again during
// execution. This protects the passed Roots; it grants no global mutation lease.
class VerifiedCopyRetryJob final {
public:
    using Pointer=std::unique_ptr<VerifiedCopyRetryJob>;
    static Observation<Pointer> create(VerifiedCopyRetryRequest);
    ~VerifiedCopyRetryJob();
    VerifiedCopyRetryState state() const noexcept { return phase_; }
    const std::optional<UnavailableObservation>& failure() const noexcept { return failure_; }
    std::string_view finish_operation() const noexcept { return finish_failure_.operation.data(); }
    const VerifiedCopyRetryFinishFailure& native_finish_failure()const noexcept{return finish_failure_;}
    VerifiedCopyRetryState advance(std::stop_token stop={});
    Observation<bool> approve();
    std::uint64_t reviewed_bytes() const noexcept { return source_offset_; }
    std::uint64_t source_bytes() const noexcept { return source_size_; }
    std::uint64_t prefix_bytes() const noexcept { return request_.candidate_prefix_bytes; }
    std::uint64_t copied_prefix_bytes() const noexcept { return copied_prefix_bytes_; }
    bool has_attempt() const noexcept { return had_attempt_; }
    OperationProgress progress() const noexcept;
    std::optional<std::array<std::byte,32>> reviewed_digest() const noexcept { return reviewed_digest_; }
    std::optional<std::array<std::byte,32>> origin_digest() const noexcept { return origin_digest_; }
    // Always called before a public terminal state, including cancellation.
    // Drains once and never waits for a separate Root failure writer. A
    // pending first writer yields copy_retry.root_failure_pending, not success.
    // Repeats refresh memory-only Root diagnostics; no native close is retried.
    Observation<bool> finish_io();
    bool finish_pending()const noexcept{return pending_roots_[0]||pending_roots_[1];}
    // Worker only, AFTER finish_io/callbacks have returned. No allocation or
    // native I/O. False means retain this job/Root and poll again outside any
    // finalizer before publishing a final cached result/worker_drained.
    bool refresh_finish_failure()noexcept;
private:
    explicit VerifiedCopyRetryJob(VerifiedCopyRetryRequest request):request_(std::move(request)){}
    Observation<bool> load_original_step();
    Observation<bool> admit_private_scope(std::stop_token);
    Observation<bool> revalidate_roots(std::stop_token = {}) const;
    Observation<bool> check_original() const;
    Observation<bool> validate_history();
    Observation<bool> source_step(std::stop_token);
    Observation<bool> check_membership(std::stop_token) const;
    Observation<bool> check_destination() const;
    Observation<bool> begin_copy(std::stop_token);
    VerifiedCopyRetryState reject(const UnavailableObservation&);
    struct FinishLatch;
    void record_finish(ObservationState,ErrorDomain,std::int64_t,std::string_view)noexcept;
    void read_root_finish_failure()noexcept;
    Observation<bool> finish_consumers();
    Observation<bool> finish_result(bool include_pending=true)const;
    VerifiedCopyRetryRequest request_;
    // Two genuine Root owners, each checked against both selected inputs and
    // the new destination namespace. Addresses are adopted only once.
    std::array<JournalScopeGuard::Pointer,6> scope_guards_{};
    std::array<bool,2> owned_roots_{};
    bool scope_ready_=false;
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
    bool finished_=false,consumers_finished_=false,had_attempt_=false,have_final_progress_=false;
    OperationProgress final_progress_{};
    VerifiedCopyRetryFinishFailure finish_failure_;
    std::array<bool,2> pending_roots_{};
    // The first observed pending writer reserves priority over subsequent
    // diagnostic placeholders and native close errors until its real tuple is
    // published. The pending Adapter tuple is never made sticky.
    std::uint8_t first_pending_root_=2;
    // Allocated at factory construction, before acquiring worker read/journal owners.
    std::stop_source drain_stop_;
};
} // namespace ck::files
