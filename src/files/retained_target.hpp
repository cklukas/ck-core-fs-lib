// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "held_child.hpp"
#include "native_operation_recovery_evidence.hpp"
#include "operation_journal_file.hpp"
#include "sha256.hpp"
#include <functional>

namespace ck::files {
struct RetainedTargetRequest final {
    HeldChild::Pointer target;
    NativeName retained_name;
    std::array<std::byte, 32> reviewed_digest{};
    NativeAbsolutePath journal_root;
    OperationJournalId journal_id;
    std::optional<NativeAbsolutePath> parent_address;
    std::function<Observation<bool>()> revalidate_ancestors;
    std::size_t chunk_bytes = 64 * 1024;
    std::function<Observation<std::unique_ptr<OperationJournalFile>>(
        const NativeAbsolutePath&, const NativeName&, bool)> open_journal = open_native_operation_journal_file;
    std::shared_ptr<PreparedJournalRoot> prepared_journal_root = {};
};
enum class RetainedTargetState { Verifying, Ready, Retained, Failed, Cancelled, NeedsReconciliation };
// Worker-owned replacement prerequisite. Original data, ACLs, xattrs and
// streams remain on the same object; no metadata recreation or expiry occurs.
// The provider must support conditional source-object rename AND exclusion of
// writers (including preexisting writable mappings) during verification/rename.
// RenameSource must also exclude namespace changes through other handles. A
// cooperative lock or ordinary sharing-only guard is insufficient. Native
// providers without a lifetime-qualified stable-content proof are Unsupported.
class RetainedTarget final {
public:
    using Pointer = std::shared_ptr<RetainedTarget>;
    static Observation<Pointer> create(RetainedTargetRequest);
    RetainedTargetState advance(std::stop_token = {}); // one bounded hash read
    RetainedTargetState state() const noexcept { return state_; }
    const std::optional<UnavailableObservation>& failure() const noexcept { return failure_; }
    const NativeName& retained_name() const noexcept { return request_.retained_name; }
    // Bind this callback to NativeOperationCopyRequest's preparation hook. The
    // new file must be fully verified before invocation. No automatic rollback
    // after ambiguous publication; both versions and journals are retained.
    Observation<bool> retain(std::stop_token = {});
private:
    RetainedTarget(RetainedTargetRequest r, HeldChild::Pointer guard,
        OperationJournal::Pointer j, std::unique_ptr<OperationJournalFile> file,
        NativeOperationRecoveryEvidence evidence)
        : request_(std::move(r)), guard_(std::move(guard)), journal_(std::move(j)),
          file_(std::move(file)), evidence_(std::move(evidence)) {}
    Observation<bool> verify_guard_and_membership() const;
    Observation<bool> append(OperationJournalState);
    Observation<bool> fail(UnavailableObservation, bool ambiguous = false);
    RetainedTargetRequest request_;
    HeldChild::Pointer guard_;
    OperationJournal::Pointer journal_;
    std::unique_ptr<OperationJournalFile> file_;
    NativeOperationRecoveryEvidence evidence_;
    Sha256 hash_;
    std::uint64_t offset_ = 0;
    RetainedTargetState state_ = RetainedTargetState::Verifying;
    std::optional<UnavailableObservation> failure_;
};
} // namespace ck::files
