// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "sync_session.hpp"
#include "native_operation_recovery_evidence.hpp"
#include "operation_journal_file.hpp"
#include <stop_token>
namespace ck::files {
enum class NativeSyncArtifactKind : std::uint32_t { RetainedOriginal=1 };
struct NativeSyncArtifact final {
    bool right=false;
    std::vector<NativeName> components;
    NativeDurableIdentity parent,object;
    SyncEntryStatus status;
    NativeSyncArtifactKind kind=NativeSyncArtifactKind::RetainedOriginal;
};
// Before mutation Planned contains every potential retained artifact. Only a
// Verified/CommitIntended record can assert their successful durable creation.
// proposed_baseline is canonical codec output, not native convergence authority.
struct NativeSyncPathRecord final {
    std::string opaque_key;
    std::vector<NativeName> components;
    SyncEntryStatus left,right;
    std::optional<NativeDurableIdentity> left_object,right_object;
    SyncAction action=SyncAction::Unchanged;
    bool skipped=false;
};
struct NativeSyncLedgerEvidence final {
    SyncSessionIdentity session;
    std::uint64_t expected_generation=0;
    SyncDigest reviewed_plan{};
    std::vector<NativeSyncPathRecord> paths;
    std::vector<NativeSyncArtifact> artifacts;
    std::optional<SyncBaseline> proposed_baseline;
};
struct NativeSyncLedgerLimits final {
    std::size_t max_ledgers=256;
    std::size_t max_total_wire_bytes=32*1024*1024;
    std::size_t max_artifacts=1024;
    SyncBaselineLimits baseline{};
};
Observation<std::vector<std::byte>> encode_native_sync_ledger(const NativeSyncLedgerEvidence&,NativeSyncLedgerLimits={});
// Additive schema: exact bounded native chains + explicit File/Directory
// statuses. Flat encode/create keep their original wire bytes and restrictions.
Observation<std::vector<std::byte>> encode_native_sync_hierarchy_ledger(const NativeSyncLedgerEvidence&,NativeSyncLedgerLimits={});
Observation<NativeSyncLedgerEvidence> decode_native_sync_ledger(std::span<const std::byte>,NativeSyncLedgerLimits={});
struct NativeSyncLoadedLedger final {
    NativeName name;
    OperationJournal::Pointer journal;
    NativeSyncLedgerEvidence evidence;
    std::size_t wire_bytes=0;
};
class NativeSyncLedger final {
public:
    static Observation<std::unique_ptr<NativeSyncLedger>> create(PreparedJournalRoot::Pointer,NativeName,
        OperationJournalId,const NativeSyncLedgerEvidence&,NativeSyncLedgerLimits={});
    static Observation<std::unique_ptr<NativeSyncLedger>> reopen(PreparedJournalRoot::Pointer,NativeName,
        OperationJournalId,NativeSyncLedgerLimits={});
    static Observation<std::unique_ptr<NativeSyncLedger>> create_hierarchy(PreparedJournalRoot::Pointer,NativeName,
        OperationJournalId,const NativeSyncLedgerEvidence&,NativeSyncLedgerLimits={});
    // Compatibility factories perform initial acquisition only; production
    // sessions/coordinators always pass their existing owner instead.
    static Observation<std::unique_ptr<NativeSyncLedger>> create(const NativeAbsolutePath&,NativeName,
        OperationJournalId,const NativeSyncLedgerEvidence&,NativeSyncLedgerLimits={});
    // Internal deterministic fault adapter; never exposed by the stable C API.
    static Observation<std::unique_ptr<NativeSyncLedger>> create_on_file(std::unique_ptr<OperationJournalFile>,
        OperationJournalId,const NativeSyncLedgerEvidence&,NativeSyncLedgerLimits={});
    static Observation<std::unique_ptr<NativeSyncLedger>> reopen(const NativeAbsolutePath&,NativeName,
        OperationJournalId,NativeSyncLedgerLimits={});
    Observation<bool> append(OperationJournalState,const NativeSyncLedgerEvidence&);
    Observation<bool> finish_io();
    const OperationJournal& journal() const noexcept {return *journal_;}
private:
    NativeSyncLedger(std::unique_ptr<OperationJournalFile> f,OperationJournal::Pointer j,NativeSyncLedgerLimits l)
        : file_(std::move(f)),journal_(std::move(j)),limits_(l) {}
    std::unique_ptr<OperationJournalFile> file_;
    OperationJournal::Pointer journal_;
    NativeSyncLedgerLimits limits_;
    bool closed_=false;
    std::optional<UnavailableObservation> close_failure_;
};
// The reserved prefix is used only INSIDE private coordinator storage. Data
// root filtering must use typed artifact records and fresh native proofs.
Observation<std::vector<NativeSyncLoadedLedger>> load_native_sync_ledgers(
    PreparedJournalRoot::Pointer,NativeSyncLedgerLimits={},std::stop_token={});
Observation<std::vector<NativeSyncLoadedLedger>> load_native_sync_ledgers(
    const NativeAbsolutePath&,NativeSyncLedgerLimits={},std::stop_token={});
} // namespace ck::files
