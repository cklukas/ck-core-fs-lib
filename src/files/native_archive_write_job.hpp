// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "private_journal_scope.hpp"
#include "metadata_capture_job.hpp"
#include "staging_namespace.hpp"
#include <array>
namespace ck::files {
// Framework-neutral archive image. Gaps are zero-filled logical bytes, never
// input addresses. The worker owns these bounded bytes after begin().
struct NativeArchiveExtent final { std::uint64_t offset=0;std::vector<std::byte> bytes; };
struct NativeArchiveWriteRequest final {
    std::shared_ptr<const DirectoryCursor> destination;
    PreparedJournalRoot::Pointer journal_root;
    NativeName destination_name,staging_hint,journal_name;
    OperationJournalId journal_id;
    std::uint64_t logical_size=0,max_logical_size=1ull<<40,max_recipe_bytes=256ull<<20;
    std::size_t max_extents=65536,step_bytes=64*1024;
    // Sparse enabling is separate from evidence of current unallocated ranges.
    bool sparse=true;
    std::uint64_t minimum_unallocated_bytes=0;
    std::vector<NativeArchiveExtent> extents;
    // Descriptive application bytes, never ownership or reopening authority.
    std::vector<std::byte> application_evidence;
    OperationJournalLimits journal_limits{};
    OperationJournalCodecLimits codec_limits{};
};
enum class NativeArchivePhase { Planned,Create,Prepare,Write,Flush,Layout,Verify,CommitIntent,Publish,Committed,CloseFile,CompleteJournal,Drain,Complete,Cancelled,NeedsReconciliation };
struct NativeArchiveFailure final {
    ObservationState state=ObservationState::Unknown;
    ErrorDomain domain=ErrorDomain::None;
    std::int64_t code=0;
    std::array<char,96> operation{};
};
struct NativeArchiveProgress final {
    NativeArchivePhase phase=NativeArchivePhase::Planned;
    std::uint64_t written_bytes=0,verified_bytes=0,content_calls=0,unallocated_bytes=0;
    StagingNamespace staging_namespace=StagingNamespace::Unknown;
    bool effects=false,publication_attempted=false,published=false,drained=false,image_verified=false,publication_uncertain=false;
    std::optional<NativeArchiveFailure> failure;
    std::array<std::byte,32> digest{};
};
// WORKER ONLY, including destruction. Creates the genuine native staging
// object itself and retains the original handle through all I/O/publication.
// At most one bounded content read OR write per advance. Journal I/O is also
// worker I/O. No path cleanup, replacement, restart ownership, cross-file
// atomicity or arbitrary-writer exclusion is claimed. Failed named stages and
// durable journals remain visible evidence; anonymous hints are never I/O.
class NativeArchiveWriteJob final {
public:
    static Observation<std::unique_ptr<NativeArchiveWriteJob>> begin(NativeArchiveWriteRequest);
    ~NativeArchiveWriteJob();
    NativeArchiveWriteJob(const NativeArchiveWriteJob&)=delete;
    NativeArchiveWriteJob& operator=(const NativeArchiveWriteJob&)=delete;
    // Native failures and even allocation exceptions drain before a terminal
    // result. Pending Root first-writer state is resolved by later memory-only
    // advances; finalizers/destructors never wait. Terminal repeats do no I/O.
    NativeArchiveProgress advance(std::stop_token={}) noexcept;
    NativeArchiveProgress finish_io() noexcept;
    const NativeArchiveProgress& progress()const noexcept;
private:
    struct Impl;
    explicit NativeArchiveWriteJob(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
}
