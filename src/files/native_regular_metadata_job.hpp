// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "metadata_capture_job.hpp"
#include "operation_metadata_job.hpp"
#include "prepared_journal_root.hpp"
#include "platform/native_metadata_stream_target.hpp"
#include <functional>
namespace ck::files {
struct NativeRegularMetadataRequest final {
    // Borrowed genuine private staging writer; its native owner outlives this
    // worker, including explicit finish_io. No caller-provided handle/path.
    OpenedEntry* target=nullptr;
    std::shared_ptr<const NativeMetadataProof> source;
    PreparedJournalRoot::Pointer journal_root;
    ContentReadLimits read_limits{64*1024};
    std::size_t max_target_stream_handles=16384;
    // Internal worker adapters, never C/UI callbacks. Membership must not read
    // content. Revalidation starts on begin=true, then advances a fresh native
    // source capture with at most ONE bounded content read per call.
    std::function<Observation<bool>(std::stop_token)> verify_membership;
    std::function<Observation<OperationMetadataStep>(bool begin,std::stop_token)> revalidate_source;
    std::function<Observation<bool>()> finish_source;
};
struct NativeRegularMetadataProgress final {
    std::uint64_t source_read_calls=0,source_read_bytes=0,target_write_calls=0,target_write_bytes=0;
    std::uint64_t verification_read_calls=0,verification_read_bytes=0;
    bool metadata_effects=false,complete=false,cancelled=false,worker_drained=false;
};
// Cooperative strict replay: fresh source proof, one bounded ADS read OR write
// per advance, independent target readers opened before final security, and
// separate source revalidation. Main DATA is verified by StreamCopyJob.
class NativeRegularMetadataJob final {
public:
    using Pointer=std::shared_ptr<NativeRegularMetadataJob>;
    // Run on the fresh source proof before creating private staging as well
    // as during worker setup. This supplies policy eligibility, not consent.
    static Observation<bool> qualify_source(const NativeMetadataProof&);
    static Observation<Pointer> create(NativeRegularMetadataRequest);
    ~NativeRegularMetadataJob();
    Observation<OperationMetadataStep> advance(OperationMetadataState,std::stop_token={});
    // Read-free guard after all independent channel digests have matched.
    // It never substitutes a manifest check for unfinished content checks.
    Observation<bool> verify(OpenedEntry&,std::stop_token={})const;
    Observation<bool> finish_io();
    const NativeRegularMetadataProgress& progress()const noexcept;
private:
    struct Impl;
    explicit NativeRegularMetadataJob(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
} // namespace ck::files
