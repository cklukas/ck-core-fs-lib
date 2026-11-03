// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "metadata_replay.hpp"
#include <limits>
#include <memory>
#include <optional>

namespace ck::files {
class MetadataCaptureJob;
class HeldChild;
class NativeMetadataProof;
// Fixed-size, allocation-free first-error event. operation has static lifetime.
struct MetadataCaptureCleanupError final {
    ObservationState state;
    ErrorDomain domain;
    std::int64_t code;
    const char* operation;
};
class MetadataCaptureFailureLatch {
public:
    virtual ~MetadataCaptureFailureLatch()=default;
    // Must not allocate, throw, block, clear an earlier error or reenter jobs.
    // A Root adapter retains its exact PreparedJournalRoot owner and forwards
    // this event to that owner's sticky consumer first-error latch.
    virtual void record_first(MetadataCaptureCleanupError)const noexcept=0;
};
namespace detail {
struct MetadataCaptureLease;
struct MetadataCaptureCleanupState;
class NativeTargetReadBudget;
// Scoped only around this API's native work. Temporary adapter closes also
// feed the same sticky error. No observer installed for unrelated operations.
class MetadataCaptureCleanupScope final {
public:
    explicit MetadataCaptureCleanupScope(const MetadataCaptureFailureLatch*)noexcept;
    ~MetadataCaptureCleanupScope();
    MetadataCaptureCleanupScope(const MetadataCaptureCleanupScope&)=delete;
    MetadataCaptureCleanupScope&operator=(const MetadataCaptureCleanupScope&)=delete;
private:
    const MetadataCaptureFailureLatch* previous_;
};
// Borrowed only by a nested worker cleanup scope. The returned observer is
// valid until the current MetadataCaptureCleanupScope chain is unwound.
const MetadataCaptureFailureLatch* current_metadata_capture_cleanup() noexcept;
void record_metadata_capture_close(MetadataCaptureCleanupError)noexcept;
void finish_native_metadata_capture(const OpenedEntry*,const MetadataReplaySnapshot&)noexcept;
// Implemented inside the platform adapter; rejects caller-created entries.
Observation<std::shared_ptr<const OpenedEntry>> open_native_metadata_capture_source(
    std::shared_ptr<const OpenedEntry>,const MetadataReplayPolicy&);
Observation<std::shared_ptr<const OpenedEntry>> open_native_directory_capture_source(
    std::shared_ptr<const DirectoryCursor>,const MetadataReplayPolicy&);
Observation<bool> seal_native_metadata_capture(MetadataCaptureJob&);
}
struct MetadataCaptureLimits final {
    ContentReadLimits read{64*1024};
    // Resource admission, NOT a single-step size limit. Files/ADS can be any
    // admitted logical size and are streamed over as many advances as needed.
    std::uint64_t max_logical_bytes=std::numeric_limits<std::uint64_t>::max();
    std::size_t max_retained_handles=16384;
    std::size_t max_metadata_bytes=64*1024*1024;
    bool valid() const noexcept;
};
// One native worker. Logical admission is cumulative; active handles/metadata
// reservations are released only when their last native owner is disposed.
class MetadataCaptureBudget final {
public:
    explicit MetadataCaptureBudget(MetadataCaptureLimits limits={}):limits_(limits){}
    std::optional<MetadataCaptureCleanupError> first_cleanup_error()const noexcept{return cleanup_error_;}
    const MetadataCaptureLimits& limits()const noexcept{return limits_;}
    std::uint64_t admitted_logical_bytes()const noexcept{return logical_;}
    std::size_t retained_handle_reservations()const noexcept{return handles_;}
    std::size_t retained_metadata_reservations()const noexcept{return metadata_;}
private:
    friend struct detail::MetadataCaptureLease;
    friend struct detail::MetadataCaptureCleanupState;
    friend class detail::NativeTargetReadBudget;
    std::optional<MetadataCaptureCleanupError> cleanup_error_;
    const MetadataCaptureLimits limits_;
    std::uint64_t logical_=0;
    std::size_t handles_=0,metadata_=0;
};
enum class MetadataCapturePhase {
    Basic,Qualify,Storage,Channels,Admission,AttributeCatalog,Attributes,Security,
    OpenChannels,ReadData,DataBoundary,VerifyAttributeCatalog,VerifyAttributes,
    VerifySecurity,VerifyChannels,FinalBasic,Seal,Complete,Cancelled,Failed
};
struct MetadataCaptureProgress final {
    MetadataCapturePhase phase=MetadataCapturePhase::Basic;
    unsigned data_pass=0;
    // Calls attempted and successfully returned bytes; a failed/cancelled
    // native read can have unreported partial I/O. These are observation work,
    // not copy/publish completion counters.
    std::uint64_t read_calls=0,read_bytes=0;
    std::uint64_t pass_bytes=0;
    std::optional<std::uint64_t> main_logical_bytes;
    // Available only when a native catalog proves the complete DATA family.
    std::optional<std::uint64_t> all_stream_logical_bytes;
    std::size_t named_stream_count=0;
};
struct MetadataCaptureAdvance final {
    MetadataCapturePhase phase;
    std::size_t content_reads=0,content_bytes=0;
};
// An observation, NOT a freeze, publication right or parent/name membership
// proof. Native source, issuer, readers and reservations remain owned. Dropping
// this object and snapshots/readers it exports belongs on the native worker.
class NativeMetadataProof final {
public:
    ~NativeMetadataProof();
    // Required before public success/baseline effects, on the owning worker.
    // Attempts all readers/views, consumes each handle once, caches first
    // error and latches Root even if a caller ignores the returned result.
    // Successful close preserves immutable values/digests; replay/readers are
    // invalid afterwards. Destructor is only a first-error-latching fallback.
    Observation<bool> finish_io()const;
    std::optional<MetadataCaptureCleanupError> cleanup_error()const noexcept;
    bool io_finished()const noexcept;
    NativeMetadataProof(const NativeMetadataProof&)=delete;
    NativeMetadataProof& operator=(const NativeMetadataProof&)=delete;
    const MetadataReplaySnapshot& snapshot()const noexcept{return snapshot_;}
    const std::optional<std::array<std::byte,32>>& main_digest()const noexcept{return main_;}
    const MetadataCaptureProgress& progress()const noexcept{return progress_;}
private:
    friend class MetadataCaptureJob;
    NativeMetadataProof(MetadataReplaySnapshot,std::optional<std::array<std::byte,32>>,
        std::shared_ptr<const OpenedEntry>,std::shared_ptr<detail::MetadataCaptureLease>,MetadataCaptureProgress);
    const MetadataReplaySnapshot snapshot_;
    const std::optional<std::array<std::byte,32>> main_;
    std::shared_ptr<const OpenedEntry> source_;
    std::shared_ptr<detail::MetadataCaptureLease> lease_;
    const MetadataCaptureProgress progress_;
    mutable bool cleanup_done_=false;
};
// Every advance issues at most ONE read_content call, with <= limits.read
// bytes. Metadata queries/CPU are bounded by policy inventory limits. No bulk
// capture/issuer/digest helper may be called from this producer.
class MetadataCaptureJob final {
public:
    ~MetadataCaptureJob();
    MetadataCaptureJob(const MetadataCaptureJob&)=delete;
    MetadataCaptureJob& operator=(const MetadataCaptureJob&)=delete;
    // Required on cancellation/failure too. Capture Complete is data-ready,
    // not public terminal success. Gate success on finish_io and Root latch.
    Observation<bool> finish_io();
    std::optional<MetadataCaptureCleanupError> cleanup_error()const noexcept;
    Observation<MetadataCaptureAdvance> advance(std::stop_token={});
    const MetadataCaptureProgress& progress()const noexcept;
    Observation<std::shared_ptr<const NativeMetadataProof>> result()const;
    static Observation<std::unique_ptr<MetadataCaptureJob>> begin(
        std::shared_ptr<const OpenedEntry>,MetadataReplayPolicy,MetadataCaptureLimits={},
        std::shared_ptr<MetadataCaptureBudget> = {},
        std::shared_ptr<const MetadataCaptureFailureLatch> cleanup_latch = {});
    // Exact private HeldChild entry; no basename/path reopen or raw getter.
    // Caller retains/refreshed held-family membership after the last read.
    // POSIX regular inputs must have been observed with ContentRead access.
    static Observation<std::unique_ptr<MetadataCaptureJob>> begin_held(
        std::shared_ptr<const HeldChild>,MetadataReplayPolicy,MetadataCaptureLimits={},
        std::shared_ptr<MetadataCaptureBudget> = {},
        std::shared_ptr<const MetadataCaptureFailureLatch> cleanup_latch = {});
    static Observation<std::unique_ptr<MetadataCaptureJob>> begin_directory(
        std::shared_ptr<const DirectoryCursor>,MetadataReplayPolicy,MetadataCaptureLimits={},
        std::shared_ptr<MetadataCaptureBudget> = {},
        std::shared_ptr<const MetadataCaptureFailureLatch> cleanup_latch = {});
    // Same-source observation verification. Read-induced atime changes are
    // excluded from version equality; this is NOT a target replay verifier.
    static Observation<std::unique_ptr<MetadataCaptureJob>> verify(
        std::shared_ptr<const NativeMetadataProof>,MetadataCaptureLimits={},
        std::shared_ptr<MetadataCaptureBudget> = {},
        std::shared_ptr<const MetadataCaptureFailureLatch> cleanup_latch = {});
    // A closed successful observation can be verified against a fresh held
    // source. Source ID/version is checked; no caller digest input is accepted.
    static Observation<std::unique_ptr<MetadataCaptureJob>> verify(
        std::shared_ptr<const OpenedEntry>,std::shared_ptr<const NativeMetadataProof>,
        MetadataCaptureLimits={},std::shared_ptr<MetadataCaptureBudget> = {},
        std::shared_ptr<const MetadataCaptureFailureLatch> cleanup_latch = {});
private:
    friend Observation<bool> detail::seal_native_metadata_capture(MetadataCaptureJob&);
    struct Impl;
    explicit MetadataCaptureJob(std::unique_ptr<Impl>);
    // Platform seal can inspect only already-verified, privately accumulated
    // bytes. No entry point accepts a frontend snapshot/digest for sealing.
    bool ready_to_seal()const noexcept;
    MetadataReplaySnapshot& sealing_snapshot();
    const std::shared_ptr<const OpenedEntry>& sealing_source()const;
    std::shared_ptr<const void> sealing_lease()const;
    std::unique_ptr<Impl> impl_;
};
} // namespace ck::files
