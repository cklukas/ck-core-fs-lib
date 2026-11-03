// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../metadata_capture_job.hpp"
namespace ck::files::detail {
// A worker-owned independent target observation, prepared BEFORE final ACLs
// and times. No raw handle, path, caller snapshot, or value-only object ID is
// accepted. This confers read/observation authority only, never publication,
// replay, deletion, or success authority. Keep it through final Tree inventory.
class NativeTargetReadSeed {
public:
    using Pointer=std::unique_ptr<NativeTargetReadSeed>;
    virtual ~NativeTargetReadSeed()=default;
    // No content reads. Opens at most one native named-stream reader per call.
    // Available(true) is Ready; Available(false) means preparation is pending.
    virtual Observation<bool> advance(std::stop_token={})=0;
    // Genuine native read-only source; subsequent capture clones preserve the
    // prepared file descriptions and their timestamp-suppression contract.
    virtual Observation<std::shared_ptr<const OpenedEntry>> source()const=0;
    // A genuine native enumeration cursor with suppressed access updates.
    // One returned cursor at a time owns enumeration position; another is
    // refused until enumeration ends or the cursor is released. Exhausted
    // cursors may remain pinned as parents; they cannot enumerate again.
    // A subsequent cursor restarts the prepared
    // independent description, without reopening under final security.
    virtual Observation<std::shared_ptr<const DirectoryCursor>> directory_cursor()=0;
    // Finish consumers/captures/cursors first, then this seed, on ALL paths.
    // Consumes actual native owners once; first native close error is latched
    // before any allocating diagnostic. No destructor-only success barrier.
    virtual Observation<bool> finish_io()=0;
};
// Target must be the still-open genuine native creator/metadata writer. The
// OPEN source proof binds exact native stream names/policy and resource limits.
// Run after streams exist, before restrictive ownership/security/final times.
#ifdef _WIN32
Observation<NativeTargetReadSeed::Pointer> begin_native_target_read_seed(
    OpenedEntry&,std::shared_ptr<const NativeMetadataProof>,MetadataCaptureLimits,
    std::shared_ptr<MetadataCaptureBudget>,std::shared_ptr<const MetadataCaptureFailureLatch>);
// Existing scan containers have no creator authority: the proof MUST describe
// this actual held directory. This read-only route grants no mutation scope.
Observation<NativeTargetReadSeed::Pointer> begin_native_directory_read_seed(
    std::shared_ptr<const DirectoryCursor>,std::shared_ptr<const NativeMetadataProof>,MetadataCaptureLimits,
    std::shared_ptr<MetadataCaptureBudget>,std::shared_ptr<const MetadataCaptureFailureLatch>);
#else
inline Observation<NativeTargetReadSeed::Pointer> begin_native_target_read_seed(
    OpenedEntry&,std::shared_ptr<const NativeMetadataProof>,MetadataCaptureLimits,
    std::shared_ptr<MetadataCaptureBudget>,std::shared_ptr<const MetadataCaptureFailureLatch>) {
    return Observation<NativeTargetReadSeed::Pointer>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"target_read.native_atime_reader_unqualified"});
}
inline Observation<NativeTargetReadSeed::Pointer> begin_native_directory_read_seed(
    std::shared_ptr<const DirectoryCursor>,std::shared_ptr<const NativeMetadataProof>,MetadataCaptureLimits,
    std::shared_ptr<MetadataCaptureBudget>,std::shared_ptr<const MetadataCaptureFailureLatch>) {
    return Observation<NativeTargetReadSeed::Pointer>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"target_read.native_directory_atime_reader_unqualified"});
}
#endif
} // namespace ck::files::detail
