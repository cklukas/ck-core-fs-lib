// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../metadata_capture_job.hpp"
namespace ck::files::detail {
// Proves the adapter-issued private target, including when no named DATA
// stream exists. Provider admission alone does not prove creation authority.
Observation<bool> qualify_native_metadata_target(OpenedEntry&,const NativeMetadataProof&);
// Internal native target owners. Factories accept a genuine private native
// target and an OPEN adapter-issued proof; no integer handle, pathname, or
// caller-created snapshot can manufacture either capability.
class NativeMetadataStreamWriter {
public:
    virtual ~NativeMetadataStreamWriter() = default;
    virtual Observation<MetadataReplayChannelState> inspect() const = 0;
    virtual Observation<std::size_t> write(std::uint64_t, std::span<const std::byte>) = 0;
    // Consumes the actual stream writer once, including its flush. Errors are
    // latched before an allocating diagnostic is constructed.
    virtual Observation<bool> finish_io() = 0;
};
class NativeMetadataStreamReader : public MetadataReplayChannelSource {
public:
    virtual Observation<bool> finish_io() = 0;
};
#ifdef _WIN32
Observation<std::unique_ptr<NativeMetadataStreamWriter>> open_native_metadata_stream_writer(
    OpenedEntry&, std::shared_ptr<const NativeMetadataProof>, const NativeFeatureIdentifier&,
    std::shared_ptr<const MetadataCaptureFailureLatch>);
// Open before restrictive final security and before the base writer closes.
// This is an independent native file description. Its private setup suppresses
// automatic access-time updates; the exposed interface has no mutation method.
Observation<std::unique_ptr<NativeMetadataStreamReader>> open_native_metadata_stream_reader(
    OpenedEntry&, std::shared_ptr<const NativeMetadataProof>, const NativeFeatureIdentifier&,
    std::shared_ptr<const MetadataCaptureFailureLatch>);
#else
inline Observation<std::unique_ptr<NativeMetadataStreamWriter>> open_native_metadata_stream_writer(
    OpenedEntry&, std::shared_ptr<const NativeMetadataProof>, const NativeFeatureIdentifier&,
    std::shared_ptr<const MetadataCaptureFailureLatch>) {
    return Observation<std::unique_ptr<NativeMetadataStreamWriter>>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "metadata_stream.native_windows_required"});
}
inline Observation<std::unique_ptr<NativeMetadataStreamReader>> open_native_metadata_stream_reader(
    OpenedEntry&, std::shared_ptr<const NativeMetadataProof>, const NativeFeatureIdentifier&,
    std::shared_ptr<const MetadataCaptureFailureLatch>) {
    return Observation<std::unique_ptr<NativeMetadataStreamReader>>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::NotApplicable), "metadata_stream.native_windows_required"});
}
#endif
} // namespace ck::files::detail
