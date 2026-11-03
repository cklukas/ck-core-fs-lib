// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "metadata_replay.hpp"
namespace ck::files {
class NativeMetadataProof;
inline constexpr std::uint64_t metadata_semantic_digest_version=3;
// No I/O: accepts only a completed, privately constructed native observation.
// Does not revalidate current source bytes or parent/name membership. Use the
// progressive verification job plus the caller's held-family refresh for use
// after capture. This hash is separate from the unnamed/main data digest.
Observation<std::array<std::byte,32>> native_metadata_proof_digest(const NativeMetadataProof&,std::stop_token={});
namespace detail {
// Encoder only, never source authority. Existing NS source+snapshot entry
// points retain their native authentication/rehash BEFORE invoking this.
Observation<std::array<std::byte,32>> metadata_snapshot_semantic_digest(const MetadataReplaySnapshot&,std::stop_token={});
}
}
