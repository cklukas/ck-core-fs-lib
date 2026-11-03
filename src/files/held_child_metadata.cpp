// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "held_child.hpp"
#include "metadata_replay.hpp"

namespace ck::files {
Observation<MetadataReplaySnapshot> HeldChild::capture_metadata(MetadataReplayPolicy policy, std::stop_token stop) const {
    return capture_metadata_replay(*child_, policy, stop);
}
Observation<bool> HeldChild::verify_metadata_source(const MetadataReplaySnapshot& snapshot, std::stop_token stop) const {
    return verify_metadata_replay_source(*child_, snapshot, stop);
}
} // namespace ck::files
