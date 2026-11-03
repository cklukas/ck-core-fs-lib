// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "metadata_replay.hpp"
#include "sync_baseline.hpp"
namespace ck::files {
// Declarative comparison facts ONLY. No native I/O, issuer authentication or
// mutation authority. A native producer must authenticate its snapshot first.
// CurrentCaller semantic metadata hashes omit actual ownership; this separate
// key lets a strict comparison require known, equal observed owners anyway.
// Object identity, query scope, ACL serialization offsets and timestamps do
// not enter the key. Unknown/unrequested ownership is never equal by default.
Observation<SyncDigest> metadata_ownership_digest(const MetadataReplaySnapshot&);
}
