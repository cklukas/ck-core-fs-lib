// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../metadata_capture_job.hpp"
namespace ck::files::detail {
// Only factory-created, still-open staging writers qualify. No raw handles,
// addresses, caller identity DTOs or reopened paths are accepted.
Observation<bool> prepare_native_archive_file(OpenedEntry&,std::uint64_t logical_size,bool sparse);
// Consumes the actual writer once. POD only, including under persistent OOM.
// The enclosing owner must dispose of the entry under its Root close observer.
std::optional<MetadataCaptureCleanupError> finish_native_archive_file(OpenedEntry&) noexcept;
}
