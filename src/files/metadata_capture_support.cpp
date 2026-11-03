// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "metadata_capture_job.hpp"

namespace ck::files {
namespace detail {
namespace { thread_local const MetadataCaptureFailureLatch* active_cleanup=nullptr; }
MetadataCaptureCleanupScope::MetadataCaptureCleanupScope(const MetadataCaptureFailureLatch* p)noexcept:previous_(active_cleanup){active_cleanup=p;}
MetadataCaptureCleanupScope::~MetadataCaptureCleanupScope(){active_cleanup=previous_;}
const MetadataCaptureFailureLatch* current_metadata_capture_cleanup()noexcept{return active_cleanup;}
void record_metadata_capture_close(MetadataCaptureCleanupError e)noexcept{if(active_cleanup)active_cleanup->record_first(e);}
} // namespace detail
bool MetadataCaptureLimits::valid()const noexcept{return read.valid()&&max_retained_handles>=8&&max_metadata_bytes>0;}
} // namespace ck::files
