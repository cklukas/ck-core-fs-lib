// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../native_name.hpp"
#include "../observation.hpp"

namespace ck::files::detail {
// Available transfers one CLOEXEC O_TMPFILE descriptor to the caller. No
// temporary name is created and no named staging fallback is attempted.
Observation<int> create_linux_anonymous_staging(int directory);

// Borrowed descriptors must remain owned by one worker. The file must be an
// adapter-created O_TMPFILE object (or its verified read-only fd successor),
// still unlinked. Publication is a hard link of this held object, no-replace.
// Any failure after a successful link is Unknown; no pathname rollback occurs.
Observation<bool> publish_linux_anonymous_staging(int file, int directory, const NativeName& name);
} // namespace ck::files::detail
