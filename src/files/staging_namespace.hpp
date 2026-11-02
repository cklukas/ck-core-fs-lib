// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include <cstdint>

namespace ck::files {
enum class StagingNamespace : std::uint8_t { Unknown = 0, Named = 1, Anonymous = 2 };
} // namespace ck::files
