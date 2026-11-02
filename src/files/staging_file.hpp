// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "native_name.hpp"
#include "staging_namespace.hpp"
#include <memory>
#include <optional>

namespace ck::files {
class OpenedEntry;

// Worker-owned creation result, never a publication receipt. Anonymous staging
// has no directory entry: a recovery hint must never be reopened or unlinked.
// Keep the entry alive until publication/disposal. A successful publication
// changes native link count, not the original creation namespace recorded here.
struct CreatedStagingFile final {
    std::unique_ptr<OpenedEntry> entry;
    StagingNamespace staging_namespace = StagingNamespace::Unknown;
    std::optional<NativeName> name;
};
} // namespace ck::files
