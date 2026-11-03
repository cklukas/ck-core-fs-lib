// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "prepared_journal_root.hpp"
namespace ck::files {
Observation<std::unique_ptr<OperationJournalFile>> open_prepared_operation_journal_file(
    PreparedJournalRoot& root, const NativeName& basename, bool create_new) {
    return root.open_journal(basename, create_new);
}
} // namespace ck::files
