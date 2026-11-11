// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "operation_journal.hpp"

namespace ck::files {

// Worker-only system entropy for a fresh, nonzero journal ID. The ID is
// descriptive. Creating the journal must still use exclusive native admission.
Observation<OperationJournalId> new_native_operation_journal_id();

} // namespace ck::files
