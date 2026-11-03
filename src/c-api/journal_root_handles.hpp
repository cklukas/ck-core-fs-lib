// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "ck_fs_journal_root.h"
#include "prepared_journal_root.hpp"
namespace ck::files {
// Private C-adapter bridge. Cached state check plus shared-reference retention
// only: safe on the start caller, no native I/O. Fails unless READY and accepting
// consumers. Capture the returned owner in the worker/request until all journal
// I/O and native teardown have finished. Never call finish_io per journal/job.
Observation<PreparedJournalRoot::Pointer> retain_prepared_journal_root(const ckfjr_root*);
} // namespace ck::files
