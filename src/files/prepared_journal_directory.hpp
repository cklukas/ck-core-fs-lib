// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "prepared_journal_root.hpp"
#include "directory_cursor.hpp"
namespace ck::files {
// Worker-only, live bounded name enumeration below a genuine prepared root.
// Retains that SAME shared capability until finish/destruction. It grants no
// child-open or mutation authority and does not claim an inventory snapshot.
// Explicitly finish on the worker, report close failure, then release the view.
// The lifecycle owner finishes the root only after all consumers have released.
class PreparedJournalDirectory : public DirectoryCursor {
public:
    virtual Observation<bool> finish_io() = 0;
protected:
    explicit PreparedJournalDirectory(ObjectIdentity identity)
        : DirectoryCursor(Observation<ObjectIdentity>::available(std::move(identity))) {}
};
Observation<std::unique_ptr<PreparedJournalDirectory>> open_prepared_journal_directory(
    PreparedJournalRoot::Pointer root);
} // namespace ck::files
