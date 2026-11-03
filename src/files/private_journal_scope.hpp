// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "held_child.hpp"
#include "prepared_journal_root.hpp"
#include <span>
#include <vector>

namespace ck::files {
// Worker-only initial address adoption for legacy callers. The returned native
// owner, rather than this address, serves every later journal operation.
Observation<PreparedJournalRoot::Pointer> acquire_native_journal_root(
    const NativeAbsolutePath&, std::stop_token = {});

// A native scan-root check is not enough on its own: mount aliases can expose a
// private directory below another acquisition ancestry. Check EVERY observed
// held entry before descending or accepting the immutable mutation plan. Keep
// the guard and root alive and repeat check_root during plan revalidation.
// Unknown/changed ancestry is a refusal. No display pathname or caller-created
// identity value is accepted as native provider evidence by this factory.
// Multiply linked regular files additionally require a fresh bounded native
// private-state membership check; ordinary external hardlinks remain usable.
// This protects the passed capability only; it is not a global/process-local
// registry of other clients' active roots or a namespace mutation lease.
class JournalScopeGuard final {
public:
    using Pointer = std::shared_ptr<JournalScopeGuard>;
    static Observation<Pointer> create(PreparedJournalRoot::Pointer,
        std::shared_ptr<const DirectoryCursor>, std::stop_token = {});
    // Selected action input: a directory must not contain/be inside Root. A
    // regular file outside Root remains usable when its parent contains Root.
    static Observation<Pointer> create_for_entry(PreparedJournalRoot::Pointer,
        const HeldChild&, std::stop_token = {});
    Observation<bool> check_root(std::stop_token = {}) const;
    // One worker assessment: the SAME native Root is checked around both
    // readonly ancestry walks. No result survives this call or skips entry
    // checks. This avoids rechecking identical Root ancestry within one step.
    static Observation<bool> check_pair(const Pointer&,const Pointer&,std::stop_token = {});
    Observation<bool> check_entry(const HeldChild&, std::stop_token = {}) const;
private:
    JournalScopeGuard(PreparedJournalRoot::Pointer root,
        std::shared_ptr<const DirectoryCursor> scan, ObjectIdentity identity, bool selected_file)
        : root_(std::move(root)), scan_(std::move(scan)), identity_(std::move(identity)), selected_file_(selected_file) {}
    static Observation<Pointer> create_impl(PreparedJournalRoot::Pointer,
        std::shared_ptr<const DirectoryCursor>, bool selected_file, std::stop_token);
    static Observation<bool> check_group(std::span<const JournalScopeGuard* const>,std::stop_token);
    Observation<bool> check_scan_ancestry(const std::vector<ObjectIdentity>&,std::stop_token) const;
    PreparedJournalRoot::Pointer root_;
    std::shared_ptr<const DirectoryCursor> scan_;
    ObjectIdentity identity_;
    bool selected_file_ = false;
};
} // namespace ck::files
