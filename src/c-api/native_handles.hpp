// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "native_filesystem.hpp"
#include "held_child.hpp"
#include "operation_recovery.hpp"

// Private definitions shared only by C ABI adapters. Never install this file.
struct ckfe_engine { ck::files::NativeFileSystem filesystem; };
struct ckfe_directory {
    std::shared_ptr<const ck::files::DirectoryCursor> cursor;
    // Requested native navigation address, recovery evidence only. Held native
    // identity remains authority; a later reopen must bind it afresh.
    std::optional<ck::files::NativeAbsolutePath> address{};
};
struct ckfe_entry {
    ck::files::HeldChild::Pointer child;
    std::optional<ck::files::NativeAbsolutePath> address{};
};
struct ckfe_recovery { ck::files::NativeOperationRecoveryInspection inspection; };
