// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once

#include "../directory_cursor.hpp"

namespace ck::files::detail {

// The scan only exposes read operations. The original native cursor stays
// alive, but callers cannot recover it or its mutators from the scan view.
class HeldDirectoryScan : public DirectoryCursor {
public:
    Observation<AdapterScope> source_scope() const override { return parent_->source_scope(); }
    Observation<BasicMetadata> inspect_basic() const override { return parent_->inspect_basic(); }
    Observation<std::unique_ptr<OpenedEntry>> open_child(const NativeName& name, EntryAccess access) const override {
        if (access != EntryAccess::MetadataOnly)
            return Observation<std::unique_ptr<OpenedEntry>>::unavailable(ObservationState::Denied,
                {ErrorDomain::Adapter, static_cast<std::int64_t>(AdapterError::InvalidAccess), "directory_scan.child_access"});
        return parent_->open_child(name, access);
    }

protected:
    explicit HeldDirectoryScan(std::shared_ptr<const DirectoryCursor> parent)
        : DirectoryCursor(parent->identity()), parent_(std::move(parent)) {}

private:
    std::shared_ptr<const DirectoryCursor> parent_;
};

} // namespace ck::files::detail
