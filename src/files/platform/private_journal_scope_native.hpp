// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../private_journal_scope.hpp"
namespace ck::files::detail {
// Certifies the genuine local native cursor and consumes its own duplicate on
// this worker. A fake cursor/scope token cannot authorize cross-scope ID use.
Observation<bool> certify_journal_scope_cursor(PreparedJournalRoot&, const DirectoryCursor&);
// Only topology fields used by the scope proof. The native factory seals the
// provider boundary; callers cannot supply an identity DTO as its authority.
struct ScopeDirectoryMetadata final {
    ObjectIdentity identity;
    std::uint64_t mount_id,link_count;
    FileTimestamp modified,changed;
};
class ScopeDirectoryCursor {
public:
    using Pointer=std::unique_ptr<ScopeDirectoryCursor>;
    virtual ~ScopeDirectoryCursor()=default;
    virtual Observation<ScopeDirectoryMetadata> inspect() const=0;
    virtual Observation<Pointer> open_parent() const=0;
};
Observation<ScopeDirectoryCursor::Pointer> open_scope_directory_cursor(
    PreparedJournalRoot::Pointer,std::shared_ptr<const DirectoryCursor>);
}
