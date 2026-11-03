// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "sync_session.hpp"
#include "native_filesystem.hpp"

namespace ck::files {
namespace {
template<class T, class U> Observation<T> propagate(const Observation<U>& o) {
    return Observation<T>::unavailable(o.state(), o.unavailable_detail()->error);
}
}
Observation<PreparedJournalRoot::Pointer> acquire_native_sync_storage_root(const NativeAbsolutePath& address) {
    NativeFileSystem fs;
    auto directory=fs.open_native_directory(address);
    if(!directory.value())return propagate<PreparedJournalRoot::Pointer>(directory);
    PreparedJournalRootRequest request;
    request.parent=std::move(directory).take_value();
    request.navigation_hint=address;
    JournalRootPreparationProgress progress;
    return prepare_native_journal_root(std::move(request),progress);
}
} // namespace ck::files
