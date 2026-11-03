// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../sync_session_reader_epoch.hpp"
#include "../directory_cursor.hpp"
namespace ck::files {class NativeHierarchyContext;namespace detail {struct HierarchyContextState;
// Defined only beside the anonymous final native backend classes. Handles,
// identity DTOs and a caller's SyncSessionBackend subclass cannot mint this brand.
bool certify_native_sync_backend(const SyncSessionBackend&)noexcept;
// Failure-only test boundary after genuine native validation; grants no facts.
inline thread_local void(*session_epoch_before_construct_test)()noexcept=nullptr;
class NativeSessionLease;
Observation<std::unique_ptr<DirectoryCursor>> open_native_session_root(const NativeSessionLease&,bool);
class NativeSessionLease final {
    friend class ck::files::NativeHierarchyContext;
    friend struct HierarchyContextState;
    friend Observation<std::unique_ptr<DirectoryCursor>> open_native_session_root(const NativeSessionLease&,bool);
    static Observation<std::shared_ptr<NativeSessionLease>> borrow(SyncSession&,const std::shared_ptr<SessionReadConsumer>&);
    explicit NativeSessionLease(std::shared_ptr<SessionReaderEpoch>,PreparedJournalRoot::Pointer,std::uint64_t);
    Observation<bool> revalidate()const;
    std::uint64_t epoch_id()const noexcept;
    Observation<std::intptr_t> handle(bool)const;
    Observation<std::unique_ptr<DirectoryCursor>> open_root(bool)const;
    std::shared_ptr<SessionReaderEpoch> epoch_;
    PreparedJournalRoot::Pointer root_;
    const std::uint64_t generation_;
    AdapterScope scope_;
};
}} // namespace ck::files::detail
