// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "private_journal_scope_native.hpp"
#include "../native_trash.hpp"
#include "native_journal_directory_bridge.hpp"
#include "prepared_journal_root_bridge.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include "legacy_native_fixture_windows.hpp"
#include "native_windows_journal_volume.hpp"
namespace ck::files::detail {
Observation<bool> certify_journal_scope_cursor(PreparedJournalRoot& root,const DirectoryCursor& cursor) {
    auto duplicate=duplicate_windows_journal_directory(cursor);
    if(!duplicate.value() && duplicate.state()==ObservationState::Unsupported)
        duplicate=duplicate_windows_trash_scope_directory(cursor);
    if(!duplicate.value()) {const auto& e=*duplicate.unavailable_detail();return Observation<bool>::unavailable(e.state,e.error);}
    // The bridge transfers one genuine native cursor duplicate. Keep only
    // scalars/stack storage until it has been explicitly consumed below.
    const auto handle=static_cast<HANDLE>(*duplicate.value());
    const auto proof=prove_windows_journal_volume(handle);
    // Consume exactly once on every result path. Latch a close failure before
    // constructing any potentially allocating Observation/error string.
    if(!::ck::files::detail::legacy_close_native_call(handle,"legacy.private_journal_scope_windows.CloseHandle.23")) {
        const auto close_code=GetLastError();
        record_prepared_journal_consumer_failure(root,ObservationState::Unknown,
            ErrorDomain::Win32,close_code,"journal_scope.cursor_close");
        return Observation<bool>::unavailable(ObservationState::Unknown,
            {ErrorDomain::Win32,close_code,"journal_scope.cursor_close"});
    }
    if(!proof.qualified)return Observation<bool>::unavailable(proof.state,{proof.domain,proof.code,proof.operation});
    return Observation<bool>::available(true);
}
namespace {
class WindowsScopeCursor final:public ScopeDirectoryCursor {
public:
    explicit WindowsScopeCursor(std::shared_ptr<const DirectoryCursor> cursor):initial_(std::move(cursor)){}
    explicit WindowsScopeCursor(std::unique_ptr<OpenedEntry> cursor):parent_(std::move(cursor)){}
    Observation<ScopeDirectoryMetadata> inspect() const override {
        const auto metadata=initial_?initial_->inspect_basic():parent_->inspect_basic();
        if(!metadata.value()) {const auto& error=*metadata.unavailable_detail();return Observation<ScopeDirectoryMetadata>::unavailable(error.state,error.error);}
        const auto& value=*metadata.value();
        if(!value.kind.value()||*value.kind.value()!=ObjectKind::Directory||!value.identity.value()||
            !value.mount_id.value()||!value.link_count.value()||!*value.link_count.value()||
            !value.modified.value()||!value.changed.value())
            return Observation<ScopeDirectoryMetadata>::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe),"journal_scope.topology_fields"});
        return Observation<ScopeDirectoryMetadata>::available({*value.identity.value(),*value.mount_id.value(),
            *value.link_count.value(),*value.modified.value(),*value.changed.value()});
    }
    Observation<Pointer> open_parent() const override {
        auto opened=initial_?initial_->open_parent_directory():parent_->open_parent_directory();
        if(!opened.value()) {const auto& error=*opened.unavailable_detail();return Observation<Pointer>::unavailable(error.state,error.error);}
        return Observation<Pointer>::available(std::make_unique<WindowsScopeCursor>(std::move(opened).take_value()));
    }
private:
    std::shared_ptr<const DirectoryCursor> initial_;
    std::unique_ptr<OpenedEntry> parent_;
};
}
Observation<ScopeDirectoryCursor::Pointer> open_scope_directory_cursor(PreparedJournalRoot::Pointer root,
    std::shared_ptr<const DirectoryCursor> cursor) {
    using P=ScopeDirectoryCursor::Pointer;
    if(!root||!cursor)return Observation<P>::unavailable(ObservationState::Failed,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidIdentifier),"journal_scope.topology_inputs"});
    // Keep the audited Windows parent-opening/version checks. This optimization
    // changes neither its Win32/native boundary nor the public cursor vtable.
    auto certified=certify_journal_scope_cursor(*root,*cursor);
    if(!certified.value()) {const auto& error=*certified.unavailable_detail();return Observation<P>::unavailable(error.state,error.error);}
    if(!*certified.value())return Observation<P>::unavailable(ObservationState::Unsupported,
        {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe),"journal_scope.topology_provider"});
    return Observation<P>::available(std::make_unique<WindowsScopeCursor>(std::move(cursor)));
}
}

#ifdef CK_FS_LEGACY_NATIVE_TEST_OBSERVERS
namespace ck::files::detail {
// Test instrumentation closure only, not native authority/async completion.
std::uint64_t legacy_native_scope_coverage()noexcept {
    return legacy_operation_bit(LegacyNativeOperation::Close)|
        legacy_operation_bit(LegacyNativeOperation::Query);
}
}
#endif
