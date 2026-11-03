// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "private_journal_scope.hpp"
#include "private_journal_membership.hpp"
#include "native_filesystem.hpp"
#include "platform/private_journal_scope_native.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include <algorithm>
#include <vector>

namespace ck::files {
namespace {
template<class T> Observation<T> refuse(const char* operation,
    ObservationState state=ObservationState::Unsupported,
    AdapterError code=AdapterError::PlanTopologyUnsafe) {
    return Observation<T>::unavailable(state,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),operation});
}
template<class T> Observation<T> forward(const UnavailableObservation& error) {
    return Observation<T>::unavailable(error.state,error.error);
}
Observation<bool> cancelled() {
    return refuse<bool>("journal_scope.cancelled",ObservationState::Changed,AdapterError::InterruptedRead);
}
bool qualified(const ObjectIdentity& id) {
    return id.scope.is_valid()&&id.object!=NativeIdentifier{}&&
        (id.scheme==IdentityScheme::PosixDeviceInode||id.scheme==IdentityScheme::WindowsFileId128||
         id.scheme==IdentityScheme::WindowsFileIndex64);
}
// This comparison is used ONLY after both sides have been produced by genuine
// local native providers. AdapterScope tokens cannot be supplied as proof of a
// shared host. Cursor certification and native Root ancestry establish it.
IdentityComparison native_identity(const ObjectIdentity& a,const ObjectIdentity& b) {
    if(!qualified(a)||!qualified(b)||a.scheme!=b.scheme||a.generation.has_value()!=b.generation.has_value())
        return IdentityComparison::Unknown;
    if(a.volume!=b.volume||a.object!=b.object)return IdentityComparison::Different;
    return a.generation==b.generation?IdentityComparison::Same:IdentityComparison::Different;
}
bool directory(const BasicMetadata& value) {
    return value.kind.value()&&*value.kind.value()==ObjectKind::Directory&&value.identity.value()&&
        qualified(*value.identity.value())&&value.link_count.value()&&*value.link_count.value()!=0&&
        value.changed.value()&&value.modified.value()&&value.mount_id.value();
}
bool stable(const detail::ScopeDirectoryMetadata& a,const detail::ScopeDirectoryMetadata& b) {
    return qualified(a.identity)&&qualified(b.identity)&&a.link_count&&b.link_count&&
        compare_identity(a.identity,b.identity)==IdentityComparison::Same&&a.mount_id==b.mount_id&&
        a.mount_id_unique==b.mount_id_unique&&a.modified==b.modified&&a.changed==b.changed;
}
Observation<bool> compare_private(const ObjectIdentity& root,const ObjectIdentity& other) {
    const auto relation=native_identity(root,other);
    if(relation==IdentityComparison::Unknown)return refuse<bool>("journal_scope.identity_namespace_unqualified");
    if(relation==IdentityComparison::Same)return refuse<bool>("journal_scope.private_root_overlap");
    return Observation<bool>::available(true);
}
Observation<bool> require_true(Observation<bool> result,const char* operation) {
    if(!result.value())return result;
    return *result.value()?std::move(result):refuse<bool>(operation);
}
}

Observation<PreparedJournalRoot::Pointer> acquire_native_journal_root(
    const NativeAbsolutePath& address,std::stop_token stop) {
    if(stop.stop_requested())return forward<PreparedJournalRoot::Pointer>(*cancelled().unavailable_detail());
    NativeFileSystem filesystem;
    auto opened=filesystem.open_native_directory(address,DirectoryLinkPolicy::RejectFinalLink);
    if(!opened.value())return forward<PreparedJournalRoot::Pointer>(*opened.unavailable_detail());
    PreparedJournalRootRequest request;
    request.parent=std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value());
    request.disposition=JournalRootDisposition::AdoptHeld;
    request.navigation_hint=address;
    JournalRootPreparationProgress progress;
    return prepare_native_journal_root(std::move(request),progress,stop);
}

Observation<JournalScopeGuard::Pointer> JournalScopeGuard::create(PreparedJournalRoot::Pointer root,
    std::shared_ptr<const DirectoryCursor> scan,std::stop_token stop) {
    return create_impl(std::move(root),std::move(scan),false,stop);
}
Observation<JournalScopeGuard::Pointer> JournalScopeGuard::create_impl(PreparedJournalRoot::Pointer root,
    std::shared_ptr<const DirectoryCursor> scan,bool selected_file,std::stop_token stop) {
    if(!root||!scan)return refuse<Pointer>("journal_scope.inputs",ObservationState::Failed,AdapterError::InvalidIdentifier);
    if(stop.stop_requested())return forward<Pointer>(*cancelled().unavailable_detail());
    auto certified=detail::certify_journal_scope_cursor(*root,*scan);
    if(!certified.value())return forward<Pointer>(*certified.unavailable_detail());
    if(!*certified.value())return refuse<Pointer>("journal_scope.native_cursor_required");
    auto observed=scan->inspect_basic();
    if(!observed.value())return forward<Pointer>(*observed.unavailable_detail());
    if(!directory(*observed.value())||!scan->identity().value()||
        compare_identity(*scan->identity().value(),*observed.value()->identity.value())!=IdentityComparison::Same)
        return refuse<Pointer>("journal_scope.scan_identity_unqualified");
    auto result=Pointer(new JournalScopeGuard(std::move(root),std::move(scan),*observed.value()->identity.value(),selected_file));
    auto checked=result->check_root(stop);
    if(!checked.value())return forward<Pointer>(*checked.unavailable_detail());
    if(!*checked.value())return refuse<Pointer>("journal_scope.false_assessment");
    return Observation<Pointer>::available(std::move(result));
}

Observation<JournalScopeGuard::Pointer> JournalScopeGuard::create_for_entry(PreparedJournalRoot::Pointer root,
    const HeldChild& entry,std::stop_token stop) {
    if(!root||!entry.parent())return refuse<Pointer>("journal_scope.entry_inputs",ObservationState::Failed,AdapterError::InvalidIdentifier);
    if(stop.stop_requested())return forward<Pointer>(*cancelled().unavailable_detail());
    auto certified=detail::certify_journal_scope_cursor(*root,*entry.parent());
    if(!certified.value())return forward<Pointer>(*certified.unavailable_detail());
    if(!*certified.value())return refuse<Pointer>("journal_scope.entry_native_parent_required");
    auto current=entry.inspect_basic();
    if(!current.value())return forward<Pointer>(*current.unavailable_detail());
    if(!current.value()->kind.value()||!current.value()->identity.value()||!entry.metadata().identity.value()||
        compare_identity(*current.value()->identity.value(),*entry.metadata().identity.value())!=IdentityComparison::Same)
        return refuse<Pointer>("journal_scope.action_entry_changed",ObservationState::Changed,AdapterError::MetadataChanged);
    auto parent=entry.parent()->inspect_basic();
    if(!parent.value())return forward<Pointer>(*parent.unavailable_detail());
    if(!directory(*parent.value())||!current.value()->mount_id.value()||
        *current.value()->mount_id.value()!=*parent.value()->mount_id.value())
        return refuse<Pointer>("journal_scope.action_mount_boundary_unqualified");
    if(*current.value()->kind.value()==ObjectKind::Directory) {
        auto opened=entry.parent()->open_directory_child(entry.name());
        if(!opened.value())return forward<Pointer>(*opened.unavailable_detail());
        if(!(*opened.value())->identity().value()||
            compare_identity(*(*opened.value())->identity().value(),*current.value()->identity.value())!=IdentityComparison::Same)
            return refuse<Pointer>("journal_scope.action_directory_changed",ObservationState::Changed,AdapterError::MetadataChanged);
        return create_impl(std::move(root),std::shared_ptr<const DirectoryCursor>(std::move(opened).take_value()),false,stop);
    }
    if(*current.value()->kind.value()!=ObjectKind::RegularFile)return refuse<Pointer>("journal_scope.action_kind_unqualified");
    auto result=create_impl(std::move(root),entry.parent(),true,stop);
    if(!result.value())return result;
    auto checked=(*result.value())->check_entry(entry,stop);
    if(!checked.value())return forward<Pointer>(*checked.unavailable_detail());
    if(!*checked.value())return refuse<Pointer>("journal_scope.action_false_assessment");
    return result;
}

Observation<bool> JournalScopeGuard::check_root(std::stop_token stop) const {
    const JournalScopeGuard* guards[]={this};
    return check_group(guards,stop);
}
Observation<bool> JournalScopeGuard::check_pair(const Pointer& left,const Pointer& right,std::stop_token stop) {
    const JournalScopeGuard* guards[]={left.get(),right.get()};
    return check_group(guards,stop);
}
Observation<bool> JournalScopeGuard::check_group(std::span<const JournalScopeGuard* const> guards,std::stop_token stop) {
    if(stop.stop_requested())return cancelled();
    if(guards.empty()||!guards.front()||!guards.front()->root_)
        return refuse<bool>("journal_scope.guard_set_inputs",ObservationState::Failed,AdapterError::InvalidIdentifier);
    const auto& root=guards.front()->root_;
    for(const auto* guard:guards)if(!guard||guard->root_.get()!=root.get())
        return refuse<bool>("journal_scope.guard_set_root",ObservationState::Failed,AdapterError::InvalidIdentifier);
    // The genuine native bridge revalidates Root BEFORE and AFTER collecting
    // the fresh held ancestry. All following operations are readonly; finish
    // with one further Root validation before returning a shared assessment.
#ifdef __linux__
    auto ancestry=detail::inspect_prepared_journal_scope_ancestry(*root);
#else
    auto ancestry=detail::inspect_prepared_journal_ancestry(*root);
#endif
    if(!ancestry.value())return forward<bool>(*ancestry.unavailable_detail());
#ifdef __linux__
    if(ancestry.value()->size()<2||ancestry.value()->size()>4096||ancestry.value()->front().mount_id==0||
        compare_identity(root->identity(),ancestry.value()->front().object)!=IdentityComparison::Same)
#else
    if(ancestry.value()->size()<2||ancestry.value()->size()>4096||
        compare_identity(root->identity(),ancestry.value()->front())!=IdentityComparison::Same)
#endif
        return refuse<bool>("journal_scope.root_ancestry_unqualified");
    for(const auto* guard:guards) {
        auto checked=guard->check_scan_ancestry(*ancestry.value(),stop);
        if(!checked.value())return checked;
        if(!*checked.value())return refuse<bool>("journal_scope.scan_false");
    }
    return require_true(root->revalidate(),"journal_scope.root_changed");
}
#ifdef __linux__
Observation<bool> JournalScopeGuard::check_scan_ancestry(const std::vector<detail::RootScopeIdentity>& ancestry,std::stop_token stop) const {
#else
Observation<bool> JournalScopeGuard::check_scan_ancestry(const std::vector<ObjectIdentity>& ancestry,std::stop_token stop) const {
#endif
    if(stop.stop_requested())return cancelled();
#ifdef __linux__
    const auto& private_scope=ancestry.front();
    const auto& private_id=private_scope.object;
#else
    const auto& private_id=ancestry.front();
#endif
    auto opened=detail::open_scope_directory_cursor(root_,scan_);
    if(!opened.value())return forward<bool>(*opened.unavailable_detail());
    auto cursor=std::move(opened).take_value();
    auto source=cursor->inspect();
    if(!source.value())return forward<bool>(*source.unavailable_detail());
    if(!qualified(source.value()->identity)||!source.value()->link_count||
        compare_identity(identity_,source.value()->identity)!=IdentityComparison::Same)
        return refuse<bool>("journal_scope.scan_changed",ObservationState::Changed,AdapterError::MetadataChanged);
#ifdef __linux__
    if(!source.value()->mount_id_unique)
        return refuse<bool>("journal_scope.scan_unique_mount_unqualified");
    // A whole-filesystem bind can report the same physical root string while
    // carrying a different mount ID. It is still an alias of the protected
    // object and cannot become a separate scope merely because '/' matched.
    const bool same_root_object=compare_identity(private_id,source.value()->identity)==IdentityComparison::Same;
    const bool same_root_scope=same_root_object && private_scope.mount_id==source.value()->mount_id_unique;
    if(same_root_object || same_root_scope)
        return refuse<bool>("journal_scope.private_root_alias");
#endif
    // Root below/equal to the scan root in its retained acquisition ancestry.
    for(std::size_t index=0;index<ancestry.size();++index) {
        if(selected_file_&&index!=0)continue;
        auto assessed=compare_private(
#ifdef __linux__
            ancestry[index].object,
#else
            ancestry[index],
#endif
            identity_);
        if(!assessed.value())return assessed;
    }
    std::vector<ObjectIdentity> visited{identity_};
    auto before=*source.value();
    auto parent=cursor->open_parent();
    if(!parent.value())return forward<bool>(*parent.unavailable_detail());
    auto current=std::move(parent).take_value();
    auto after=cursor->inspect();
    if(!after.value())return forward<bool>(*after.unavailable_detail());
    if(!stable(before,*after.value()))return refuse<bool>("journal_scope.scan_ancestry_changed",ObservationState::Changed,AdapterError::MetadataChanged);
    for(std::size_t depth=0;depth<4096;++depth) {
        if(stop.stop_requested())return cancelled();
        auto now=current->inspect();
        if(!now.value())return forward<bool>(*now.unavailable_detail());
        if(!qualified(now.value()->identity)||!now.value()->link_count)return refuse<bool>("journal_scope.ancestor_unqualified");
        const auto& id=now.value()->identity;
        auto assessed=compare_private(private_id,id);
        if(!assessed.value())return assessed;
        const auto endpoint=compare_identity(before.identity,id);
        if(endpoint==IdentityComparison::Unknown)return refuse<bool>("journal_scope.ancestor_namespace_unqualified");
        // A same-volume mount edge can hide the physical parent of a bind
        // alias. A different-volume boundary is qualified only when the same
        // native boundary appears in the Root's retained ancestry (or the
        // original subject lives on a different physical volume entirely).
        if(before.mount_id!=now.value()->mount_id
#ifdef __linux__
            || before.mount_id_unique!=now.value()->mount_id_unique
#endif
            ) {
            const bool same_volume=before.identity.volume==id.volume;
            const bool subject_on_root_volume=identity_.volume==private_id.volume;
            const bool known_boundary=std::any_of(ancestry.begin(),ancestry.end(),[&](const auto& known){
                return native_identity(
#ifdef __linux__
                    known.object,
#else
                    known,
#endif
                    before.identity)==IdentityComparison::Same;
            });
            if(same_volume||(subject_on_root_volume&&!known_boundary))
                return refuse<bool>("journal_scope.mount_alias_unqualified");
        }
        if(endpoint==IdentityComparison::Same)
            return Observation<bool>::available(true);
        if(std::any_of(visited.begin(),visited.end(),[&](const auto& seen){return compare_identity(seen,id)!=IdentityComparison::Different;}))
            return refuse<bool>("journal_scope.ancestor_cycle");
        visited.push_back(id);
        before=*now.value();
        auto next=current->open_parent();
        if(!next.value())return forward<bool>(*next.unavailable_detail());
        after=current->inspect();
        if(!after.value())return forward<bool>(*after.unavailable_detail());
        if(!stable(before,*after.value()))return refuse<bool>("journal_scope.ancestor_changed",ObservationState::Changed,AdapterError::MetadataChanged);
        current=std::move(next).take_value();
    }
    return refuse<bool>("journal_scope.ancestry_limit");
}

Observation<bool> JournalScopeGuard::check_entry(const HeldChild& entry,std::stop_token stop) const {
    if(stop.stop_requested())return cancelled();
    auto root_checked=require_true(root_->revalidate(),"journal_scope.root_unqualified");
    if(!root_checked.value())return root_checked;
    auto certified=detail::certify_journal_scope_cursor(*root_,*entry.parent());
    if(!certified.value())return certified;
    if(!*certified.value())return refuse<bool>("journal_scope.entry_native_parent_required");
    auto current=entry.inspect_basic();
    if(!current.value())return forward<bool>(*current.unavailable_detail());
    if(!current.value()->identity.value()||!entry.metadata().identity.value()||
        compare_identity(*current.value()->identity.value(),*entry.metadata().identity.value())!=IdentityComparison::Same)
        return refuse<bool>("journal_scope.entry_changed",ObservationState::Changed,AdapterError::MetadataChanged);
    auto parent=entry.parent()->inspect_basic();
    if(!parent.value())return forward<bool>(*parent.unavailable_detail());
    if(!directory(*parent.value())||!current.value()->mount_id.value()||
        *current.value()->mount_id.value()!=*parent.value()->mount_id.value())
        return refuse<bool>("journal_scope.entry_mount_boundary_unqualified");
    auto separated=compare_private(root_->identity(),*current.value()->identity.value());
    if(!separated.value())return separated;
    if(!current.value()->kind.value())return refuse<bool>("journal_scope.entry_kind_unknown");
    if(*current.value()->kind.value()==ObjectKind::RegularFile) {
        if(!detail::private_membership_entry_qualified(*current.value()))
            return refuse<bool>("journal_scope.entry_links_unqualified");
        // Directory ancestry cannot establish the membership of a file with
        // several names. Resolve that case with a fresh, bounded native walk
        // of private state, rather than rejecting ordinary user hardlinks.
        if(*current.value()->link_count.value()>1) {
            auto membership=qualify_private_journal_disjointness(*root_,entry,{},stop);
            if(!membership.value())return membership;
            if(!*membership.value())return refuse<bool>("journal_scope.entry_membership_false");
        }
        auto after=entry.inspect_basic();
        if(!after.value())return forward<bool>(*after.unavailable_detail());
        if(!detail::private_membership_entry_same(*current.value(),*after.value()))
            return refuse<bool>("journal_scope.entry_membership_changed",ObservationState::Changed,AdapterError::MetadataChanged);
    }
    return require_true(root_->revalidate(),"journal_scope.entry_root_changed");
}
} // namespace ck::files
