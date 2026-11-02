// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_operation_recovery.hpp"

#include "directory_cursor.hpp"
#include "sha256.hpp"

#include <cstdint>
#include <atomic>

namespace ck::files {
namespace {
template <class T>
Observation<T> rejected(AdapterError code, const char* operation,
                        ObservationState state = ObservationState::Failed) {
    return Observation<T>::unavailable(state,
        {ErrorDomain::Adapter, static_cast<std::int64_t>(code), operation});
}

Observation<bool> forward(const UnavailableObservation& detail) {
    return Observation<bool>::unavailable(detail.state, detail.error);
}

Observation<bool> verify_error(AdapterError code, const char* operation,
                               ObservationState state = ObservationState::Unknown) {
    return rejected<bool>(code, operation, state);
}
}

namespace {
bool before_publication(const OperationJournal& journal,std::size_t item) {
    for(const auto& r:journal.records()) if(r.item==item) switch(r.state) {
    case OperationJournalState::Planned:case OperationJournalState::Prepared:case OperationJournalState::Copied:
    case OperationJournalState::Verified:case OperationJournalState::Failed:case OperationJournalState::Cancelled:break;
    default:return false;
    }
    return journal.state(item).has_value();
}
}
struct NativeStagingOwnershipReceipt::State {
    OperationJournal::Pointer journal;
    std::size_t item;
    std::shared_ptr<const DirectoryCursor> destination;
    std::shared_ptr<OpenedEntry> created;
    ObjectIdentity parent_identity,created_identity;
    std::optional<NativeName> named_component;
    StagingNamespace staging_namespace;
    std::atomic<bool> consumed{false};
    State(OperationJournal::Pointer j,std::size_t i,std::shared_ptr<const DirectoryCursor> d,std::shared_ptr<OpenedEntry> c,
        ObjectIdentity parent,ObjectIdentity object,std::optional<NativeName> name,StagingNamespace ns)
        :journal(std::move(j)),item(i),destination(std::move(d)),created(std::move(c)),parent_identity(std::move(parent)),
         created_identity(std::move(object)),named_component(std::move(name)),staging_namespace(ns){}
};
NativeStagingOwnershipReceipt::NativeStagingOwnershipReceipt(std::shared_ptr<State> state) noexcept:state_(std::move(state)){}
NativeStagingOwnershipReceipt::~NativeStagingOwnershipReceipt()=default;
Observation<NativeStagingOwnershipReceipt::Pointer> NativeStagingOwnershipReceipt::bind_created(
    OperationJournal::Pointer journal,std::size_t item,std::shared_ptr<const DirectoryCursor> destination,
    std::shared_ptr<OpenedEntry> created,std::optional<NativeName> named_component,StagingNamespace staging_namespace) {
    using R=Observation<Pointer>;
    if(!journal||!destination||!created||!before_publication(*journal,item)||
        (staging_namespace!=StagingNamespace::Named&&staging_namespace!=StagingNamespace::Anonymous)||
        (staging_namespace==StagingNamespace::Named&&(!named_component||!named_component->is_valid()))||
        (staging_namespace==StagingNamespace::Anonymous&&named_component))
        return rejected<Pointer>(AdapterError::PlanInvalid,"native_recovery.ownership_creator_input");
    auto parent=destination->inspect_basic();auto object=created->inspect_basic();
    if(!parent.value())return R::unavailable(parent.state(),parent.unavailable_detail()->error);
    if(!object.value())return R::unavailable(object.state(),object.unavailable_detail()->error);
    const auto* p=parent.value()->identity.value();const auto* id=object.value()->identity.value();
    if(!p||!id||!object.value()->kind.value()||*object.value()->kind.value()!=ObjectKind::RegularFile||
        compare_identity(*p,*p)!=IdentityComparison::Same||compare_identity(*id,*id)!=IdentityComparison::Same||p->scope!=id->scope)
        return rejected<Pointer>(AdapterError::UnqualifiedIdentity,"native_recovery.ownership_creator_identity");
    auto state=std::make_shared<State>(std::move(journal),item,std::move(destination),std::move(created),*p,*id,std::move(named_component),staging_namespace);
    return R::available(Pointer(new NativeStagingOwnershipReceipt(std::move(state))));
}
Observation<bool> cleanup_native_unpublished_staging(const NativeOperationRecoveryCleanupRequest& request) {
    // No native lookup or disposition is attempted for restart/value-only input.
    if(!request.ownership||!request.ownership->state_)
        return verify_error(AdapterError::UnqualifiedIdentity,"native_recovery.cleanup_live_ownership_required");
    auto& owner=*request.ownership->state_;
    if(owner.consumed.load()||request.artifact.item!=owner.item||!owner.journal||
        owner.journal->state(owner.item)!=request.artifact.state||!before_publication(*owner.journal,owner.item))
        return verify_error(AdapterError::PlanDecisionStale,"native_recovery.cleanup_live_state");
    if(!request.destination||!request.artifact.evidence||!request.artifact.evidence->staging_identity)
        return verify_error(AdapterError::UnqualifiedIdentity,"native_recovery.cleanup_evidence");
    const auto ns=request.artifact.evidence->staging_namespace;
    if((ns!=StagingNamespace::Named&&ns!=StagingNamespace::Anonymous)||ns!=owner.staging_namespace||(ns==StagingNamespace::Named&&
        (!owner.named_component||*owner.named_component!=request.artifact.evidence->staging_name)))
        return verify_error(AdapterError::PlanDecisionStale,"native_recovery.cleanup_namespace");
    auto parent=request.destination->inspect_basic();auto original_parent=owner.destination->inspect_basic();
    auto object=owner.created->inspect_basic();
    if(!parent.value())return forward(*parent.unavailable_detail());
    if(!original_parent.value())return forward(*original_parent.unavailable_detail());
    if(!object.value())return forward(*object.unavailable_detail());
    const auto* p=parent.value()->identity.value();const auto* op=original_parent.value()->identity.value();const auto* id=object.value()->identity.value();
    if(!p||!op||!id||!object.value()->kind.value()||*object.value()->kind.value()!=ObjectKind::RegularFile||
        compare_identity(*p,owner.parent_identity)!=IdentityComparison::Same||compare_identity(*op,owner.parent_identity)!=IdentityComparison::Same||
        compare_identity(*p,request.destination_identity)!=IdentityComparison::Same||compare_identity(*id,owner.created_identity)!=IdentityComparison::Same||
        !request.artifact.evidence->destination_identity.matches_live(*p)||!request.artifact.evidence->staging_identity->matches_live(*id))
        return verify_error(AdapterError::PlanDecisionStale,"native_recovery.cleanup_live_identity",ObservationState::Changed);
    bool expected=false;
    if(!owner.consumed.compare_exchange_strong(expected,true))return verify_error(AdapterError::PlanDecisionStale,"native_recovery.cleanup_consumed");
    if(ns==StagingNamespace::Named) {
        // The original held stage remains alive throughout the adapter's
        // identity-bound disposition, preventing ID reuse between observations.
        auto discarded=request.destination->discard_child(*owner.named_component,*id);
        if(!discarded.value())return forward(*discarded.unavailable_detail());
        if(!*discarded.value())return rejected<bool>(AdapterError::InvalidNativeResult,"native_recovery.cleanup_result");
    }
    // Anonymous objects are disposed only through their actual created owner.
    // Never open/unlink the evidence's hint, even if it names an unrelated file.
    return owner.created->finish_content_writes();
}

Observation<bool> verify_native_published_destination(
    const NativeOperationRecoveryVerificationRequest& request) {
    if (!request.destination || !request.destination_identity.scope.is_valid() ||
        request.destination_identity.scheme == IdentityScheme::Unknown || request.max_bytes == 0)
        return rejected<bool>(AdapterError::PlanInvalid, "native_recovery.verify_request");
    if (!request.artifact.evidence || !request.artifact.evidence->content_digest ||
        !request.artifact.evidence->published_identity ||
        !request.artifact.evidence->destination_name.is_valid())
        return verify_error(AdapterError::UnqualifiedIdentity, "native_recovery.verify_receipt");
    if (request.artifact.state != OperationJournalState::DestinationCommitted &&
        request.artifact.state != OperationJournalState::SourceRetired &&
        request.artifact.state != OperationJournalState::Complete)
        return verify_error(AdapterError::PlanDecisionStale, "native_recovery.verify_state");

    const auto current_destination = request.destination->identity();
    if (!current_destination.value()) return forward(*current_destination.unavailable_detail());
    if (compare_identity(*current_destination.value(), request.destination_identity) != IdentityComparison::Same ||
        !request.artifact.evidence->destination_identity.matches_live(*current_destination.value()))
        return verify_error(AdapterError::PlanDecisionStale,
                            "native_recovery.verify_destination_changed", ObservationState::Changed);

    auto opened = request.destination->open_child(request.artifact.evidence->destination_name,
                                                   EntryAccess::ContentRead);
    if (!opened.value()) return forward(*opened.unavailable_detail());
    auto metadata = (*opened.value())->inspect_basic();
    if (!metadata.value()) return forward(*metadata.unavailable_detail());
    if (!metadata.value()->identity.value() || !metadata.value()->kind.value() ||
        *metadata.value()->kind.value() != ObjectKind::RegularFile)
        return verify_error(AdapterError::MetadataChanged, "native_recovery.verify_kind",
                            ObservationState::Changed);
    if (!request.artifact.evidence->published_identity->matches_live(
            *metadata.value()->identity.value()))
        return verify_error(AdapterError::PlanDecisionStale,
                            "native_recovery.verify_published_identity", ObservationState::Changed);
    if (!metadata.value()->logical_size.value() ||
        *metadata.value()->logical_size.value() > request.max_bytes)
        return verify_error(AdapterError::InventoryLimit, "native_recovery.verify_size");

    Sha256 digest;
    std::uint64_t offset = 0;
    for (;;) {
        auto content = (*opened.value())->read_content({64 * 1024}, offset);
        if (!content.value()) return forward(*content.unavailable_detail());
        if (content.value()->bytes.size() > request.max_bytes - offset)
            return verify_error(AdapterError::InventoryLimit, "native_recovery.verify_bytes");
        digest.update(std::span<const std::byte>(content.value()->bytes));
        offset += content.value()->bytes.size();
        if (content.value()->complete) break;
        if (content.value()->bytes.empty())
            return verify_error(AdapterError::InvalidNativeResult,
                                "native_recovery.verify_no_progress");
    }
    if (offset != *metadata.value()->logical_size.value())
        return verify_error(AdapterError::MetadataChanged,
                            "native_recovery.verify_length", ObservationState::Changed);
    return Observation<bool>::available(
        digest.digest() == *request.artifact.evidence->content_digest);
}
} // namespace ck::files
