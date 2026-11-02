// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "retained_target.hpp"
#include <algorithm>

namespace ck::files {
namespace {
UnavailableObservation rejected(const char* op, ObservationState state = ObservationState::Changed,
    AdapterError code = AdapterError::PlanDecisionStale) {
    return {state, {ErrorDomain::Adapter, static_cast<std::int64_t>(code), op}};
}
template<class T> Observation<T> unavailable(const UnavailableObservation& e) {
    return Observation<T>::unavailable(e.state, e.error);
}
bool same(const ObjectIdentity& a, const ObjectIdentity& b) { return compare_identity(a,b) == IdentityComparison::Same; }
template<class T> bool equal(const Observation<T>& a, const Observation<T>& b) {
    return a.value() && b.value() ? *a.value() == *b.value() :
        !a.value() && !b.value() && a.state() == b.state() && a.unavailable_detail()->error == b.unavailable_detail()->error;
}
bool version(const BasicMetadata& a, const BasicMetadata& b) {
    return a.identity.value() && b.identity.value() && same(*a.identity.value(), *b.identity.value()) &&
        a.logical_size.value() && b.logical_size.value() && equal(a.logical_size,b.logical_size) &&
        a.modified.value() && b.modified.value() && equal(a.modified,b.modified) &&
        a.changed.value() && b.changed.value() && equal(a.changed,b.changed) &&
        equal(a.kind,b.kind) && equal(a.link_count,b.link_count) && equal(a.posix_permissions,b.posix_permissions) &&
        equal(a.posix_uid,b.posix_uid) && equal(a.posix_gid,b.posix_gid) && equal(a.windows_attributes,b.windows_attributes);
}
NativeName journal_name(const RetainedTargetRequest& r) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string n = ".ck-retention-";
    for (const auto byte : r.journal_id.bytes) {
        const auto b = std::to_integer<unsigned>(byte); n += hex[b >> 4]; n += hex[b & 15];
    }
    n += ".journal";
    if (r.target->name().posix_bytes()) return *NativeName::from_posix(n);
    std::u16string w(n.begin(),n.end()); return *NativeName::from_windows(w);
}
}
Observation<RetainedTarget::Pointer> RetainedTarget::create(RetainedTargetRequest r) {
    if (!r.target || !r.revalidate_ancestors || !r.open_journal || !r.retained_name.is_valid() ||
        r.retained_name.encoding() != r.target->name().encoding() || r.retained_name == r.target->name() ||
        !r.chunk_bytes || r.chunk_bytes > ContentReadLimits::hard_max_bytes ||
        !r.target->metadata().identity.value() || !r.target->parent_identity().value() ||
        !r.target->metadata().kind.value() || *r.target->metadata().kind.value() != ObjectKind::RegularFile ||
        !r.target->metadata().logical_size.value() || !r.target->metadata().modified.value() || !r.target->metadata().changed.value() ||
        !r.target->metadata().link_count.value() || *r.target->metadata().link_count.value() != 1)
        return unavailable<Pointer>(rejected("retained_target.input",ObservationState::Failed,AdapterError::PlanInvalid));
    const auto capability = r.target->parent()->qualify_identity_bound_rename();
    if (!capability.value()) return unavailable<Pointer>(*capability.unavailable_detail());
    if (!*capability.value()) return unavailable<Pointer>(rejected("retained_target.rename_unqualified",ObservationState::Unsupported,AdapterError::ProviderReviewRequired));
    auto guard = HeldChild::observe_with_access(r.target->parent(),r.target->name(),EntryAccess::ContentRead | EntryAccess::RenameSource);
    if (!guard.value()) return unavailable<Pointer>(*guard.unavailable_detail());
    if (!version(r.target->metadata(),(*guard.value())->metadata())) return unavailable<Pointer>(rejected("retained_target.changed"));
    // This proof belongs to the exact retained guard, not its provider, file
    // identity, stat brackets, or the fact that DELETE/read access was granted.
    const auto stable = (*guard.value())->qualify_stable_content();
    if (!stable.value()) return unavailable<Pointer>(*stable.unavailable_detail());
    if (!*stable.value()) return unavailable<Pointer>(rejected("retained_target.stable_content_unqualified",ObservationState::Unsupported,AdapterError::ProviderReviewRequired));
    // Establish the reviewed namespace binding only after the guard is active.
    // Refresh the ordinary observation, not a second DELETE guard: the first
    // guard must continue denying new DELETE opens through the entire operation.
    const auto membership = r.target->refresh();
    const auto current = (*guard.value())->inspect_basic();
    const auto parent_now = r.target->parent()->inspect_basic();
    if (!membership.value()) return unavailable<Pointer>(*membership.unavailable_detail());
    if (!current.value()) return unavailable<Pointer>(*current.unavailable_detail());
    if (!parent_now.value()) return unavailable<Pointer>(*parent_now.unavailable_detail());
    if (!parent_now.value()->identity.value() || !same(*r.target->parent_identity().value(), *parent_now.value()->identity.value()) ||
        !version(r.target->metadata(),(*membership.value())->metadata()) || !version(r.target->metadata(),*current.value()))
        return unavailable<Pointer>(rejected("retained_target.guarded_membership_changed"));
    const auto parent = NativeDurableIdentity::from_live(*r.target->parent_identity().value());
    const auto object = NativeDurableIdentity::from_live(*r.target->metadata().identity.value());
    if (!parent || !object) return unavailable<Pointer>(rejected("retained_target.identity",ObservationState::Unknown,AdapterError::UnqualifiedIdentity));
    auto journal = OperationJournal::create(FileOperation::Move,r.journal_id,{1,16,1024 * 1024});
    if (!journal.value()) return unavailable<Pointer>(*journal.unavailable_detail());
    const auto safe_root = prepare_native_operation_journal_root(r.journal_root);
    if (!safe_root.value()) return unavailable<Pointer>(*safe_root.unavailable_detail());
    auto file = r.open_journal(r.journal_root,journal_name(r),true);
    if (!file.value()) return unavailable<Pointer>(*file.unavailable_detail());
    if (!*file.value()) return unavailable<Pointer>(rejected("retained_target.null_journal",ObservationState::Failed,AdapterError::InvalidNativeResult));
    NativeOperationRecoveryEvidence evidence{r.target->name(),r.retained_name,*parent,*object,*parent,*object,
        r.parent_address,r.reviewed_digest,{}};
    auto value = Pointer(new RetainedTarget(std::move(r),*guard.value(),*journal.value(),
        std::move(file).take_value(),std::move(evidence)));
    const auto planned = value->append(OperationJournalState::Planned);
    if (!planned.value()) return unavailable<Pointer>(*planned.unavailable_detail());
    return Observation<Pointer>::available(std::move(value));
}
Observation<bool> RetainedTarget::verify_guard_and_membership() const {
    const auto stable = guard_->qualify_stable_content();
    if (!stable.value()) return stable;
    if (!*stable.value()) return unavailable<bool>(rejected("retained_target.stable_content_unqualified",ObservationState::Unsupported,AdapterError::ProviderReviewRequired));
    const auto parent = guard_->parent()->inspect_basic();
    const auto membership = request_.target->refresh();
    const auto current = guard_->inspect_basic();
    if (!parent.value()) return unavailable<bool>(*parent.unavailable_detail());
    if (!membership.value()) return unavailable<bool>(*membership.unavailable_detail());
    if (!current.value()) return unavailable<bool>(*current.unavailable_detail());
    if (!parent.value()->identity.value() || !same(*guard_->parent_identity().value(), *parent.value()->identity.value()) ||
        !version(request_.target->metadata(),(*membership.value())->metadata()) || !version(request_.target->metadata(),*current.value()))
        return unavailable<bool>(rejected("retained_target.guarded_membership_changed"));
    return Observation<bool>::available(true);
}
Observation<bool> RetainedTarget::append(OperationJournalState state) {
    auto encoded = encode_native_operation_recovery_evidence(evidence_,{1024 * 1024,256 * 1024});
    if (!encoded.value()) return unavailable<bool>(*encoded.unavailable_detail());
    return append_operation_journal_file(*file_,*journal_,
        {journal_->records().size() + 1,0,state,std::move(encoded).take_value()});
}
Observation<bool> RetainedTarget::fail(UnavailableObservation e, bool ambiguous) {
    failure_ = e;
    const auto marked = append(ambiguous ? OperationJournalState::NeedsReconciliation : OperationJournalState::Failed);
    state_ = ambiguous || !marked.value() ? RetainedTargetState::NeedsReconciliation : RetainedTargetState::Failed;
    return unavailable<bool>(e);
}
RetainedTargetState RetainedTarget::advance(std::stop_token stop) {
    if (state_ != RetainedTargetState::Verifying) return state_;
    if (stop.stop_requested()) {
        const auto cancelled = append(OperationJournalState::Cancelled);
        state_ = cancelled.value() ? RetainedTargetState::Cancelled : RetainedTargetState::NeedsReconciliation;
        if (!cancelled.value()) failure_ = *cancelled.unavailable_detail();
        return state_;
    }
    const auto before = verify_guard_and_membership();
    if (!before.value()) { fail(*before.unavailable_detail()); return state_; }
    const auto read = guard_->read_content({request_.chunk_bytes},offset_,stop);
    if (!read.value()) { fail(*read.unavailable_detail()); return state_; }
    const auto size = *guard_->metadata().logical_size.value();
    if (offset_ > size || read.value()->bytes.size() > size - offset_ ||
        (read.value()->bytes.empty() && !read.value()->complete)) {
        fail(rejected("retained_target.read_length")); return state_;
    }
    hash_.update(read.value()->bytes); offset_ += read.value()->bytes.size();
    if (!read.value()->complete) return state_;
    const auto after = guard_->inspect_basic();
    if (!after.value()) { fail(*after.unavailable_detail()); return state_; }
    if (offset_ != size || hash_.digest() != request_.reviewed_digest || !version(request_.target->metadata(),*after.value())) {
        fail(rejected("retained_target.digest_or_version")); return state_;
    }
    const auto stable_after = verify_guard_and_membership();
    if (!stable_after.value()) { fail(*stable_after.unavailable_detail()); return state_; }
    const auto prepared = append(OperationJournalState::Prepared);
    if (!prepared.value()) { failure_ = *prepared.unavailable_detail(); state_ = RetainedTargetState::NeedsReconciliation; }
    else state_ = RetainedTargetState::Ready;
    return state_;
}
Observation<bool> RetainedTarget::retain(std::stop_token stop) {
    if (state_ == RetainedTargetState::Retained) return Observation<bool>::available(true);
    if (state_ != RetainedTargetState::Ready) return unavailable<bool>(rejected("retained_target.not_ready",ObservationState::Failed,AdapterError::PlanInvalid));
    if (stop.stop_requested()) return unavailable<bool>(rejected("retained_target.cancelled",ObservationState::Failed,AdapterError::InterruptedRead));
    const auto before = verify_guard_and_membership();
    if (!before.value()) return fail(*before.unavailable_detail());
    const auto ancestry = request_.revalidate_ancestors();
    if (!ancestry.value()) return fail(*ancestry.unavailable_detail());
    if (!*ancestry.value()) return fail(rejected("retained_target.ancestors_changed"));
    const auto after = verify_guard_and_membership();
    if (!after.value()) return fail(*after.unavailable_detail());
    const auto intended = append(OperationJournalState::CommitIntended);
    if (!intended.value()) { failure_ = *intended.unavailable_detail(); state_ = RetainedTargetState::NeedsReconciliation; return unavailable<bool>(*intended.unavailable_detail()); }
    // No cancel check after durable intent. A lease break while flushing intent
    // still refuses before namespace mutation and preserves the journal.
    const auto at_use = verify_guard_and_membership();
    if (!at_use.value()) return fail(*at_use.unavailable_detail());
    const auto renamed = guard_->rename_noreplace(*guard_->parent(),request_.retained_name);
    if (!renamed.value()) return fail(*renamed.unavailable_detail(),renamed.state() != ObservationState::Unsupported && renamed.state() != ObservationState::Denied && renamed.state() != ObservationState::Changed);
    if (!*renamed.value()) return fail(rejected("retained_target.invalid_rename",ObservationState::Unknown,AdapterError::InvalidNativeResult),true);
    evidence_.published_identity = evidence_.source_identity;
    for (const auto phase : {OperationJournalState::DestinationCommitted,OperationJournalState::SourceRemovalIntended,
             OperationJournalState::SourceRetired,OperationJournalState::Complete}) {
        const auto recorded = append(phase);
        if (!recorded.value()) { failure_ = *recorded.unavailable_detail(); state_ = RetainedTargetState::NeedsReconciliation; return unavailable<bool>(*recorded.unavailable_detail()); }
    }
    state_ = RetainedTargetState::Retained;
    return Observation<bool>::available(true);
}
} // namespace ck::files
